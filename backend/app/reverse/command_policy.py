"""Shared host/container command policy for Reverse tools."""

from __future__ import annotations

import os
import posixpath
import re
from typing import Any

WORKSPACE = "/workspace"
INPUTS = "/workspace/inputs"
OUTPUT = "/workspace/output"
TOOLS = "/workspace/tools"

# The model selects a logical identity; the broker supplies the absolute executable,
# so executable paths coming from the model are never trusted.
EXECUTABLE_PATHS: dict[str, str] = {
    "file": "/usr/bin/file",
    "strings": "/usr/bin/strings",
    "hexdump": "/usr/bin/hexdump",
    "xxd": "/usr/bin/xxd",
    "binwalk": "/usr/bin/binwalk",
    "python3": "/usr/bin/python3",
    "python": "/usr/bin/python3",
    "7z": "/usr/bin/7z",
    "7za": "/usr/bin/7za",
    "p7zip": "/usr/bin/7z",
    "unzip": "/usr/bin/unzip",
    "unrar": "/usr/bin/7z",
    "upx": "/usr/bin/upx-ucl",
    "sha256sum": "/usr/bin/sha256sum",
    "md5sum": "/usr/bin/md5sum",
    "sha1sum": "/usr/bin/sha1sum",
    "sha512sum": "/usr/bin/sha512sum",
    "cat": "/usr/bin/cat",
    "head": "/usr/bin/head",
    "tail": "/usr/bin/tail",
    "grep": "/usr/bin/grep",
    "awk": "/usr/bin/awk",
    "sed": "/usr/bin/sed",
    "cut": "/usr/bin/cut",
    "sort": "/usr/bin/sort",
    "uniq": "/usr/bin/uniq",
    "ls": "/usr/bin/ls",
    "find": "/usr/bin/find",
    "stat": "/usr/bin/stat",
    "wc": "/usr/bin/wc",
    "diff": "/usr/bin/diff",
    "cmp": "/usr/bin/cmp",
    "test": "/usr/bin/test",
    "mkdir": "/usr/bin/mkdir",
    "mv": "/usr/bin/mv",
    "chmod": "/usr/bin/chmod",
    "rm": "/usr/bin/rm",
    "readelf": "/usr/bin/readelf",
    "objdump": "/usr/bin/objdump",
    "nm": "/usr/bin/nm",
    "pecheck": "/usr/local/bin/pecheck",
    "yara": "/usr/bin/yara",
}

MUTATING_EXECUTABLES = {
    "mkdir", "mv", "chmod", "rm", "binwalk", "7z", "7za", "p7zip", "unzip", "unrar", "upx",
}
BLOCKED_TEXT = ("/proc/", "/sys/", "/dev/", "/etc/", "../", "..\\")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalize_workspace_path(value: str, cwd: str = WORKSPACE) -> str:
    if not isinstance(value, str) or not value or CONTROL_RE.search(value):
        raise ValueError("Path is empty or contains control characters")
    path = value if value.startswith("/") else posixpath.join(cwd, value)
    normalized = posixpath.normpath(path)
    if normalized != WORKSPACE and not normalized.startswith(WORKSPACE + "/"):
        raise ValueError("Path must remain within /workspace")
    return normalized


def _mutation_targets(executable: str, args: list[str], cwd: str) -> list[str]:
    targets: list[str] = []
    output_next = False
    for index, arg in enumerate(args):
        if output_next:
            targets.append(arg)
            output_next = False
            continue
        if executable == "unzip" and arg == "-d":
            output_next = True
            continue
        if executable == "binwalk" and arg in {"-C", "--directory"}:
            output_next = True
            continue
        if executable == "binwalk" and arg.startswith("--directory="):
            targets.append(arg.split("=", 1)[1])
            continue
        if arg.startswith("-"):
            if arg.startswith("-o") and len(arg) > 2:
                targets.append(arg[2:])
            continue
        if executable == "chmod" and index == 0 and re.fullmatch(r"[0-7]{3,4}", arg):
            continue
        if executable == "chmod" and index == 0 and re.fullmatch(r"[ugoa]+[+-=][rwxXst]+", arg):
            continue
        if executable in {"binwalk", "7z", "7za", "p7zip", "unzip", "unrar", "upx"}:
            # Input artifacts are legitimate non-option operands. Explicit output
            # switches/directories are checked above or by absolute-path checks.
            continue
        targets.append(arg)
    return [normalize_workspace_path(value, cwd) for value in targets]


def validate_run_command(cmd: list[str], cwd: str = WORKSPACE) -> tuple[bool, str]:
    if not isinstance(cmd, list) or not cmd or len(cmd) > 64:
        return False, "run_cmd requires 1-64 argv strings"
    if any(not isinstance(item, str) or not item or len(item) > 65_536 for item in cmd):
        return False, "Command arguments must be bounded non-empty strings"
    try:
        normalized_cwd = normalize_workspace_path(cwd)
    except ValueError as exc:
        return False, str(exc)
    executable = os.path.basename(cmd[0])
    if executable not in EXECUTABLE_PATHS:
        return False, f"NOT_IN_ALLOWLIST:{executable}"
    for arg in cmd[1:]:
        if CONTROL_RE.search(arg) or any(blocked in arg for blocked in BLOCKED_TEXT):
            return False, "Command argument violates the workspace policy"
        if arg.startswith("/"):
            try:
                normalize_workspace_path(arg, normalized_cwd)
            except ValueError as exc:
                return False, str(exc)
    if executable == "find" and any(
        arg in {"-exec", "-execdir", "-ok", "-okdir", "-delete"} for arg in cmd[1:]
    ):
        return False, "find execution and deletion actions are not allowed"
    if executable == "awk" and any(
        token in " ".join(cmd[1:]).lower() for token in ("system(", "getline", "|")
    ):
        return False, "awk process-launching constructs are not allowed"
    if executable == "sed":
        program = " ".join(cmd[1:])
        if re.search(r"(?:^|;)\s*e(?:\s|$)|s.*/e(?:\s|$)", program):
            return False, "sed execute commands are not allowed"
    if executable in {"python", "python3"}:
        args = cmd[1:]
        if args and args[0] not in {"-c", "-"}:
            try:
                script = normalize_workspace_path(args[0], normalized_cwd)
            except ValueError as exc:
                return False, str(exc)
            if not (script.startswith(OUTPUT + "/") or script.startswith(TOOLS + "/")):
                return False, "Python may execute only model-authored helpers under output/tools"
    if executable in MUTATING_EXECUTABLES:
        if normalized_cwd == INPUTS or normalized_cwd.startswith(INPUTS + "/"):
            return False, "Mutating commands cannot use the sealed input directory as cwd"
        if executable in {"7z", "7za", "p7zip", "unrar"}:
            operation = next((arg for arg in cmd[1:] if not arg.startswith("-")), "")
            if operation not in {"e", "l", "t", "x"}:
                return False, "Archive tools are limited to extract, list, and test operations"
        if executable == "upx" and "-d" not in cmd[1:]:
            return False, "UPX is limited to decompression with an explicit output"
        try:
            targets = _mutation_targets(executable, cmd[1:], normalized_cwd)
        except ValueError as exc:
            return False, str(exc)
        if any(path == INPUTS or path.startswith(INPUTS + "/") for path in targets):
            return False, "Commands cannot mutate sealed input artifacts"
        if executable == "upx" and "-d" in cmd[1:] and not any(
            arg.startswith("-o") for arg in cmd[1:]
        ):
            return False, "UPX decompression requires an explicit -o/workspace/output/... target"
    return True, "Command allowed"


def validate_tool_request(request: dict[str, Any]) -> tuple[bool, str]:
    tool = request.get("tool")
    if tool == "run_cmd":
        return validate_run_command(request.get("cmd"), request.get("cwd", WORKSPACE))
    if tool in {"read_file", "write_file", "list_dir"}:
        try:
            path = normalize_workspace_path(str(request.get("path") or ""))
        except ValueError as exc:
            return False, str(exc)
        if tool == "write_file" and not (
            path.startswith(OUTPUT + "/") or path.startswith(TOOLS + "/")
        ):
            return False, "write_file may write only below /workspace/output or /workspace/tools"
        return True, "Path allowed"
    return False, f"Unknown tool: {tool}"


def executable_for(requested: str) -> str:
    return EXECUTABLE_PATHS[os.path.basename(requested)]
