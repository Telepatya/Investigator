#!/usr/bin/env python3
"""Container broker for the one-operation Reverse tool protocol."""

from __future__ import annotations

import base64
import json
import os
import resource
import secrets
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/usr/local/lib/investigator")
from reverse_policy import (  # noqa: E402
    OUTPUT,
    TOOLS,
    WORKSPACE,
    executable_for,
    normalize_workspace_path,
    validate_tool_request,
)

MAX_REQUEST_BYTES = 1_900_000
MAX_WRITE_BYTES = 1_000_000
MAX_BROKER_OUTPUT = 2_000_000


def fail(message: str, code: int = 2) -> None:
    print(json.dumps({"success": False, "error": message[:4000]}))
    raise SystemExit(code)


def limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))


def contained_path(value: object, *, must_exist: bool = False) -> Path:
    try:
        normalized = normalize_workspace_path(str(value or ""))
        target = Path(normalized).resolve(strict=must_exist)
        target.relative_to(Path(WORKSPACE).resolve(strict=True))
    except (FileNotFoundError, ValueError):
        fail("Path escaped /workspace or does not exist")
    if target.is_symlink():
        fail("Symlink targets are not accepted")
    return target


def schema_ok(request: dict) -> bool:
    tool = request.get("tool")
    keys = set(request)
    if tool == "run_cmd":
        return {"tool", "cmd"}.issubset(keys) and keys <= {
            "tool", "cmd", "timeout", "cwd", "stdin_base64",
        }
    if tool == "read_file":
        return {"tool", "path"}.issubset(keys) and keys <= {"tool", "path", "max_bytes"}
    if tool == "write_file":
        return keys == {"tool", "path", "content_base64"}
    if tool == "list_dir":
        return keys == {"tool", "path"}
    return False


def run_cmd(request: dict) -> dict:
    cmd = request["cmd"]
    executable = os.path.basename(cmd[0])
    cwd = normalize_workspace_path(request.get("cwd", WORKSPACE))
    timeout = int(request.get("timeout", 30))
    if timeout < 1 or timeout > 300:
        fail("Invalid command timeout")
    command = [executable_for(executable), *cmd[1:]]
    if executable in {"python", "python3"}:
        command = ["/usr/local/bin/python-tool-runner", *cmd[1:]]
    stdin = request.get("stdin_base64") or ""
    try:
        stdin_bytes = base64.b64decode(stdin, validate=True) if stdin else None
    except ValueError:
        fail("stdin_base64 is malformed")
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            input=stdin_bytes,
            capture_output=True,
            timeout=timeout,
            shell=False,
            preexec_fn=limits,
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Command timed out after {timeout} seconds",
            "duration": time.monotonic() - started,
        }
    return {
        "success": completed.returncode == 0,
        "stdout": completed.stdout[:MAX_BROKER_OUTPUT].decode("utf-8", errors="replace"),
        "stderr": completed.stderr[:MAX_BROKER_OUTPUT].decode("utf-8", errors="replace"),
        "returncode": completed.returncode,
        "duration": time.monotonic() - started,
        "metadata": {"executable": executable, "args_count": len(cmd) - 1},
        "broker_truncated": (
            len(completed.stdout) > MAX_BROKER_OUTPUT or len(completed.stderr) > MAX_BROKER_OUTPUT
        ),
    }


def read_file(request: dict) -> dict:
    maximum = int(request.get("max_bytes", 100_000))
    if maximum < 1 or maximum > 10_000_000:
        fail("Invalid read_file size")
    path = contained_path(request["path"], must_exist=True)
    if not path.is_file():
        fail("read_file target is not a regular file")
    with path.open("rb") as handle:
        content = handle.read(maximum + 1)
    truncated = len(content) > maximum
    content = content[:maximum]
    return {
        "success": True,
        "content_base64": base64.b64encode(content).decode("ascii"),
        "truncated": truncated,
        "size": len(content),
    }


def write_file(request: dict) -> dict:
    path = contained_path(request["path"])
    if not (str(path).startswith(OUTPUT + os.sep) or str(path).startswith(TOOLS + os.sep)):
        fail("write_file target is outside output/tools")
    try:
        content = base64.b64decode(request["content_base64"], validate=True)
    except ValueError:
        fail("content_base64 is malformed")
    if len(content) > MAX_WRITE_BYTES:
        fail("write_file content exceeds 1,000,000 bytes")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                fail("write_file did not complete")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    return {"success": True, "size": len(content), "path": str(path)}


def list_dir(request: dict) -> dict:
    path = contained_path(request["path"], must_exist=True)
    if not path.is_dir():
        fail("list_dir target is not a directory")
    items = []
    for item in sorted(path.iterdir(), key=lambda entry: entry.name)[:2000]:
        if item.is_symlink():
            continue
        stat = item.stat()
        items.append({
            "name": item.name,
            "type": "directory" if item.is_dir() else "file",
            "size": stat.st_size if item.is_file() else 0,
            "modified": stat.st_mtime,
        })
    return {"success": True, "items": items}


def versions() -> None:
    commands = {
        "python": ["/usr/bin/python3", "--version"],
        "file": ["/usr/bin/file", "--version"],
        "binutils": ["/usr/bin/objdump", "--version"],
        "binwalk": ["/usr/bin/binwalk", "--help"],
        "upx": ["/usr/bin/upx-ucl", "--version"],
        "yara": ["/usr/bin/yara", "--version"],
        "7z": ["/usr/bin/7z"],
    }
    result = {}
    for name, command in commands.items():
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=5, shell=False)
            lines = [line.strip() for line in (completed.stdout or completed.stderr).splitlines() if line.strip()]
            result[name] = lines[0][:200] if lines else "unknown"
        except Exception:
            result[name] = "unavailable"
    print(json.dumps(result, sort_keys=True))


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--versions":
        versions()
        return
    if len(sys.argv) != 2:
        fail("Expected one encoded tool request")
    try:
        raw = base64.urlsafe_b64decode(sys.argv[1].encode())
        if len(raw) > MAX_REQUEST_BYTES:
            fail("Tool request is too large")
        request = json.loads(raw)
    except Exception:
        fail("Malformed tool request")
    if not isinstance(request, dict) or not schema_ok(request):
        fail("Tool request failed container schema validation")
    allowed, reason = validate_tool_request(request)
    if not allowed:
        fail(reason)
    handlers = {
        "run_cmd": run_cmd,
        "read_file": read_file,
        "write_file": write_file,
        "list_dir": list_dir,
    }
    try:
        result = handlers[request["tool"]](request)
    except SystemExit:
        raise
    except Exception as exc:
        result = {"success": False, "error": str(exc)[:4000]}
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
