#!/usr/bin/env python3
"""Run model-authored Python helpers under restricted semantics inside Docker."""

from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

WORKSPACE = Path("/workspace").resolve()
INPUTS = (WORKSPACE / "inputs").resolve()
OUTPUT = (WORKSPACE / "output").resolve()
TOOLS = (WORKSPACE / "tools").resolve()
TMP = Path("/tmp").resolve()
READ_ROOTS = (
    WORKSPACE,
    Path("/usr/lib/python3.10").resolve(),
    Path("/usr/lib/python3/dist-packages").resolve(),
    Path("/usr/local/lib/python3.10").resolve(),
    TMP,
)


def contained(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root)
        return True
    except ValueError:
        return False


def validate_script(value: str) -> Path:
    script = Path(value).resolve(strict=True)
    if not script.is_file() or script.is_symlink():
        raise PermissionError("Python helper is not a regular file")
    if not (contained(script, OUTPUT) or contained(script, TOOLS)):
        raise PermissionError("Python may execute only helpers below output/tools")
    return script


def write_requested(mode: object, flags: object) -> bool:
    if isinstance(mode, str) and any(marker in mode for marker in ("w", "a", "x", "+")):
        return True
    if isinstance(flags, int):
        mask = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        return bool(flags & mask)
    return False


def allowed_mutation_path(value: object) -> bool:
    if isinstance(value, int):
        return True
    try:
        path = Path(os.fsdecode(value)).resolve(strict=False)
    except (TypeError, ValueError):
        return False
    return contained(path, OUTPUT) or contained(path, TOOLS) or contained(path, TMP)


def allowed_read_path(value: object) -> bool:
    if isinstance(value, int):
        return True
    try:
        path = Path(os.fsdecode(value)).resolve(strict=False)
    except (TypeError, ValueError):
        return False
    return any(contained(path, root) for root in READ_ROOTS)


def audit(event: str, args: tuple[object, ...]) -> None:
    denied_prefixes = (
        "socket.", "subprocess.", "ctypes.", "pty.",
        "os.exec", "os.spawn", "os.posix_spawn", "os.fork", "os.system",
    )
    if event.startswith(denied_prefixes) or event == "builtins.breakpoint":
        raise PermissionError(f"Python analysis policy blocked audit event: {event}")
    if event in {"os.kill", "os.killpg"}:
        raise PermissionError(f"Python analysis policy blocked audit event: {event}")
    if event == "open" and args:
        mode = args[1] if len(args) > 1 else None
        flags = args[2] if len(args) > 2 else None
        if write_requested(mode, flags) and not allowed_mutation_path(args[0]):
            raise PermissionError("Python helpers may write only below output/tools or /tmp")
        if not write_requested(mode, flags) and not allowed_read_path(args[0]):
            raise PermissionError("Python helpers may read only workspace and Python library paths")
    if event in {
        "os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.chown",
        "os.link", "os.symlink", "os.truncate", "os.rename",
    }:
        path_args = args[:2] if event in {"os.rename", "os.link", "os.symlink"} else args[:1]
        if any(not allowed_mutation_path(value) for value in path_args):
            raise PermissionError("Python helpers cannot mutate sealed inputs or the root filesystem")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python3 [-c CODE | HELPER.py] [args...]", file=sys.stderr)
        return 2
    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    TOOLS.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONHASHSEED"] = "0"
    sys.dont_write_bytecode = True
    sys.addaudithook(audit)
    if sys.argv[1] == "-c":
        if len(sys.argv) < 3 or len(sys.argv[2].encode("utf-8")) > 60_000:
            raise ValueError("Python -c source is empty or exceeds 60,000 bytes")
        source = sys.argv[2]
        compile(source, "<reverse-helper>", "exec")
        sys.argv = ["-c", *sys.argv[3:]]
        namespace = {"__name__": "__main__", "__file__": "<reverse-helper>"}
        exec(compile(source, "<reverse-helper>", "exec"), namespace, namespace)
        return 0
    if sys.argv[1] == "-":
        source = sys.stdin.buffer.read(60_001)
        if len(source) > 60_000:
            raise ValueError("Python stdin source exceeds 60,000 bytes")
        code = compile(source, "<reverse-stdin-helper>", "exec")
        sys.argv = ["-", *sys.argv[2:]]
        namespace = {"__name__": "__main__", "__file__": "<reverse-stdin-helper>"}
        exec(code, namespace, namespace)
        return 0
    script = validate_script(sys.argv[1])
    sys.argv = [str(script), *sys.argv[2:]]
    runpy.run_path(str(script), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
