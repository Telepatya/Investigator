#!/usr/bin/env python3
"""Targeted entry-point disassembly wrapper with fixed objdump identity and flags."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pefile


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: pedisasm FILE", file=sys.stderr)
        return 2
    path = Path(sys.argv[1]).resolve(strict=True)
    command = ["/usr/bin/objdump", "--disassemble", "-M", "intel"]
    try:
        pe = pefile.PE(str(path), fast_load=True)
        start = int(pe.OPTIONAL_HEADER.ImageBase) + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        command.extend([
            f"--start-address={start}",
            f"--stop-address={start + 0x2000}",
        ])
    except pefile.PEFormatError:
        pass
    command.extend(["--", str(path)])
    completed = subprocess.run(
        command,
        capture_output=True,
        timeout=30,
        shell=False,
    )
    sys.stdout.buffer.write(completed.stdout)
    sys.stderr.buffer.write(completed.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
