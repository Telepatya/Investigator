#!/usr/bin/env python3
"""Extract a MiniDump VA range or reconstruct an in-memory PE below output/."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, "/usr/local/lib/investigator")
from minidump_core import MiniDump, MiniDumpError


def number(value: str) -> int:
    return int(value, 0)


def safe_output(value: str) -> Path:
    root = Path("/workspace/output").resolve(strict=True)
    target = Path(value).resolve(strict=False)
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise MiniDumpError("output must remain beneath /workspace/output") from exc
    if target == root or target.is_symlink():
        raise MiniDumpError("invalid output path")
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dump")
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--start", type=number)
    choice.add_argument("--module")
    choice.add_argument("--candidate", type=int)
    parser.add_argument("--size", type=number)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        dump = MiniDump(args.dump)
        pe = None
        if args.start is not None:
            if args.size is None:
                raise MiniDumpError("--size is required with --start")
            content, missing = dump.read_virtual(args.start, args.size)
            mode = {"kind": "virtual_range", "start": args.start, "size": args.size}
        else:
            if args.module is not None:
                wanted = args.module.lower()
                module = next((row for row in dump.modules if wanted in {
                    row["name"].lower(), Path(row["name"].replace("\\", "/")).name.lower(),
                    row["base_hex"].lower(), str(row["base"]),
                }), None)
                if not module:
                    raise MiniDumpError(f"module not found: {args.module}")
                base = module["base"]
                mode = {"kind": "module", "module": module["name"], "base": base}
            else:
                candidates = dump.pe_candidates()
                if args.candidate is None or args.candidate < 0 or args.candidate >= len(candidates):
                    raise MiniDumpError("candidate index is out of range")
                base = candidates[args.candidate]["base"]
                mode = {"kind": "embedded_pe_candidate", "candidate": args.candidate, "base": base}
            content, missing, pe = dump.reconstruct_pe(base)
        if missing:
            print("ANALYSIS_BLOCKED " + json.dumps({"affected_ranges": missing, **mode}), file=os.sys.stderr)
            return 3
        output = safe_output(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
        with temporary.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
        print(json.dumps({"success": True, "output": str(output), "size": len(content),
                          "mode": mode, "pe": pe}, indent=2, sort_keys=True))
        return 0
    except (OSError, MiniDumpError, ValueError) as exc:
        print(json.dumps({"success": False, "error": str(exc)}), file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
