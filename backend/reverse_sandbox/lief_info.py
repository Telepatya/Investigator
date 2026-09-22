#!/usr/bin/env python3
"""Cross-format structural summary using pinned LIEF."""

from __future__ import annotations

import json
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: lief-info <binary>", file=sys.stderr)
        return 2
    try:
        import lief

        binary = lief.parse(sys.argv[1])
        if binary is None:
            raise ValueError("LIEF did not recognize the input")
        sections = []
        for section in list(getattr(binary, "sections", []) or [])[:4096]:
            sections.append({"name": str(section.name), "virtual_address": int(section.virtual_address),
                             "offset": int(section.offset), "size": int(section.size),
                             "entropy": float(section.entropy)})
        libraries = [str(item) for item in list(getattr(binary, "libraries", []) or [])[:4096]]
        result = {"success": True, "format": type(binary).__module__.split(".")[-1],
                  "entrypoint": int(getattr(binary, "entrypoint", 0) or 0),
                  "imagebase": int(getattr(binary, "imagebase", 0) or 0),
                  "sections": sections, "libraries": libraries,
                  "lief_version": lief.__version__}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
