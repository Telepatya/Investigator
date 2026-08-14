#!/usr/bin/env python3
"""Print deterministic JSON facts from a Windows MiniDump without executing it."""

from __future__ import annotations

import json
import sys

sys.path.insert(0, "/usr/local/lib/investigator")
from minidump_core import MiniDump, MiniDumpError


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: minidump-info <dump>", file=sys.stderr)
        return 2
    try:
        dump = MiniDump(sys.argv[1])
        ranges = []
        missing = []
        for row in dump.memory_ranges:
            info = dump.info_for(row.start)
            available = max(0, min(row.size, len(dump.data) - row.file_offset))
            item = {"start": row.start, "start_hex": f"0x{row.start:x}", "end": row.end,
                    "end_hex": f"0x{row.end:x}", "size": row.size,
                    "file_offset": row.file_offset,
                    "protection": info.get("protection") if info else None,
                    "state": info.get("state") if info else None,
                    "type": info.get("type") if info else None,
                    "backing_bytes": available}
            ranges.append(item)
            if available != row.size:
                missing.append({"start": row.start + available, "end": row.end,
                                "size": row.size - available, "reason": "truncated backing bytes"})
        threads = []
        for thread in dump.threads:
            ip = thread.get("instruction_pointer")
            module = dump.module_for(ip) if ip is not None else None
            memory = dump.info_for(ip) if ip is not None else None
            threads.append({**thread, "ip_module": module.get("name") if module else None,
                            "ip_protection": memory.get("protection") if memory else None,
                            "ip_private": bool(memory and memory.get("type") == 0x20000),
                            "ip_in_dump": dump.range_for(ip) is not None if ip is not None else False})
        result = {
            "success": True,
            "format": "Windows MiniDump",
            "stream_count": len(dump.streams),
            "streams": dump.streams,
            "architecture": dump.architecture,
            "flags": dump.flags,
            "timestamp": dump.timestamp,
            "modules": dump.modules,
            "threads": threads,
            "memory_ranges": ranges,
            "memory_info": dump.memory_info,
            "embedded_pe_candidates": dump.pe_candidates(),
            "missing_backing_ranges": missing,
            "analysis_blocked": bool(missing),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, MiniDumpError) as exc:
        print(json.dumps({"success": False, "error": str(exc),
                          "unsupported_structure": "unsupported structure" in str(exc).lower()}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
