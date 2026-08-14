#!/usr/bin/env python3
"""Bounded pyelftools-backed ELF metadata and symbol inspection."""

from __future__ import annotations

import json
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: elf-inspect <elf>", file=sys.stderr)
        return 2
    try:
        from elftools.elf.elffile import ELFFile

        with open(sys.argv[1], "rb") as stream:
            elf = ELFFile(stream)
            sections = [{"name": section.name, "type": str(section["sh_type"]),
                         "address": int(section["sh_addr"]), "offset": int(section["sh_offset"]),
                         "size": int(section["sh_size"]), "flags": int(section["sh_flags"])}
                        for section in list(elf.iter_sections())[:4096]]
            segments = [{"type": str(segment["p_type"]), "virtual_address": int(segment["p_vaddr"]),
                         "file_size": int(segment["p_filesz"]),
                         "memory_size": int(segment["p_memsz"]), "flags": int(segment["p_flags"])}
                        for segment in list(elf.iter_segments())[:4096]]
            symbols = []
            for section in elf.iter_sections():
                if not hasattr(section, "iter_symbols"):
                    continue
                for symbol in section.iter_symbols():
                    if len(symbols) >= 20_000:
                        break
                    symbols.append({"name": symbol.name[:1000], "value": int(symbol["st_value"]),
                                    "size": int(symbol["st_size"]),
                                    "type": str(symbol["st_info"]["type"])})
            result = {"success": True, "format": "ELF", "class": elf.elfclass,
                      "little_endian": elf.little_endian, "machine": str(elf["e_machine"]),
                      "entry_point": int(elf["e_entry"]), "sections": sections,
                      "segments": segments, "symbols": symbols,
                      "symbol_count_returned": len(symbols)}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
