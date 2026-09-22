#!/usr/bin/env python3
"""Bounded MiniDump parser shared by the offline inspection/extraction CLIs."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

STREAM_NAMES = {
    3: "ThreadListStream", 4: "ModuleListStream", 5: "MemoryListStream",
    6: "ExceptionStream", 7: "SystemInfoStream", 8: "ThreadExListStream",
    9: "Memory64ListStream", 15: "MiscInfoStream", 16: "MemoryInfoListStream",
}
ARCH_NAMES = {0: "x86", 5: "arm", 9: "amd64", 12: "arm64"}
PROTECT_NAMES = {
    0x01: "PAGE_NOACCESS", 0x02: "PAGE_READONLY", 0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY", 0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE", 0x80: "PAGE_EXECUTE_WRITECOPY",
}
MAX_STREAMS = 4096
MAX_RECORDS = 200_000
MAX_EXTRACT = 512 * 1024 * 1024


class MiniDumpError(ValueError):
    pass


@dataclass(frozen=True)
class MemoryRange:
    start: int
    size: int
    file_offset: int

    @property
    def end(self) -> int:
        return self.start + self.size


class MiniDump:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if len(self.data) < 32 or self.data[:4] != b"MDMP":
            raise MiniDumpError("unsupported structure: DOS/PE input is not a MiniDump")
        self.version, count, directory = struct.unpack_from("<III", self.data, 4)
        self.timestamp = struct.unpack_from("<I", self.data, 20)[0]
        self.flags = struct.unpack_from("<Q", self.data, 24)[0]
        if count > MAX_STREAMS:
            raise MiniDumpError(f"unsupported structure: stream count {count} exceeds {MAX_STREAMS}")
        self.streams = []
        self.by_type: dict[int, list[tuple[int, int]]] = {}
        self._bounds(directory, count * 12, "stream directory")
        for index in range(count):
            stream_type, size, rva = struct.unpack_from("<III", self.data, directory + index * 12)
            self._bounds(rva, size, f"stream {stream_type}")
            item = {"index": index, "type": stream_type,
                    "name": STREAM_NAMES.get(stream_type, f"StreamType{stream_type}"),
                    "size": size, "rva": rva}
            self.streams.append(item)
            self.by_type.setdefault(stream_type, []).append((rva, size))
        self.architecture = self._system_info()
        self.modules = self._modules()
        self.memory_ranges = self._memory_ranges()
        self.memory_info = self._memory_info()
        self.threads = self._threads()

    def _bounds(self, offset: int, size: int, label: str) -> None:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise MiniDumpError(f"truncated {label}: file range {offset:#x}+{size:#x} is unavailable")

    def _stream(self, stream_type: int) -> tuple[int, int] | None:
        rows = self.by_type.get(stream_type) or []
        return rows[0] if rows else None

    def _utf16(self, rva: int) -> str:
        if not rva:
            return ""
        self._bounds(rva, 4, "UTF-16 string length")
        size = struct.unpack_from("<I", self.data, rva)[0]
        if size > 2 * 1024 * 1024:
            raise MiniDumpError("unsupported structure: oversized UTF-16 string")
        self._bounds(rva + 4, size, "UTF-16 string")
        return self.data[rva + 4:rva + 4 + size].decode("utf-16-le", errors="replace")

    def _system_info(self) -> dict:
        stream = self._stream(7)
        if not stream or stream[1] < 24:
            return {"code": None, "name": "unknown"}
        rva, _ = stream
        arch, level, revision = struct.unpack_from("<HHH", self.data, rva)
        processors, product = struct.unpack_from("<BB", self.data, rva + 6)
        major, minor, build, platform = struct.unpack_from("<IIII", self.data, rva + 8)
        return {"code": arch, "name": ARCH_NAMES.get(arch, f"architecture-{arch}"),
                "processor_level": level, "processor_revision": revision,
                "processor_count": processors, "product_type": product,
                "os_version": f"{major}.{minor}.{build}", "platform_id": platform}

    def _modules(self) -> list[dict]:
        stream = self._stream(4)
        if not stream:
            return []
        rva, size = stream
        if size < 4:
            raise MiniDumpError("truncated module list")
        count = struct.unpack_from("<I", self.data, rva)[0]
        if count > MAX_RECORDS or 4 + count * 108 > size:
            raise MiniDumpError("unsupported structure: invalid module list size")
        rows = []
        for index in range(count):
            offset = rva + 4 + index * 108
            base, image_size, checksum, timestamp, name_rva = struct.unpack_from(
                "<QIIII", self.data, offset
            )
            rows.append({"index": index, "base": base, "base_hex": f"0x{base:x}",
                         "end": base + image_size, "size": image_size,
                         "checksum": checksum, "timestamp": timestamp,
                         "name": self._utf16(name_rva)})
        return rows

    def _memory_ranges(self) -> list[MemoryRange]:
        ranges: list[MemoryRange] = []
        stream64 = self._stream(9)
        if stream64:
            rva, size = stream64
            if size < 16:
                raise MiniDumpError("truncated Memory64ListStream")
            count, base_rva = struct.unpack_from("<QQ", self.data, rva)
            if count > MAX_RECORDS or 16 + count * 16 > size:
                raise MiniDumpError("unsupported structure: invalid memory64 list")
            file_offset = base_rva
            for index in range(count):
                start, length = struct.unpack_from("<QQ", self.data, rva + 16 + index * 16)
                ranges.append(MemoryRange(start, length, file_offset))
                file_offset += length
        stream = self._stream(5)
        if stream:
            rva, size = stream
            if size < 4:
                raise MiniDumpError("truncated MemoryListStream")
            count = struct.unpack_from("<I", self.data, rva)[0]
            if count > MAX_RECORDS or 4 + count * 16 > size:
                raise MiniDumpError("unsupported structure: invalid memory list")
            for index in range(count):
                start, length, file_rva = struct.unpack_from("<QII", self.data, rva + 4 + index * 16)
                ranges.append(MemoryRange(start, length, file_rva))
        return sorted({(row.start, row.size, row.file_offset): row for row in ranges}.values(),
                      key=lambda row: (row.start, row.file_offset))

    def _memory_info(self) -> list[dict]:
        stream = self._stream(16)
        if not stream:
            return []
        rva, size = stream
        if size < 16:
            raise MiniDumpError("truncated MemoryInfoListStream")
        header_size, entry_size, count = struct.unpack_from("<IIQ", self.data, rva)
        if entry_size < 48 or count > MAX_RECORDS or header_size + count * entry_size > size:
            raise MiniDumpError("unsupported structure: invalid memory info list")
        rows = []
        for index in range(count):
            offset = rva + header_size + index * entry_size
            base, allocation_base = struct.unpack_from("<QQ", self.data, offset)
            allocation_protect = struct.unpack_from("<I", self.data, offset + 16)[0]
            region_size = struct.unpack_from("<Q", self.data, offset + 24)[0]
            state, protect, kind = struct.unpack_from("<III", self.data, offset + 32)
            rows.append({"base": base, "end": base + region_size, "size": region_size,
                         "allocation_base": allocation_base,
                         "allocation_protect": allocation_protect, "state": state,
                         "protect": protect, "protection": PROTECT_NAMES.get(protect & 0xff, f"0x{protect:x}"),
                         "type": kind})
        return rows

    def _threads(self) -> list[dict]:
        stream = self._stream(3) or self._stream(8)
        if not stream:
            return []
        rva, size = stream
        if size < 4:
            raise MiniDumpError("truncated thread list")
        count = struct.unpack_from("<I", self.data, rva)[0]
        entry_size = 64 if self._stream(8) == stream else 48
        if count > MAX_RECORDS or 4 + count * entry_size > size:
            raise MiniDumpError("unsupported structure: invalid thread list")
        rows = []
        for index in range(count):
            offset = rva + 4 + index * entry_size
            tid, suspend, priority_class, priority, teb = struct.unpack_from("<IIIIQ", self.data, offset)
            stack_start, stack_size, stack_rva = struct.unpack_from("<QII", self.data, offset + 24)
            context_size, context_rva = struct.unpack_from("<II", self.data, offset + 40)
            ip = self._instruction_pointer(context_rva, context_size)
            rows.append({"index": index, "thread_id": tid, "suspend_count": suspend,
                         "priority_class": priority_class, "priority": priority, "teb": teb,
                         "stack_start": stack_start, "stack_size": stack_size,
                         "stack_rva": stack_rva, "context_rva": context_rva,
                         "context_size": context_size, "instruction_pointer": ip,
                         "instruction_pointer_hex": f"0x{ip:x}" if ip is not None else None})
        return rows

    def _instruction_pointer(self, rva: int, size: int) -> int | None:
        if not rva or not size or rva + size > len(self.data):
            return None
        arch = self.architecture.get("name")
        candidates = ((248, 8), (256, 8)) if arch == "amd64" else ((184, 4), (188, 4))
        for offset, width in candidates:
            if size >= offset + width:
                value = int.from_bytes(self.data[rva + offset:rva + offset + width], "little")
                if value:
                    return value
        return None

    def range_for(self, address: int) -> MemoryRange | None:
        return next((row for row in self.memory_ranges if row.start <= address < row.end), None)

    def module_for(self, address: int) -> dict | None:
        exact = [row for row in self.modules if row["base"] == address]
        if exact:
            return min(exact, key=lambda row: row["size"])
        containing = [row for row in self.modules if row["base"] <= address < row["end"]]
        return min(containing, key=lambda row: row["size"], default=None)

    def info_for(self, address: int) -> dict | None:
        return next((row for row in self.memory_info if row["base"] <= address < row["end"]), None)

    def read_virtual(self, start: int, size: int) -> tuple[bytes, list[dict]]:
        if size < 0 or size > MAX_EXTRACT:
            raise MiniDumpError(f"requested extraction exceeds {MAX_EXTRACT} bytes")
        output = bytearray()
        missing = []
        current = start
        end = start + size
        while current < end:
            row = self.range_for(current)
            if not row:
                next_start = min((item.start for item in self.memory_ranges if item.start > current), default=end)
                gap_end = min(end, next_start)
                missing.append({"start": current, "end": gap_end, "size": gap_end - current,
                                "reason": "virtual range absent from dump"})
                current = gap_end
                continue
            take = min(end, row.end) - current
            file_offset = row.file_offset + current - row.start
            if file_offset + take > len(self.data):
                missing.append({"start": current, "end": current + take, "size": take,
                                "reason": "range backing bytes truncated"})
            else:
                output.extend(self.data[file_offset:file_offset + take])
            current += take
        return bytes(output), missing

    def pe_header(self, base: int) -> dict | None:
        header, missing = self.read_virtual(base, 4096)
        if missing or len(header) < 0x100 or header[:2] != b"MZ":
            return None
        pe_offset = struct.unpack_from("<I", header, 0x3c)[0]
        if pe_offset > len(header) - 24 or header[pe_offset:pe_offset + 4] != b"PE\0\0":
            return None
        sections = struct.unpack_from("<H", header, pe_offset + 6)[0]
        optional_size = struct.unpack_from("<H", header, pe_offset + 20)[0]
        optional = pe_offset + 24
        magic = struct.unpack_from("<H", header, optional)[0]
        if magic not in {0x10b, 0x20b}:
            return None
        entry_rva = struct.unpack_from("<I", header, optional + 16)[0]
        image_size = struct.unpack_from("<I", header, optional + 56)[0]
        headers_size = struct.unpack_from("<I", header, optional + 60)[0]
        section_offset = optional + optional_size
        parsed = []
        for index in range(min(sections, 96)):
            offset = section_offset + index * 40
            if offset + 40 > len(header):
                break
            name = header[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", header, offset + 8)
            characteristics = struct.unpack_from("<I", header, offset + 36)[0]
            parsed.append({"name": name, "virtual_size": virtual_size,
                           "virtual_address": virtual_address, "raw_size": raw_size,
                           "raw_offset": raw_offset, "characteristics": characteristics})
        return {"base": base, "entry_rva": entry_rva, "entry_point": base + entry_rva,
                "image_size": image_size, "headers_size": headers_size,
                "bitness": 64 if magic == 0x20b else 32, "sections": parsed}

    def pe_candidates(self, limit: int = 256) -> list[dict]:
        rows = []
        seen: set[int] = set()
        for memory in self.memory_ranges:
            if len(rows) >= limit or memory.file_offset >= len(self.data):
                break
            available = min(memory.size, len(self.data) - memory.file_offset)
            blob = self.data[memory.file_offset:memory.file_offset + available]
            position = blob.find(b"MZ")
            while position >= 0 and len(rows) < limit:
                base = memory.start + position
                if base not in seen:
                    header = self.pe_header(base)
                    if header:
                        seen.add(base)
                        module = self.module_for(base)
                        info = self.info_for(base)
                        rows.append({**header, "index": len(rows), "base_hex": f"0x{base:x}",
                                     "listed_module": module["name"] if module else None,
                                     "protection": info.get("protection") if info else None,
                                     "private": bool(info and info.get("type") == 0x20000)})
                position = blob.find(b"MZ", position + 2)
        return rows

    def reconstruct_pe(self, base: int) -> tuple[bytes, list[dict], dict]:
        pe = self.pe_header(base)
        if not pe:
            raise MiniDumpError(f"no valid in-memory PE header at 0x{base:x}")
        maximum = max(
            [pe["headers_size"], *(
                section["raw_offset"] + section["raw_size"] for section in pe["sections"]
            )]
        )
        if maximum <= 0 or maximum > MAX_EXTRACT:
            raise MiniDumpError("reconstructed PE exceeds extraction limit")
        output = bytearray(maximum)
        missing: list[dict] = []
        headers, gaps = self.read_virtual(base, min(pe["headers_size"], maximum))
        output[:len(headers)] = headers
        missing.extend(gaps)
        for section in pe["sections"]:
            size = min(section["raw_size"], max(section["virtual_size"], section["raw_size"]))
            if not size:
                continue
            content, gaps = self.read_virtual(base + section["virtual_address"], size)
            raw_offset = section["raw_offset"]
            output[raw_offset:raw_offset + len(content)] = content
            missing.extend(gaps)
        return bytes(output), missing, pe
