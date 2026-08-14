#!/usr/bin/env python3
"""Bounded, non-executing PyInstaller CArchive inspection and bytecode disassembly."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import struct
import sys
import zlib
from pathlib import Path
from typing import Any

MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
MAX_ENTRIES = 4096
MAX_EXTRACTED_BYTES = 64 * 1024 * 1024
MAX_DISASSEMBLY_CHARS = 500_000


def invariant(
    name: str, passed: bool, expected: Any, actual: Any, severity: str = "error"
) -> dict[str, Any]:
    return {
        "name": name, "passed": bool(passed), "severity": severity,
        "expected": expected, "actual": actual,
    }


def bounded_decompress(data: bytes, expected_size: int) -> bytes:
    if expected_size < 0 or expected_size > MAX_EXTRACTED_BYTES:
        raise ValueError(f"declared expanded size {expected_size} exceeds the safety limit")
    decoder = zlib.decompressobj()
    expanded = decoder.decompress(data, MAX_EXTRACTED_BYTES + 1)
    expanded += decoder.flush(MAX_EXTRACTED_BYTES + 1 - len(expanded))
    if len(expanded) > MAX_EXTRACTED_BYTES or decoder.unconsumed_tail:
        raise ValueError("expanded entry exceeds the safety limit")
    return expanded


def python_version(value: int) -> str:
    major = value // 100
    minor = value % 100
    return f"{major}.{minor}"


def inspect_archive(path: Path) -> tuple[dict[str, Any], bytes]:
    data = path.read_bytes()
    file_size = len(data)
    cookie_offset = data.rfind(MAGIC)
    if cookie_offset < 0:
        raise ValueError("PyInstaller CArchive cookie magic was not found")
    remaining = file_size - cookie_offset
    cookie_size = 88 if remaining >= 88 else 24
    if remaining < cookie_size:
        raise ValueError("PyInstaller cookie is truncated")
    _magic, package_length, toc_offset, toc_length, pyver = struct.unpack_from(
        "!8sIIII", data, cookie_offset
    )
    cookie_end = cookie_offset + cookie_size
    package_base = cookie_end - package_length
    toc_start = package_base + toc_offset
    toc_end = toc_start + toc_length
    checks = [
        invariant("cookie_within_file", cookie_end <= file_size, f"<= {file_size}", cookie_end),
        invariant("package_base_non_negative", package_base >= 0, ">= 0", package_base),
        invariant("toc_within_package", package_base <= toc_start <= toc_end <= cookie_offset, f"{package_base}..{cookie_offset}", f"{toc_start}..{toc_end}"),
        invariant("cookie_ends_at_eof", cookie_end == file_size, file_size, cookie_end, "warning"),
    ]
    if not all(item["passed"] for item in checks[:3]):
        raise ValueError("PyInstaller cookie/TOC bounds are inconsistent")

    entries: list[dict[str, Any]] = []
    cursor = toc_start
    while cursor < toc_end and len(entries) < MAX_ENTRIES:
        if cursor + 18 > toc_end:
            checks.append(invariant("toc_entry_header", False, f"<= {toc_end}", cursor + 18))
            break
        entry_size, position, packed_size, unpacked_size, compressed, typecode = struct.unpack_from(
            "!iIIIBc", data, cursor
        )
        if entry_size < 18 or cursor + entry_size > toc_end:
            checks.append(invariant("toc_entry_size", False, f"18..{toc_end - cursor}", entry_size))
            break
        raw_name = data[cursor + 18:cursor + entry_size].split(b"\0", 1)[0]
        name = raw_name.decode("utf-8", errors="replace")
        absolute = package_base + position
        range_valid = package_base <= absolute <= absolute + packed_size <= toc_start
        header = data[absolute:absolute + min(4, packed_size)].hex() if range_valid else ""
        entries.append({
            "index": len(entries),
            "name": name,
            "type": typecode.decode("ascii", errors="replace"),
            "compressed": bool(compressed),
            "position": position,
            "absolute_offset": absolute,
            "packed_size": packed_size,
            "unpacked_size": unpacked_size,
            "range_valid": range_valid,
            "header_hex": header,
            "zlib_header_plausible": bool(
                range_valid and packed_size >= 2 and data[absolute] == 0x78
                and ((data[absolute] << 8) + data[absolute + 1]) % 31 == 0
            ) if compressed else None,
        })
        cursor += entry_size
    checks.append(invariant("toc_fully_parsed", cursor == toc_end, toc_end, cursor))
    checks.append(invariant("entry_limit", len(entries) < MAX_ENTRIES or cursor == toc_end, f"<= {MAX_ENTRIES}", len(entries)))
    invalid_ranges = [entry["index"] for entry in entries if not entry["range_valid"]]
    checks.append(invariant("entry_ranges_within_package", not invalid_ranges, [], invalid_ranges[:32]))

    declared = python_version(pyver)
    runtime = f"{sys.version_info.major}.{sys.version_info.minor}"
    warnings: list[str] = []
    if declared != runtime:
        warnings.append(
            f"Embedded Python {declared} bytecode is not runtime-compatible with Python {runtime}; use xdis rather than marshal/dis from the host runtime."
        )
    result = {
        "success": True,
        "format": "pyinstaller-carchive",
        "path": str(path),
        "file_size": file_size,
        "sha256": hashlib.sha256(data).hexdigest(),
        "cookie_offset": cookie_offset,
        "cookie_size": cookie_size,
        "cookie_end": cookie_end,
        "package_length": package_length,
        "package_base": package_base,
        "toc_offset": toc_offset,
        "toc_length": toc_length,
        "python_version": declared,
        "runtime_python": runtime,
        "bytecode_runtime_compatible": declared == runtime,
        "invariants": checks,
        "entries": entries,
        "warnings": warnings,
    }
    return result, data


def entry_payload(result: dict[str, Any], data: bytes, selector: str) -> tuple[dict[str, Any], bytes]:
    entry = next(
        (item for item in result["entries"] if item["name"] == selector),
        None,
    )
    if entry is None and selector.isdigit():
        index = int(selector)
        entry = next((item for item in result["entries"] if item["index"] == index), None)
    if entry is None:
        raise ValueError(f"archive entry not found: {selector}")
    if not entry["range_valid"]:
        raise ValueError(f"archive entry has invalid bounds: {selector}")
    start = int(entry["absolute_offset"])
    packed = data[start:start + int(entry["packed_size"])]
    payload = bounded_decompress(packed, int(entry["unpacked_size"])) if entry["compressed"] else packed
    if len(payload) != int(entry["unpacked_size"]):
        raise ValueError(
            f"entry size mismatch: declared {entry['unpacked_size']}, decoded {len(payload)}"
        )
    return entry, payload


def safe_output(value: str) -> Path:
    target = Path(value).resolve()
    output = Path("/workspace/output").resolve()
    try:
        target.relative_to(output)
    except ValueError as exc:
        raise ValueError("extraction output must remain below /workspace/output") from exc
    if target.is_symlink():
        raise ValueError("symlink output targets are not accepted")
    return target


def disassemble(payload: bytes, version: str) -> str:
    try:
        from xdis.disasm import disco
        from xdis.magics import by_version, magic2int
        from xdis.unmarshal import load_code
    except ImportError as exc:
        raise ValueError("xdis is unavailable in this sandbox image") from exc
    magic = by_version.get(version)
    if not magic:
        raise ValueError(f"xdis has no magic mapping for Python {version}")
    magic_int = magic2int(magic)
    code = load_code(io.BytesIO(payload), magic_int, bytes_for_s=True, code_objects={})
    rendered = io.StringIO()
    parts = tuple(int(item) for item in version.split("."))
    disco(parts, code, 0, out=rendered, magic_int=magic_int)
    value = rendered.getvalue()
    return value[:MAX_DISASSEMBLY_CHARS]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("--extract", metavar="NAME_OR_INDEX")
    parser.add_argument("--output")
    parser.add_argument("--disassemble", metavar="NAME_OR_INDEX")
    args = parser.parse_args()
    try:
        result, data = inspect_archive(Path(args.archive))
        if args.extract:
            if not args.output:
                raise ValueError("--extract requires --output")
            entry, payload = entry_payload(result, data, args.extract)
            output = safe_output(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
            temporary.write_bytes(payload)
            os.replace(temporary, output)
            result["extraction"] = {
                "entry": entry["name"], "output": str(output), "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        if args.disassemble:
            entry, payload = entry_payload(result, data, args.disassemble)
            result["disassembly"] = {
                "entry": entry["name"],
                "engine": "xdis",
                "python_version": result["python_version"],
                "text": disassemble(payload, result["python_version"]),
            }
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)[:4000]}))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
