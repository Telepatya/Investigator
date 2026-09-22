#!/usr/bin/env python3
"""Bounded PE reverse-engineering metadata; never maps or executes sample code."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pefile


CAPABILITY_APIS = {
    "process execution": {"createprocess", "shellexecute", "winexec", "createthread"},
    "process injection": {
        "virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection",
        "queueuserapc", "setthreadcontext", "openprocess",
    },
    "services and persistence": {
        "createservice", "startservice", "openservice", "regsetvalue", "schtasks",
        "setwindowshookex",
    },
    "networking": {
        "internetopen", "internetconnect", "httpopenrequest", "winhttpopen", "wsastartup",
        "connect", "send", "recv", "urldownloadtofile", "dnsquery",
    },
    "filesystem": {
        "createfile", "writefile", "deletefile", "movefile", "copyfile", "findfirstfile",
    },
    "registry": {"regopenkey", "regcreatekey", "regsetvalue", "regdeletevalue"},
    "anti-analysis": {
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "gettickcount", "queryperformancecounter",
    },
    "credentials and tokens": {
        "credread", "cryptunprotectdata", "openprocesstoken", "adjusttokenprivileges",
        "logonuser", "lsaopenpolicy",
    },
    "cryptography": {"cryptencrypt", "cryptdecrypt", "bcryptencrypt", "bcryptdecrypt"},
    "named-pipe IPC": {"createnamedpipe", "connectnamedpipe", "callnamedpipe", "waitnamedpipe"},
}


def decoded(value: bytes | None) -> str:
    return value.decode("utf-8", errors="replace") if value else ""


def bounded_strings(data: bytes) -> list[str]:
    ascii_values = [decoded(match) for match in re.findall(rb"[\x20-\x7e]{6,}", data)]
    wide_values = [decoded(match.replace(b"\x00", b"")) for match in re.findall(
        rb"(?:[\x20-\x7e]\x00){6,}", data
    )]
    unique: list[str] = []
    seen: set[str] = set()
    for value in ascii_values + wide_values:
        if value not in seen:
            seen.add(value)
            unique.append(value[:500])
        if len(unique) >= 400:
            break
    return unique


def resource_count(pe: pefile.PE) -> int:
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if not root:
        return 0
    count = 0
    stack = [root]
    while stack and count < 10000:
        node = stack.pop()
        for entry in getattr(node, "entries", [])[:512]:
            count += 1
            directory = getattr(entry, "directory", None)
            if directory:
                stack.append(directory)
    return count


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: pecheck FILE", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    data = path.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)

    imports = []
    import_symbols: list[str] = []
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:128]:
        names = []
        for item in descriptor.imports[:256]:
            name = decoded(item.name) if item.name else f"ordinal:{item.ordinal}"
            names.append(name)
            import_symbols.append(name)
        imports.append({"dll": decoded(descriptor.dll), "symbols": names})

    delay_imports = []
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])[:64]:
        names = [decoded(item.name) if item.name else f"ordinal:{item.ordinal}"
                 for item in descriptor.imports[:256]]
        delay_imports.append({"dll": decoded(descriptor.dll), "symbols": names})
        import_symbols.extend(names)

    exports = []
    export_directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_directory:
        exports = [
            {"name": decoded(item.name) or None, "ordinal": int(item.ordinal), "address": hex(int(item.address))}
            for item in export_directory.symbols[:512]
        ]

    entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    entry_section = None
    sections = []
    packing_indicators = []
    suspicious_names = {"upx0", "upx1", "upx2", ".aspack", ".adata", "petite", ".packed"}
    for section in pe.sections[:128]:
        name = decoded(section.Name.rstrip(b"\x00"))
        characteristics = int(section.Characteristics)
        executable = bool(characteristics & 0x20000000)
        writable = bool(characteristics & 0x80000000)
        entropy = round(float(section.get_entropy()), 3)
        start = int(section.VirtualAddress)
        span = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        if start <= entry_rva < start + span:
            entry_section = name
        if executable and writable:
            packing_indicators.append(f"writable and executable section: {name}")
        if executable and entropy >= 7.2:
            packing_indicators.append(f"high-entropy executable section: {name} ({entropy})")
        if name.lower() in suspicious_names:
            packing_indicators.append(f"packer-associated section name: {name}")
        sections.append({
            "name": name,
            "virtual_address": hex(start),
            "virtual_size": int(section.Misc_VirtualSize),
            "raw_size": int(section.SizeOfRawData),
            "entropy": entropy,
            "executable": executable,
            "writable": writable,
            "characteristics": hex(characteristics),
        })
    if entry_section is None:
        packing_indicators.append("entry point is not contained in a declared section")
    if len(import_symbols) <= 5 and len(data) > 32 * 1024:
        packing_indicators.append("unusually small import surface for file size")

    overlay_offset = pe.get_overlay_data_start_offset()
    overlay = data[overlay_offset:] if overlay_offset is not None else b""
    if overlay:
        packing_indicators.append(f"overlay data present ({len(overlay)} bytes)")

    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    security = directories[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    dll_chars = int(pe.OPTIONAL_HEADER.DllCharacteristics)
    strings = bounded_strings(data)
    evidence_tokens = [value.lower() for value in import_symbols + strings]
    capabilities = []
    for capability, needles in CAPABILITY_APIS.items():
        matches = sorted({
            token for token in evidence_tokens
            if any(needle in token for needle in needles)
        })[:20]
        if matches:
            capabilities.append({"capability": capability, "evidence": matches})

    pdb_paths = []
    for match in re.findall(rb"RSDS.{20}([^\x00]{1,500})\x00", data, re.DOTALL)[:20]:
        pdb_paths.append(decoded(match))

    result = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": hex(int(pe.FILE_HEADER.Machine)),
        "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
        "entry_point_rva": hex(entry_rva),
        "entry_point_section": entry_section,
        "image_base": hex(int(pe.OPTIONAL_HEADER.ImageBase)),
        "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
        "imphash": pe.get_imphash() or None,
        "mitigations": {
            "aslr": bool(dll_chars & 0x0040),
            "dep_nx": bool(dll_chars & 0x0100),
            "high_entropy_va": bool(dll_chars & 0x0020),
            "control_flow_guard": bool(dll_chars & 0x4000),
        },
        "digital_signature": {
            "present": bool(security.VirtualAddress and security.Size),
            "size": int(security.Size),
        },
        "tls": {
            "present": bool(tls),
            "callback_table_address": hex(int(tls.struct.AddressOfCallBacks)) if tls else None,
        },
        "resources": {"entry_count": resource_count(pe)},
        "pdb_paths": pdb_paths,
        "overlay": {
            "offset": overlay_offset,
            "size": len(overlay),
            "sha256": hashlib.sha256(overlay).hexdigest() if overlay else None,
        },
        "sections": sections,
        "imports": imports,
        "delay_imports": delay_imports,
        "exports": exports,
        "capability_hints": capabilities,
        "packing_indicators": packing_indicators,
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
