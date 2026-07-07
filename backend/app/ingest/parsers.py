"""Parsers for endpoint evidence: Velociraptor JSONL/JSON/CSV/EVTX/ZIP collections
and Microsoft Defender Advanced Hunting (Device* table) JSON/CSV exports."""

from __future__ import annotations

import csv
import json
import re
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.ingest.normalize import (
    decode_win_codes,
    extract_entity,
    extract_host,
    extract_timestamp,
    summarize_row,
    truncate,
)

# Map artifact-name fragments to event categories
CATEGORY_HINTS = [
    ("pslist", "process"),
    ("process", "process"),
    ("netstat", "network"),
    ("network", "network"),
    ("connections", "network"),
    ("dns", "network"),
    ("services", "persistence"),
    ("autoruns", "persistence"),
    ("scheduledtasks", "persistence"),
    ("startup", "persistence"),
    ("runkeys", "persistence"),
    ("wmi", "persistence"),
    ("evtx", "eventlog"),
    ("eventlogs", "eventlog"),
    ("security", "eventlog"),
    ("prefetch", "execution"),
    ("amcache", "execution"),
    ("shimcache", "execution"),
    ("bam", "execution"),
    ("userassist", "execution"),
    ("mft", "filesystem"),
    ("ntfs", "filesystem"),
    ("timeline", "filesystem"),
    ("recyclebin", "filesystem"),
    ("usn", "filesystem"),
    ("users", "account"),
    ("logon", "account"),
    ("browser", "browser"),
    ("chrome", "browser"),
    ("firefox", "browser"),
    ("edge", "browser"),
]


def categorize(source_name: str) -> str:
    lower = source_name.lower()
    for fragment, category in CATEGORY_HINTS:
        if fragment in lower:
            return category
    return "artifact"


def normalize_row(row: dict[str, Any], source: str) -> dict[str, Any]:
    """Convert a raw artifact row into unified Event kwargs."""
    if _is_vr_evtx_row(row):
        return _normalize_vr_evtx_row(row, source)
    if _is_usn_journal_row(row, source):
        return _normalize_usn_journal_row(row, source)
    if _is_defender_row(row, source):
        return _normalize_defender_row(row, source)
    return {
        "timestamp": extract_timestamp(row),
        "host": extract_host(row),
        "source": source,
        "category": categorize(source),
        "entity": extract_entity(row),
        "severity": "info",
        "summary": summarize_row(row),
        "raw": _json_safe(row),
    }


_USN_REASON_BITS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x80000000: "CLOSE",
}


def _row_get(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value
    wanted = {name.lower().replace(" ", "").replace("_", "") for name in names}
    for key, value in row.items():
        if (
            isinstance(key, str)
            and key.lower().replace(" ", "").replace("_", "") in wanted
            and value not in (None, "")
        ):
            return value
    return None


def _usn_reason_tokens(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(v).upper() for v in value if str(v).strip()]
    text = str(value).strip()
    try:
        number = int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        number = None
    if number is not None:
        return [name for bit, name in _USN_REASON_BITS.items() if number & bit]
    tokens = [
        token.upper()
        for token in re.split(r"[^A-Za-z0-9_]+", text)
        if token and token.upper() not in {"USN", "REASON"}
    ]
    return tokens


def _usn_action(tokens: list[str]) -> str:
    token_set = set(tokens)
    if "RENAME_NEW_NAME" in token_set:
        return "rename_new"
    if "RENAME_OLD_NAME" in token_set:
        return "rename_old"
    if "FILE_CREATE" in token_set:
        return "create"
    if "FILE_DELETE" in token_set:
        return "delete"
    if "CLOSE" in token_set and len(token_set) == 1:
        return "close"
    if token_set & {"DATA_OVERWRITE", "DATA_EXTEND", "DATA_TRUNCATION", "BASIC_INFO_CHANGE"}:
        return "modify"
    return "change"


def _usn_path(row: dict[str, Any]) -> str:
    value = _row_get(
        row,
        "FullPath", "OSPath", "Path", "TargetFilename", "TargetPath",
        "FilePath", "Name", "FileName", "Filename",
    )
    return str(value).strip() if value not in (None, "") else ""


def _usn_file_reference(row: dict[str, Any]) -> str:
    value = _row_get(
        row,
        "FileReferenceNumber", "FileReference", "FileId", "FileID",
        "FileIdentifier", "MFTReference", "MFTId", "MFTID", "FRN",
    )
    seq = _row_get(row, "Sequence", "SequenceNumber", "Seq", "MFTSequence")
    if value in (None, ""):
        return ""
    ref = str(value).strip()
    return f"{ref}:{str(seq).strip()}" if seq not in (None, "") else ref


def _is_usn_journal_row(row: dict[str, Any], source: str) -> bool:
    lower_source = (source or "").lower()
    source_hint = any(hint in lower_source for hint in ("usn", "$j", "journal"))
    reason = _row_get(row, "Reason", "UpdateReason", "USNReason")
    return bool(source_hint and reason and _usn_path(row))


def _normalize_usn_journal_row(row: dict[str, Any], source: str) -> dict[str, Any]:
    raw = _json_safe(row)
    if not isinstance(raw, dict):
        raw = dict(row)
    path = _usn_path(row)
    tokens = _usn_reason_tokens(_row_get(row, "Reason", "UpdateReason", "USNReason"))
    action = _usn_action(tokens)
    reason = "|".join(tokens) if tokens else str(_row_get(row, "Reason") or "change")
    file_ref = _usn_file_reference(row)
    raw.update({
        "usn_journal": True,
        "UsnAction": action,
        "UsnReasonTokens": tokens,
        "UsnPath": path,
        "UsnFileName": _basename(path),
        "UsnFileReference": file_ref,
    })
    return {
        "timestamp": extract_timestamp(row),
        "host": extract_host(row),
        "source": source,
        "category": "filesystem",
        "entity": path,
        "severity": "info",
        "summary": f"$J USN {action.replace('_', ' ')}: {path} ({reason})",
        "raw": raw,
    }


# ---------------------------------------------------------------------------
# Microsoft Defender / M365 Advanced Hunting (Device* tables)
# ---------------------------------------------------------------------------
# Exported Advanced Hunting rows are flat dicts with a stable column vocabulary
# (DeviceName, ActionType, InitiatingProcess*). They map onto the same unified
# Event/Process schema as Sysmon/EVTX, so once normalized the existing detection,
# correlation, process-tree and timeline machinery works over them unchanged.
# All recognition is gated behind _is_defender_row so non-Defender rows are
# parsed exactly as before.

_DEFENDER_INITIATING_KEYS = (
    "InitiatingProcessFileName", "InitiatingProcessCommandLine",
    "InitiatingProcessId", "InitiatingProcessAccountName",
    "InitiatingProcessFolderPath",
)

_DEFENDER_TABLE_NAMES = (
    "deviceprocessevents", "devicenetworkevents", "devicefileevents",
    "deviceregistryevents", "devicelogonevents", "deviceimageloadevents",
    "devicenetworkinfo", "deviceevents", "deviceinfo",
)


def _dstr(raw: dict[str, Any], *names: str) -> str:
    """First non-empty value among names (case/underscore-insensitive), stripped."""
    val = _row_get(raw, *names)
    return str(val).strip() if val not in (None, "") else ""


def _defender_source_table(source: str) -> str:
    """Defender table name inferred from the source/filename, else ''."""
    low = (source or "").lower()
    for name in _DEFENDER_TABLE_NAMES:
        if name in low:
            return name
    return "advancedhunting" if "advancedhunting" in low else ""


def _is_defender_row(row: dict[str, Any], source: str) -> bool:
    """Recognize a Microsoft Defender Advanced Hunting export row."""
    if _defender_source_table(source):
        return True
    if _row_get(row, "DeviceId", "DeviceName") in (None, ""):
        return False
    if _row_get(row, "ActionType") not in (None, ""):
        return True
    return any(_row_get(row, key) not in (None, "") for key in _DEFENDER_INITIATING_KEYS)


def _defender_table(row: dict[str, Any], source: str) -> str:
    """Resolve the Advanced Hunting table: explicit column, then source name,
    then a column-signature fallback so a table is always chosen."""
    explicit = _dstr(row, "Type", "_TableName", "TableName").lower()
    for name in _DEFENDER_TABLE_NAMES:
        if explicit and name in explicit:
            return name
    table = _defender_source_table(source)
    if table and table != "advancedhunting":
        return table
    action = _dstr(row, "ActionType").lower()
    if "logon" in action or "logoff" in action or _dstr(row, "LogonType"):
        return "devicelogonevents"
    if "registry" in action or _dstr(row, "RegistryKey", "RegistryValueName"):
        return "deviceregistryevents"
    if _dstr(row, "RemoteIP", "RemotePort") or action in ("connectionsuccess", "connectionfailed", "inboundconnectionaccepted"):
        return "devicenetworkevents"
    if _dstr(row, "FileOriginUrl", "PreviousFileName", "PreviousFolderPath") or action.startswith("file"):
        return "devicefileevents"
    if action == "imageloaded":
        return "deviceimageloadevents"
    if (_dstr(row, "ProcessCommandLine") and _dstr(row, "ProcessId")) or action == "processcreated":
        return "deviceprocessevents"
    return table or "advancedhunting"


def _defender_proc(raw: dict[str, Any]) -> str:
    """Initiating (parent) process basename for a Defender row."""
    return _basename(_dstr(raw, "InitiatingProcessFolderPath")) or _dstr(raw, "InitiatingProcessFileName")


def _defender_additional_fields(raw: dict[str, Any]) -> dict[str, Any]:
    """Parse the DeviceEvents AdditionalFields JSON blob (a string) into a dict.
    Returns {} when absent or unparseable."""
    val = _row_get(raw, "AdditionalFields")
    if isinstance(val, dict):
        return val
    if isinstance(val, str) and val.strip():
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {}


# DeviceEvents ActionTypes that describe cross-process access/injection. Mapped to
# a synthetic Sysmon EventID so the engine's existing _check_cross_process_event
# detection fires (remote-thread family -> 8, process-access/memory family -> 10).
_DEFENDER_REMOTE_THREAD_ACTIONS = {
    "createremotethreadapicall", "queueuserapcremoteapicall",
    "setthreadcontextremoteapicall",
}
_DEFENDER_PROC_ACCESS_ACTIONS = {
    "openprocessapicall", "readprocessmemoryapicall", "writeprocessmemoryapicall",
    "writetolsassprocessmemory", "ntallocatevirtualmemoryremoteapicall",
    "ntprotectvirtualmemoryremoteapicall", "ntmapviewofsectionremoteapicall",
}


def _map_defender_injection(event: dict[str, Any], raw: dict[str, Any], action: str) -> bool:
    """Stamp the raw keys the engine's cross-process detection reads for injection
    DeviceEvents. Returns True when the row was an injection action, else False."""
    al = action.lower()
    if al in _DEFENDER_REMOTE_THREAD_ACTIONS:
        eid = "8"
    elif al in _DEFENDER_PROC_ACCESS_ACTIONS:
        eid = "10"
    else:
        return False

    extra = _defender_additional_fields(raw)

    def af(*names: str) -> str:
        return _dstr(extra, *names) if extra else ""

    source = _dstr(raw, "InitiatingProcessFolderPath") or _dstr(raw, "InitiatingProcessFileName")
    source_pid = _dstr(raw, "InitiatingProcessId")
    # For injection DeviceEvents the acted-upon (target) process is the row-level
    # FileName/FolderPath; AdditionalFields carries target pid / access details.
    target = (_dstr(raw, "FolderPath") or _dstr(raw, "FileName")
              or af("TargetImageFileName", "TargetFileName", "TargetImage"))
    target_pid = af("TargetProcessId", "TargetPID") or _dstr(raw, "TargetProcessId")
    granted = af("GrantedAccess", "DesiredAccess", "AccessMask")

    # No Channel is set (Defender rows have none), so _eid_channel_ok passes EID 8/10.
    raw["EventID"] = eid
    if source:
        raw["SourceImage"] = source
    if source_pid:
        raw["SourceProcessId"] = source_pid
    if target:
        raw["TargetImage"] = target
    if target_pid:
        raw["TargetProcessId"] = target_pid
    if granted:
        raw["GrantedAccess"] = granted
    start_addr = af("StartAddress", "RemoteThreadStartAddress")
    if start_addr:
        raw["StartAddress"] = start_addr

    event["category"] = "process"
    event["entity"] = _basename(source) or event.get("entity")
    verb = "created a remote thread in" if eid == "8" else "accessed"
    event["summary"] = (
        f"{action}: {_basename(source) or 'process'} {verb} "
        f"{_basename(target) or '<unknown>'}"
        + (f" (access {granted})" if granted else "")
    )
    return True


def _defender_file_tokens(action: str) -> list[str]:
    """USN-style reason tokens for a DeviceFileEvents ActionType, so the engine's
    existing file-lifecycle collectors track Defender file changes like a USN journal."""
    return {
        "filecreated": ["FILE_CREATE"],
        "filerenamed": ["RENAME_NEW_NAME"],
        "filedeleted": ["FILE_DELETE"],
    }.get(action.lower(), [])


def _map_defender_process(event: dict[str, Any], raw: dict[str, Any]) -> None:
    image = _dstr(raw, "FolderPath") or _dstr(raw, "FileName")
    base = _basename(image) or _dstr(raw, "FileName")
    event["category"] = "process"
    event["entity"] = base or event.get("entity")
    cmd = _dstr(raw, "ProcessCommandLine")
    parent = _defender_proc(raw)
    summary = f"Process created: {image or base or '<unknown>'}"
    if cmd:
        summary += f" — {truncate(cmd, 300)}"
    if parent:
        summary += f" (parent: {parent})"
    event["summary"] = summary


def _map_defender_network(event: dict[str, Any], raw: dict[str, Any]) -> None:
    event["category"] = "network"
    proc = _defender_proc(raw)
    event["entity"] = proc or event.get("entity")
    # Copy into the raw keys the detection engine consumes for network events
    # (identical shape to the Sysmon EID-3 mapping, so C2/beacon rules fire).
    for key, src in (("Raddr", "RemoteIP"), ("Rport", "RemotePort"),
                     ("Laddr", "LocalIP"), ("Lport", "LocalPort"), ("Proto", "Protocol")):
        val = _dstr(raw, src)
        if val:
            raw[key] = val
    url = _dstr(raw, "RemoteUrl")
    if url and not raw.get("Url"):
        raw["Url"] = url
    remote = _dstr(raw, "RemoteIP") or url
    summary = f"{proc or 'unknown'} → {remote or '<unknown>'}"
    if _dstr(raw, "RemotePort"):
        summary += f":{_dstr(raw, 'RemotePort')}"
    if _dstr(raw, "Protocol"):
        summary += f" ({_dstr(raw, 'Protocol')})"
    if url and url != remote:
        summary += f", url {truncate(url, 200)}"
    event["summary"] = summary


def _map_defender_file(event: dict[str, Any], raw: dict[str, Any]) -> None:
    action = _dstr(raw, "ActionType")
    path = _dstr(raw, "FolderPath") or _dstr(raw, "FileName")
    name = _dstr(raw, "FileName") or _basename(path)
    event["category"] = "filesystem"
    event["entity"] = name or event.get("entity")
    proc = _defender_proc(raw)

    # Download provenance: FileOriginUrl/ReferrerUrl feed the existing
    # _download_evidence/_download_origin logic (Url/ReferrerUrl/FullPath are
    # already the keys it reads), so URL→file→process chains reconstruct.
    origin = _dstr(raw, "FileOriginUrl")
    referrer = _dstr(raw, "FileOriginReferrerUrl")
    if origin and not raw.get("Url"):
        raw["Url"] = origin
    if referrer and not raw.get("ReferrerUrl"):
        raw["ReferrerUrl"] = referrer
    if path and not raw.get("FullPath"):
        raw["FullPath"] = path

    # File-lifecycle: mirror the synthetic USN keys _normalize_usn_journal_row
    # emits, so the engine's create/rename/delete collectors track this file.
    tokens = _defender_file_tokens(action)
    if tokens:
        raw["usn_journal"] = True
        raw["UsnReasonTokens"] = tokens
        raw["UsnPath"] = path
        raw["UsnFileName"] = name
        # File content hash is a stable identity across create/rename/delete.
        raw["UsnFileReference"] = _dstr(raw, "SHA256", "SHA1", "MD5")
        prev = _dstr(raw, "PreviousFolderPath") or _dstr(raw, "PreviousFileName")
        if prev:
            raw["PreviousFileFullPath"] = prev

    verb = {
        "filecreated": "created", "filerenamed": "renamed",
        "filedeleted": "deleted", "filemodified": "modified",
    }.get(action.lower(), "touched")
    if action.lower() == "filerenamed" and raw.get("PreviousFileFullPath"):
        summary = f"{proc or 'process'} renamed {raw['PreviousFileFullPath']} → {path or name}"
    else:
        summary = f"{proc or 'process'} {verb} {path or name or '<unknown>'}"
    if origin:
        summary += f" (from {truncate(origin, 200)})"
    event["summary"] = summary


def _map_defender_deviceevents(event: dict[str, Any], raw: dict[str, Any]) -> None:
    action = _dstr(raw, "ActionType")
    # Cross-process access / injection: feed the engine's existing EID 8/10 detection.
    if _map_defender_injection(event, raw, action):
        return
    proc = _defender_proc(raw)
    url = _dstr(raw, "RemoteUrl")
    if ("browserlaunched" in action.lower()) or (url and "url" in action.lower()):
        event["category"] = "browser"
        event["entity"] = url or proc or event.get("entity")
        if url and not raw.get("Url"):
            raw["Url"] = url
        event["summary"] = f"Site visited: {truncate(url, 200) or '<unknown>'}" + (
            f" (by {proc})" if proc else "")
        return
    event["category"] = "eventlog"
    event["entity"] = proc or event.get("entity")
    if url and not raw.get("Url"):
        raw["Url"] = url
    detail = _dstr(raw, "FileName") or url or _dstr(raw, "RemoteIP")
    event["summary"] = (f"{action}" if action else "Device event") + (
        f": {truncate(detail, 200)}" if detail else "") + (f" (by {proc})" if proc else "")


def _map_defender_registry(event: dict[str, Any], raw: dict[str, Any]) -> None:
    event["category"] = "persistence"
    key = _dstr(raw, "RegistryKey")
    val = _dstr(raw, "RegistryValueName")
    if key and not raw.get("KeyPath"):
        # The engine matches PERSISTENCE_REGISTRY_PATHS against raw KeyPath.
        raw["KeyPath"] = key
    event["entity"] = val or key or event.get("entity")
    proc = _defender_proc(raw)
    action = _dstr(raw, "ActionType")
    data = _dstr(raw, "RegistryValueData")
    summary = f"{action or 'Registry change'}: {key}" + (f"\\{val}" if val else "")
    if data:
        summary += f" = {truncate(data, 200)}"
    if proc:
        summary += f" (by {proc})"
    event["summary"] = summary


def _map_defender_logon(event: dict[str, Any], raw: dict[str, Any]) -> None:
    event["category"] = "account"
    user = _dstr(raw, "AccountName") or _dstr(raw, "AccountUpn")
    event["entity"] = user or event.get("entity")
    ltype = _dstr(raw, "LogonType")
    remote = _dstr(raw, "RemoteIP") or _dstr(raw, "RemoteDeviceName")
    action = _dstr(raw, "ActionType") or "Logon"
    domain = _dstr(raw, "AccountDomain")
    summary = f"{action}: {domain + chr(92) if domain else ''}{user or '<unknown>'}"
    if ltype:
        summary += f" (type {ltype})"
    if remote:
        summary += f" from {remote}"
    event["summary"] = summary


def _map_defender_imageload(event: dict[str, Any], raw: dict[str, Any]) -> None:
    event["category"] = "process"
    proc = _defender_proc(raw)
    img = _dstr(raw, "FolderPath") or _dstr(raw, "FileName")
    event["entity"] = proc or event.get("entity")
    event["summary"] = f"Image loaded: {img or '<unknown>'}" + (f" by {proc}" if proc else "")


def _map_defender_generic(event: dict[str, Any], raw: dict[str, Any]) -> None:
    table = str(raw.get("_defender_table") or "")
    event["category"] = categorize(table) if table else "artifact"
    event["entity"] = _defender_proc(raw) or event.get("entity")
    action = _dstr(raw, "ActionType")
    event["summary"] = (f"{action}: " if action else "") + summarize_row(raw)


_DEFENDER_TABLE_MAPPERS = {
    "deviceprocessevents": _map_defender_process,
    "devicenetworkevents": _map_defender_network,
    "devicefileevents": _map_defender_file,
    "deviceevents": _map_defender_deviceevents,
    "deviceregistryevents": _map_defender_registry,
    "devicelogonevents": _map_defender_logon,
    "deviceimageloadevents": _map_defender_imageload,
}


def _normalize_defender_row(row: dict[str, Any], source: str) -> dict[str, Any]:
    table = _defender_table(row, source)
    raw = _json_safe(row)
    if not isinstance(raw, dict):
        raw = dict(row)
    raw["_defender_table"] = table
    host = _dstr(raw, "DeviceName", "DeviceId")
    event: dict[str, Any] = {
        "timestamp": extract_timestamp(row),
        "host": host or extract_host(row),
        "source": source,
        "category": "artifact",
        "entity": None,
        "severity": "info",
        "summary": "",
        "raw": raw,
    }
    _DEFENDER_TABLE_MAPPERS.get(table, _map_defender_generic)(event, raw)
    if not event.get("entity"):
        init = _dstr(raw, "InitiatingProcessFileName")
        event["entity"] = _basename(init) or host or f"Defender {table}"
    if not event.get("summary"):
        event["summary"] = summarize_row(raw)
    return event


def _is_plain_json(obj: Any) -> bool:
    """True if obj is composed only of types json.dumps serializes unchanged,
    so _json_safe can return it as-is without a serialize round-trip."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return True
    if isinstance(obj, dict):
        return all(
            isinstance(k, str) and _is_plain_json(v) for k, v in obj.items()
        )
    if isinstance(obj, list):
        return all(_is_plain_json(v) for v in obj)
    return False


def _json_safe(obj: Any) -> Any:
    # Fast path: plain-JSON objects serialize unchanged and json.dumps would
    # return them as-is, so skip the per-row dumps. Note json.dumps also accepts
    # int/float dict keys and tuples; those fall through to the exact old path.
    if _is_plain_json(obj):
        return obj
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return json.loads(json.dumps(obj, default=str))


def parse_jsonl(path: Path, source: str) -> Iterator[dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                yield normalize_row(row, source)


def parse_json(path: Path, source: str) -> Iterator[dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        prefix = f.read(4096).lstrip()
    if prefix.startswith("["):
        yield from _parse_json_array_stream(path, source)
        return
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return
    if isinstance(data, dict):
        data = [data]
    if isinstance(data, list):
        for row in data:
            if isinstance(row, dict):
                yield normalize_row(row, source)


def _parse_json_array_stream(path: Path, source: str) -> Iterator[dict[str, Any]]:
    """Stream a top-level JSON array without materializing large artifacts."""
    decoder = json.JSONDecoder()
    buf = ""
    in_array = False
    done = False

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        while not done:
            chunk = f.read(1024 * 1024)
            if chunk:
                buf += chunk
            elif not buf.strip():
                break

            while True:
                buf = buf.lstrip()
                if not in_array:
                    if not buf:
                        break
                    if buf[0] != "[":
                        return
                    buf = buf[1:]
                    in_array = True
                    continue
                if not buf:
                    break
                if buf[0] == "]":
                    done = True
                    buf = buf[1:]
                    break
                if buf[0] == ",":
                    buf = buf[1:]
                    continue
                try:
                    row, idx = decoder.raw_decode(buf)
                except json.JSONDecodeError:
                    if chunk:
                        break
                    return
                buf = buf[idx:]
                if isinstance(row, dict):
                    yield normalize_row(row, source)
            if not chunk and not done:
                break


def parse_csv(path: Path, source: str) -> Iterator[dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        try:
            reader = csv.DictReader(f)
            for row in reader:
                if row:
                    yield normalize_row(dict(row), source)
        except csv.Error:
            return


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


def _basename(path: Any) -> str:
    """Filename component of a Windows/Unix path ('' when absent)."""
    p = str(path or "").strip().strip('"').replace("/", "\\").rstrip("\\")
    return p.rsplit("\\", 1)[-1].strip()


def _map_sysmon_event(event: dict[str, Any], row: dict[str, Any], eid: str) -> None:
    """Per-EventID mapping for Sysmon operational events (mutates event in place)."""
    raw = event["raw"]

    def g(key: str) -> str:
        val = row.get(key)
        return str(val).strip() if val not in (None, "") else ""

    image = g("Image")
    base = _basename(image)
    if eid == "1":
        event["category"] = "process"
        event["entity"] = base or event.get("entity")
        summary = f"Process created: {image or '<unknown>'}"
        cmdline = g("CommandLine")
        if cmdline:
            summary += f" — {truncate(cmdline, 300)}"
        details = [d for d in (
            f"parent: {_basename(g('ParentImage'))}" if g("ParentImage") else "",
            f"user: {g('User')}" if g("User") else "",
        ) if d]
        if details:
            summary += f" ({', '.join(details)})"
        event["summary"] = summary
    elif eid == "3":
        event["category"] = "network"
        event["entity"] = base or event.get("entity")
        # Copy into the raw keys the detection engine consumes for network events
        raw["Raddr"] = g("DestinationIp")
        raw["Rport"] = g("DestinationPort")
        raw["Laddr"] = g("SourceIp")
        raw["Lport"] = g("SourcePort")
        raw["Proto"] = g("Protocol")
        summary = (
            f"{base or image or 'unknown'} → "
            f"{g('DestinationIp')}:{g('DestinationPort')} ({g('Protocol')})"
        )
        if g("DestinationHostname"):
            summary += f", hostname {g('DestinationHostname')}"
        event["summary"] = summary
    elif eid == "5":
        event["category"] = "process"
        event["entity"] = base or event.get("entity")
        event["summary"] = f"Process terminated: {image or '<unknown>'}"
    elif eid == "7":
        event["category"] = "process"
        event["entity"] = base or event.get("entity")
        event["summary"] = f"Image loaded: {image or '<unknown>'} loaded {g('ImageLoaded')}"
    elif eid == "8":
        src_img = g("SourceImage")
        event["category"] = "process"
        event["entity"] = _basename(src_img) or event.get("entity")
        # Inherently notable at ingest; the detect engine may escalate further
        event["severity"] = "medium"
        event["summary"] = (
            f"CreateRemoteThread: {src_img} → {g('TargetImage')} (start {g('StartAddress')})"
        )
    elif eid == "10":
        src_img = g("SourceImage")
        event["category"] = "process"
        event["entity"] = _basename(src_img) or event.get("entity")
        event["summary"] = (
            f"ProcessAccess: {src_img} → {g('TargetImage')} (access {g('GrantedAccess')})"
        )
    elif eid == "11":
        event["category"] = "filesystem"
        event["entity"] = base or event.get("entity")
        event["summary"] = f"{base or image or 'unknown'} created {g('TargetFilename')}"
    elif eid in ("12", "13", "14"):
        event["category"] = "persistence"
        event["entity"] = base or event.get("entity")
        target = g("TargetObject")
        # The engine matches PERSISTENCE_REGISTRY_PATHS against raw KeyPath
        raw["KeyPath"] = target
        action = g("EventType") or {
            "12": "Registry object added/deleted",
            "13": "Registry value set",
            "14": "Registry key/value renamed",
        }[eid]
        summary = f"{action}: {target}"
        if eid == "13" and g("Details"):
            summary += f" = {truncate(g('Details'), 200)}"
        if base:
            summary += f" (by {base})"
        event["summary"] = summary
    elif eid == "22":
        event["category"] = "network"
        event["entity"] = base or event.get("entity")
        event["summary"] = f"DNS query: {g('QueryName')} → {truncate(g('QueryResults'), 200)}"
    else:
        event["category"] = "eventlog"
        if base:
            event["entity"] = base


def _map_security_4688(event: dict[str, Any], row: dict[str, Any]) -> None:
    """Security 4688 (process creation) mapped to a first-class process event."""
    raw = event["raw"]
    new_proc = str(row.get("NewProcessName") or "").strip()
    base = _basename(new_proc)
    event["category"] = "process"
    if base:
        event["entity"] = base
    cmdline = str(row.get("CommandLine") or "").strip()
    if not cmdline:
        # some renderings name the field e.g. "Process Command Line"
        for k, v in row.items():
            if (
                isinstance(k, str) and v not in (None, "")
                and k.lower().replace(" ", "").replace("_", "") == "processcommandline"
            ):
                cmdline = str(v).strip()
                break
    if cmdline and not raw.get("CommandLine"):
        raw["CommandLine"] = cmdline
    parent = _basename(row.get("ParentProcessName"))
    summary = f"Process created: {new_proc or '<unknown>'}"
    if cmdline:
        summary += f" — {truncate(cmdline, 300)}"
    if parent:
        summary += f" (parent: {parent})"
    event["summary"] = summary


# Windows event log account/logon activity mapped to the "account" category
_ACCOUNT_EVENT_IDS = {
    "4624", "4625", "4634", "4647", "4648", "4672", "4720", "4722",
    "4724", "4725", "4726", "4728", "4732", "4756",
}
_LOGON_TYPE_NAMES = {
    "2": "interactive", "3": "network", "4": "batch", "5": "service",
    "7": "unlock", "8": "network-cleartext", "9": "new-credentials",
    "10": "remote-interactive (RDP)", "11": "cached-interactive",
}


def _is_vr_evtx_row(row: dict[str, Any]) -> bool:
    """Velociraptor Windows.EventLogs.* rows: nested System dict + EventData/Message."""
    return isinstance(row.get("System"), dict) and (
        "EventData" in row or "UserData" in row or "Message" in row or "EventID" in row
    )


def _flatten_vr_evtx_row(row: dict[str, Any]) -> dict[str, Any]:
    """Flatten a Velociraptor EVTX row so EventData fields sit at the top level of
    raw, where the detection engine, entity graph, and process extraction read them.
    Drops the bulky System envelope and truncates the rendered Message."""
    system = row.get("System") if isinstance(row.get("System"), dict) else {}
    flat: dict[str, Any] = {}

    event_data = row.get("EventData")
    if isinstance(event_data, dict):
        data = event_data.get("Data")
        if isinstance(data, list) and set(event_data) <= {"Data", "Binary"}:
            # classic providers emit unnamed positional values
            flat["Data"] = [str(d) for d in data]
        else:
            flat.update(event_data)
    user_data = row.get("UserData")
    if isinstance(user_data, dict):
        for v in user_data.values():
            if isinstance(v, dict):
                flat.update(v)

    eid = row.get("EventID", system.get("EventID"))
    if isinstance(eid, dict):
        eid = eid.get("Value")
    provider = system.get("Provider")
    if isinstance(provider, dict):
        provider = provider.get("Name")
    flat["EventID"] = eid
    flat["Channel"] = row.get("Channel") or system.get("Channel")
    if provider:
        flat["Provider"] = provider
    computer = system.get("Computer")
    if computer:
        flat["Computer"] = computer
    record_id = row.get("EventRecordID", system.get("EventRecordID"))
    if record_id is not None:
        flat["EventRecordID"] = record_id
    if row.get("TimeCreated"):
        flat["TimeCreated"] = row["TimeCreated"]
    if row.get("OSPath"):
        flat["OSPath"] = row["OSPath"]
    message = row.get("Message")
    if isinstance(message, str) and message.strip():
        flat["Message"] = truncate(message.strip(), 500)
    return decode_win_codes(flat)


def _message_first_line(flat: dict[str, Any]) -> str:
    msg = str(flat.get("Message") or "").strip()
    return msg.splitlines()[0].strip() if msg else ""


def _normalize_vr_evtx_row(row: dict[str, Any], source: str) -> dict[str, Any]:
    flat = _flatten_vr_evtx_row(row)
    eid = str(flat.get("EventID") or "")
    channel = str(flat.get("Channel") or "")
    provider = str(flat.get("Provider") or "")
    event: dict[str, Any] = {
        "timestamp": extract_timestamp(flat) or extract_timestamp(row),
        "host": flat.get("Computer") or extract_host(row),
        "source": source,
        "category": "eventlog",
        "entity": None,
        "severity": "info",
        "summary": "",
        "raw": _json_safe(flat),
    }
    flat = event["raw"]

    def g(key: str) -> str:
        val = flat.get(key)
        return str(val).strip() if val not in (None, "") else ""

    # Event IDs are only unique within a channel: 4625 in the Application channel
    # has nothing to do with failed logons. Gate every well-known ID accordingly.
    is_security = channel == "Security" or provider == "Microsoft-Windows-Security-Auditing"

    if channel == SYSMON_CHANNEL or provider == SYSMON_PROVIDER:
        _map_sysmon_event(event, flat, eid)
    elif eid == "4688" and is_security:
        _map_security_4688(event, flat)
    elif eid in _ACCOUNT_EVENT_IDS and is_security:
        event["category"] = "account"
        user = g("TargetUserName") or g("SubjectUserName") or g("AccountName")
        event["entity"] = user or None
        if eid in ("4624", "4625"):
            ltype = g("LogonType")
            ltype_desc = _LOGON_TYPE_NAMES.get(ltype, ltype)
            ip = g("IpAddress")
            outcome = "Logon" if eid == "4624" else "FAILED logon"
            summary = f"{outcome}: {g('TargetDomainName')}\\{user or '<unknown>'}"
            if ltype:
                summary += f" (type {ltype}: {ltype_desc})"
            if ip and ip != "-":
                summary += f" from {ip}"
            event["summary"] = summary
        else:
            event["summary"] = _message_first_line(flat) or summarize_row(flat)
    elif (eid == "7045" and channel == "System") or (eid == "4697" and is_security):
        event["category"] = "persistence"
        event["entity"] = g("ServiceName") or None
        event["summary"] = (
            f"Service installed: {g('ServiceName') or '<unnamed>'} -> "
            f"{g('ImagePath') or g('ServiceFileName') or '<unknown image>'}"
            + (f" ({g('StartType')})" if g("StartType") else "")
        )
    elif (eid in ("4698", "4702") and is_security) or (
        eid == "106" and "taskscheduler" in channel.lower()
    ):
        event["category"] = "persistence"
        event["entity"] = g("TaskName") or None
        event["summary"] = (
            f"Scheduled task {'created' if eid in ('4698', '106') else 'updated'}: "
            f"{g('TaskName') or '<unnamed>'}"
        )
    elif eid == "1102" and is_security:
        event["entity"] = g("SubjectUserName") or None
        event["summary"] = "Security event log cleared" + (
            f" by {g('SubjectUserName')}" if g("SubjectUserName") else ""
        )
    elif eid == "4104" and "powershell" in (channel + provider).lower():
        event["category"] = "execution"
        script = g("ScriptBlockText")
        event["summary"] = f"PowerShell script block: {truncate(script, 300)}" if script else (
            _message_first_line(flat) or "PowerShell script block logged"
        )
        event["entity"] = "powershell.exe"
    else:
        base = _basename(flat.get("Image") or flat.get("ProcessName"))
        if base:
            event["entity"] = base

    if not event["summary"]:
        event["summary"] = _message_first_line(flat) or summarize_row(flat)
    if not event.get("entity"):
        event["entity"] = f"EventID {eid or '?'} ({channel})"
    return event


def parse_evtx(path: Path, source: str) -> Iterator[dict[str, Any]]:
    try:
        from Evtx.Evtx import Evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        return

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    try:
        with Evtx(str(path)) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    row: dict[str, Any] = {}
                    system = root.find("e:System", ns)
                    if system is not None:
                        eid = system.find("e:EventID", ns)
                        row["EventID"] = eid.text if eid is not None else None
                        provider = system.find("e:Provider", ns)
                        if provider is not None:
                            row["Provider"] = provider.get("Name")
                        computer = system.find("e:Computer", ns)
                        if computer is not None:
                            row["Computer"] = computer.text
                        tc = system.find("e:TimeCreated", ns)
                        if tc is not None:
                            row["SystemTime"] = tc.get("SystemTime")
                        channel = system.find("e:Channel", ns)
                        if channel is not None:
                            row["Channel"] = channel.text
                    event_data = root.find("e:EventData", ns)
                    if event_data is not None:
                        for data in event_data.findall("e:Data", ns):
                            name = data.get("Name") or f"Data{len(row)}"
                            row[name] = data.text
                    row = decode_win_codes(row)
                    event = normalize_row(row, source)
                    event["category"] = "eventlog"
                    eid = str(row.get("EventID") or "")
                    channel = str(row.get("Channel") or "")
                    provider = str(row.get("Provider") or "")
                    if channel == SYSMON_CHANNEL or provider == SYSMON_PROVIDER:
                        _map_sysmon_event(event, row, eid)
                    elif eid == "4688" and (
                        channel == "Security"
                        or provider == "Microsoft-Windows-Security-Auditing"
                    ):
                        _map_security_4688(event, row)
                    elif _basename(row.get("Image")):
                        # rows carrying process context beat "EventID N (channel)"
                        event["entity"] = _basename(row.get("Image"))
                    if not event.get("entity"):
                        event["entity"] = f"EventID {row.get('EventID')} ({row.get('Channel', '')})"
                    yield event
                except Exception:
                    continue
    except Exception:
        return


# Apache/Tomcat/nginx access log (Common + Combined Log Format)
_CLF_RE = re.compile(
    r'^(?P<client_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)")?'
)


def parse_textlog(path: Path, source: str) -> Iterator[dict[str, Any]]:
    """Parse text logs. Recognizes web access logs (CLF/Combined); otherwise
    emits one event per line as a generic log entry."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            m = _CLF_RE.match(line)
            if m:
                g = m.groupdict()
                req = g.get("request") or ""
                parts = req.split()
                method = parts[0] if parts else ""
                pathq = parts[1] if len(parts) > 1 else ""
                user = g.get("user") if g.get("user") not in ("-", None) else None
                raw = {
                    "client_ip": g.get("client_ip"),
                    "user": user,
                    "request": req,
                    "method": method,
                    "path": pathq,
                    "status": g.get("status"),
                    "size": g.get("size"),
                    "referer": g.get("referer"),
                    "user_agent": g.get("useragent"),
                    "log_line": line,
                }
                yield {
                    "timestamp": extract_timestamp({"timestamp": g.get("ts")}),
                    "host": None,
                    "source": source,
                    "category": "weblog",
                    "entity": g.get("client_ip"),
                    "severity": "info",
                    "summary": f"{method} {pathq} -> {g.get('status')} ({g.get('client_ip')}"
                               + (f", user {user}" if user else "") + ")",
                    "raw": raw,
                }
            else:
                yield {
                    "timestamp": None,
                    "host": None,
                    "source": source,
                    "category": "log",
                    "entity": None,
                    "severity": "info",
                    "summary": summarize_row({"line": line}),
                    "raw": {"log_line": line},
                }


PARSABLE_EXTENSIONS = {".json", ".jsonl", ".csv", ".evtx", ".txt", ".log"}


def parse_file(path: Path, source: str | None = None) -> Iterator[dict[str, Any]]:
    src = source or path.stem
    suffix = path.suffix.lower()
    if suffix in (".txt", ".log"):
        yield from parse_textlog(path, src)
        return
    if suffix == ".jsonl":
        yield from parse_jsonl(path, src)
    elif suffix == ".json":
        # Velociraptor often writes JSONL with .json extension; sniff first line
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            prefix = f.read(8192).lstrip()
        if prefix.startswith("["):
            yield from parse_json(path, src)
        elif prefix.startswith("{") and "\n" in prefix:
            yield from parse_jsonl(path, src)
        else:
            try:
                first, idx = json.JSONDecoder().raw_decode(prefix)
                is_jsonl = isinstance(first, dict) and prefix[idx:].lstrip().startswith("{")
            except json.JSONDecodeError:
                is_jsonl = prefix.startswith("{")
            if is_jsonl:
                yield from parse_jsonl(path, src)
            else:
                yield from parse_json(path, src)
    elif suffix == ".csv":
        yield from parse_csv(path, src)
    elif suffix == ".evtx":
        yield from parse_evtx(path, src)


def iter_zip_members(zip_path: Path, extract_dir: Path) -> Iterator[tuple[Path, str]]:
    """Extract parsable members of a Velociraptor collector ZIP; yield (path, source_name)."""
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            member_path = Path(info.filename)
            if member_path.suffix.lower() not in PARSABLE_EXTENSIONS:
                continue
            target = extract_dir / member_path.name
            # avoid collisions
            counter = 1
            while target.exists():
                target = extract_dir / f"{member_path.stem}_{counter}{member_path.suffix}"
                counter += 1
            with zf.open(info) as src_f, open(target, "wb") as dst_f:
                while True:
                    chunk = src_f.read(1024 * 1024)
                    if not chunk:
                        break
                    dst_f.write(chunk)
            # derive source name from the artifact path inside the zip
            source = _source_from_member(member_path)
            yield target, source


def _source_from_member(member: Path) -> str:
    """Velociraptor collector zips store results under results/Artifact.Name.json."""
    name = member.stem
    # strip common prefixes
    for part in member.parts:
        if part.lower() in ("results", "uploads", "files"):
            continue
    return name
