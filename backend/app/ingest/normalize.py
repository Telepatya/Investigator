"""Normalization helpers: map raw artifact rows to unified Event fields."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

TIMESTAMP_KEYS = [
    "timestamp", "Timestamp", "TimeStamp", "time", "Time", "EventTime",
    "event_time", "UtcTime", "SystemTime", "@timestamp", "ts", "TimeCreated",
    "CreateTime", "created", "Created", "mtime", "Mtime", "MTime",
    "LastRunTime", "LastModified", "KeyLastWriteTimestamp", "StartTime",
    "atime", "ctime", "btime", "LastWriteTime", "FirstRunTime",
]

HOST_KEYS = ["Hostname", "hostname", "Computer", "computer", "Fqdn", "host", "Host", "ClientId"]


def parse_timestamp(value: Any) -> datetime | None:
    """Best-effort timestamp parsing for the many formats Velociraptor emits."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        # Heuristic: distinguish seconds / millis / micros / nanos epochs
        v = float(value)
        if v <= 0:
            return None
        if v > 1e17:
            v /= 1e9
        elif v > 1e14:
            v /= 1e6
        elif v > 1e11:
            v /= 1e3
        try:
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, str):
        s = value.strip()
        if not s or s in ("-", "N/A", "0"):
            return None
        # numeric string epoch
        if re.fullmatch(r"\d{9,19}(\.\d+)?", s):
            return parse_timestamp(float(s))
        # normalize timezone suffix
        s = s.replace("Z", "+00:00")
        # try common formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S %Z",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
            "%d/%b/%Y:%H:%M:%S",
        ]
        # trim excess fractional digits (python supports max 6)
        m = re.match(r"(.*\.\d{6})\d+(.*)", s)
        if m:
            s = m.group(1) + m.group(2)
        for fmt in formats:
            try:
                dt = datetime.strptime(s, fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        try:
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def extract_timestamp(row: dict[str, Any]) -> datetime | None:
    for key in TIMESTAMP_KEYS:
        if key in row and row[key]:
            ts = parse_timestamp(row[key])
            if ts:
                return ts
    # nested SystemTime (EVTX style)
    system = row.get("System") or {}
    if isinstance(system, dict):
        time_created = system.get("TimeCreated") or {}
        if isinstance(time_created, dict):
            ts = parse_timestamp(time_created.get("SystemTime"))
            if ts:
                return ts
    return None


def extract_host(row: dict[str, Any]) -> str | None:
    for key in HOST_KEYS:
        val = row.get(key)
        if isinstance(val, str) and val:
            return val
    system = row.get("System")
    if isinstance(system, dict):
        val = system.get("Computer")
        if isinstance(val, str) and val:
            return val
    return None


# Windows event log message-table placeholders seen in boot/config events (4826 etc.)
WIN_MESSAGE_CODES = {
    "%%1842": "Enabled",
    "%%1843": "Disabled",
    "%%1844": "Not Configured",
    "%%1845": "Disabled by policy",
    "%%1846": "System Default",
    "%%1847": "Custom",
    "%%1848": "Off",
    "%%1849": "On",
}


def decode_win_codes(row: dict[str, Any]) -> dict[str, Any]:
    """Replace %%18xx message-table placeholders with readable text."""
    out: dict[str, Any] = {}
    for k, v in row.items():
        if isinstance(v, str) and v in WIN_MESSAGE_CODES:
            out[k] = WIN_MESSAGE_CODES[v]
        else:
            out[k] = v
    return out


def truncate(value: str, limit: int = 500) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def summarize_row(row: dict[str, Any], max_fields: int = 6) -> str:
    """Build a compact human-readable summary from the most informative fields."""
    preferred = [
        "Message", "message",
        # process/file/network context first: these say what actually happened
        "Image", "CommandLine", "Cmdline", "ParentImage",
        "TargetFilename", "TargetObject", "DestinationIp", "DestinationPort",
        "QueryName",
        "Name", "name", "FullPath", "OSPath", "Path",
        "ImagePath", "Url", "TargetPath", "Exe",
        "EventID", "Channel", "Provider", "User", "Username", "ServiceName",
        "Laddr", "Raddr", "Status",
        "KernelDebug", "TestSigning", "DisableIntegrityChecks", "FlightSigning",
        "SubjectUserName", "request", "client_ip", "user_agent",
    ]
    parts: list[str] = []
    used: set[str] = set()
    for key in preferred:
        if key in row and row[key] not in (None, "", [], {}):
            parts.append(f"{key}={truncate(str(row[key]), 200)}")
            used.add(key)
            if len(parts) >= max_fields:
                break
    if not parts:
        for key, val in row.items():
            if key in used or val in (None, "", [], {}):
                continue
            if isinstance(val, (dict, list)):
                continue
            parts.append(f"{key}={truncate(str(val), 120)}")
            if len(parts) >= max_fields:
                break
    return "; ".join(parts) if parts else truncate(str(row), 300)


def extract_entity(row: dict[str, Any]) -> str | None:
    for key in ("FullPath", "OSPath", "Path", "Name", "name", "ImagePath", "Exe",
                "TargetPath", "ServiceName", "Url", "KeyPath", "Laddr"):
        val = row.get(key)
        if isinstance(val, str) and val:
            return truncate(val, 500)
    return None
