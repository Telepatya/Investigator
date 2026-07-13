"""Normalization helpers: map raw artifact rows to unified Event fields."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

# Hoisted out of parse_timestamp's hot path so they compile once, not per call.
_NUMERIC_TS_RE = re.compile(r"\d{9,19}(\.\d+)?")
_FRAC_TRIM_RE = re.compile(r"(.*\.\d{6})\d+(.*)")

# Timestamp formats tried in order. Order is semantic (e.g. %m/%d vs %d/%m both
# parse some strings, with different results) — do NOT reorder, and never insert
# slash-date formats before the ISO family. Slash dates are tried US-order
# (%m/%d) first; day <= 12 is inherently ambiguous and resolves US-style.
_TIMESTAMP_FORMATS = (
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
    # Sentinel / Log Analytics / Defender portal grid exports render times in a
    # locale 12-hour format ("7/8/2026, 11:57:31.123 AM"). Grids show the
    # analyst's display timezone; values are treated as UTC (no zone in string).
    # AM/PM vs 24h and comma vs no-comma shapes are disjoint under strptime, so
    # these cannot shadow the formats above.
    "%m/%d/%Y, %I:%M:%S.%f %p",
    "%m/%d/%Y, %I:%M:%S %p",
    "%m/%d/%Y %I:%M:%S.%f %p",
    "%m/%d/%Y %I:%M:%S %p",
    "%d/%m/%Y, %I:%M:%S.%f %p",
    "%d/%m/%Y, %I:%M:%S %p",
    "%m/%d/%Y, %H:%M:%S.%f",
    "%m/%d/%Y, %H:%M:%S",
    "%d/%m/%Y, %H:%M:%S.%f",
    "%d/%m/%Y, %H:%M:%S",
    "%m/%d/%Y %H:%M:%S.%f",
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
)

TIMESTAMP_KEYS = [
    "timestamp", "Timestamp", "TimeStamp", "time", "Time", "EventTime",
    "event_time", "UtcTime", "SystemTime", "@timestamp", "ts", "TimeCreated",
    "CreateTime", "created", "Created", "mtime", "Mtime", "MTime",
    "LastRunTime", "LastModified", "KeyLastWriteTimestamp", "StartTime",
    "atime", "ctime", "btime", "LastWriteTime", "FirstRunTime",
    # Sentinel / Log Analytics exports of the Defender tables use TimeGenerated.
    "TimeGenerated",
]

# Normalized (lowercased, non-alphanumeric stripped) timestamp column names, used
# as a fuzzy fallback so labelled variants that don't match a key above are still
# recognized: "Timestamp [UTC]", "TimeStamp [UTC]", "TimeGenerated [UTC]",
# "Time Generated", etc. (portal / Log Analytics / Sentinel CSV exports).
_NORMALIZED_TS_KEYS = {re.sub(r"[^a-z0-9]", "", k.lower()) for k in TIMESTAMP_KEYS} | {
    "timegeneratedutc", "timestamputc", "eventtimeutc", "createdtimeutc",
    "generatedtime", "datetime", "datetimeutc",
}

HOST_KEYS = ["Hostname", "hostname", "Computer", "computer", "Fqdn", "host", "Host",
             "DeviceName", "DeviceId", "ClientId"]


def parse_timestamp(value: Any) -> datetime | None:
    """Best-effort timestamp parsing for the many formats logs and artifacts emit."""
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
        if _NUMERIC_TS_RE.fullmatch(s):
            return parse_timestamp(float(s))
        return _parse_timestamp_str(s)
    return None


@lru_cache(maxsize=4096)
def _parse_timestamp_str(s: str) -> datetime | None:
    """Parse a non-empty, non-numeric timestamp string. Cached: pure function
    returning immutable (tz-aware) datetimes, so results are safe to share.
    Tests that depend on _TIMESTAMP_FORMATS must call cache_clear() in setup."""
    # normalize timezone suffix
    s = s.replace("Z", "+00:00")
    # trim excess fractional digits (python supports max 6)
    m = _FRAC_TRIM_RE.match(s)
    if m:
        s = m.group(1) + m.group(2)
    for fmt in _TIMESTAMP_FORMATS:
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


def extract_timestamp(row: dict[str, Any]) -> datetime | None:
    for key in TIMESTAMP_KEYS:
        if key in row and row[key]:
            ts = parse_timestamp(row[key])
            if ts:
                return ts
    # Fuzzy fallback for labelled timestamp columns ("TimeGenerated",
    # "Timestamp [UTC]", ...) so Sentinel / Log Analytics exports still populate
    # the timeline (which requires a timestamp).
    for key, val in row.items():
        if isinstance(key, str) and val and re.sub(r"[^a-z0-9]", "", key.lower()) in _NORMALIZED_TS_KEYS:
            ts = parse_timestamp(val)
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
    # Fast path: most rows carry no placeholders, so skip rebuilding the dict.
    # Callers always pass a freshly-built per-row dict, so returning it as-is is
    # equivalent to the copy the rebuild would have produced.
    if not any(isinstance(v, str) and v in WIN_MESSAGE_CODES for v in row.values()):
        return row
    return {
        k: (WIN_MESSAGE_CODES[v] if isinstance(v, str) and v in WIN_MESSAGE_CODES else v)
        for k, v in row.items()
    }


def truncate(value: str, limit: int = 500) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


_SUMMARY_PREFERRED = (
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
)


def summarize_row(row: dict[str, Any], max_fields: int = 6) -> str:
    """Build a compact human-readable summary from the most informative fields."""
    preferred = _SUMMARY_PREFERRED
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
