"""Microsoft Sentinel / Log Analytics table mappers beyond the Defender Device*
Advanced Hunting tables (which parsers.py already handles).

Covers SecurityEvent (Windows events via AMA/MMA), Syslog (Linux logs forwarded
to Sentinel), SigninLogs and AuditLogs (Entra ID). Each maps onto the same
unified Event schema so the existing detection / timeline machinery applies:
  - SecurityEvent reuses the Windows EventID classifier (_apply_windows_event_mapping),
    so 4624/4625/4720/7045/1102/4698/4826 detections fire unchanged.
  - Syslog delegates to the Linux classifier, so a "Failed password" line stamps
    the same Auth* raw keys whether it arrived as /var/log/auth.log or here.

Recognition is gated behind is_sentinel_row so non-Sentinel rows are unaffected.
"""

from __future__ import annotations

import json
import re
from typing import Any
from xml.etree import ElementTree as ET

from app.ingest.linux import classify_syslog_event
from app.ingest.normalize import extract_timestamp, truncate

_SENTINEL_TABLE_NAMES = ("securityevent", "syslog", "signinlogs", "auditlogs")

# Entra sign-in ResultType -> short description (for readable summaries).
ENTRA_SIGNIN_CODES = {
    "0": "success",
    "50053": "account locked / smart-lockout",
    "50055": "expired password",
    "50057": "account disabled",
    "50074": "MFA required",
    "50076": "MFA required (conditional access)",
    "50079": "MFA registration required",
    "50126": "invalid username or password",
    "53003": "blocked by conditional access",
    "500121": "MFA denied / timed out",
}


def _sget(row: dict[str, Any], *names: str) -> str:
    """First non-empty value among names (case/space/underscore-insensitive)."""
    for name in names:
        val = row.get(name)
        if val not in (None, ""):
            return str(val).strip()
    wanted = {name.lower().replace(" ", "").replace("_", "") for name in names}
    for key, val in row.items():
        normalized = (
            key.lower().replace(" ", "").replace("_", "")
            if isinstance(key, str)
            else ""
        )
        if normalized in wanted and val not in (None, ""):
            return str(val).strip()
    return ""


def _table_from_source(source: str, row: dict[str, Any]) -> str:
    low = (source or "").lower()
    explicit = str(row.get("_TableName") or row.get("Type") or "").lower()
    for name in _SENTINEL_TABLE_NAMES:
        if name in explicit or name in low:
            return name
    return ""


def sentinel_table(row: dict[str, Any], source: str) -> str:
    """Resolve the Sentinel table by name, then by column signature."""
    table = _table_from_source(source, row)
    if table:
        return table
    if _sget(row, "EventID") and (
        _sget(row, "Activity") or _sget(row, "EventSourceName")
        or (_sget(row, "Computer") and _sget(row, "EventData"))
    ):
        return "securityevent"
    if _sget(row, "SyslogMessage") or (
        _sget(row, "Facility") and _sget(row, "SeverityLevel") and _sget(row, "Computer")
    ):
        return "syslog"
    if _sget(row, "UserPrincipalName") and _sget(row, "ResultType"):
        return "signinlogs"
    if _sget(row, "OperationName") and _sget(row, "Category") and (
        _sget(row, "InitiatedBy") or _sget(row, "TargetResources")
    ):
        return "auditlogs"
    return ""


def is_sentinel_row(row: dict[str, Any], source: str) -> bool:
    return bool(sentinel_table(row, source))


# ---------------------------------------------------------------------------
# SecurityEvent
# ---------------------------------------------------------------------------

# EventID -> Channel used when SecurityEvent has no Channel column. SecurityEvent
# is overwhelmingly the Security channel; a few IDs live in System and would fail
# _eid_channel_ok (disabling their detection) if defaulted to Security.
_EID_CHANNEL = {
    "7045": "System", "7036": "System", "7034": "System", "104": "System",
    "106": "Microsoft-Windows-TaskScheduler/Operational",
}
_EVENTDATA_RE = re.compile(r'<Data\s+Name="([^"]+)"\s*>([^<]*)</Data>', re.IGNORECASE)


def _flatten_eventdata(flat: dict[str, Any]) -> None:
    """Parse SecurityEvent's EventData XML string into promoted top-level keys,
    filling only names AMA didn't already promote to columns. Mutates flat."""
    raw_xml = flat.get("EventData")
    if not isinstance(raw_xml, str) or "<Data" not in raw_xml:
        return
    pairs: list[tuple[str, str]] = []
    try:
        # EventData may or may not have a single root element; wrap defensively.
        root = ET.fromstring(f"<EventData>{raw_xml}</EventData>"
                             if not raw_xml.lstrip().startswith("<EventData")
                             else raw_xml)
        for data in root.iter():
            name = data.get("Name")
            if name:
                pairs.append((name, (data.text or "").strip()))
    except ET.ParseError:
        pairs = [(m.group(1), m.group(2).strip()) for m in _EVENTDATA_RE.finditer(raw_xml)]
    for name, value in pairs:
        if name and value and not flat.get(name):
            flat[name] = value
    flat["EventData"] = truncate(raw_xml, 500)


def prepare_securityevent(row: dict[str, Any]) -> dict[str, Any]:
    """Flatten and enrich a Sentinel SecurityEvent row for the shared Windows
    EventID mapper. The mapper itself remains owned by parsers.py, avoiding an
    import cycle between the generic parser and Sentinel recognition."""
    flat = dict(row)
    flat["EventID"] = str(_sget(row, "EventID") or "")
    if not flat.get("Channel"):
        flat["Channel"] = _EID_CHANNEL.get(flat["EventID"], "Security")
    _flatten_eventdata(flat)

    # Account is "DOMAIN\user"; fill whichever Target* fields are still missing.
    account = _sget(flat, "Account")
    if account and "\\" in account:
        dom, _, user = account.partition("\\")
        if dom and not flat.get("TargetDomainName"):
            flat["TargetDomainName"] = dom
        if user and not flat.get("TargetUserName"):
            flat["TargetUserName"] = user

    return flat


# ---------------------------------------------------------------------------
# Syslog table
# ---------------------------------------------------------------------------

def _map_syslog_table(row: dict[str, Any], source: str) -> dict[str, Any]:
    rec = {
        "ts": extract_timestamp(row),
        "host": _sget(row, "Computer", "HostName") or None,
        "ident": _sget(row, "ProcessName", "SyslogIdentifier"),
        "pid": _sget(row, "ProcessID"),
        "message": _sget(row, "SyslogMessage"),
    }
    extra = {
        "Facility": _sget(row, "Facility"),
        "SeverityLevel": _sget(row, "SeverityLevel"),
        "SentinelTable": "Syslog",
    }
    return classify_syslog_event(rec, source, extra)


# ---------------------------------------------------------------------------
# SigninLogs (Entra ID)
# ---------------------------------------------------------------------------

def _map_signinlogs(row: dict[str, Any], source: str) -> dict[str, Any]:
    upn = _sget(row, "UserPrincipalName")
    ip = _sget(row, "IPAddress", "IpAddress")
    app = _sget(row, "AppDisplayName")
    result = _sget(row, "ResultType")
    result_text = _sget(row, "ResultDescription") or ENTRA_SIGNIN_CODES.get(result, f"result {result}")
    outcome = "success" if result == "0" else "failure"
    raw: dict[str, Any] = {
        "linux_log": False,
        "AuthProto": "entra",
        "AuthOutcome": outcome,
        "AuthUser": upn,
        "SrcIp": ip,
        "AppDisplayName": app,
        "ResultType": result,
        "SentinelTable": "SigninLogs",
    }
    for col in ("RiskLevelDuringSignIn", "RiskState", "ConditionalAccessStatus", "Location"):
        val = _sget(row, col)
        if val:
            raw[col] = val
    raw = {k: v for k, v in raw.items() if v not in (None, "")}
    summary = (f"Entra sign-in {outcome}: {upn or '<unknown>'}"
               + (f" from {ip}" if ip else "")
               + (f" -> {app}" if app else "")
               + f" ({result_text})")
    return {
        "timestamp": extract_timestamp(row),
        "host": None,
        "source": source,
        "category": "account",
        "entity": upn or None,
        "severity": "info",
        "summary": truncate(summary, 400),
        "raw": raw,
    }


# ---------------------------------------------------------------------------
# AuditLogs (Entra ID)
# ---------------------------------------------------------------------------

def _json_field(row: dict[str, Any], name: str) -> Any:
    val = row.get(name)
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str) and val.strip():
        try:
            return json.loads(val)
        except (ValueError, TypeError):
            return None
    return None


def _audit_initiator(row: dict[str, Any]) -> str:
    initiated = _json_field(row, "InitiatedBy")
    if isinstance(initiated, dict):
        for section in ("user", "app"):
            block = initiated.get(section)
            if isinstance(block, dict):
                who = block.get("userPrincipalName") or block.get("displayName")
                if who:
                    return str(who)
    return _sget(row, "Identity") or ""


def _audit_target(row: dict[str, Any]) -> str:
    targets = _json_field(row, "TargetResources")
    if isinstance(targets, list):
        for t in targets:
            if isinstance(t, dict):
                who = t.get("userPrincipalName") or t.get("displayName")
                if who:
                    return str(who)
    return ""


def _map_auditlogs(row: dict[str, Any], source: str) -> dict[str, Any]:
    op = _sget(row, "OperationName")
    result = _sget(row, "Result")
    initiator = _audit_initiator(row)
    target = _audit_target(row)
    raw: dict[str, Any] = {
        "linux_log": False,
        "EntraOperation": op,
        "EntraResult": result,
        "Initiator": initiator,
        "Target": target,
        "AuditCategory": _sget(row, "Category"),
        "SentinelTable": "AuditLogs",
    }
    raw = {k: v for k, v in raw.items() if v not in (None, "")}
    summary = (f"{op or 'Entra operation'}"
               + (f" ({result})" if result else "")
               + (f" by {initiator}" if initiator else "")
               + (f" on {target}" if target else ""))
    return {
        "timestamp": extract_timestamp(row),
        "host": None,
        "source": source,
        "category": "account",
        "entity": target or initiator or None,
        "severity": "info",
        "summary": truncate(summary, 400),
        "raw": raw,
    }


_SENTINEL_TABLE_MAPPERS = {
    "syslog": _map_syslog_table,
    "signinlogs": _map_signinlogs,
    "auditlogs": _map_auditlogs,
}


def normalize_sentinel_row(
    row: dict[str, Any], source: str, table: str | None = None
) -> dict[str, Any]:
    table = table or sentinel_table(row, source)
    mapper = _SENTINEL_TABLE_MAPPERS.get(table)
    if mapper:
        return mapper(row, source)
    raise ValueError(f"Sentinel table requires parser-owned mapping: {table or '<unknown>'}")
