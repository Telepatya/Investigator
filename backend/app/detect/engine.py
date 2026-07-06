"""Deterministic detection engine. Runs over ingested events/processes before the LLM."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from app.detect.rules import (
    EXPECTED_PARENTS,
    LOLBINS,
    LOW_SIGNAL_LOLBINS,
    PERSISTENCE_REGISTRY_PATHS,
    SCHEDULED_TASK_SCRIPT_HOSTS,
    SUSPICIOUS_CMDLINE_PATTERNS,
    SUSPICIOUS_EXECUTION_DIRS,
    SUSPICIOUS_PARENT_CHILD_MAP,
    SYSTEM_PROCESS_PATHS,
    TASK_UPDATER_MASQUERADES,
    WEB_ATTACK_PATTERNS,
)
from app.store import cases as case_store
from app.store.database import Event, Finding, MemoryResult, Process

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}
EVENT_STREAM_BATCH_SIZE = 10000
_MEMPROCFS_TIMELINE_SOURCE = ":forensic/csv/timeline"
_EXECUTABLE_ARTIFACT_RE = re.compile(r"\.(?:exe|dll|ps1|bat|cmd|vbs|js|scr|com)$", re.IGNORECASE)
_USN_EXECUTABLE_ARTIFACT_RE = re.compile(
    r"\.(?:exe|dll|sys|scr|com|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|cpl|msi|jar|lnk)$",
    re.IGNORECASE,
)
_USN_SCRIPT_EXTENSIONS = {
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".scr", ".com", ".cpl", ".lnk",
}
_USN_DECOY_EXTENSIONS = {
    ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".zip", ".rar", ".7z", ".iso",
}
_USN_TEMPORARY_EXTENSIONS = {
    ".tmp", ".temp", ".partial", ".part", ".crdownload", ".download",
}
_USN_USER_WRITABLE_HINTS = tuple(SUSPICIOUS_EXECUTION_DIRS) + (
    r"\users\public",
    r"\downloads",
    r"\desktop",
    r"\appdata\local",
    r"\appdata\roaming",
)
_TASK_ACTION_RE = re.compile(r"^(?P<name>.*?)\s+-\s+\[(?P<action>.*?)\]\s+\((?P<meta>.*?)\)\s*$")
_TASK_ARTIFACT_HINTS = (
    r"\windows\system32\tasks\\",
    r"\windows\syswow64\tasks\\",
    r"\windows\tasks\\",
)
_WINDOWS_ROOT_EXEC_RE = re.compile(r"^\\windows\\[^\\]+\.exe$")
_WEAK_MEMPROCFS_FINDEVIL_TYPES = {
    "HIGH_ENTROPY", "PRIVATE_RX", "PRIVATE_RWX", "NOIMAGE_RX", "NOIMAGE_RWX",
    "PE_PATCHED", "PE_NOLINK", "THREAD", "DRIVER_PATH", "PROC_DEBUG", "PEB_BAD_LDR",
}

# Signal classes treated as independent evidence in the correlation pass:
# flag -> (baseline severity contribution, representative ATT&CK technique).
# Includes flags set by the memory pipeline (hidden/injected/hollowing-suspect).
CORRELATION_FLAGS: dict[str, tuple[str, str]] = {
    "lolbin": ("medium", "T1218"),
    "suspicious-cmdline": ("medium", "T1059"),
    "suspicious-path": ("medium", "T1204"),
    "masquerade": ("high", "T1036.005"),
    "bad-parent-child": ("high", "T1204.002"),
    "anomalous-parent": ("high", "T1055"),
    "hidden": ("critical", "T1014"),
    "injected": ("high", "T1055"),
    "hollowing-suspect": ("high", "T1055.012"),
    "cross-process": ("high", "T1055"),
    "yara-hit": ("high", "T1071"),
}

SENSITIVE_PROCESS_NAMES = {
    "lsass.exe", "lsaiso.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "samss.exe", "smss.exe", "securityhealthservice.exe", "msmpeng.exe",
    "windefend.exe", "senseir.exe", "sensece.exe", "chrome.exe", "msedge.exe",
    "firefox.exe", "powershell.exe", "pwsh.exe", "cmd.exe",
}


def _normalize_path(raw_path: str) -> str:
    """Normalize kernel/device path prefixes so location checks compare like with like."""
    p = (raw_path or "").strip().lower().replace("/", "\\")
    p = re.sub(r"^\\\?\?\\", "", p)
    p = re.sub(r"^\\\\\?\\", "", p)
    p = re.sub(r"^\\device\\harddiskvolume\d+", "", p)
    p = re.sub(r"^\\systemroot\b", r"\\windows", p)
    p = re.sub(r"^%systemroot%", r"\\windows", p)
    p = re.sub(r"^%windir%", r"\\windows", p)
    if re.match(r"^[a-z]:", p):
        p = p[2:]
    return p


def _addr_scope(addr: str) -> str:
    """Classify a remote address: local (loopback/unspecified), private (RFC1918/link-local), public."""
    a = (addr or "").strip().lower().strip("[]")
    if not a or a == "*" or a.startswith(("127.", "0.0.0.0", "::")):
        return "local"
    if a.startswith(("10.", "192.168.", "169.254.")) or re.match(r"172\.(1[6-9]|2\d|3[01])\.", a):
        return "private"
    if ":" in a and a.startswith(("fe80", "fc", "fd")):
        return "private"
    return "public"


# Windows Event IDs are only unique per channel: EventID 4625 in the Application
# channel is unrelated to failed logons. When a row carries channel information,
# only apply well-known-ID heuristics in the channel that defines them.
_EID_EXPECTED_CHANNELS: dict[str, tuple[str, ...]] = {
    "1102": ("security",),
    "4720": ("security",),
    "4698": ("security",),
    "4688": ("security",),
    "4625": ("security",),
    "4624": ("security",),
    "4672": ("security",),
    "4826": ("security",),
    "7045": ("system",),
    "106": ("microsoft-windows-taskscheduler/operational",),
    "8": ("microsoft-windows-sysmon/operational",),
    "10": ("microsoft-windows-sysmon/operational",),
}


def _eid_channel_ok(raw: dict[str, Any], eid: str) -> bool:
    expected = _EID_EXPECTED_CHANNELS.get(eid)
    if not expected:
        return True
    channel = _field(raw, "Channel").strip().lower()
    if not channel:
        return True  # sources without channel info keep legacy behavior
    return channel in expected


def _add_finding(
    session,
    existing: set[tuple[str, str]],
    title: str,
    description: str,
    severity: str,
    techniques: list[str],
    evidence: dict[str, Any],
    source: str,
) -> None:
    key = (title, str(evidence.get("entity") or evidence.get("pid") or evidence.get("summary", ""))[:200])
    if key in existing:
        return
    existing.add(key)
    session.add(
        Finding(
            title=title,
            description=description,
            severity=severity,
            mitre_techniques=techniques,
            evidence=evidence,
            source=source,
        )
    )


def _escalate_event(session, event: Event, severity: str, reason: str | None = None) -> None:
    if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(event.severity, 0):
        event.severity = severity
        if reason:
            event.severity_reason = reason


def _is_memprocfs_timeline_event(event: Event, raw: dict[str, Any]) -> bool:
    source = (event.source or "").lower()
    return _MEMPROCFS_TIMELINE_SOURCE in source or str(raw.get("memprocfs_csv") or "").lower().startswith("timeline")


def _timeline_type(raw: dict[str, Any]) -> str:
    return _field(raw, "Type", "TimelineType").strip().upper()


def _timeline_action(raw: dict[str, Any]) -> str:
    return _field(raw, "Action").strip().upper()


def _timeline_text(event: Event, raw: dict[str, Any]) -> str:
    return _field(raw, "Text", "Path", "Name", "Detail") or (event.summary or "")


def _event_command_text(event: Event, raw: dict[str, Any]) -> str:
    if _is_memprocfs_timeline_event(event, raw):
        keys = ("CommandLine", "Cmdline", "CmdLine", "Args", "Parameters")
        if _timeline_type(raw) in {"PROC", "SHTASK", "TASK"}:
            keys = (*keys, "Text")
        return " ".join(str(_field(raw, key)) for key in keys if _field(raw, key))
    else:
        keys = (
            "CommandLine", "Cmdline", "CmdLine", "Args", "Parameters", "Text",
            "ImagePath", "Path", "UserPath", "KernelPath", "ServiceFileName",
        )
        return " ".join(str(v) for v in [event.summary, *(_field(raw, key) for key in keys)] if v)


def _timeline_action_word(action: str) -> str:
    return {"CRE": "created", "MOD": "modified", "DEL": "deleted"}.get(action.upper(), action.lower())


def _is_usn_journal_event(event: Event, raw: dict[str, Any]) -> bool:
    source = (event.source or "").lower()
    return bool(raw.get("usn_journal")) or (
        any(hint in source for hint in ("usn", "$j", "journal"))
        and bool(_field(raw, "Reason", "UpdateReason", "USNReason", "UsnReasonTokens"))
    )


def _usn_reason_tokens(raw: dict[str, Any]) -> set[str]:
    tokens = raw.get("UsnReasonTokens")
    if isinstance(tokens, list):
        return {str(t).upper() for t in tokens if str(t).strip()}
    reason = _field(raw, "Reason", "UpdateReason", "USNReason")
    if not reason:
        return set()
    try:
        number = int(reason, 16) if str(reason).lower().startswith("0x") else int(reason)
    except ValueError:
        number = None
    if number is not None:
        bit_names = {
            0x00000100: "FILE_CREATE",
            0x00000200: "FILE_DELETE",
            0x00001000: "RENAME_OLD_NAME",
            0x00002000: "RENAME_NEW_NAME",
            0x80000000: "CLOSE",
        }
        return {name for bit, name in bit_names.items() if number & bit}
    return {
        token.upper()
        for token in re.split(r"[^A-Za-z0-9_]+", reason)
        if token and token.upper() not in {"USN", "REASON"}
    }


def _usn_path(event: Event, raw: dict[str, Any]) -> str:
    return _field(
        raw,
        "UsnPath", "FullPath", "OSPath", "Path", "TargetFilename", "TargetPath",
        "FilePath", "Name", "FileName", "Filename",
    ) or (event.entity or "")


def _usn_file_reference(raw: dict[str, Any]) -> str:
    ref = _field(
        raw,
        "UsnFileReference", "FileReferenceNumber", "FileReference", "FileId",
        "FileID", "FileIdentifier", "MFTReference", "MFTId", "MFTID", "FRN",
    )
    if not ref:
        return ""
    if ":" in ref:
        return ref
    seq = _field(raw, "Sequence", "SequenceNumber", "Seq", "MFTSequence")
    return f"{ref}:{seq}" if seq else ref


def _extension(path: str) -> str:
    base = _basename(path)
    m = re.search(r"(\.[A-Za-z0-9]{1,12})$", base)
    return m.group(1).lower() if m else ""


def _is_usn_executable_path(path: str) -> bool:
    return bool(_USN_EXECUTABLE_ARTIFACT_RE.search(path or ""))


def _is_user_writable_path(path: str) -> bool:
    npath = _normalize_path(path)
    return any(hint in npath for hint in _USN_USER_WRITABLE_HINTS)


def _is_double_extension(path: str) -> bool:
    base = _basename(path)
    parts = base.lower().split(".")
    if len(parts) < 3:
        return False
    return f".{parts[-2]}" in _USN_DECOY_EXTENSIONS and f".{parts[-1]}" in _USN_SCRIPT_EXTENSIONS


def _is_powershell_policy_test_artifact(path: str) -> bool:
    base = _basename(path).lower()
    return base.startswith("__psscriptpolicytest_") and ".ps1" in base


def _is_high_value_usn_rename(old_path: str, new_path: str) -> bool:
    if not _is_usn_executable_path(new_path):
        return False
    old_ext = _extension(old_path)
    new_ext = _extension(new_path)
    if not new_ext or old_ext == new_ext:
        return False
    if old_ext in _USN_TEMPORARY_EXTENSIONS:
        return False
    if _is_double_extension(new_path):
        return True
    return old_ext in _USN_DECOY_EXTENSIONS and new_ext in _USN_SCRIPT_EXTENSIONS


def _usn_create_severity(path: str) -> str | None:
    if not _is_usn_executable_path(path) or not _is_user_writable_path(path):
        return None
    if _is_powershell_policy_test_artifact(path):
        return None
    if _is_double_extension(path):
        return "low"
    return None


def _check_usn_journal_event(
    session,
    existing: set[tuple[str, str]],
    event: Event,
    raw: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    if not _is_usn_journal_event(event, raw):
        return
    tokens = _usn_reason_tokens(raw)
    path = _usn_path(event, raw)
    if not path or not _is_usn_executable_path(path):
        return
    if "FILE_CREATE" in tokens:
        severity = _usn_create_severity(path)
        if not severity:
            return
        reason = (
            "Context: $J USN journal recorded executable/script creation in a "
            "user-writable path; kept for timeline and execution correlation"
        )
        _escalate_event(session, event, severity, reason)


def _analyze_usn_rename_chains(
    session,
    existing: set[tuple[str, str]],
    usn_events: list[Event],
) -> None:
    old_by_ref: dict[str, Event] = {}
    fallback_old: list[Event] = []

    def event_sort_key(event: Event) -> tuple[str, int]:
        ts = event.timestamp.isoformat() if event.timestamp else ""
        return (ts, event.id or 0)

    for event in sorted(usn_events, key=event_sort_key):
        raw = event.raw or {}
        tokens = _usn_reason_tokens(raw)
        if not (tokens & {"RENAME_OLD_NAME", "RENAME_NEW_NAME"}):
            continue
        ref = _usn_file_reference(raw)
        path = _usn_path(event, raw)
        if "RENAME_OLD_NAME" in tokens:
            if ref:
                old_by_ref[ref] = event
            elif len(fallback_old) < 200:
                fallback_old.append(event)
            continue
        if "RENAME_NEW_NAME" not in tokens:
            continue
        old_event = old_by_ref.get(ref) if ref else (fallback_old.pop() if fallback_old else None)
        if old_event is None:
            continue
        old_raw = old_event.raw or {}
        old_path = _usn_path(old_event, old_raw)
        if not path or not old_path:
            continue
        new_exec = _is_usn_executable_path(path)
        old_exec = _is_usn_executable_path(old_path)
        if not new_exec and not old_exec:
            continue
        ext_changed = _extension(path) != _extension(old_path)
        suspicious_path = _is_user_writable_path(path) or _is_user_writable_path(old_path)
        double_ext = _is_double_extension(path)
        high_value_rename = _is_high_value_usn_rename(old_path, path)
        if not high_value_rename:
            continue
        severity = "medium"
        signals = []
        if ref:
            signals.append("same FileReferenceNumber links old and new names")
        if double_ext:
            signals.append("new name uses a decoy/double extension")
        elif ext_changed:
            signals.append("rename changed a decoy document/archive/media extension into a script extension")
        if suspicious_path:
            signals.append("rename occurred in a user-writable or staging path")
        _add_finding(
            session,
            existing,
            title="USN Journal: file renamed to executable/script extension",
            description=(
                f"The NTFS $UsnJrnl:$J journal links a rename from {old_path[:300]} "
                f"to {path[:300]}. This is useful because the journal preserves old/new "
                "names for the same file reference, exposing extension flips that normal "
                "directory listings miss. Treat as a medium-confidence lead until execution "
                "or download evidence corroborates it. Signals: " + "; ".join(signals) + "."
            ),
            severity=severity,
            techniques=["T1036", "T1204"],
            evidence={
                "entity": path,
                "old_path": old_path[:700],
                "new_path": path[:700],
                "file_reference": ref or None,
                "old_event_id": old_event.id,
                "new_event_id": event.id,
                "signals": signals,
            },
            source=f"event:{event.source}",
        )
        _escalate_event(
            session,
            old_event,
            severity,
            "Detection: $J USN journal rename chain old name for executable/script extension flip",
        )
        _escalate_event(
            session,
            event,
            severity,
            "Detection: $J USN journal rename chain new name is executable/script artifact",
        )


def _parse_memprocfs_task_text(text: str) -> dict[str, Any] | None:
    m = _TASK_ACTION_RE.match(text or "")
    if not m:
        return None
    action = m.group("action").strip()
    if "::" in action:
        exe, args = [part.strip() for part in action.split("::", 1)]
        action = f"{exe} {args}".strip()
    return {
        "name": m.group("name").strip(),
        "action": action,
        "run_as": m.group("meta").strip("- "),
        "run_level": "",
        "schedule": "",
        "high_freq": False,
    }


def _check_memprocfs_timeline_event(
    session,
    existing: set[tuple[str, str]],
    event: Event,
    raw: dict[str, Any],
    evidence: dict[str, Any],
    task_records: list[dict[str, Any]],
    persistence_artifacts: list[tuple[str, str, str, str]],
) -> None:
    mem_csv = str(raw.get("memprocfs_csv") or "").lower()
    if mem_csv == "tasks.csv":
        action = " ".join(
            str(v) for v in [_field(raw, "CommandLine"), _field(raw, "Parameters")] if v and v != "---"
        ).strip()
        task_name = _field(raw, "TaskPath", "TaskName", "GUID")
        task_record = {
            "name": task_name,
            "action": action,
            "run_as": _field(raw, "User"),
            "run_level": "",
            "schedule": "",
            "high_freq": False,
            "origin": "MemProcFS tasks.csv",
            "event": event,
        }
        if action or task_name:
            task_records.append(task_record)
        top = _check_cmdline(session, existing, action, evidence, f"event:{event.source}")
        if top:
            _escalate_event(
                session, event, top,
                f"Detection: scheduled-task action matched suspicious command-line patterns ({top})",
            )
        return

    if not _is_memprocfs_timeline_event(event, raw):
        return
    typ = _timeline_type(raw)
    action = _timeline_action(raw)
    text = _timeline_text(event, raw)
    lower = text.lower()
    if typ == "PROC":
        top = _check_cmdline(session, existing, text, evidence, f"event:{event.source}")
        if top:
            _escalate_event(
                session, event, top,
                f"Detection: process command line matched suspicious patterns ({top})",
            )

    if typ == "REG":
        for fragment, technique, desc in PERSISTENCE_REGISTRY_PATHS:
            if fragment in lower:
                if not _memprocfs_registry_persistence_is_specific(fragment, lower):
                    break
                _add_finding(
                    session, existing,
                    title=f"MemProcFS timeline: {desc}",
                    description=f"Registry timeline row touched a persistence location: {text[:500]}",
                    severity="high",
                    techniques=[technique],
                    evidence={**evidence, "timeline_type": typ, "timeline_action": action, "text": text[:700]},
                    source=f"event:{event.source}",
                )
                _escalate_event(session, event, "high", f"Detection: {desc}")
                for exe in set(_EXE_TOKEN_RE.findall(lower)):
                    persistence_artifacts.append(
                        (_basename(exe), "MemProcFS registry persistence", text[:200], technique)
                    )
                break

    if typ in {"SHTASK", "TASK"}:
        parsed = _parse_memprocfs_task_text(text)
        if parsed:
            parsed["origin"] = "MemProcFS timeline"
            parsed["event"] = event
            task_records.append(parsed)
            action_base = _basename(_first_exe_token(parsed.get("action") or ""))
            if action_base:
                persistence_artifacts.append(
                    (action_base, "MemProcFS scheduled task", text[:200], "T1053.005")
                )
        elif action in {"CRE", "MOD"}:
            _add_finding(
                session, existing,
                title="MemProcFS timeline: scheduled-task artifact changed",
                description=f"Scheduled-task timeline row changed: {text[:500]}",
                severity="medium",
                techniques=["T1053.005"],
                evidence={**evidence, "timeline_type": typ, "timeline_action": action, "text": text[:700]},
                source=f"event:{event.source}",
            )
            _escalate_event(
                session, event, "medium",
                "Detection: scheduled-task timeline artifact was created/modified",
            )

    if typ in {"NTFS", "FILE"} and action in {"CRE", "MOD"}:
        npath = _normalize_path(text)
        executable = bool(_EXECUTABLE_ARTIFACT_RE.search(npath))
        suspicious_dir = any(d in npath for d in SUSPICIOUS_EXECUTION_DIRS)
        task_artifact = any(hint in npath for hint in _TASK_ARTIFACT_HINTS)
        if executable and suspicious_dir:
            # Passive filesystem presence in temp/AppData is common on analyst and
            # developer workstations. Keep it visible in timeline severity, but only
            # make a Finding when correlated process execution points at the same path.
            _escalate_event(
                session, event, "low",
                "Detection: executable created/modified in a user-writable/staging directory",
            )
        elif task_artifact:
            _add_finding(
                session, existing,
                title="MemProcFS timeline: scheduled-task file changed",
                description=(
                    f"Scheduled-task filesystem artifact was {_timeline_action_word(action)}: "
                    f"{text[:500]}"
                ),
                severity="medium",
                techniques=["T1053.005"],
                evidence={**evidence, "timeline_type": typ, "timeline_action": action, "path": text[:700]},
                source=f"event:{event.source}",
            )
            _escalate_event(
                session, event, "medium",
                "Detection: scheduled-task filesystem artifact changed",
            )


def _check_cmdline(session, existing, text: str, evidence: dict[str, Any], source: str) -> str | None:
    """Returns highest severity matched, adds findings."""
    if not text:
        return None
    lower = text.lower()
    top: str | None = None
    for regex, technique, description, severity in SUSPICIOUS_CMDLINE_PATTERNS:
        m = regex.search(lower)
        if m:
            matched = m.group(0).strip() or description  # lookahead-only rules match empty
            _add_finding(
                session, existing,
                title=description,
                description=f"Suspicious command line matched '{matched}': {text[:500]}",
                severity=severity,
                techniques=[technique],
                evidence=evidence,
                source=source,
            )
            if top is None or SEVERITY_RANK[severity] > SEVERITY_RANK[top]:
                top = severity
    return top


def _scan_cmdline_severity(text: str) -> str | None:
    """Highest severity any cmdline pattern matches, WITHOUT emitting findings.

    Used when a matched pattern serves as one *signal* inside a larger graded
    detection (e.g. scheduled-task analysis) so we don't double-emit findings.
    """
    if not text:
        return None
    lower = text.lower()
    top: str | None = None
    for regex, _tech, _desc, severity in SUSPICIOUS_CMDLINE_PATTERNS:
        if regex.search(lower) and (top is None or SEVERITY_RANK[severity] > SEVERITY_RANK[top]):
            top = severity
    return top


def _aware(dt: datetime) -> datetime:
    """Coerce naive datetimes (SQLite round-trips) to UTC so comparisons never raise."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _field(raw: dict[str, Any], *names: str) -> str:
    """Fetch the first present raw field, tolerating case/space/underscore variants."""
    for n in names:
        v = raw.get(n)
        if v not in (None, ""):
            return str(v)
    wanted = {n.lower().replace(" ", "").replace("_", "") for n in names}
    for k, v in raw.items():
        if isinstance(k, str) and k.lower().replace(" ", "").replace("_", "") in wanted and v not in (None, ""):
            return str(v)
    return ""


def _parse_access_mask(value: str) -> int | None:
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None


def _dangerous_process_access(access: int | None) -> bool:
    if access is None:
        return False
    if access in (0x1F0FFF, 0x1FFFFF, 0x143A, 0x1410, 0x1FFFF):
        return True
    return bool(access & (0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0800))


def _process_text_is_sensitive(*values: str) -> bool:
    text = " ".join(v or "" for v in values).lower().replace("/", "\\")
    return any(name in text for name in SENSITIVE_PROCESS_NAMES)


def _first_exe_token(command: str) -> str:
    """First executable token of an action/command string (handles quoting)."""
    c = (command or "").strip()
    if not c:
        return ""
    if c[0] in "\"'":
        end = c.find(c[0], 1)
        return c[1:end].strip() if end > 0 else c[1:].strip()
    m = re.match(r"(\S+(?:\.exe|\.bat|\.cmd|\.ps1|\.vbs|\.js|\.dll|\.sys|\.msi|\.scr|\.com))", c, re.IGNORECASE)
    if m:
        return m.group(1)
    first = c.split()[0]
    # Unquoted path with spaces ("C:\Program Files\...\x.exe args"): only when the
    # text clearly starts with a filesystem path, take the shortest prefix ending
    # in an executable extension.
    if ":" in first or "\\" in first:
        m = re.match(r"([^\"<>|]*?\.(?:exe|bat|cmd|ps1|vbs|js|dll|com|sys|msi|scr))(?:\s|$)", c, re.IGNORECASE)
        if m:
            return m.group(1)
    return first


def _basename(path: str) -> str:
    p = (path or "").strip().strip('"').replace("/", "\\").rstrip("\\")
    return p.rsplit("\\", 1)[-1].strip().lower()


_GUID_NAME_RE = re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$")
_HEX_NAME_RE = re.compile(r"^[0-9a-f]{12,}$")
_VOWELS = set("aeiou")


def _looks_machine_generated(name: str) -> str | None:
    """Heuristic for machine-generated names (GUIDs, random strings, single letters).

    Deliberately conservative: it contributes one *signal*, never a finding by itself.
    """
    n = (name or "").strip().lower()
    if not n:
        return None
    if _GUID_NAME_RE.match(n):
        return "GUID-like name"
    if len(n) == 1 and n.isalpha():
        return "single-letter name"
    if n.isalnum():
        letters = [c for c in n if c.isalpha()]
        if len(n) >= 8 and letters and not any(c in _VOWELS for c in letters):
            return "vowel-less random-looking string"
        if _HEX_NAME_RE.match(n):
            return "long hex string"
        run = best = 0
        for c in n:
            if c.isalpha() and c not in _VOWELS:
                run += 1
                best = max(best, run)
            else:
                run = 0
        if len(n) >= 8 and best >= 7:
            return "improbable consonant sequence"
    return None


# Tolerates the quoted-path form ('"C:\...\schtasks.exe" /create'): a closing
# quote/apostrophe may sit between the extension and the whitespace.
_SCHTASKS_CREATE_RE = re.compile(r"schtasks(?:\.exe)?[\"']?\s+.{0,100}/create\b", re.IGNORECASE)
# Remote payload source in a task action (/tr value or 4698 Command+Arguments):
# an HTTP(S) URL or a UNC path.
_REMOTE_ACTION_RE = re.compile(r"https?://|\\\\", re.IGNORECASE)


def _parse_schtasks_create(text: str) -> dict[str, Any] | None:
    """Extract task name/action/run-as/schedule from a `schtasks /create` command line."""
    if not text or not _SCHTASKS_CREATE_RE.search(text):
        return None

    def grab(flag: str) -> str:
        # Values may be double- or single-quoted ('/tr "mshta.exe https://..."').
        m = re.search(rf"/{flag}\b[:\s]+(\"[^\"]*\"|'[^']*'|\S+)", text, re.IGNORECASE)
        return m.group(1).strip("\"'") if m else ""

    sc = grab("sc").lower()
    mo = grab("mo")
    ri = grab("ri")
    high_freq = False
    if sc == "minute":
        try:
            high_freq = int(mo or "1") < 15
        except ValueError:
            high_freq = True
    if ri:
        try:
            high_freq = high_freq or 0 < int(ri) < 15
        except ValueError:
            pass
    schedule = " ".join(x for x in (f"/sc {sc}" if sc else "", f"/mo {mo}" if mo else "", f"/ri {ri}" if ri else "") if x)
    return {
        "name": grab("tn"),
        "action": grab("tr"),
        "run_as": grab("ru"),
        "run_level": grab("rl"),
        "schedule": schedule,
        "high_freq": high_freq,
    }


def _parse_task_xml(xml: str) -> dict[str, Any]:
    """Extract action/run-as/repetition from scheduled-task XML (4698 TaskContent)."""
    x = xml or ""

    def tag(t: str) -> str:
        m = re.search(rf"<{t}>\s*([^<]*?)\s*</{t}>", x, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    command = tag("command")
    args = tag("arguments")
    action = (command + " " + args).strip()
    high_freq = False
    schedule = ""
    m = re.search(r"<interval>\s*pt([0-9hms.]+)\s*</interval>", x.lower())
    if m:
        spec = m.group(1)
        h = re.search(r"(\d+)h", spec)
        mi = re.search(r"(\d+)m", spec)
        s = re.search(r"(\d+)s", spec)
        total_s = (int(h.group(1)) * 3600 if h else 0) + (int(mi.group(1)) * 60 if mi else 0) + (int(s.group(1)) if s else 0)
        schedule = f"repetition interval PT{spec.upper()}"
        high_freq = 0 < total_s < 15 * 60
    return {
        "name": "",
        "action": action,
        "run_as": tag("userid"),
        "run_level": tag("runlevel"),
        "schedule": schedule,
        "high_freq": high_freq,
    }


# System-ish roots: a SYSTEM-privileged task action living under these is normal.
_SYSTEMISH_PREFIXES = ("\\windows\\", "\\program files")


def _task_signals(rec: dict[str, Any]) -> tuple[list[str], bool]:
    """Independent suspicion signals for one (merged) scheduled-task record.

    Returns (signals, strong): `strong` marks a remote-payload action, which has
    no routine-administration analogue and justifies a high-severity finding on
    its own (the graded 1-signal -> medium rule does not apply to it).
    """
    signals: list[str] = []
    strong = False
    action = rec.get("action") or ""
    exe = _first_exe_token(action)
    npath = _normalize_path(exe)
    base = _basename(exe)
    base_noext = re.sub(r"\.(exe|bat|cmd|ps1|vbs|js|com)$", "", base)

    if npath and "\\" in npath and any(d in npath for d in SUSPICIOUS_EXECUTION_DIRS):
        signals.append(f"action executable resides in a user-writable/staging directory ({exe})")

    if base_noext in SCHEDULED_TASK_SCRIPT_HOSTS:
        sev = _scan_cmdline_severity(action)
        if sev and SEVERITY_RANK[sev] >= SEVERITY_RANK["medium"]:
            signals.append(
                f"action is a script host/LOLBin ({base or base_noext}) with a suspicious "
                f"command line (component severity: {sev})"
            )

    # STRONG signal: the action re-fetches its payload from a remote host (URL or
    # UNC source). Legitimate updaters run local binaries; a task whose action
    # pulls code over the network at trigger time is persistence with remote
    # payload staging (T1053.005 + T1105).
    if _REMOTE_ACTION_RE.search(action):
        strong = True
        signals.append(
            f"task action references a remote payload source (URL/UNC): {action[:200]}"
        )

    run_as = (rec.get("run_as") or "").lower()
    run_level = (rec.get("run_level") or "").lower()
    privileged = "system" in run_as or "s-1-5-18" in run_as or "highest" in run_level
    if privileged and npath and "\\" in npath and not npath.startswith(_SYSTEMISH_PREFIXES):
        signals.append(
            f"runs as SYSTEM/highest privilege while the action lives outside system paths ({exe})"
        )

    tname = rec.get("name") or ""
    tbase = tname.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1].strip().lower()
    reason = _looks_machine_generated(tbase)
    if reason:
        signals.append(f"task name '{tname}' looks machine-generated ({reason})")
    else:
        for fragment, expected_dir in TASK_UPDATER_MASQUERADES:
            if fragment not in tbase or expected_dir in npath:
                continue
            if npath and "\\" in npath:
                signals.append(
                    f"task name '{tname}' masquerades as a vendor updater but the action "
                    f"'{exe}' is outside the vendor directory (expected '{expected_dir}')"
                )
                break
            # Bare action ("mshta.exe https://...") carries no path to check against
            # the vendor directory; a script host or remote source is still a mismatch.
            if base_noext in SCHEDULED_TASK_SCRIPT_HOSTS or _REMOTE_ACTION_RE.search(action):
                signals.append(
                    f"task name '{tname}' masquerades as a vendor updater but the action "
                    f"is a script host / remote payload, not the vendor's updater "
                    f"({(action or exe)[:160]})"
                )
                break

    if rec.get("high_freq"):
        signals.append(
            f"high-frequency schedule ({rec.get('schedule') or 'repetition under 15 minutes'}) "
            "- beacon-like persistence cadence"
        )
    return signals, strong


def _analyze_scheduled_tasks(
    session,
    existing: set[tuple[str, str]],
    task_records: list[dict[str, Any]],
    persistence_artifacts: list[tuple[str, str, str, str]],
) -> None:
    """Grade scheduled-task creations by number of independent suspicion signals.

    0 signals -> no finding (normal admin activity). 1 -> medium lead. >=2 -> high.
    Records from event logs (4698/106) and from schtasks /create command lines are
    merged by task name, so corroboration across sources raises confidence without
    producing duplicate findings.
    """
    merged: dict[str, dict[str, Any]] = {}
    for rec in task_records:
        name = (rec.get("name") or "").strip()
        key = name.lower().lstrip("\\") or ("action:" + (rec.get("action") or "").strip().lower()[:120])
        if not key or key == "action:":
            continue
        slot = merged.setdefault(key, {
            "name": name, "action": "", "run_as": "", "run_level": "",
            "schedule": "", "high_freq": False, "origins": set(), "events": [],
        })
        for f in ("name", "action", "run_as", "run_level", "schedule"):
            if not slot[f] and rec.get(f):
                slot[f] = rec[f]
        slot["high_freq"] = slot["high_freq"] or bool(rec.get("high_freq"))
        slot["origins"].add(rec.get("origin") or "unknown")
        if rec.get("event") is not None:
            slot["events"].append(rec["event"])

    for key, rec in merged.items():
        signals, strong = _task_signals(rec)
        if not signals:
            continue  # ordinary task creation: normal admin activity, no finding
        display = rec["name"] or _first_exe_token(rec["action"]) or key
        corroborated = {"event log", "process"} <= rec["origins"]
        techniques = ["T1053.005"] + (["T1105"] if strong else [])
        if len(signals) == 1 and not strong:
            title = f"Scheduled task with suspicious property: {display}"
            severity = "medium"
            desc_head = (
                "One suspicious property observed on this scheduled task. A single property "
                "also occurs in legitimate software deployment and admin scripting; treat as "
                "a lead and corroborate before escalating."
            )
        else:
            title = f"Anomalous scheduled task: {display}"
            severity = "high"
            if strong and len(signals) == 1:
                desc_head = (
                    "The task action fetches its payload from a remote source at trigger "
                    "time. That property alone has no routine-administration analogue and "
                    "is consistent with scheduled-task persistence staging a remote payload "
                    "(T1053.005 + T1105)."
                )
            else:
                desc_head = (
                    f"{len(signals)} independent suspicious properties observed on one scheduled "
                    "task. In combination they are consistent with scheduled-task persistence "
                    "(T1053.005) rather than routine administration."
                )
        evidence: dict[str, Any] = {
            "entity": display,
            "task_name": rec["name"],
            "action": (rec["action"] or "")[:500],
            "run_as": rec["run_as"],
            "schedule": rec["schedule"],
            "signals": signals,
            "observed_via": sorted(rec["origins"]),
        }
        description = desc_head + " Signals: " + "; ".join(signals) + "."
        if corroborated:
            evidence["corroboration"] = (
                "corroborated by process + event log: a task-creation event and a "
                "schtasks /create command line reference the same task name"
            )
            description += (
                " Creation is corroborated by both a process command line and an "
                "event-log record for the same task name, raising confidence."
            )
        _add_finding(
            session, existing,
            title=title,
            description=description,
            severity=severity,
            techniques=techniques,
            evidence=evidence,
            source="task-heuristics",
        )
        action_base = _basename(_first_exe_token(rec["action"]))
        if action_base:
            persistence_artifacts.append(
                (action_base, "scheduled task", f"{display} -> {rec['action'][:200]}", "T1053.005")
            )
        for e in rec["events"]:
            _escalate_event(session, e, severity, f"Detection: {title}")


# Accounts whose special-privilege logons (4672) are routine, plus prefixes for
# per-session window-manager/font-driver accounts.
_WELLKNOWN_PRIV_ACCOUNTS = {
    "system", "local service", "network service", "anonymous logon",
    "window manager", "font driver host", "-",
}

# Basenames too generic to pair a persistence artifact with a flagged process:
# every case has flagged powershell/cmd processes, so matching on these would
# manufacture correlations.
_PAIRING_GENERIC_HOSTS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "svchost.exe", "explorer.exe",
    "conhost.exe", "reg.exe", "schtasks.exe", "sc.exe", "net.exe", "net1.exe",
    "wmic.exe", "msiexec.exe",
}

_WEVTUTIL_CL_RE = re.compile(r"wevtutil(?:\.exe)?\s+cl\b")
_EXE_TOKEN_RE = re.compile(r"[\w][\w\-.]{0,80}\.exe\b")
_BASE64_BLOB_RE = re.compile(r"[a-z0-9+/]{80,}={0,2}")
_SERVICE_INTERPRETER_RE = re.compile(r"\b(?:powershell|pwsh|cmd\.exe|rundll32)\b|comspec")


def _mem_result_technique(plugin: str, summary: str) -> list[str]:
    text = f"{plugin} {summary}".lower()
    techniques: list[str] = []
    if "yara" in text or "cobalt" in text or "empire" in text or "beacon" in text:
        techniques.append("T1071")
    if "malfind" in text or "injection" in text or "shellcode" in text:
        techniques.append("T1055")
    if "hollow" in text:
        techniques.append("T1055.012")
    if not techniques:
        techniques.append("T1055")
    return sorted(set(techniques))


def _memprocfs_registry_persistence_is_specific(fragment: str, text: str) -> bool:
    if "image file execution options" in fragment:
        return any(token in text for token in (
            r"\debugger", r"\globalflag", r"\silentprocessexit", r"\monitorprocess",
        ))
    if "currentversion\\run" in fragment:
        normalized = text.rstrip("\\")
        return not normalized.endswith((
            r"currentversion\run",
            r"currentversion\runonce",
            r"policies\explorer\run",
        ))
    if "shellserviceobjectdelayload" in fragment:
        return not text.rstrip("\\").endswith(r"shellserviceobjectdelayload")
    return True


def _memory_result_promotable(result: MemoryResult) -> bool:
    plugin = (result.plugin or "").lower()
    if plugin != "memprocfs_findevil":
        return result.severity in ("high", "critical")
    data = result.data or {}
    row = data.get("row") if isinstance(data, dict) else {}
    row_type = str((row or {}).get("Type") or "").upper()
    # MemProcFS findevil is intentionally noisy: entropy, private executable
    # memory, patched-image and debug flags are common on developer/security
    # workstations. Treat them as timeline/context unless another detector
    # independently corroborates the process.
    if row_type in _WEAK_MEMPROCFS_FINDEVIL_TYPES:
        return False
    return result.severity == "critical"


def _promote_memory_results(session, existing: set[tuple[str, str]]) -> None:
    for result in session.scalars(
        select(MemoryResult).where(MemoryResult.severity.in_(["high", "critical"]))
    ):
        if not _memory_result_promotable(result):
            continue
        plugin = result.plugin or "memory"
        entity = result.process_name or (f"pid {result.pid}" if result.pid is not None else plugin)
        title = f"Memory forensic indicator: {plugin}"
        if result.process_name:
            title += f" on {result.process_name}"
        _add_finding(
            session, existing,
            title=title,
            description=(result.summary or "")[:1000],
            severity=result.severity,
            techniques=_mem_result_technique(plugin, result.summary or ""),
            evidence={
                "entity": entity,
                "pid": result.pid,
                "plugin": plugin,
                "memory_result_id": result.id,
                "summary": (result.summary or "")[:500],
                "data": result.data or {},
            },
            source=f"memory:{plugin}",
        )


def _check_cross_process_event(
    session,
    existing: set[tuple[str, str]],
    event: Event,
    raw: dict[str, Any],
    evidence: dict[str, Any],
) -> str | None:
    eid = str(_field(raw, "EventID", "Event Id", "event_id"))
    if eid and not _eid_channel_ok(raw, eid):
        eid = ""
    source_image = _field(raw, "SourceImage", "Source Image", "SourceProcessName", "Process")
    target_image = _field(raw, "TargetImage", "Target Image", "TargetProcessName", "Target")
    source_pid = _field(raw, "SourceProcessId", "SourceProcessID", "SourcePID")
    target_pid = _field(raw, "TargetProcessId", "TargetProcessID", "TargetPID")

    if eid == "8":
        start_address = _field(raw, "StartAddress", "Start Address")
        severity = "critical" if _process_text_is_sensitive(target_image) else "high"
        _add_finding(
            session, existing,
            title="Remote thread creation",
            description=(
                f"Sysmon Event 8 shows {source_image or event.entity or 'a process'} creating a "
                f"thread in {target_image or 'another process'}"
                + (f" at {start_address}" if start_address else "")
                + ". This is direct process-injection telemetry; confirm whether the source is an "
                "expected debugger, EDR, accessibility tool, or developer utility before concluding compromise."
            ),
            severity=severity,
            techniques=["T1055.002"],
            evidence={
                **evidence,
                "source_image": source_image,
                "target_image": target_image,
                "source_pid": source_pid or None,
                "target_pid": target_pid or None,
                "start_address": start_address or None,
            },
            source=f"event:{event.source}",
        )
        return severity

    if eid == "10":
        access_raw = _field(raw, "GrantedAccess", "Granted Access", "AccessMask")
        access = _parse_access_mask(access_raw)
        sensitive = _process_text_is_sensitive(target_image)
        dangerous = _dangerous_process_access(access)
        if not (sensitive or dangerous):
            return None
        severity = "critical" if sensitive and dangerous else "high"
        reasons = []
        if sensitive:
            reasons.append("target process is sensitive")
        if dangerous:
            reasons.append("access mask permits memory/thread/handle manipulation")
        _add_finding(
            session, existing,
            title="Suspicious process access",
            description=(
                f"Sysmon Event 10 shows {source_image or event.entity or 'a process'} opening "
                f"{target_image or 'another process'} with access {access_raw or 'unknown'}. "
                + "; ".join(reasons)
                + ". Process access is common on workstations, so this is only raised when the "
                "target/access combination can support credential theft, dumping, or injection."
            ),
            severity=severity,
            techniques=["T1055", "T1003"],
            evidence={
                **evidence,
                "source_image": source_image,
                "target_image": target_image,
                "source_pid": source_pid or None,
                "target_pid": target_pid or None,
                "granted_access": access_raw or None,
                "sensitive_target": sensitive,
                "dangerous_access": dangerous,
            },
            source=f"event:{event.source}",
        )
        return severity

    if event.category == "handle" and str(raw.get("risk") or "").lower() in {"high", "critical"}:
        severity = str(raw.get("risk"))
        _add_finding(
            session, existing,
            title="Suspicious cross-process handle",
            description=(
                f"{raw.get('Process') or event.entity or 'A process'} holds a "
                f"{raw.get('Type') or 'process'} handle to "
                f"{raw.get('TargetProcess') or raw.get('Name') or 'another target'}"
                + (f" with access {raw.get('Access')}" if raw.get("Access") else "")
                + ". " + "; ".join(raw.get("risk_reasons") or ["high-risk handle relationship"])
            ),
            severity=severity,
            techniques=["T1055"],
            evidence={**evidence, **{k: v for k, v in raw.items() if k != "plugin"}},
            source=f"event:{event.source}",
        )
        return severity

    return None


# Tokens too generic to correlate artifacts by name (platform/arch/installer noise).
_CORR_TOKEN_STOP = {
    "amd64", "x86", "x64", "arm64", "win32", "win64", "setup", "install",
    "installer", "signed", "release", "windows", "microsoft", "update",
    "service", "driver", "temp", "portable", "latest", "download",
}


def _corr_tokens(text: str) -> set[str]:
    """Distinctive name tokens for cross-artifact correlation ('go-winpmem_amd64
    _1.0-rc1_signed.exe' -> {'winpmem'})."""
    return {
        t for t in re.split(r"[^a-z0-9]+", (text or "").lower())
        if len(t) >= 5 and not t.isdigit() and t not in _CORR_TOKEN_STOP
    }


_ZONE_URL_RE = re.compile(r"(ReferrerUrl|HostUrl)=(\S+)", re.IGNORECASE)
_DOWNLOAD_PAYLOAD_RE = re.compile(
    r"\.(?:exe|msi|dll|sys|ps1|bat|cmd|vbs|js|scr|com|zip|7z|rar|gz|iso|cab)$",
    re.IGNORECASE,
)
# A download older than this cannot credibly be "the origin" of a service install.
_DOWNLOAD_CORRELATION_WINDOW_S = 72 * 3600


def _download_origin(raw: dict[str, Any]) -> str | None:
    """Referrer/host URL from a Zone.Identifier ADS blob, if present."""
    zone = str(raw.get("_ZoneIdentifierContent") or raw.get("ZoneIdentifierContent") or "")
    m = _ZONE_URL_RE.search(zone)
    return m.group(2)[:300] if m else None


def _event_needed_for_provenance(event: Event, raw: dict[str, Any]) -> bool:
    eid = str(raw.get("EventID") or "")
    if eid and _eid_channel_ok(raw, eid) and eid in {"11", "12", "13", "4697", "7045"}:
        return True
    if _field(raw, "DownloadedFilePath", "Download Path", "TargetPath") and (
        "download" in (event.source or "").lower() or raw.get("_ZoneIdentifierContent")
    ):
        return True
    if _is_usn_journal_event(event, raw):
        tokens = _usn_reason_tokens(raw)
        return bool(
            tokens & {"FILE_CREATE", "RENAME_NEW_NAME"}
            and _is_usn_executable_path(_usn_path(event, raw))
        )
    return False


def _artifact_path_key(path: str) -> str:
    p = (path or "").strip().strip('"').replace("/", "\\")
    p = re.sub(r"^\\\\\.\\", "", p)
    p = re.sub(r"^\\\?\\", "", p)
    return _normalize_path(p)


def _artifact_match_confidence(artifact_path: str, exec_path: str) -> str | None:
    if not artifact_path or not exec_path:
        return None
    artifact_key = _artifact_path_key(artifact_path)
    exec_key = _artifact_path_key(exec_path)
    if artifact_key and exec_key and artifact_key == exec_key:
        return "exact-path"
    if _basename(artifact_path) != _basename(exec_path):
        return None
    tokens = _corr_tokens(_basename(artifact_path))
    if tokens and tokens & _corr_tokens(_basename(exec_path)):
        return "distinctive-basename"
    return None


def _collect_file_artifacts(events: list[Event]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen: set[tuple[int | None, str, str]] = set()
    for event in events:
        raw = event.raw or {}
        path = ""
        kind = ""
        origin = None
        dl_path = _field(raw, "DownloadedFilePath", "Download Path", "TargetPath")
        if dl_path and ("download" in (event.source or "").lower() or raw.get("_ZoneIdentifierContent")):
            path = dl_path
            kind = "download"
            origin = _download_origin(raw)
        elif _is_usn_journal_event(event, raw):
            tokens = _usn_reason_tokens(raw)
            if not (tokens & {"FILE_CREATE", "RENAME_NEW_NAME"}):
                continue
            path = _usn_path(event, raw)
            kind = "USN rename" if "RENAME_NEW_NAME" in tokens else "USN create"
            if not _is_user_writable_path(path):
                continue
        if not path:
            continue
        base = _basename(path)
        if base in _PAIRING_GENERIC_HOSTS or not _DOWNLOAD_PAYLOAD_RE.search(base):
            continue
        key = (event.id, kind, _artifact_path_key(path))
        if key in seen:
            continue
        seen.add(key)
        artifacts.append({
            "event": event,
            "path": path,
            "base": base,
            "kind": kind,
            "origin": origin,
        })
    return artifacts


def _correlate_file_execution_provenance(
    session,
    existing: set[tuple[str, str]],
    events: list[Event],
    processes: list[Process],
) -> None:
    artifacts = _collect_file_artifacts(events)
    if not artifacts:
        return
    executions_by_base: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_exec: set[tuple[str, int | None, str]] = set()
    for proc in processes:
        exec_path = proc.path or proc.name or ""
        if not exec_path or _basename(exec_path) in _PAIRING_GENERIC_HOSTS:
            continue
        key = (proc.session_id, proc.pid, _artifact_path_key(exec_path) or _basename(exec_path))
        if key in seen_exec:
            continue
        seen_exec.add(key)
        entry = {
            "path": exec_path,
            "base": _basename(exec_path),
            "timestamp": proc.start_time,
            "severity": proc.severity,
            "pid": proc.pid,
            "process": proc.name,
            "cmdline": proc.cmdline,
            "session_id": proc.session_id,
            "event": None,
        }
        executions_by_base[entry["base"]].append(entry)
    for event in events:
        raw = event.raw or {}
        eid = str(raw.get("EventID") or "")
        if eid and not _eid_channel_ok(raw, eid):
            continue
        if eid not in {"1", "4688"}:
            continue
        image = _field(raw, "Image", "NewProcessName")
        if not image or _basename(image) in _PAIRING_GENERIC_HOSTS:
            continue
        key = ("event", event.id, _artifact_path_key(image) or _basename(image))
        if key in seen_exec:
            continue
        seen_exec.add(key)
        entry = {
            "path": image,
            "base": _basename(image),
            "timestamp": event.timestamp,
            "severity": event.severity,
            "pid": _field(raw, "ProcessId", "NewProcessId") or None,
            "process": _basename(image),
            "cmdline": _field(raw, "CommandLine", "Cmdline"),
            "session_id": None,
            "event": event,
        }
        executions_by_base[entry["base"]].append(entry)

    for artifact in artifacts:
        event = artifact["event"]
        best: tuple[float, str, dict[str, Any]] | None = None
        for execution in executions_by_base.get(artifact["base"], []):
            confidence = _artifact_match_confidence(artifact["path"], execution["path"])
            if not confidence:
                continue
            if event.timestamp and execution["timestamp"]:
                gap = (_aware(execution["timestamp"]) - _aware(event.timestamp)).total_seconds()
                if not (0 <= gap <= _DOWNLOAD_CORRELATION_WINDOW_S):
                    continue
            else:
                gap = _DOWNLOAD_CORRELATION_WINDOW_S
            rank = 0 if confidence == "exact-path" else 1
            score = gap + (rank * _DOWNLOAD_CORRELATION_WINDOW_S)
            if best is None or score < best[0]:
                best = (gap, confidence, execution)
        if not best:
            continue
        gap, confidence, execution = best
        exec_rank = SEVERITY_RANK.get(execution["severity"], 0)
        artifact_rank = SEVERITY_RANK.get(event.severity, 0)
        if confidence != "exact-path" and max(exec_rank, artifact_rank) < SEVERITY_RANK["medium"]:
            continue
        severity = "high" if max(exec_rank, artifact_rank) >= SEVERITY_RANK["high"] else "medium"
        gap_txt = "unknown time after" if gap == _DOWNLOAD_CORRELATION_WINDOW_S else (
            f"{gap/60:.0f} minutes after" if gap < 5400 else f"{gap/3600:.1f} hours after"
        )
        _add_finding(
            session,
            existing,
            title=f"File artifact later executed: {artifact['base']}",
            description=(
                f"A {artifact['kind']} artifact ({artifact['path'][:300]}) was later executed as "
                f"{execution['path'][:300]} ({gap_txt} the artifact timestamp). Match confidence: "
                f"{confidence}. This links filesystem/download evidence to execution, but still "
                "requires analyst review for expected installers, developer tooling, or admin utilities."
            ),
            severity=severity,
            techniques=["T1204", "T1105"],
            evidence={
                "entity": execution["path"],
                "artifact_path": artifact["path"][:700],
                "artifact_kind": artifact["kind"],
                "artifact_event_id": event.id,
                "execution_path": execution["path"][:700],
                "execution_pid": execution["pid"],
                "execution_session_id": execution["session_id"],
                "execution_event_id": execution["event"].id if execution["event"] else None,
                "match_confidence": confidence,
                "gap_seconds": None if gap == _DOWNLOAD_CORRELATION_WINDOW_S else round(gap, 1),
                "origin_url": artifact["origin"],
            },
            source="correlation",
        )
        _escalate_event(
            session,
            event,
            severity,
            f"Correlated: {artifact['kind']} artifact later executed as {execution['base']}",
        )
        if execution["event"] is not None:
            _escalate_event(
                session,
                execution["event"],
                severity,
                f"Correlated: process execution matched prior {artifact['kind']} artifact",
            )


def _correlate_service_provenance(
    session,
    existing: set[tuple[str, str]],
    events: list[Event],
    processes: list[Process],
) -> None:
    """Trace each installed service back to its origin: the process that dropped
    the binary, the process that registered/installed it, and the download the
    binary most plausibly came from. Emits one finding per service with the full
    chain, and records the chain as graph edges for the entity map."""
    # --- group service installs by service name ---
    installs: dict[str, dict[str, Any]] = {}
    # --- correlation source indexes ---
    downloads: list[tuple[Event, str, set[str]]] = []  # (event, path, tokens)
    # basename -> (event, creator/provenance label, source label)
    file_creates: dict[str, list[tuple[Event, str, str]]] = defaultdict(list)
    reg_writes: list[tuple[Event, str, str]] = []  # (event, target_object_lower, writer image)
    proc_creates: list[tuple[Event, str, str]] = []  # (event, image, cmdline)

    for e in events:
        raw = e.raw or {}
        eid = str(raw.get("EventID") or "")
        if eid and not _eid_channel_ok(raw, eid):
            continue
        if eid in ("7045", "4697"):
            svc = _field(raw, "ServiceName", "Service Name").strip()
            if not svc:
                continue
            slot = installs.setdefault(svc.lower(), {
                "name": svc, "events": [], "images": [], "client_pids": set(),
            })
            slot["events"].append(e)
            image = _field(raw, "ImagePath", "Image Path", "ServiceFileName", "PathName")
            if image and image not in slot["images"]:
                slot["images"].append(image)
            client_pid = _parse_access_mask(_field(raw, "ClientProcessId")) if eid == "4697" else None
            if client_pid:
                slot["client_pids"].add(client_pid)
            continue
        dl_path = _field(raw, "DownloadedFilePath", "Download Path", "TargetPath")
        if dl_path and ("download" in (e.source or "").lower() or raw.get("_ZoneIdentifierContent")):
            base = _basename(dl_path)
            # Only executable/archive downloads can plausibly originate a service;
            # media/source files sharing a vendor token are coincidence.
            if _DOWNLOAD_PAYLOAD_RE.search(base):
                downloads.append((e, dl_path, _corr_tokens(base)))
            continue
        if _is_usn_journal_event(e, raw):
            tokens = _usn_reason_tokens(raw)
            usn_path = _usn_path(e, raw)
            usn_base = _basename(usn_path)
            if (
                usn_path
                and _DOWNLOAD_PAYLOAD_RE.search(usn_base)
                and (tokens & {"FILE_CREATE", "RENAME_NEW_NAME"})
            ):
                file_creates[usn_base].append((e, "NTFS $J journal", "USN journal"))
            continue
        if eid == "11":
            target = _field(raw, "TargetFilename", "Target Filename")
            if target:
                file_creates[_basename(target)].append((e, _field(raw, "Image"), "Sysmon file-create"))
        elif eid in ("12", "13"):
            target = _field(raw, "TargetObject").lower()
            if "\\services\\" in target:
                reg_writes.append((e, target, _field(raw, "Image")))
        elif eid in ("1", "4688"):
            image = _field(raw, "Image", "NewProcessName")
            if image:
                proc_creates.append((e, image, _field(raw, "CommandLine", "Cmdline")))

    if not installs:
        return

    proc_by_pid: dict[int, Process] = {}
    for p in processes:
        proc_by_pid.setdefault(p.pid, p)

    for key, slot in installs.items():
        svc_events: list[Event] = slot["events"]
        times = sorted(e.timestamp for e in svc_events if e.timestamp)
        first_ts = _aware(times[0]) if times else None
        svc_tokens = _corr_tokens(slot["name"])
        for img in slot["images"]:
            svc_tokens |= _corr_tokens(_basename(_first_exe_token(img)))
        chain_bits: list[str] = []
        chain_edges: list[dict[str, str]] = []
        correlated_ids: list[int] = []
        install_sev = max(
            (e.severity for e in svc_events),
            key=lambda s: SEVERITY_RANK.get(s, 0), default="medium",
        )

        # 1. dropper: who wrote the service binary to disk (Sysmon 11)
        droppers: dict[str, list[str]] = defaultdict(list)
        dropper_sources: dict[str, set[str]] = defaultdict(set)
        for img in slot["images"]:
            base = _basename(_first_exe_token(img))
            for fc_event, creator, source_label in file_creates.get(base, []):
                if creator and _basename(creator) != "system":
                    droppers[creator].append(base)
                    dropper_sources[creator].add(source_label)
                    correlated_ids.append(fc_event.id)
        for creator, bases in list(droppers.items())[:3]:
            source_txt = ", ".join(sorted(dropper_sources.get(creator) or {"file telemetry"}))
            chain_bits.append(
                f"the service binary ({', '.join(sorted(set(bases))[:3])}) was written to disk "
                f"by/observed through {creator} ({source_txt})"
            )
            chain_edges.append({
                "src_type": "process", "src": creator,
                "verb": "dropped binary for", "dst_type": "service", "dst": slot["name"],
            })

        # 2. registry writer on the service key (excluding services.exe, which is
        # the SCM acting on behalf of the real caller and carries no attribution)
        for rw_event, target, writer in reg_writes:
            if f"\\services\\{key}" in target and writer and _basename(writer) != "services.exe":
                chain_bits.append(f"its registry key was written by {writer}")
                chain_edges.append({
                    "src_type": "process", "src": writer,
                    "verb": "registered", "dst_type": "service", "dst": slot["name"],
                })
                correlated_ids.append(rw_event.id)
                break

        # 3. installer process: 4697 names the client PID directly; otherwise the
        # nearest earlier process creation sharing a distinctive name token
        for pid in sorted(slot["client_pids"])[:3]:
            p = proc_by_pid.get(pid)
            if p:
                chain_bits.append(
                    f"installed by {p.name} (pid {pid}, per Event 4697 ClientProcessId)"
                )
                chain_edges.append({
                    "src_type": "process", "src": p.path or p.name,
                    "verb": "installed", "dst_type": "service", "dst": slot["name"],
                })
        if svc_tokens and not slot["client_pids"]:
            best: tuple[float, Event, str, str] | None = None
            for pc_event, image, cmdline in proc_creates:
                if not pc_event.timestamp or not first_ts:
                    continue
                gap = (first_ts - _aware(pc_event.timestamp)).total_seconds()
                if not (0 <= gap <= 3600):
                    continue
                if svc_tokens & (_corr_tokens(_basename(image)) | _corr_tokens(cmdline)):
                    if best is None or gap < best[0]:
                        best = (gap, pc_event, image, cmdline)
            if best:
                gap, pc_event, image, cmdline = best
                parent = _field(pc_event.raw or {}, "ParentImage", "ParentProcessName")
                chain = (f"{_basename(parent)} -> " if parent else "") + _basename(image)
                chain_bits.append(
                    f"likely initiated by {chain} started {gap:.0f}s before the install"
                    + (f" (cmdline: {cmdline[:160]})" if cmdline else "")
                )
                chain_edges.append({
                    "src_type": "process", "src": image,
                    "verb": "installed", "dst_type": "service", "dst": slot["name"],
                })
                correlated_ids.append(pc_event.id)

        # 4. origin download: name-token match on downloaded files preceding install
        dl_match: tuple[float, Event, str] | None = None
        for dl_event, dl_path, dl_tokens in downloads:
            if not (svc_tokens & dl_tokens):
                continue
            if not (first_ts and dl_event.timestamp):
                continue
            gap = (first_ts - _aware(dl_event.timestamp)).total_seconds()
            if not (0 <= gap <= _DOWNLOAD_CORRELATION_WINDOW_S):
                continue
            if dl_match is None or gap < dl_match[0]:
                dl_match = (gap, dl_event, dl_path)
        if dl_match:
            gap, dl_event, dl_path = dl_match
            origin = _download_origin(dl_event.raw or {})
            gap_txt = f"{gap/60:.0f} minutes" if gap < 5400 else f"{gap/3600:.1f} hours"
            chain_bits.append(
                f"the matching file {_basename(dl_path)} was downloaded {gap_txt} before "
                f"the first install"
                + (f" from {origin}" if origin else "")
            )
            chain_edges.append({
                "src_type": "file", "src": dl_path.lstrip("\\\\.\\"),
                "verb": "origin of", "dst_type": "service", "dst": slot["name"],
            })
            correlated_ids.append(dl_event.id)
            _escalate_event(
                session, dl_event, install_sev,
                f"Correlated: this download ({_basename(dl_path)}) is the likely origin of "
                f"service '{slot['name']}', first installed {gap_txt} later"
                + (f"; source URL {origin}" if origin else ""),
            )

        if not chain_bits:
            continue

        span = ""
        if times:
            span = f" between {times[0].isoformat()} and {times[-1].isoformat()}" if len(times) > 1 else f" at {times[0].isoformat()}"
        _add_finding(
            session, existing,
            title=f"Service provenance traced: {slot['name']}",
            description=(
                f"Service '{slot['name']}' was installed {len(svc_events)} time(s){span} "
                f"(image(s): {'; '.join(slot['images'][:4])}). Provenance correlation: "
                + "; ".join(chain_bits) + "."
            ),
            severity=install_sev,
            techniques=["T1543.003", "T1105"],
            evidence={
                "entity": slot["name"],
                "service_name": slot["name"],
                "install_count": len(svc_events),
                "image_paths": slot["images"][:8],
                "chain": chain_bits,
                "chain_edges": chain_edges,
                "correlated_event_ids": correlated_ids[:20],
            },
            source="correlation",
        )


# Prefix marking severities set by the taint-propagation pass. Events carrying it
# never become taint *sources* on later runs, so severity cannot cascade
# name-by-name across the whole case.
_PROPAGATION_MARKER = "Flagged-entity match"
_FILE_TOKEN_RE = re.compile(
    r"[\w][\w\-.]{2,80}\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|scr|com)\b", re.IGNORECASE
)


def _propagate_flagged_entities(session, events: list[Event], processes: list[Process]) -> int:
    """Severity taint propagation across the case timeline.

    Collects every process/DLL/file name that anything already flagged low or
    above (the process table, memory-analysis results, or detection-escalated
    events), then raises any event that mentions one of those names to the same
    severity, recording on the event where the severity came from.
    """
    tainted: dict[str, tuple[int, str]] = {}  # basename -> (severity rank, origin text)

    def taint(name: str, severity: str, origin: str) -> None:
        base = _basename(name)
        rank = SEVERITY_RANK.get(severity, 0)
        # Generic host binaries (powershell/cmd/svchost/...) appear in nearly every
        # event; propagating on their name alone would repaint the entire timeline.
        if not base or len(base) < 4 or base in _PAIRING_GENERIC_HOSTS:
            return
        if rank < SEVERITY_RANK["low"]:
            return
        cur = tainted.get(base)
        if cur is None or rank > cur[0]:
            tainted[base] = (rank, origin)

    for p in processes:
        if SEVERITY_RANK.get(p.severity, 0) < SEVERITY_RANK["low"]:
            continue
        flags = ", ".join(p.flags or []) or "no flags recorded"
        origin = (
            f"process {p.name} (pid {p.pid}) was flagged {p.severity} "
            f"by process/memory detections ({flags})"
        )
        taint(p.name or "", p.severity, origin)
        taint(_basename(_normalize_path(p.path or "")), p.severity, origin)

    for r in session.scalars(
        select(MemoryResult).where(MemoryResult.severity.in_(["low", "medium", "high", "critical"]))
    ):
        summary = (r.summary or "")[:160]
        pid_part = f" (pid {r.pid})" if r.pid is not None else ""
        if r.process_name:
            taint(
                r.process_name, r.severity,
                f"memory analysis ({r.plugin}) flagged process "
                f"{r.process_name}{pid_part} as {r.severity}: {summary}",
            )
        for tok in set(_FILE_TOKEN_RE.findall(r.summary or "")):
            taint(
                tok, r.severity,
                f"memory analysis ({r.plugin}) flagged {r.severity} activity "
                f"referencing {_basename(tok)}{pid_part}: {summary}",
            )

    for e in events:
        if SEVERITY_RANK.get(e.severity, 0) < SEVERITY_RANK["low"]:
            continue
        if (e.severity_reason or "").startswith(_PROPAGATION_MARKER):
            continue
        for tok in set(_FILE_TOKEN_RE.findall(e.entity or "")):
            taint(
                tok, e.severity,
                f"a {e.severity}-severity event from {e.source} involved "
                f"{_basename(tok)}: {(e.summary or '')[:140]}",
            )

    if not tainted:
        return 0

    names = sorted(tainted, key=len, reverse=True)
    pattern = re.compile(
        r"(?<![\w-])(?:" + "|".join(re.escape(n) for n in names) + r")(?![\w-])",
        re.IGNORECASE,
    )
    changed = 0
    for e in events:
        hay = " ".join(
            filter(None, [e.summary, e.entity, json.dumps(e.raw or {}, default=str)])
        )
        matches = {m.lower() for m in pattern.findall(hay)}
        if not matches:
            continue
        best = max(matches, key=lambda n: tainted[n][0])
        rank, origin = tainted[best]
        if rank <= SEVERITY_RANK.get(e.severity, 0):
            continue
        others = sorted(matches - {best})
        reason = f"{_PROPAGATION_MARKER}: this event references '{best}' — {origin}"
        if others:
            reason += f" (also references flagged: {', '.join(others[:4])})"
        _escalate_event(session, e, _RANK_TO_SEVERITY[rank], reason)
        changed += 1
    return changed


def run_detections_sync(case_id: str) -> int:
    """Run all detection heuristics for a case. Returns number of findings added."""
    session = case_store.get_session(case_id)
    try:
        existing: set[tuple[str, str]] = set()
        for f in session.scalars(select(Finding)):
            existing.add((f.title, str(f.evidence.get("entity") or f.evidence.get("pid") or f.evidence.get("summary", ""))[:200]))
        before = len(existing)

        processes = list(session.scalars(select(Process)))
        proc_by_pid: dict[tuple[str, int], Process] = {}
        for p in processes:
            proc_by_pid[(p.session_id, p.pid)] = p

        # Scheduled-task creations observed anywhere in the case (4698/106 events,
        # schtasks /create command lines); analyzed and cross-corroborated at the end.
        task_records: list[dict[str, Any]] = []
        # Persistence artifacts (task actions, service images, run-key targets) for the
        # persistence + execution pairing pass: (exe basename, kind, detail, technique).
        persistence_artifacts: list[tuple[str, str, str, str]] = []

        # --- Process heuristics ---
        cmdline_rank: dict[tuple[str, int], int] = {}
        for proc in processes:
            name = (proc.name or "").lower()
            path = _normalize_path(proc.path or "")
            cmdline = proc.cmdline or ""
            flags = list(proc.flags or [])
            evidence = {
                "pid": proc.pid, "ppid": proc.ppid, "entity": proc.name,
                "path": proc.path, "cmdline": (cmdline or "")[:500],
            }

            # LOLBin usage with non-trivial command line
            if name in LOLBINS and cmdline and len(cmdline.split()) > 1:
                technique, desc = LOLBINS[name]
                _add_finding(
                    session, existing,
                    title=f"LOLBin activity: {proc.name}",
                    description=f"{desc}. Command line: {cmdline[:500]}",
                    severity="low" if name in LOW_SIGNAL_LOLBINS else "medium",
                    techniques=[technique],
                    evidence=evidence,
                    source="process-heuristics",
                )
                flags.append("lolbin")

            # Suspicious command line patterns
            top = _check_cmdline(session, existing, cmdline, evidence, "process-heuristics")
            if top:
                flags.append("suspicious-cmdline")
                cmdline_rank[(proc.session_id, proc.pid)] = SEVERITY_RANK[top]
                if SEVERITY_RANK[top] > SEVERITY_RANK.get(proc.severity, 0):
                    proc.severity = top

            # schtasks /create in a process command line feeds the scheduled-task
            # analysis (and corroborates 4698 events for the same task name).
            if cmdline and name.startswith("schtasks"):
                parsed = _parse_schtasks_create(cmdline)
                if parsed:
                    parsed["origin"] = "process"
                    parsed["event"] = None
                    task_records.append(parsed)

            # Masquerading: system process from wrong path. Path is normalized (device
            # paths, \??\, \SystemRoot) and placeholder/bare-name paths never fire.
            if name in SYSTEM_PROCESS_PATHS and path and "\\" in path:
                expected = SYSTEM_PROCESS_PATHS[name]
                if expected not in path:
                    _add_finding(
                        session, existing,
                        title=f"System process masquerade: {proc.name}",
                        description=(
                            f"{proc.name} running from '{proc.path}' instead of expected "
                            f"location containing '{expected}'. Consistent with masquerading "
                            "tradecraft; verify the image path source before concluding."
                        ),
                        severity="high",
                        techniques=["T1036.005"],
                        evidence={**evidence, "normalized_path": path},
                        source="process-heuristics",
                    )
                    flags.append("masquerade")
                    if SEVERITY_RANK.get(proc.severity, 0) < SEVERITY_RANK["high"]:
                        proc.severity = "high"

            # Execution from suspicious directories
            if path and any(d in path for d in SUSPICIOUS_EXECUTION_DIRS):
                _add_finding(
                    session, existing,
                    title=f"Execution from suspicious directory: {proc.name}",
                    description=f"Process executing from user-writable/staging path: {proc.path}",
                    severity="medium",
                    techniques=["T1204"],
                    evidence=evidence,
                    source="process-heuristics",
                )
                flags.append("suspicious-path")
                if SEVERITY_RANK.get(proc.severity, 0) < SEVERITY_RANK["medium"]:
                    proc.severity = "medium"

            path_base = _basename(path)
            root_name = re.sub(r"\.exe$", "", path_base)
            if path and _WINDOWS_ROOT_EXEC_RE.match(path) and _looks_machine_generated(root_name):
                _add_finding(
                    session, existing,
                    title=f"Random-looking executable in Windows root: {proc.name}",
                    description=(
                        f"{proc.name} ran directly from the Windows directory ({proc.path}). "
                        "Legitimate Windows binaries usually live under System32/SysWOW64 or "
                        "well-known component folders; a random-looking executable at this "
                        "level is consistent with staged malware."
                    ),
                    severity="high",
                    techniques=["T1036.005", "T1204"],
                    evidence={**evidence, "normalized_path": path},
                    source="process-heuristics",
                )
                flags.extend(["suspicious-path", "masquerade"])
                if SEVERITY_RANK.get(proc.severity, 0) < SEVERITY_RANK["high"]:
                    proc.severity = "high"

            # Parent/child anomalies
            parent = proc_by_pid.get((proc.session_id, proc.ppid)) if proc.ppid else None
            if parent:
                pname = (parent.name or "").lower()
                parent_flags = set(parent.flags or [])
                # PPID reuse: a "parent" that started after the child cannot be the real
                # parent -- the original parent exited and its PID was recycled.
                pid_reused = bool(
                    parent.start_time and proc.start_time and parent.start_time > proc.start_time
                )
                parent_gone = bool(parent_flags & {"terminated", "exited"})
                parent_evidence = {
                    **evidence, "parent": parent.name, "parent_pid": parent.pid,
                    "parent_start_time": parent.start_time.isoformat() if parent.start_time else None,
                    "child_start_time": proc.start_time.isoformat() if proc.start_time else None,
                    "pid_reuse_suspected": pid_reused,
                }
                # Known-bad pairs (skip when the parent PID was demonstrably reused)
                if not pid_reused:
                    bad_pair = SUSPICIOUS_PARENT_CHILD_MAP.get((pname, name))
                    if bad_pair is not None:
                        technique, desc = bad_pair
                        _add_finding(
                            session, existing,
                            title=f"Suspicious process chain: {parent.name} -> {proc.name}",
                            description=f"{desc}. Child cmdline: {(cmdline or 'n/a')[:400]}",
                            severity="high",
                            techniques=[technique],
                            evidence=parent_evidence,
                            source="process-heuristics",
                        )
                        flags.append("bad-parent-child")
                        if SEVERITY_RANK.get(proc.severity, 0) < SEVERITY_RANK["high"]:
                            proc.severity = "high"
                # Broken expected parentage for core system processes
                if name in EXPECTED_PARENTS and pname and pname not in EXPECTED_PARENTS[name]:
                    if pid_reused:
                        _add_finding(
                            session, existing,
                            title=f"Unresolved parentage for {proc.name}",
                            description=(
                                f"{proc.name} (pid {proc.pid}) records ppid {parent.pid} ({parent.name}), "
                                f"but that process started after the child. The PPID was likely reused "
                                "after the real parent exited; not treated as injection evidence."
                            ),
                            severity="low",
                            techniques=["T1055"],
                            evidence=parent_evidence,
                            source="process-heuristics",
                        )
                    elif parent_gone:
                        pass  # parent terminated: parentage is unknown, not anomalous
                    else:
                        _add_finding(
                            session, existing,
                            title=f"Anomalous parent for {proc.name}",
                            description=(
                                f"{proc.name} (pid {proc.pid}) spawned by {parent.name} (pid {parent.pid}); "
                                f"expected parent: {', '.join(EXPECTED_PARENTS[name])}. "
                                "Start times are consistent with a live parent (PID reuse ruled out "
                                "where timestamps exist); candidate for process injection or hollowing."
                            ),
                            severity="high",
                            techniques=["T1055"],
                            evidence=parent_evidence,
                            source="process-heuristics",
                        )
                        flags.append("anomalous-parent")
                        if SEVERITY_RANK.get(proc.severity, 0) < SEVERITY_RANK["high"]:
                            proc.severity = "high"

            proc.flags = sorted(set(flags))

        # --- Correlation pass: independent signal classes stacking on one process ---
        # >= 2 distinct classes (engine flags and/or memory-pipeline flags) produce one
        # composite finding at a severity one rank above the strongest component.
        for proc in processes:
            signals = sorted(s for s in (proc.flags or []) if s in CORRELATION_FLAGS)
            if len(signals) < 2:
                continue
            base = max(SEVERITY_RANK[CORRELATION_FLAGS[s][0]] for s in signals)
            if "suspicious-cmdline" in signals:
                base = max(base, cmdline_rank.get((proc.session_id, proc.pid), 0))
            severity = _RANK_TO_SEVERITY[min(base + 1, SEVERITY_RANK["critical"])]
            _add_finding(
                session, existing,
                title=f"Correlated indicators on {proc.name} (pid {proc.pid})",
                description=(
                    f"{proc.name} (pid {proc.pid}) accumulated {len(signals)} independent signal "
                    f"classes: {', '.join(signals)}. Each signal alone has benign explanations; "
                    "in combination they are consistent with an actively compromised process."
                ),
                severity=severity,
                techniques=sorted({CORRELATION_FLAGS[s][1] for s in signals}),
                evidence={
                    "pid": proc.pid, "entity": proc.name, "session_id": proc.session_id,
                    "signals": signals,
                    "component_max_severity": _RANK_TO_SEVERITY[base],
                },
                source="correlation",
            )
            if SEVERITY_RANK[severity] > SEVERITY_RANK.get(proc.severity, 0):
                proc.severity = severity

        session.commit()

        # --- MemoryResult bridge ---
        # Memory analysis can produce high-confidence indicators even when no
        # event-log fields exist to match, so promote those rows into Findings.
        _promote_memory_results(session, existing)
        session.commit()

        # --- Event heuristics ---
        event_stream = session.scalars(select(Event).execution_options(yield_per=EVENT_STREAM_BATCH_SIZE))
        provenance_events: list[Event] = []
        beacon_tracker: dict[str, list[Event]] = defaultdict(list)
        web_ip_tracker: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"total": 0, "errors": 0, "auth_fail": 0, "auth_ok": set(), "events": []}
        )
        # Logon trackers (4624/4625/4672). No-ops when the fields aren't ingested.
        logon_fail: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "first": None, "events": []}
        )
        logon_success: dict[tuple[str, str], list[Event]] = defaultdict(list)
        rdp_logons: dict[str, dict[str, Any]] = {}
        priv_logons: dict[str, dict[str, Any]] = {}
        # Log-clear events (1102 / wevtutil cl) for the intrusion-window correlation.
        log_clear_marks: list[tuple[Event, str]] = []
        # NTFS $UsnJrnl:$J rename rows are correlated by FileReferenceNumber after
        # this event pass, so old/new names become one timeline lead.
        usn_events: list[Event] = []

        for event in event_stream:
            raw = event.raw or {}
            if _event_needed_for_provenance(event, raw):
                provenance_events.append(event)
            is_usn_event = _is_usn_journal_event(event, raw)
            # Memory-pipeline events carry our own descriptive summaries (e.g. "Hidden
            # process detected: lsass.exe ..."); scanning those re-triggers patterns on
            # text that merely describes a finding. Only scan real embedded command lines.
            if is_usn_event:
                summary_text = ""
            elif (event.source or "").startswith("memory:") or event.category == "memory":
                summary_text = " ".join(
                    str(v) for v in [raw.get("CommandLine"), raw.get("Cmdline")] if v
                )
            else:
                summary_text = _event_command_text(event, raw)
            evidence = {
                "event_id": event.id, "entity": event.entity,
                "source": event.source, "summary": event.summary[:300],
            }

            if is_usn_event:
                tokens = _usn_reason_tokens(raw)
                path = _usn_path(event, raw)
                if tokens & {"RENAME_OLD_NAME", "RENAME_NEW_NAME"}:
                    usn_events.append(event)
                if _is_usn_executable_path(path) and (
                    "FILE_CREATE" in tokens or tokens & {"RENAME_OLD_NAME", "RENAME_NEW_NAME"}
                ):
                    _check_usn_journal_event(session, existing, event, raw, evidence)
                continue

            cross_process_severity = _check_cross_process_event(session, existing, event, raw, evidence)
            if cross_process_severity:
                _escalate_event(
                    session, event, cross_process_severity,
                    "Detection: cross-process injection/access telemetry (remote thread, "
                    "dangerous process access, or high-risk handle)",
                )

            top = _check_cmdline(session, existing, summary_text, evidence, f"event:{event.source}")
            if top:
                _escalate_event(
                    session, event, top,
                    f"Detection: embedded command line matched suspicious patterns ({top})",
                )

            _check_memprocfs_timeline_event(
                session, existing, event, raw, evidence, task_records, persistence_artifacts
            )

            # wevtutil cl in an embedded command line: track for the log-clear window pass
            if _WEVTUTIL_CL_RE.search(summary_text.lower()):
                log_clear_marks.append((event, "Event log clearing"))

            # schtasks /create embedded in an event (e.g. 4688 process creation)
            parsed_task = _parse_schtasks_create(summary_text)
            if parsed_task:
                parsed_task["origin"] = "process"
                parsed_task["event"] = event
                task_records.append(parsed_task)

            # Persistence registry paths
            key_path = str(raw.get("KeyPath") or raw.get("Key") or raw.get("Name") or "").lower()
            if event.category == "persistence" or "registry" in event.source.lower():
                matched_runkey = False
                for fragment, technique, desc in PERSISTENCE_REGISTRY_PATHS:
                    if fragment in key_path or fragment in summary_text.lower():
                        _add_finding(
                            session, existing,
                            title=desc,
                            description=f"Persistence location touched: {event.summary[:400]}",
                            severity="high",
                            techniques=[technique],
                            evidence=evidence,
                            source=f"event:{event.source}",
                        )
                        _escalate_event(session, event, "high", f"Detection: {desc}")
                        matched_runkey = True
                if matched_runkey:
                    for exe in set(_EXE_TOKEN_RE.findall(summary_text.lower())):
                        persistence_artifacts.append(
                            (_basename(exe), "registry autorun", event.summary[:200], "T1547.001")
                        )

            # Security event log signals
            eid = str(raw.get("EventID") or "")
            if eid and not _eid_channel_ok(raw, eid):
                eid = ""
            if eid == "1102":
                _add_finding(
                    session, existing,
                    title="Security event log cleared",
                    description=f"Event 1102 (audit log cleared): {event.summary[:300]}",
                    severity="critical",
                    techniques=["T1070.001"],
                    evidence=evidence,
                    source=f"event:{event.source}",
                )
                _escalate_event(
                    session, event, "critical",
                    "Detection: security event log cleared (Event 1102, anti-forensics)",
                )
                log_clear_marks.append((event, "Security event log cleared"))
            elif eid == "4720":
                _add_finding(
                    session, existing,
                    title="New user account created",
                    description=f"Event 4720: {event.summary[:300]}",
                    severity="medium",
                    techniques=["T1136.001"],
                    evidence=evidence,
                    source=f"event:{event.source}",
                )
                _escalate_event(
                    session, event, "medium",
                    "Detection: new user account created (Event 4720)",
                )
            elif eid == "4698":
                # Task creation itself is routine admin activity; instead of an
                # unconditional finding, feed the graded scheduled-task analysis.
                parsed = _parse_task_xml(
                    _field(raw, "TaskContent", "TaskContentNew", "Content", "TaskXml", "Xml")
                )
                parsed["name"] = _field(raw, "TaskName", "Task Name") or (event.entity or "")
                parsed["run_as"] = parsed.get("run_as") or _field(raw, "RunAsUser", "User")
                parsed["origin"] = "event log"
                parsed["event"] = event
                task_records.append(parsed)
            elif eid == "106" and _field(raw, "TaskName", "Task Name"):
                # Task Scheduler operational log: task registered (name + user only)
                task_records.append({
                    "name": _field(raw, "TaskName", "Task Name"),
                    "run_as": _field(raw, "UserContext", "User", "UserName"),
                    "origin": "event log",
                    "event": event,
                })
            elif eid == "7045":
                svc_name = _field(raw, "ServiceName", "Service Name") or ""
                image = _field(raw, "ImagePath", "Image Path", "ServiceFileName", "PathName") or ""
                image_l = image.lower()
                npath = _normalize_path(_first_exe_token(image))
                reasons: list[str] = []
                techniques = ["T1543.003"]
                if npath and "\\" in npath and any(d in npath for d in SUSPICIOUS_EXECUTION_DIRS):
                    reasons.append(
                        f"service binary in a user-writable/staging path ({image[:200]})"
                    )
                if image_l and _SERVICE_INTERPRETER_RE.search(image_l):
                    reasons.append(
                        "service image invokes a shell/script interpreter "
                        "(powershell/cmd/rundll32/%COMSPEC%) instead of a dedicated binary"
                    )
                if image_l and _BASE64_BLOB_RE.search(image_l):
                    reasons.append(
                        "service image contains a long base64-like blob (possible encoded payload)"
                    )
                svc_l = svc_name.lower()
                if svc_l == "psexesvc":
                    reasons.append("service name PSEXESVC: PsExec remote-execution service")
                    techniques.append("T1570")
                elif svc_l and (
                    _looks_machine_generated(svc_l)
                    or (
                        len(svc_l) == 4 and svc_l.isalnum()
                        and (any(c.isdigit() for c in svc_l) or not any(c in _VOWELS for c in svc_l))
                    )
                ):
                    reasons.append(
                        f"service name '{svc_name}' looks machine-generated "
                        "(random/PsExec-style short name)"
                    )
                severity = "high" if reasons else "medium"
                description = f"Event 7045 (service installation): {event.summary[:300]}"
                if reasons:
                    description += (
                        " Escalated medium->high because: " + "; ".join(reasons) + ". "
                        "Service installs are routine for software deployment; these "
                        "properties are what make this one consistent with malicious "
                        "service persistence."
                    )
                _add_finding(
                    session, existing,
                    title="New service installed",
                    description=description,
                    severity=severity,
                    techniques=techniques,
                    evidence={
                        **evidence,
                        "entity": svc_name or evidence.get("entity"),
                        "service_name": svc_name, "image_path": image[:500],
                        "escalation_reasons": reasons,
                    },
                    source=f"event:{event.source}",
                )
                _escalate_event(
                    session, event, severity,
                    "Detection: new service installed (Event 7045)"
                    + (f" — {'; '.join(reasons)}" if reasons else ""),
                )
                image_base = _basename(_first_exe_token(image))
                if image_base:
                    persistence_artifacts.append(
                        (image_base, "service installation (7045)",
                         f"{svc_name or 'unnamed service'} -> {image[:200]}", "T1543.003")
                    )
            elif eid == "4826":
                kernel_debug = str(raw.get("KernelDebug") or "").lower()
                test_signing = str(raw.get("TestSigning") or "").lower()
                integrity = str(raw.get("DisableIntegrityChecks") or "").lower()
                flagged = []
                if "enabled" in kernel_debug or kernel_debug == "on":
                    flagged.append("Kernel debugging ENABLED")
                if "enabled" in test_signing or test_signing == "on":
                    flagged.append("Test Signing ENABLED (unsigned drivers allowed)")
                if "enabled" in integrity or integrity == "on" or "disabled by" in integrity:
                    flagged.append("Code integrity checks DISABLED")
                if flagged:
                    _add_finding(
                        session, existing,
                        title="Boot config weakens driver signing (Event 4826)",
                        description=(
                            "Event 4826 (Boot Configuration Data loaded) shows a security-relevant "
                            "boot policy: " + "; ".join(flagged) + ". This lets an attacker load "
                            "unsigned/malicious kernel drivers (rootkits, BYOVD) and evade defenses. "
                            f"Host: {event.host or raw.get('Computer', 'unknown')}, time: "
                            f"{event.timestamp.isoformat() if event.timestamp else 'n/a'}."
                        ),
                        severity="high",
                        techniques=["T1553.006", "T1014"],
                        evidence={**evidence, "KernelDebug": raw.get("KernelDebug"),
                                  "TestSigning": raw.get("TestSigning"),
                                  "DisableIntegrityChecks": raw.get("DisableIntegrityChecks")},
                        source=f"event:{event.source}",
                    )
                    _escalate_event(
                        session, event, "high",
                        "Detection: boot configuration weakens driver signing (Event 4826)",
                    )
            elif eid == "4625":
                _escalate_event(session, event, "low", "Detection: failed logon (Event 4625)")
                ip = _field(raw, "IpAddress", "IPAddress", "SourceNetworkAddress",
                            "Source Network Address", "WorkstationName")
                user = _field(raw, "TargetUserName", "Target User Name", "AccountName")
                if ip in ("-", "::1", "127.0.0.1"):
                    ip = ""
                if ip or user:
                    stat = logon_fail[(ip.lower(), user.lower())]
                    stat["count"] += 1
                    if event.timestamp and (
                        stat["first"] is None or _aware(event.timestamp) < _aware(stat["first"])
                    ):
                        stat["first"] = event.timestamp
                    if len(stat["events"]) < 200:
                        stat["events"].append(event)
            elif eid == "4624":
                ip = _field(raw, "IpAddress", "IPAddress", "SourceNetworkAddress",
                            "Source Network Address", "WorkstationName")
                user = _field(raw, "TargetUserName", "Target User Name", "AccountName")
                ltype = _field(raw, "LogonType", "Logon Type")
                if ip in ("-", "::1", "127.0.0.1"):
                    ip = ""
                if ip or user:
                    logon_success[(ip.lower(), user.lower())].append(event)
                # Type-10 (RemoteInteractive/RDP) logons are recorded but only surfaced
                # when the account is also referenced by another finding (correlation-gated)
                ul = user.lower()
                if (
                    ltype == "10" and user and not user.endswith("$")
                    and ul not in _WELLKNOWN_PRIV_ACCOUNTS
                    and not ul.startswith(("dwm-", "umfd-"))
                ):
                    rdp = rdp_logons.setdefault(ul, {"display": user, "count": 0, "ips": set(), "events": []})
                    rdp["count"] += 1
                    if ip:
                        rdp["ips"].add(ip)
                    if len(rdp["events"]) < 50:
                        rdp["events"].append(event)
            elif eid == "4672":
                user = _field(raw, "SubjectUserName", "Subject User Name", "AccountName")
                ul = user.lower()
                if (
                    user and not user.endswith("$")
                    and ul not in _WELLKNOWN_PRIV_ACCOUNTS
                    and not ul.startswith(("dwm-", "umfd-"))
                ):
                    pv = priv_logons.setdefault(ul, {"display": user, "count": 0, "events": []})
                    pv["count"] += 1
                    if len(pv["events"]) < 50:
                        pv["events"].append(event)

            # Web access-log attack detection
            if event.category == "weblog":
                _check_weblog(session, existing, event, raw, web_ip_tracker)

            # Beaconing-shaped network events: same remote endpoint many times
            if event.category == "network" and event.timestamp:
                raddr = str(raw.get("Raddr") or raw.get("raddr") or raw.get("RemoteAddress") or "")
                if raddr and _addr_scope(raddr) != "local":
                    beacon_tracker[raddr].append(event)

        _analyze_usn_rename_chains(session, existing, usn_events)

        # Beacon candidates: >= 5 connections to same endpoint with regular-ish spacing
        # over a meaningful window (a burst within one second is not a beacon).
        for raddr, evts in beacon_tracker.items():
            if len(evts) < 5:
                continue
            times = sorted(e.timestamp for e in evts if e.timestamp)
            if len(times) < 5:
                continue
            deltas = [(t2 - t1).total_seconds() for t1, t2 in zip(times, times[1:])]
            deltas = [d for d in deltas if d > 0]
            if not deltas:
                continue
            mean = sum(deltas) / len(deltas)
            if mean <= 0:
                continue
            variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
            cv = (variance ** 0.5) / mean
            span = (times[-1] - times[0]).total_seconds()
            if cv < 0.35 and 5 <= mean <= 3600 and span >= max(60.0, mean * 4):
                scope = _addr_scope(raddr)
                internal = scope == "private"
                severity = "medium" if internal else "high"
                _add_finding(
                    session, existing,
                    title=(
                        f"Possible internal C2 relay beaconing to {raddr}" if internal
                        else f"Possible C2 beaconing to {raddr}"
                    ),
                    description=(
                        f"{len(evts)} connections to {raddr} with regular interval "
                        f"(~{mean:.0f}s, coefficient of variation {cv:.2f}, over {span:.0f}s). "
                        "Regular-cadence traffic is consistent with C2 beaconing"
                        + (
                            "; the address is private/link-local, so polling of an internal "
                            "service is a plausible benign explanation."
                            if internal
                            else "; scheduled application polling can produce the same shape."
                        )
                    ),
                    severity=severity,
                    techniques=["T1071", "T1573"],
                    evidence={
                        "entity": raddr, "count": len(evts), "mean_interval_s": round(mean, 1),
                        "interval_cv": round(cv, 2), "span_s": round(span, 1), "scope": scope,
                        "first_seen": times[0].isoformat(), "last_seen": times[-1].isoformat(),
                    },
                    source="network-heuristics",
                )
                for e in evts:
                    _escalate_event(
                        session, e, severity,
                        f"Detection: beaconing-shaped traffic to {raddr} "
                        f"(~{mean:.0f}s interval over {len(evts)} connections)",
                    )

        # Aggregate web-log signals per client IP: scanning and brute force
        for ip, stat in web_ip_tracker.items():
            total = stat["total"]
            # Scanning: many requests, high error ratio
            if total >= 30 and stat["errors"] >= 20 and stat["errors"] / max(total, 1) >= 0.4:
                _add_finding(
                    session, existing,
                    title=f"Web scanning / enumeration from {ip}",
                    description=(
                        f"{ip} made {total} requests with {stat['errors']} error responses "
                        f"({stat['errors'] / total * 100:.0f}% errors). High-volume 4xx/5xx traffic "
                        "is characteristic of automated vulnerability scanning or content discovery."
                    ),
                    severity="medium",
                    techniques=["T1595", "T1190"],
                    evidence={"entity": ip, "total_requests": total, "errors": stat["errors"]},
                    source="weblog-heuristics",
                )
            # Brute force: many auth failures
            if stat["auth_fail"] >= 5:
                succeeded = bool(stat["auth_ok"])
                _add_finding(
                    session, existing,
                    title=f"{'Successful ' if succeeded else ''}brute force against web app from {ip}",
                    description=(
                        f"{ip} triggered {stat['auth_fail']} HTTP 401/403 auth failures"
                        + (
                            f", then obtained authenticated access as {', '.join(sorted(stat['auth_ok']))} "
                            "(200/302 after failures). Likely successful credential brute force."
                            if succeeded
                            else ". Repeated authentication failures indicate a brute-force attempt."
                        )
                    ),
                    severity="critical" if succeeded else "high",
                    techniques=["T1110"] + (["T1078"] if succeeded else []),
                    evidence={"entity": ip, "auth_failures": stat["auth_fail"],
                              "authenticated_users": sorted(stat["auth_ok"])},
                    source="weblog-heuristics",
                )
                for e in stat["events"][:200]:
                    _escalate_event(
                        session, e, "high",
                        f"Detection: web brute-force activity from {ip} "
                        f"({stat['auth_fail']} auth failures)",
                    )

        # --- Scheduled-task analysis (merged 4698/106/schtasks records, graded) ---
        _analyze_scheduled_tasks(session, existing, task_records, persistence_artifacts)

        # --- Windows logon brute force (4625 volume, optionally capped by a 4624) ---
        for (ip, user), stat in logon_fail.items():
            if stat["count"] < 10:
                continue
            combo = f"{user or 'unknown-user'}@{ip or 'unknown-source'}"
            successes: list[Event] = []
            for (sip, suser), evs in logon_success.items():
                if suser == user and (sip == ip or not sip or not ip):
                    successes.extend(evs)
            succ_after = [
                e for e in successes
                if not e.timestamp or not stat["first"]
                or _aware(e.timestamp) >= _aware(stat["first"])
            ]
            base_evidence = {
                "entity": combo, "source_ip": ip or None, "target_user": user or None,
                "failed_attempts": stat["count"],
                "first_failure": stat["first"].isoformat() if stat["first"] else None,
            }
            if succ_after:
                succ_ts = [e.timestamp for e in succ_after if e.timestamp]
                _add_finding(
                    session, existing,
                    title=f"Brute force followed by successful logon: {combo}",
                    description=(
                        f"{stat['count']} failed logons (4625) for {combo} were followed by a "
                        f"successful logon (4624) for the same account/source combination. "
                        "Failure volume alone can be a misconfigured service or a typo storm; "
                        "the subsequent success for the very same pairing is what makes this "
                        "consistent with a completed credential brute force."
                    ),
                    severity="critical",
                    techniques=["T1110", "T1078"],
                    evidence={
                        **base_evidence,
                        "successful_logons": len(succ_after),
                        "first_success": min(_aware(t) for t in succ_ts).isoformat() if succ_ts else None,
                    },
                    source="logon-heuristics",
                )
                for e in stat["events"]:
                    _escalate_event(
                        session, e, "high",
                        f"Detection: brute force followed by successful logon for {combo}",
                    )
                for e in succ_after[:50]:
                    _escalate_event(
                        session, e, "high",
                        f"Detection: successful logon after brute-force failures for {combo}",
                    )
            else:
                _add_finding(
                    session, existing,
                    title=f"Authentication brute force attempts: {combo}",
                    description=(
                        f"{stat['count']} failed logons (4625) for {combo} with no matching "
                        "success observed. Consistent with a brute-force/password-spray "
                        "attempt; a locked-out account, an expired service credential, or a "
                        "misconfigured scheduled job can produce the same pattern."
                    ),
                    severity="medium",
                    techniques=["T1110"],
                    evidence=base_evidence,
                    source="logon-heuristics",
                )
                for e in stat["events"]:
                    _escalate_event(
                        session, e, "medium",
                        f"Detection: authentication brute-force attempts for {combo}",
                    )

        # --- Persistence + execution pairing: artifact action executed as a flagged process ---
        flagged_by_base: dict[str, list[Process]] = defaultdict(list)
        for proc in processes:
            if set(proc.flags or []) & set(CORRELATION_FLAGS):
                flagged_by_base[_basename(proc.name or "")].append(proc)
        artifacts_by_base: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        for base, kind, detail, tech in persistence_artifacts:
            if base and base not in _PAIRING_GENERIC_HOSTS:
                artifacts_by_base[base].append((kind, detail, tech))
        for base, links in artifacts_by_base.items():
            procs = flagged_by_base.get(base)
            if not procs:
                continue
            all_flags = sorted({f for p in procs for f in (p.flags or []) if f in CORRELATION_FLAGS})
            _add_finding(
                session, existing,
                title=f"Persistence artifact executed: {base}",
                description=(
                    f"A persistence artifact ({'; '.join(f'{k}: {d}' for k, d, _t in links[:3])}) "
                    f"points at '{base}', and a process with that basename is present in the "
                    f"process table carrying independent suspicious signals ({', '.join(all_flags)}). "
                    "Persistence installation plus matching flagged execution is consistent with "
                    "an implant that is both installed and running, not a dormant leftover."
                ),
                severity="high",
                techniques=sorted({t for _k, _d, t in links}),
                evidence={
                    "entity": base,
                    "persistence_links": [f"{k}: {d}" for k, d, _t in links[:5]],
                    "pids": [p.pid for p in procs[:20]],
                    "process_signals": all_flags,
                },
                source="correlation",
            )

        # --- Correlation-gated logon findings: only when the account already appears
        # --- in another finding for this case (no baseline available, so standalone
        # --- RDP/special-privilege logons stay silent).
        if rdp_logons or priv_logons:
            session.flush()  # make this run's pending findings visible to the queries below
            gated_prefixes = (
                "rdp logon by account", "special-privilege logon by account",
            )
            finding_blobs: list[tuple[str, str]] = []
            for f in session.scalars(select(Finding)):
                tl = (f.title or "").lower()
                if tl.startswith(gated_prefixes):
                    continue
                blob = " ".join([
                    tl, str((f.evidence or {}).get("entity") or ""), (f.description or "")[:300],
                ]).lower()
                finding_blobs.append((f.title, blob))

            def _referencing_titles(account: str) -> list[str]:
                if len(account) < 4:  # short names substring-match everything
                    return []
                pat = re.compile(rf"(?<![\w]){re.escape(account)}(?![\w])")
                return [t for t, blob in finding_blobs if pat.search(blob)][:5]

            for ul, rdp in rdp_logons.items():
                titles = _referencing_titles(ul)
                if not titles:
                    continue
                _add_finding(
                    session, existing,
                    title=f"RDP logon by account referenced in other findings: {rdp['display']}",
                    description=(
                        f"{rdp['count']} RemoteInteractive (logon type 10) logon(s) by "
                        f"'{rdp['display']}'"
                        + (f" from {', '.join(sorted(rdp['ips'])[:5])}" if rdp["ips"] else "")
                        + ". RDP logons are routine administration on their own; this is "
                        "recorded only because the account also appears in other findings "
                        "for this case, where interactive access may indicate hands-on-"
                        "keyboard activity."
                    ),
                    severity="low",
                    techniques=["T1021.001", "T1078"],
                    evidence={
                        "entity": rdp["display"], "logon_count": rdp["count"],
                        "source_ips": sorted(rdp["ips"])[:10],
                        "correlated_findings": titles,
                    },
                    source="logon-heuristics",
                )
            for ul, pv in priv_logons.items():
                titles = _referencing_titles(ul)
                if not titles:
                    continue
                _add_finding(
                    session, existing,
                    title=f"Special-privilege logon by account referenced in other findings: {pv['display']}",
                    description=(
                        f"{pv['count']} special-privilege logon(s) (4672) by '{pv['display']}', "
                        "an account outside the well-known service identities. On its own this "
                        "is normal admin activity; it is recorded because the account also "
                        "appears in other findings for this case, so its privileged sessions "
                        "define where elevated access was available to the activity under "
                        "investigation."
                    ),
                    severity="low",
                    techniques=["T1078"],
                    evidence={
                        "entity": pv["display"], "logon_count": pv["count"],
                        "correlated_findings": titles,
                    },
                    source="logon-heuristics",
                )

        # --- Service provenance: trace installed services back to the dropping /
        # --- installing process and the download the binary came from.
        _correlate_service_provenance(session, existing, provenance_events, processes)
        _correlate_file_execution_provenance(session, existing, provenance_events, processes)

        # --- Severity taint propagation: events mentioning a flagged process/DLL/file
        # --- name inherit its severity, with provenance recorded on the event.
        # NOTE: _propagate_flagged_entities iterates its events argument twice (it
        # collects taint on the first pass and escalates on the second), so it must
        # be given a materialized list -- a single-use streaming ScalarResult would
        # be exhausted after the first pass and silently escalate nothing.
        _propagate_flagged_entities(
            session,
            list(session.scalars(select(Event).execution_options(yield_per=EVENT_STREAM_BATCH_SIZE))),
            processes,
        )

        # --- Log-clear-after-activity: a 1102/wevtutil-cl that postdates high/critical
        # --- activity likely caps an active intrusion window (timestamps required).
        if log_clear_marks:
            session.flush()  # the 1102/wevtutil findings may still be pending
            clear_event_ids = {e.id for e, _t in log_clear_marks}
            hi_events = list(session.scalars(
                select(Event)
                .where(Event.severity.in_(["high", "critical"]))
                .execution_options(yield_per=EVENT_STREAM_BATCH_SIZE)
            ))
            hi_events = [e for e in hi_events if e.timestamp and e.id not in clear_event_ids]
            hi_procs = [
                p for p in processes
                if p.start_time and SEVERITY_RANK.get(p.severity, 0) >= SEVERITY_RANK["high"]
            ]
            for clear_event, finding_title in log_clear_marks:
                if not clear_event.timestamp:
                    continue
                ct = _aware(clear_event.timestamp)
                prior = [
                    f"event: {e.summary[:120]}" for e in hi_events if _aware(e.timestamp) < ct
                ] + [
                    f"process: {p.name} (pid {p.pid}, flags: {', '.join(p.flags or []) or 'n/a'})"
                    for p in hi_procs if _aware(p.start_time) < ct
                ]
                if not prior:
                    continue
                for f in session.scalars(select(Finding).where(Finding.title == finding_title)):
                    ev = dict(f.evidence or {})
                    ev["intrusion_window_capped"] = True
                    ev["prior_activity"] = prior[:10]
                    f.evidence = ev
                    if "caps an active intrusion window" not in (f.description or ""):
                        f.description = (f.description or "") + (
                            f" Correlation: this log clear occurred AFTER {len(prior)} "
                            "high/critical-severity activities in the case timeline, so it "
                            "likely caps an active intrusion window (anti-forensics closing "
                            "out an operation) rather than routine log maintenance."
                        )

        session.commit()

        after = len(existing)
        return after - before
    finally:
        session.close()


def _check_weblog(session, existing, event, raw, web_ip_tracker) -> None:
    """Detect web attacks in a single access-log event and accumulate per-IP stats."""
    ip = str(raw.get("client_ip") or event.entity or "unknown")
    request = str(raw.get("request") or "")
    status = str(raw.get("status") or "")
    user = raw.get("user")
    req_lower = request.lower()

    stat = web_ip_tracker[ip]
    stat["total"] += 1
    stat["events"].append(event)
    if status and status[0] in ("4", "5"):
        stat["errors"] += 1
    if status in ("401", "403"):
        stat["auth_fail"] += 1
    # Successful authenticated access to the Tomcat manager after failures
    if user and status in ("200", "302") and "/manager" in req_lower:
        stat["auth_ok"].add(str(user))

    evidence = {
        "entity": ip, "request": request[:400], "status": status,
        "user": user, "event_id": event.id,
    }
    matched_top: str | None = None
    for pattern, technique, desc, severity in WEB_ATTACK_PATTERNS:
        if pattern in req_lower:
            # /manager/html on its own is very noisy; only flag when authenticated
            if pattern == "/manager/html" and not user:
                continue
            _add_finding(
                session, existing,
                title=f"Web attack: {desc}",
                description=f"{desc} from {ip}: \"{request[:300]}\" (HTTP {status})",
                severity=severity,
                techniques=[technique],
                evidence=evidence,
                source="weblog-heuristics",
            )
            if matched_top is None or SEVERITY_RANK[severity] > SEVERITY_RANK[matched_top]:
                matched_top = severity
    if matched_top:
        _escalate_event(
            session, event, matched_top,
            f"Detection: web attack pattern in request from {ip}",
        )
