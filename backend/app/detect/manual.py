"""Analyst-created ("manual") findings.

Detections wipe and regenerate the findings table on every rebuild, so a finding
an analyst raises by hand cannot live only in that table. Like the benign /
disabled-rule overrides, manual findings are persisted in the per-case
``case_meta`` table and re-materialised into the findings table:

  * immediately when the analyst adds or removes one via the API, and
  * at the end of every detection run,

so they always appear in the Findings view and count toward active findings.
Each carries ``source="manual"`` and ``evidence["manual"]=True`` so the UI can
tag it and this module can find and replace exactly its own rows.
"""

from __future__ import annotations

import json
import hashlib
import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import delete as sqldelete, select

from app.store import cases as case_store
from app.store.database import Event, Finding, acquire_session_write_lock

_MANUAL_KEY = "manual_findings"
_MANUAL_EVENT_BASELINES_KEY = "manual_event_severity_baselines"
_MANUAL_EVENT_SYNC_KEY = "manual_event_severity_sync"
_MANUAL_EVENT_SYNC_VERSION = "2"
_MANUAL_EVENT_REASON = "Analyst-flagged event"
SEVERITIES = {"info", "low", "medium", "high", "critical"}
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_FILE_PATH_KEYS = (
    "DownloadedFilePath", "FullPath", "OSPath", "TargetFilename",
    "Target Filename", "Path", "FilePath", "TargetPath", "FileName",
    "Filename", "ServiceFileName", "ImagePath", "PathName",
)
_PROCESS_PATH_KEYS = (
    "NewProcessName", "Image", "ProcessName", "ParentProcessName",
    "ParentImage", "Owner", "Process",
)


def _load(session) -> list[dict]:
    raw = case_store.get_meta(session, _MANUAL_KEY)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [it for it in data if isinstance(it, dict)] if isinstance(data, list) else []


def _store(session, items: list[dict]) -> None:
    case_store.set_meta(session, _MANUAL_KEY, json.dumps(items))


def get_manual_findings(session) -> list[dict]:
    return _load(session)


_NODE_TYPES = {
    "user", "account", "host", "ip", "process",
    "service", "file", "url", "registry", "domain",
}


def _basename(v: str) -> str:
    return re.split(r"[\\/]", (v or "").strip())[-1] or (v or "").strip()


def _clean_path(value: object) -> str:
    path = str(value or "").strip().strip('"')
    path = re.split(r";\s*(?:Mtime|_ZoneIdentifier)", path, maxsplit=1, flags=re.IGNORECASE)[0]
    for prefix in ("\\\\?\\", "\\\\.\\", "\\??\\"):
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    return path.replace("/", "\\").rstrip("\\")


def _same_pathish(target: str, candidate: object) -> bool:
    candidate_path = _clean_path(candidate)
    if not candidate_path:
        return False
    target_path = _clean_path(target)
    if "\\" in target_path or "/" in target:
        return candidate_path.lower() == target_path.lower()
    return _basename(candidate_path).lower() == _basename(target_path).lower()


def _event_file_path(ev) -> str:
    raw = ev.raw or {}
    for key in _FILE_PATH_KEYS:
        value = _clean_path(raw.get(key))
        if value:
            return value
    match = re.search(
        r"(?:DownloadedFilePath|FullPath|OSPath|TargetFilename)=([^;\r\n]+)",
        ev.summary or "",
        re.IGNORECASE,
    )
    return _clean_path(match.group(1)) if match else ""


def _looks_like_ip(v: str) -> bool:
    parts = (v or "").split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in (v or "") and any(c in "0123456789abcdefABCDEF" for c in v)


def derive_event_node(ev) -> tuple[str, str, list[dict]]:
    """Best-effort (node_type, node_value, links) for the entity an event flag is
    about, so the map can materialise it and connect it to the host / actor /
    process the event ties it to. Returns ("", "", []) when nothing usable."""
    raw = ev.raw or {}

    def norm(x) -> str:
        return str(x).strip() if x not in (None, "") else ""

    host = norm(raw.get("Computer") or raw.get("Hostname") or ev.host)
    actor = norm(raw.get("SubjectUserName") or raw.get("User") or raw.get("AccountName"))
    proc = norm(raw.get("NewProcessName") or raw.get("Image") or raw.get("ProcessName"))
    file_path = _event_file_path(ev)
    entity = file_path or norm(ev.entity) or (_basename(proc) if proc else host)
    if not entity:
        return "", "", []

    low = entity.lower()
    if file_path:
        ntype, nval = "file", file_path
    elif _looks_like_ip(entity):
        ntype, nval = "ip", entity
    elif ev.category == "filesystem" and ("\\" in entity or "/" in entity):
        ntype, nval = "file", _clean_path(entity)
    elif low.endswith((".exe", ".dll", ".sys", ".scr")):
        ntype, nval = "process", entity if ("\\" in entity or "/" in entity) else _basename(entity)
    elif ev.category == "process" or ev.category == "network":
        ntype, nval = "process", _basename(entity)
    elif "\\" in entity or "/" in entity or "." in _basename(entity):
        ntype, nval = "file", entity
    else:
        ntype, nval = "file", entity

    links: list[dict] = []
    if host and host.lower() != nval.lower():
        links.append({"type": "host", "value": host, "verb": "seen on"})
    if actor and actor.lower() != nval.lower():
        links.append({"type": "user", "value": actor, "verb": "involving"})
    if proc:
        pb = _basename(proc)
        if pb.lower() != nval.lower():
            links.append({"type": "process", "value": pb, "verb": "involving"})
    return ntype, nval, links


def _event_mentions_node(ev, node_type: str, node_value: str) -> bool:
    raw = ev.raw or {}
    if node_type == "file":
        values = [raw.get(key) for key in _FILE_PATH_KEYS]
        values.append(ev.entity)
        match = re.search(
            r"(?:DownloadedFilePath|FullPath|OSPath|TargetFilename)=([^;\r\n]+)",
            ev.summary or "",
            re.IGNORECASE,
        )
        if match:
            values.append(match.group(1))
        return any(_same_pathish(node_value, value) for value in values)
    if node_type == "process":
        return any(
            _same_pathish(node_value, raw.get(key)) for key in _PROCESS_PATH_KEYS
        ) or _same_pathish(node_value, ev.entity)
    if node_type in {"user", "account"}:
        return any(
            str(raw.get(key) or "").lower() == node_value.lower()
            for key in ("user", "SubjectUserName", "TargetUserName", "User", "AccountName")
        )
    if node_type == "host":
        return (ev.host or "").lower() == node_value.lower() or any(
            str(raw.get(key) or "").lower() == node_value.lower()
            for key in ("Computer", "Hostname")
        )
    if node_type == "ip":
        return any(
            str(raw.get(key) or "").lower() == node_value.lower()
            for key in ("client_ip", "IpAddress", "SourceIp", "Raddr", "ForeignAddr", "DestinationIp")
        )
    return node_value.lower() in (ev.summary or "").lower()


def _impact_signature(items: list[dict]) -> str:
    relevant = [
        {
            key: item.get(key)
            for key in ("id", "severity", "ref_type", "ref_id", "node_type", "node_value")
        }
        for item in items
    ]
    payload = json.dumps(relevant, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{_MANUAL_EVENT_SYNC_VERSION}:{payload}".encode()).hexdigest()


def _load_event_baselines(session) -> dict[str, dict]:
    raw = case_store.get_meta(session, _MANUAL_EVENT_BASELINES_KEY)
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def restore_manual_event_severities(session) -> int:
    """Restore detector/parser severity before rebuilding manual event impacts."""
    acquire_session_write_lock(session)
    baselines = _load_event_baselines(session)
    restored = 0
    for event_id, baseline in baselines.items():
        if not str(event_id).isdigit() or not isinstance(baseline, dict):
            continue
        event = session.get(Event, int(event_id))
        if event is None or not (event.severity_reason or "").startswith(_MANUAL_EVENT_REASON):
            continue
        event.severity = str(baseline.get("severity") or "info")
        event.severity_reason = baseline.get("severity_reason")
        restored += 1
    case_store.set_meta(session, _MANUAL_EVENT_BASELINES_KEY, "{}")
    case_store.set_meta(session, _MANUAL_EVENT_SYNC_KEY, "")
    return restored


def _sync_manual_event_severities(session, items: list[dict]) -> None:
    from app.detect import overrides

    restore_manual_event_severities(session)
    event_items = [
        item for item in items
        if item.get("ref_type") == "event" and str(item.get("ref_id") or "").isdigit()
    ]
    if not event_items:
        return

    events = list(session.scalars(select(Event)))
    by_id = {event.id: event for event in events}
    impacts: dict[int, tuple[int, dict]] = {}
    metadata_changed = False
    benign_keys = overrides.get_benign_keys(session)
    for item in event_items:
        referenced = by_id.get(int(item["ref_id"]))
        if referenced is None:
            continue
        node_type, node_value, links = derive_event_node(referenced)
        if node_type and node_value and (
            item.get("node_type") != node_type or item.get("node_value") != node_value
        ):
            item["node_type"] = node_type
            item["node_value"] = node_value
            item["links"] = links
            metadata_changed = True

        evidence = {"summary": item.get("ref_label") or item.get("title")}
        if node_type and node_value:
            evidence["entity"] = node_value
        is_benign = overrides.finding_key(str(item.get("title") or ""), evidence) in benign_keys
        rank = 0 if is_benign else _SEVERITY_RANK.get(str(item.get("severity") or "info"), 0)
        candidates = [referenced]
        if node_type and node_value:
            candidates.extend(
                event for event in events
                if event.id != referenced.id and _event_mentions_node(event, node_type, node_value)
            )
        for event in candidates:
            current = impacts.get(event.id)
            if current is None or rank > current[0]:
                impacts[event.id] = (rank, item)

    if metadata_changed:
        _store(session, items)

    baselines: dict[str, dict] = {}
    for event_id, (rank, item) in impacts.items():
        event = by_id[event_id]
        if rank <= _SEVERITY_RANK.get(event.severity, 0):
            continue
        baselines[str(event_id)] = {
            "severity": event.severity,
            "severity_reason": event.severity_reason,
        }
        event.severity = str(item["severity"])
        relation = "referenced directly" if str(event.id) == str(item["ref_id"]) else "references the same entity"
        event.severity_reason = (
            f"{_MANUAL_EVENT_REASON}: {relation} as manual finding "
            f"{item['id']} ({item['title']})"
        )
    case_store.set_meta(session, _MANUAL_EVENT_BASELINES_KEY, json.dumps(baselines))


def ensure_manual_findings_applied(session) -> bool:
    """Repair legacy manual event findings once, then remain a cheap metadata check."""
    items = _load(session)
    if case_store.get_meta(session, _MANUAL_EVENT_SYNC_KEY) == _impact_signature(items):
        return False
    apply_manual_findings(session)
    return True


def add_manual_finding(
    session,
    *,
    title: str,
    severity: str,
    description: str = "",
    mitre_techniques: list | None = None,
    ref_type: str = "",
    ref_id: str = "",
    ref_label: str = "",
    node_type: str = "",
    node_value: str = "",
    links: list | None = None,
) -> dict:
    acquire_session_write_lock(session)
    title = (title or "").strip()
    if not title:
        raise ValueError("title required")
    if severity not in SEVERITIES:
        raise ValueError("invalid severity")
    clean_links = [
        {"type": lk["type"], "value": str(lk["value"])[:200], "verb": str(lk.get("verb") or "connected to")[:60]}
        for lk in (links or [])
        if isinstance(lk, dict) and lk.get("type") in _NODE_TYPES and lk.get("value")
    ][:12]
    item = {
        "id": uuid.uuid4().hex,
        "title": title[:512],
        "description": (description or "").strip(),
        "severity": severity,
        "mitre_techniques": [str(t) for t in (mitre_techniques or [])][:12],
        "ref_type": ref_type,
        "ref_id": str(ref_id),
        "ref_label": (ref_label or "")[:200],
        # The map node this finding materialises: for an entity flag the entity
        # itself, for an event flag the entity derived from the event. Empty
        # node_type/value keeps the finding list-only. links connect that node to
        # related entities so a brand-new node is not left floating.
        "node_type": node_type if node_type in _NODE_TYPES else "",
        "node_value": (node_value or "")[:200],
        "links": clean_links,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    items = _load(session)
    items.append(item)
    _store(session, items)
    return item


def remove_manual_finding(session, manual_id: str) -> bool:
    acquire_session_write_lock(session)
    items = _load(session)
    kept = [it for it in items if it.get("id") != manual_id]
    if len(kept) == len(items):
        return False
    _store(session, kept)
    return True


def apply_manual_findings(session) -> int:
    """Replace this module's rows in the findings table with the persisted set.

    Idempotent: safe after a detections rebuild (table wiped) or after a single
    add/remove (some manual rows may already be present)."""
    session.execute(sqldelete(Finding).where(Finding.source == "manual"))
    items = _load(session)
    _sync_manual_event_severities(session, items)
    for it in items:
        label = it.get("ref_label") or it["title"]
        ref_type = it.get("ref_type") or "item"
        node_value = it.get("node_value") or ""
        evidence = {
            "manual": True,
            "manual_id": it["id"],
            "ref_type": it.get("ref_type"),
            "ref_id": it.get("ref_id"),
            "ref_label": it.get("ref_label"),
            # Kept stable so overrides.finding_key() (and thus a benign mark)
            # survives re-materialisation across rebuilds.
            "summary": label,
            "created_at": it.get("created_at"),
        }
        # node_type/value drive _attach_manual_nodes(): the map node this finding
        # creates (or colours, if it already exists) plus its correlation links.
        # "entity" also feeds overrides.finding_key() and suppression tokens.
        if it.get("node_type") and node_value:
            evidence["node_type"] = it["node_type"]
            evidence["node_value"] = node_value
            evidence["entity"] = node_value
            if it.get("links"):
                evidence["links"] = it["links"]
        session.add(
            Finding(
                title=it["title"],
                description=it.get("description") or f"Manually flagged {ref_type}: {label}.",
                severity=it["severity"],
                mitre_techniques=list(it.get("mitre_techniques") or []),
                source="manual",
                evidence=evidence,
            )
        )
    session.flush()
    case_store.set_meta(session, _MANUAL_EVENT_SYNC_KEY, _impact_signature(items))
    return len(items)
