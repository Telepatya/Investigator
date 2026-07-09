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
import uuid
from datetime import datetime, timezone

from sqlalchemy import delete as sqldelete

from app.store import cases as case_store
from app.store.database import Finding

_MANUAL_KEY = "manual_findings"
SEVERITIES = {"info", "low", "medium", "high", "critical"}


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
    import re
    return re.split(r"[\\/]", (v or "").strip())[-1] or (v or "").strip()


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
    entity = norm(ev.entity) or (_basename(proc) if proc else host)
    if not entity:
        return "", "", []

    low = entity.lower()
    if _looks_like_ip(entity):
        ntype, nval = "ip", entity
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
    return len(items)
