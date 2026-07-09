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
    ref_entity: str = "",
) -> dict:
    title = (title or "").strip()
    if not title:
        raise ValueError("title required")
    if severity not in SEVERITIES:
        raise ValueError("invalid severity")
    item = {
        "id": uuid.uuid4().hex,
        "title": title[:512],
        "description": (description or "").strip(),
        "severity": severity,
        "mitre_techniques": [str(t) for t in (mitre_techniques or [])][:12],
        "ref_type": ref_type,
        "ref_id": str(ref_id),
        "ref_label": (ref_label or "")[:200],
        # Entity value this finding should colour on the map. For an entity flag
        # that is the entity itself; for an event flag it is the event's entity
        # (if any). Empty means the finding stays list-only.
        "ref_entity": (ref_entity or (ref_label if ref_type == "entity" else "") or "")[:200],
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
        # An "entity" token lets _attach_findings() colour the matching map node
        # with this finding's severity, so a manual critical flag lights up the
        # entity graph the same way a detector finding does.
        if it.get("ref_entity"):
            evidence["entity"] = it["ref_entity"]
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
