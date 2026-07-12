"""User overrides for detections: mark-benign findings and disabled rules.

Both are stored in the per-case ``case_meta`` key/value table (not on the
findings themselves) so they survive the findings table being wiped and
regenerated on a detections *rebuild*. They are applied in two places:

  * at the end of every detection run (``apply_overrides``), and
  * immediately when a user toggles one via the API,

so the Findings view reflects the choice without waiting for a re-run.

A suppressed finding is not deleted -- its severity is forced to ``info`` and
its original severity stashed in ``evidence['suppressed_from']`` so re-enabling
a rule (or un-marking a finding) restores exactly what the engine produced.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from sqlalchemy import select

from app.store import cases as case_store
from app.store.database import Finding, acquire_session_write_lock

_DISABLED_RULES_KEY = "disabled_rules"
_BENIGN_FINDINGS_KEY = "benign_findings"
_SUPPRESSION_AUDIT_KEY = "suppression_audit"
_SUPPRESSION_REVISION_KEY = "suppression_revision"
SUPPRESSED_SEVERITY = "info"

# Findings whose title carries a variable subject (a process/service/account name
# or a "parent -> child" pair). Collapse the whole family to one rule id so that
# "disable this rule" covers every entity the rule fires on, not just this one.
_VARIABLE_TITLE_RULES: list[tuple[str, str]] = [
    ("LOLBin activity", "lolbin-activity"),
    ("Execution from suspicious directory", "execution-from-suspicious-directory"),
    ("System process masquerade", "system-process-masquerade"),
    ("Random-looking executable in Windows root", "random-executable-windows-root"),
    ("Service-hosted executable in Windows root", "service-executable-windows-root"),
    ("RemCom named-pipe activity by", "remcom-named-pipe-activity"),
    ("Suspicious process chain", "suspicious-process-chain"),
    ("Anomalous parent for", "anomalous-parent"),
    ("Unresolved parentage for", "unresolved-parentage"),
    ("Correlated indicators on", "correlated-indicators"),
    ("File artifact later executed", "file-artifact-later-executed"),
    ("Persistence artifact executed", "persistence-artifact-executed"),
    ("Authentication brute force attempts", "auth-brute-force"),
    ("RDP logon by account", "rdp-logon"),
    ("Special-privilege logon by account", "special-privilege-logon"),
]


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").strip().lower()).strip("-") or "rule"


def rule_id_for(title: str, source: str = "") -> str:
    """Stable identifier for the detection rule that produced a finding.

    Findings from the same rule share a rule id even when their titles embed a
    different entity, so disabling a rule suppresses the whole family.
    """
    t = title or ""
    if t.startswith("Web attack: "):
        return "web-" + _slug(t[len("Web attack: "):])
    for prefix, rid in _VARIABLE_TITLE_RULES:
        if t.startswith(prefix):
            return rid
    return _slug(t)


def finding_key(title: str, evidence: dict | None) -> str:
    """Stable identity for a single finding across detection rebuilds.

    Mirrors the dedup key used when the finding is first created so a benign
    mark survives the findings table being wiped and regenerated.
    """
    ev = evidence or {}
    ent = str(ev.get("entity") or ev.get("pid") or ev.get("summary") or "")[:200]
    return f"{title}␟{ent}"


# --- persisted state (case_meta) --------------------------------------------

def _load_set(session, key: str) -> set[str]:
    raw = case_store.get_meta(session, key)
    if not raw:
        return set()
    try:
        return set(json.loads(raw))
    except (ValueError, TypeError):
        return set()


def _store_set(session, key: str, values: set[str]) -> None:
    case_store.set_meta(session, key, json.dumps(sorted(values)))


def _load_audit(session) -> dict[str, dict]:
    raw = case_store.get_meta(session, _SUPPRESSION_AUDIT_KEY)
    if not raw:
        return {}
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def get_suppression_revision(session) -> int:
    try:
        return int(case_store.get_meta(session, _SUPPRESSION_REVISION_KEY) or 0)
    except (TypeError, ValueError):
        return 0


def _bump_suppression_revision(session) -> int:
    revision = get_suppression_revision(session) + 1
    case_store.set_meta(session, _SUPPRESSION_REVISION_KEY, str(revision))
    return revision


def get_disabled_rules(session) -> set[str]:
    return _load_set(session, _DISABLED_RULES_KEY)


def get_benign_keys(session) -> set[str]:
    return _load_set(session, _BENIGN_FINDINGS_KEY)


def set_rule_disabled(session, rule_id: str, disabled: bool) -> set[str]:
    acquire_session_write_lock(session)
    rules = get_disabled_rules(session)
    before = set(rules)
    if disabled:
        rules.add(rule_id)
    else:
        rules.discard(rule_id)
    _store_set(session, _DISABLED_RULES_KEY, rules)
    if rules != before:
        _bump_suppression_revision(session)
    return rules


def set_finding_benign(
    session,
    key: str,
    benign: bool,
    *,
    actor: str = "analyst",
    rationale: str = "",
    confidence: str | None = None,
    evidence_refs: list[dict] | None = None,
) -> set[str]:
    acquire_session_write_lock(session)
    keys = get_benign_keys(session)
    before = set(keys)
    audit = _load_audit(session)
    if benign:
        keys.add(key)
        audit[key] = {
            "actor": actor,
            "rationale": rationale.strip()[:2000],
            "confidence": confidence,
            "evidence_refs": (evidence_refs or [])[:20],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    else:
        keys.discard(key)
        audit.pop(key, None)
    _store_set(session, _BENIGN_FINDINGS_KEY, keys)
    case_store.set_meta(session, _SUPPRESSION_AUDIT_KEY, json.dumps(audit, sort_keys=True))
    if keys != before:
        _bump_suppression_revision(session)
    return keys


def get_suppression_details(session, finding: Finding) -> dict | None:
    """Return durable audit metadata for the finding's current suppression."""
    disabled = get_disabled_rules(session)
    benign = get_benign_keys(session)
    reason = is_suppressed(finding.title, finding.source, finding.evidence, disabled, benign)
    if reason is None:
        return None
    key = finding_key(finding.title, finding.evidence)
    audit = _load_audit(session).get(key, {}) if reason == "marked benign" else {}
    return {
        "reason": reason,
        "actor": audit.get("actor") or ("analyst" if reason == "marked benign" else "rule"),
        "rationale": audit.get("rationale") or "",
        "confidence": audit.get("confidence"),
        "evidence_refs": audit.get("evidence_refs") or [],
        "timestamp": audit.get("timestamp"),
    }


# --- application -------------------------------------------------------------

def is_suppressed(title: str, source: str, evidence: dict | None,
                  disabled: set[str], benign: set[str]) -> str | None:
    """Return the suppression reason for a finding, or None."""
    if rule_id_for(title, source) in disabled:
        return "rule disabled"
    if finding_key(title, evidence) in benign:
        return "marked benign"
    return None


def apply_overrides(session) -> int:
    """Force every disabled-rule / benign finding to ``info`` (stashing the
    original severity), and restore any finding no longer suppressed. Returns
    the number of findings whose severity changed."""
    acquire_session_write_lock(session)
    disabled = get_disabled_rules(session)
    benign = get_benign_keys(session)
    changed = 0
    for f in session.scalars(select(Finding)):
        ev = dict(f.evidence or {})
        reason = is_suppressed(f.title, f.source, f.evidence, disabled, benign)
        if reason:
            if "suppressed_from" not in ev:
                ev["suppressed_from"] = f.severity
            ev["suppressed_reason"] = reason
            f.evidence = ev
            if f.severity != SUPPRESSED_SEVERITY:
                f.severity = SUPPRESSED_SEVERITY
                changed += 1
        elif "suppressed_from" in ev:
            restored = ev.pop("suppressed_from")
            ev.pop("suppressed_reason", None)
            f.evidence = ev
            if f.severity != restored:
                f.severity = restored
                changed += 1
    return changed
