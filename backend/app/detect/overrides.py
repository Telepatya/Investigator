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

from sqlalchemy import select

from app.store import cases as case_store
from app.store.database import Finding

_DISABLED_RULES_KEY = "disabled_rules"
_BENIGN_FINDINGS_KEY = "benign_findings"
SUPPRESSED_SEVERITY = "info"

# Findings whose title carries a variable subject (a process/service/account name
# or a "parent -> child" pair). Collapse the whole family to one rule id so that
# "disable this rule" covers every entity the rule fires on, not just this one.
_VARIABLE_TITLE_RULES: list[tuple[str, str]] = [
    ("LOLBin activity", "lolbin-activity"),
    ("Execution from suspicious directory", "execution-from-suspicious-directory"),
    ("System process masquerade", "system-process-masquerade"),
    ("Random-looking executable in Windows root", "random-executable-windows-root"),
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


def get_disabled_rules(session) -> set[str]:
    return _load_set(session, _DISABLED_RULES_KEY)


def get_benign_keys(session) -> set[str]:
    return _load_set(session, _BENIGN_FINDINGS_KEY)


def set_rule_disabled(session, rule_id: str, disabled: bool) -> set[str]:
    rules = get_disabled_rules(session)
    if disabled:
        rules.add(rule_id)
    else:
        rules.discard(rule_id)
    _store_set(session, _DISABLED_RULES_KEY, rules)
    return rules


def set_finding_benign(session, key: str, benign: bool) -> set[str]:
    keys = get_benign_keys(session)
    if benign:
        keys.add(key)
    else:
        keys.discard(key)
    _store_set(session, _BENIGN_FINDINGS_KEY, keys)
    return keys


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
