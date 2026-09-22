"""Reads and writes for global detection-rule state.

Every mutation bumps ``rules_state.revision`` in the same transaction as the change
itself, so the revision is a reliable cache key: a reader that has seen revision N
has seen every write that produced it.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from sqlalchemy import select

from app.rules import limits
from app.rules.database import (
    STATE_ROW_ID,
    BuiltinRuleOverride,
    CustomRule,
    RulesState,
    get_rules_session,
)
from app.rules.registry import BUILTIN_RULES, RULES_BY_ID
from app.rules.sigma_compile import (
    CompiledRule,
    SigmaRuleError,
    compile_rule,
    parse_rules,
)
from app.store.database import acquire_session_write_lock

logger = logging.getLogger(__name__)

VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _bump_revision(session) -> int:
    state = session.get(RulesState, STATE_ROW_ID)
    if state is None:
        state = RulesState(id=STATE_ROW_ID, revision=1)
        session.add(state)
    state.revision = int(state.revision or 0) + 1
    state.updated_at = _utcnow()
    return state.revision


def current_revision() -> int:
    session = get_rules_session()
    try:
        state = session.get(RulesState, STATE_ROW_ID)
        return int(state.revision) if state is not None else 0
    finally:
        session.close()


# --- reads -------------------------------------------------------------------


def _compile_stored(row: CustomRule) -> CompiledRule | None:
    """Compile a stored rule, refusing one whose source no longer matches its digest.

    A hand-edited database row is the only way this mismatch happens, and running it
    would mean executing rule text that never passed validation.
    """
    digest = hashlib.sha256((row.yaml_source or "").encode("utf-8")).hexdigest()
    if digest != row.content_sha256:
        logger.error(
            "Custom rule %s failed its integrity check and was not loaded", row.slug
        )
        return None
    try:
        parsed = parse_rules(row.yaml_source)
        return compile_rule(parsed[0], row.yaml_source)
    except SigmaRuleError:
        # A rule that no longer compiles is skipped, never fatal: one bad rule must
        # not take the rest of the rule set down with it.
        logger.warning("Custom rule %s no longer compiles and was skipped", row.slug)
        return None


def load_active_state() -> tuple[dict[str, bool], dict[str, str], list[CompiledRule]]:
    """Built-in enable states, severity overrides, and compiled enabled custom rules."""
    session = get_rules_session()
    try:
        states: dict[str, bool] = {}
        severities: dict[str, str] = {}
        for row in session.scalars(select(BuiltinRuleOverride)):
            if row.rule_id not in RULES_BY_ID:
                continue
            states[row.rule_id] = bool(row.enabled)
            if row.severity_override:
                severities[row.rule_id] = row.severity_override
        compiled: list[CompiledRule] = []
        rows = session.scalars(
            select(CustomRule)
            .where(CustomRule.enabled.is_(True))
            .where(CustomRule.compile_status == "ok")
            .order_by(CustomRule.created_at)
        )
        for row in rows:
            rule = _compile_stored(row)
            if rule is not None:
                compiled.append(rule)
        return states, severities, compiled
    finally:
        session.close()


def list_builtin_overrides() -> dict[str, BuiltinRuleOverride]:
    session = get_rules_session()
    try:
        return {row.rule_id: row for row in session.scalars(select(BuiltinRuleOverride))}
    finally:
        session.close()


def list_custom_rules() -> list[CustomRule]:
    session = get_rules_session()
    try:
        return list(session.scalars(select(CustomRule).order_by(CustomRule.updated_at.desc())))
    finally:
        session.close()


def get_custom_rule(rule_id: str) -> CustomRule | None:
    session = get_rules_session()
    try:
        return session.get(CustomRule, rule_id)
    finally:
        session.close()


def count_ungated_enabled() -> int:
    """Enabled custom rules with no derivable literal gate."""
    _, _, compiled = load_active_state()
    return sum(1 for rule in compiled if not rule.literals)


# --- writes ------------------------------------------------------------------


def set_builtin_state(
    rule_id: str,
    *,
    enabled: bool | None = None,
    severity_override: str | None = None,
    clear_severity: bool = False,
    note: str | None = None,
) -> dict[str, Any]:
    """Update an analyst-editable field on a built-in rule."""
    if rule_id not in RULES_BY_ID:
        raise ValueError(f"Unknown rule id: {rule_id}")
    spec = RULES_BY_ID[rule_id]
    if severity_override is not None:
        if severity_override not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity_override}")
        if "severity" not in spec.editable:
            raise ValueError(f"Rule '{rule_id}' does not support a severity override")

    session = get_rules_session()
    try:
        acquire_session_write_lock(session)
        row = session.get(BuiltinRuleOverride, rule_id)
        if row is None:
            row = BuiltinRuleOverride(rule_id=rule_id, enabled=True)
            session.add(row)
        if enabled is not None:
            row.enabled = bool(enabled)
        if clear_severity:
            row.severity_override = None
        elif severity_override is not None:
            row.severity_override = severity_override
        if note is not None:
            row.note = str(note)[: limits.MAX_NOTE_LENGTH]
        row.updated_at = _utcnow()
        revision = _bump_revision(session)
        session.commit()
        return {
            "rule_id": rule_id,
            "enabled": bool(row.enabled),
            "severity_override": row.severity_override,
            "note": row.note,
            "revision": revision,
        }
    finally:
        session.close()


def _unique_slug(session, base: str, exclude_id: str | None = None) -> str:
    slug = base
    suffix = 2
    while True:
        query = select(CustomRule).where(CustomRule.slug == slug)
        if exclude_id:
            query = query.where(CustomRule.id != exclude_id)
        if session.scalars(query).first() is None:
            return slug
        slug = f"{base}-{suffix}"
        suffix += 1


def _enabled_custom_count(session, exclude_id: str | None = None) -> int:
    query = select(CustomRule).where(CustomRule.enabled.is_(True))
    if exclude_id:
        query = query.where(CustomRule.id != exclude_id)
    return len(list(session.scalars(query)))


def create_custom_rule(
    yaml_source: str,
    *,
    origin: str = "yaml",
    source_builtin_id: str | None = None,
    enabled: bool = True,
) -> dict[str, Any]:
    """Validate, compile and store a new Sigma rule.

    Compilation happens before anything is written, so a rule that cannot run is
    reported to the analyst rather than persisted in a state that silently matches
    nothing.
    """
    parsed = parse_rules(yaml_source)
    if len(parsed) != 1:
        raise SigmaRuleError(
            f"Expected one rule, found {len(parsed)}. Use import for a bundle."
        )
    compiled = compile_rule(parsed[0], yaml_source)

    session = get_rules_session()
    try:
        acquire_session_write_lock(session)
        if enabled and _enabled_custom_count(session) >= limits.MAX_ENABLED_CUSTOM_RULES:
            raise ValueError(
                f"At most {limits.MAX_ENABLED_CUSTOM_RULES} custom rules can be enabled"
            )
        if enabled and not compiled.literals:
            ungated = _count_ungated(session)
            if ungated >= limits.MAX_UNFILTERED_RULES:
                raise ValueError(
                    f"At most {limits.MAX_UNFILTERED_RULES} rules without a literal "
                    "prefilter can be enabled, because each one is evaluated against "
                    "every process and event. Narrow this rule or disable another."
                )
        row = CustomRule(
            id=str(uuid.uuid4()),
            slug=_unique_slug(session, compiled.slug),
            title=compiled.title,
            enabled=bool(enabled),
            severity=compiled.severity,
            techniques=list(compiled.techniques),
            yaml_source=compiled.yaml_source,
            content_sha256=compiled.content_sha256,
            compile_status="ok",
            compile_error=None,
            compiled_meta={
                "literals": sorted(compiled.literals),
                "warnings": list(compiled.warnings),
                "unmapped_fields": list(compiled.unmapped_fields),
                "logsource": compiled.logsource_label,
                "gated": compiled.gated,
            },
            origin=origin,
            source_builtin_id=source_builtin_id,
        )
        session.add(row)
        revision = _bump_revision(session)
        session.commit()
        return {"id": row.id, "slug": row.slug, "revision": revision}
    finally:
        session.close()


def _count_ungated(session, exclude_id: str | None = None) -> int:
    count = 0
    for row in session.scalars(
        select(CustomRule).where(CustomRule.enabled.is_(True)).where(CustomRule.compile_status == "ok")
    ):
        if row.id != exclude_id and not (row.compiled_meta or {}).get("gated", True):
            count += 1
    return count


def update_custom_rule(
    rule_id: str,
    *,
    yaml_source: str | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    session = get_rules_session()
    try:
        acquire_session_write_lock(session)
        row = session.get(CustomRule, rule_id)
        if row is None:
            raise ValueError("Rule not found")
        if yaml_source is not None:
            parsed = parse_rules(yaml_source)
            if len(parsed) != 1:
                raise SigmaRuleError(f"Expected one rule, found {len(parsed)}")
            compiled = compile_rule(parsed[0], yaml_source)
            row.title = compiled.title
            row.severity = compiled.severity
            row.techniques = list(compiled.techniques)
            row.yaml_source = compiled.yaml_source
            row.content_sha256 = compiled.content_sha256
            row.compile_status = "ok"
            row.compile_error = None
            row.compiled_meta = {
                "literals": sorted(compiled.literals),
                "warnings": list(compiled.warnings),
                "unmapped_fields": list(compiled.unmapped_fields),
                "logsource": compiled.logsource_label,
                "gated": compiled.gated,
            }
            row.slug = _unique_slug(session, compiled.slug, exclude_id=rule_id)
        if enabled is not None:
            if enabled and not row.enabled:
                if _enabled_custom_count(session, exclude_id=rule_id) >= limits.MAX_ENABLED_CUSTOM_RULES:
                    raise ValueError(
                        f"At most {limits.MAX_ENABLED_CUSTOM_RULES} custom rules can be enabled"
                    )
            row.enabled = bool(enabled)
        if row.compile_status != "ok":
            # Never let a rule that failed to compile become active.
            row.enabled = False
        if row.enabled and not (row.compiled_meta or {}).get("gated", True):
            if _count_ungated(session, exclude_id=rule_id) >= limits.MAX_UNFILTERED_RULES:
                raise ValueError(
                    f"At most {limits.MAX_UNFILTERED_RULES} rules without a literal "
                    "prefilter can be enabled"
                )
        row.updated_at = _utcnow()
        revision = _bump_revision(session)
        session.commit()
        return {"id": row.id, "slug": row.slug, "enabled": row.enabled, "revision": revision}
    finally:
        session.close()


def delete_custom_rule(rule_id: str) -> bool:
    session = get_rules_session()
    try:
        acquire_session_write_lock(session)
        row = session.get(CustomRule, rule_id)
        if row is None:
            return False
        session.delete(row)
        _bump_revision(session)
        session.commit()
        return True
    finally:
        session.close()


def import_rules(yaml_source: str) -> dict[str, Any]:
    """Import a Sigma bundle, reporting each rule's outcome independently.

    A rule that fails to compile is stored disabled with its error attached, and the
    others still import. Losing an entire rule set because one document was malformed
    is the failure mode this avoids.
    """
    encoded = (yaml_source or "").encode("utf-8", errors="ignore")
    if len(encoded) > limits.MAX_IMPORT_BYTES:
        raise ValueError(f"Import is {len(encoded)} bytes; the limit is {limits.MAX_IMPORT_BYTES}")

    documents = [chunk for chunk in _split_documents(yaml_source) if chunk.strip()]
    if len(documents) > limits.MAX_IMPORT_DOCS:
        raise ValueError(f"Import holds {len(documents)} documents; the limit is {limits.MAX_IMPORT_DOCS}")

    imported: list[dict[str, str]] = []
    rejected: list[dict[str, Any]] = []
    for index, document in enumerate(documents):
        try:
            result = create_custom_rule(document, origin="import", enabled=False)
            imported.append({"index": index, "id": result["id"], "slug": result["slug"]})
        except (SigmaRuleError, ValueError) as exc:
            rejected.append({"index": index, "error": str(exc)})
    return {"imported": imported, "rejected": rejected, "revision": current_revision()}


def _split_documents(text: str) -> Iterable[str]:
    """Split a multi-document YAML stream while keeping each document's text intact."""
    current: list[str] = []
    for line in (text or "").splitlines():
        if line.strip() == "---" and current:
            yield "\n".join(current)
            current = []
            continue
        if line.strip() == "---":
            continue
        current.append(line)
    if current:
        yield "\n".join(current)


def export_rules(rule_ids: Sequence[str] | None = None) -> str:
    """Render selected custom rules back to a Sigma bundle."""
    rows = list_custom_rules()
    if rule_ids:
        wanted = set(rule_ids)
        rows = [row for row in rows if row.id in wanted or row.slug in wanted]
    return "\n---\n".join(row.yaml_source.strip() for row in rows) + "\n" if rows else ""


def builtin_state_summary() -> dict[str, Any]:
    """Enabled/disabled counts for the catalog, for the Rules page header."""
    overrides = list_builtin_overrides()
    disabled = sum(1 for row in overrides.values() if not row.enabled)
    return {
        "total": len(BUILTIN_RULES),
        "disabled": disabled,
        "overridden": len(overrides),
    }
