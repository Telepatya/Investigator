"""HTTP API for the Rules page.

All mutating routes sit behind the application-wide origin check installed in
``app.main``, which is the same protection every other write in this local-only tool
relies on. What is added here is input validation: a rule id must exist in the
built-in catalog, a severity must be one the engine understands, and rule text must
compile before it is stored.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Response

from app.rules import fork as fork_module
from app.rules import limits, profile, store
from app.rules.database import CustomRule
from app.rules.registry import BUILTIN_RULES, RULES_BY_ID, RuleSpec
from app.rules.schemas import (
    BuiltinRuleUpdate,
    CustomRuleCreate,
    CustomRuleUpdate,
    ForkRequest,
    ForkResponse,
    MutationResponse,
    RuleDetail,
    RuleImportResponse,
    RuleListResponse,
    RuleSummary,
    RuleValidateRequest,
    RuleValidateResponse,
)
from app.rules.sigma_compile import SigmaRuleError, compile_rule, parse_rules

router = APIRouter(prefix="/api/rules", tags=["rules"])

_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,159}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")


def _validated_builtin(rule_id: str) -> RuleSpec:
    if not _RULE_ID_RE.fullmatch(rule_id or ""):
        raise HTTPException(400, "Invalid rule id")
    spec = RULES_BY_ID.get(rule_id)
    if spec is None:
        raise HTTPException(404, f"Unknown rule id: {rule_id}")
    return spec


def _validated_custom_id(rule_id: str) -> str:
    if not _UUID_RE.fullmatch(rule_id or ""):
        raise HTTPException(400, "Invalid rule id")
    return rule_id


def _builtin_summary(spec: RuleSpec, override) -> RuleSummary:
    return RuleSummary(
        id=spec.id,
        title=spec.title,
        kind=spec.kind,
        platform=spec.platform,
        severity=(override.severity_override if override and override.severity_override else spec.severity),
        techniques=list(spec.techniques),
        source="builtin",
        enabled=bool(override.enabled) if override else True,
        family=spec.family,
        is_family=spec.family is None and any(item.family == spec.id for item in BUILTIN_RULES),
        editable=sorted(spec.editable),
        forkable=spec.forkable,
        severity_override=(override.severity_override if override else None),
        legacy_rule_ids=list(spec.legacy_rule_ids),
    )


def _custom_summary(row: CustomRule) -> RuleSummary:
    meta = row.compiled_meta or {}
    return RuleSummary(
        id=row.id,
        title=row.title,
        kind="sigma",
        platform=str(meta.get("logsource") or "any"),
        severity=row.severity,
        techniques=list(row.techniques or ()),
        source="custom",
        enabled=bool(row.enabled),
        editable=["enabled", "yaml_source"],
        forkable=False,
        gated=bool(meta.get("gated", True)),
        compile_status=row.compile_status,
        compile_error=row.compile_error,
        warnings=list(meta.get("warnings") or ()),
    )


@router.get("", response_model=RuleListResponse)
def list_rules(
    q: str = "",
    source: str = "all",
    kind: str = "",
    platform: str = "",
    severity: str = "",
    enabled: str = "",
) -> RuleListResponse:
    """The whole catalog, filtered.

    The catalog is a few hundred rows, so it is returned in one response and the
    page filters client-side; the query parameters exist for deep links and for
    callers that want a narrow slice.
    """
    overrides = store.list_builtin_overrides() if _has_state() else {}
    summaries: list[RuleSummary] = []

    if source in ("all", "builtin"):
        for spec in BUILTIN_RULES:
            summaries.append(_builtin_summary(spec, overrides.get(spec.id)))

    custom_rows = store.list_custom_rules() if _has_state() else []
    if source in ("all", "custom"):
        summaries.extend(_custom_summary(row) for row in custom_rows)

    needle = (q or "").strip().lower()
    if needle:
        summaries = [
            item
            for item in summaries
            if needle in item.title.lower()
            or needle in item.id.lower()
            or any(needle in technique.lower() for technique in item.techniques)
        ]
    if kind:
        summaries = [item for item in summaries if item.kind == kind]
    if platform:
        summaries = [item for item in summaries if item.platform == platform]
    if severity:
        summaries = [item for item in summaries if item.severity == severity]
    if enabled in ("true", "false"):
        wanted = enabled == "true"
        summaries = [item for item in summaries if item.enabled is wanted]

    disabled_total = sum(1 for row in overrides.values() if not row.enabled)
    ungated_total = sum(
        1
        for row in custom_rows
        if row.enabled and not (row.compiled_meta or {}).get("gated", True)
    )
    return RuleListResponse(
        revision=store.current_revision() if _has_state() else 0,
        rules=summaries,
        total=len(summaries),
        builtin_total=len(BUILTIN_RULES),
        custom_total=len(custom_rows),
        disabled_total=disabled_total,
        ungated_total=ungated_total,
    )


def _has_state() -> bool:
    from app.rules.database import rules_db_exists

    return rules_db_exists()


@router.get("/{rule_id}", response_model=RuleDetail)
def get_rule(rule_id: str) -> RuleDetail:
    if _UUID_RE.fullmatch(rule_id or ""):
        row = store.get_custom_rule(rule_id) if _has_state() else None
        if row is None:
            raise HTTPException(404, "Rule not found")
        meta = row.compiled_meta or {}
        summary = _custom_summary(row)
        return RuleDetail(
            **summary.model_dump(),
            description="",
            logic=row.yaml_source,
            yaml_source=row.yaml_source,
            logsource=str(meta.get("logsource") or ""),
            unmapped_fields=list(meta.get("unmapped_fields") or ()),
            origin=row.origin,
            source_builtin_id=row.source_builtin_id,
        )

    spec = _validated_builtin(rule_id)
    overrides = store.list_builtin_overrides() if _has_state() else {}
    override = overrides.get(spec.id)
    summary = _builtin_summary(spec, override)
    preview = ""
    if spec.forkable:
        try:
            preview = fork_module.build_fork_yaml(spec)
        except ValueError:
            preview = ""
    return RuleDetail(
        **summary.model_dump(),
        description=spec.description,
        logic=spec.logic,
        yaml_source=preview,
        note=(override.note if override else ""),
    )


@router.patch("/builtin/{rule_id}", response_model=MutationResponse)
def update_builtin(rule_id: str, body: BuiltinRuleUpdate) -> MutationResponse:
    spec = _validated_builtin(rule_id)
    if body.severity_override is not None and "severity" not in spec.editable:
        raise HTTPException(
            400,
            f"Rule '{rule_id}' exposes only {sorted(spec.editable)}; its severity is "
            "fixed because it is a family switch.",
        )
    try:
        result = store.set_builtin_state(
            rule_id,
            enabled=body.enabled,
            severity_override=body.severity_override,
            clear_severity=body.clear_severity,
            note=body.note,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    profile.invalidate_cache()
    return MutationResponse(revision=result["revision"])


@router.post("/custom", response_model=MutationResponse)
def create_custom(body: CustomRuleCreate) -> MutationResponse:
    try:
        result = store.create_custom_rule(body.yaml_source, enabled=body.enabled)
    except SigmaRuleError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    profile.invalidate_cache()
    return MutationResponse(revision=result["revision"])


@router.patch("/custom/{rule_id}", response_model=MutationResponse)
def update_custom(rule_id: str, body: CustomRuleUpdate) -> MutationResponse:
    _validated_custom_id(rule_id)
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(400, "No changes supplied")
    try:
        result = store.update_custom_rule(
            rule_id,
            yaml_source=changes.get("yaml_source"),
            enabled=changes.get("enabled"),
        )
    except SigmaRuleError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(404 if str(exc) == "Rule not found" else 400, str(exc)) from exc
    profile.invalidate_cache()
    return MutationResponse(revision=result["revision"])


@router.delete("/custom/{rule_id}", response_model=MutationResponse)
def delete_custom(rule_id: str) -> MutationResponse:
    _validated_custom_id(rule_id)
    if not store.delete_custom_rule(rule_id):
        raise HTTPException(404, "Rule not found")
    profile.invalidate_cache()
    return MutationResponse(revision=store.current_revision())


@router.post("/validate", response_model=RuleValidateResponse)
def validate_rule(body: RuleValidateRequest) -> RuleValidateResponse:
    """Compile a rule without storing it, so the editor can report before saving."""
    try:
        parsed = parse_rules(body.yaml_source)
        if len(parsed) != 1:
            return RuleValidateResponse(
                ok=False, error=f"Expected one rule, found {len(parsed)}"
            )
        compiled = compile_rule(parsed[0], body.yaml_source)
    except SigmaRuleError as exc:
        return RuleValidateResponse(ok=False, error=str(exc))
    return RuleValidateResponse(
        ok=True,
        title=compiled.title,
        severity=compiled.severity,
        techniques=list(compiled.techniques),
        logsource=compiled.logsource_label,
        literals=sorted(compiled.literals),
        gated=compiled.gated,
        warnings=list(compiled.warnings),
        unmapped_fields=list(compiled.unmapped_fields),
    )


@router.post("/builtin/{rule_id}/fork", response_model=ForkResponse)
def fork_builtin(rule_id: str, body: ForkRequest) -> ForkResponse:
    """Create an editable Sigma approximation of a built-in rule."""
    spec = _validated_builtin(rule_id)
    if not spec.forkable:
        raise HTTPException(
            400,
            f"Rule '{rule_id}' is stateful or multi-signal and has no Sigma equivalent.",
        )
    try:
        yaml_source = fork_module.build_fork_yaml(spec)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    try:
        result = store.create_custom_rule(
            yaml_source, origin="fork", source_builtin_id=spec.id, enabled=False
        )
    except SigmaRuleError as exc:
        # The generated rule failed to compile: that is a defect in the fork
        # template, not analyst error, and must not be stored half-working.
        raise HTTPException(
            500, f"The generated fork for '{rule_id}' did not compile: {exc}"
        ) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    if body.disable_builtin:
        store.set_builtin_state(rule_id, enabled=False)
    profile.invalidate_cache()
    return ForkResponse(
        id=result["id"],
        slug=result["slug"],
        yaml_source=yaml_source,
        revision=store.current_revision(),
    )


@router.post("/import", response_model=RuleImportResponse)
def import_rules(body: RuleValidateRequest) -> RuleImportResponse:
    """Import a Sigma bundle.

    Rules are imported disabled and reported individually: one malformed document
    never prevents the rest of a bundle from loading.
    """
    try:
        result = store.import_rules(body.yaml_source)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    profile.invalidate_cache()
    return RuleImportResponse(**result)


@router.get("/export/bundle")
def export_bundle(ids: str = "") -> Response:
    """Download selected custom rules as a Sigma bundle."""
    wanted = [item for item in (ids or "").split(",") if item.strip()]
    body = store.export_rules(wanted) if _has_state() else ""
    return Response(
        content=body,
        media_type="application/yaml",
        headers={
            "Content-Disposition": 'attachment; filename="investigator-rules.yml"',
            # Analyst-authored text must never be rendered inline by the browser.
            "X-Content-Type-Options": "nosniff",
        },
    )
