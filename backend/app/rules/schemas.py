"""Request and response models for the rules API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.rules import limits

Severity = Literal["info", "low", "medium", "high", "critical"]


class RuleSummary(BaseModel):
    """One row in the rules table."""

    id: str
    title: str
    kind: str
    platform: str
    severity: str
    techniques: list[str] = Field(default_factory=list)
    source: Literal["builtin", "custom"] = "builtin"
    enabled: bool = True
    family: str | None = None
    is_family: bool = False
    editable: list[str] = Field(default_factory=list)
    forkable: bool = False
    severity_override: str | None = None
    # Legacy ids let the UI relate a rule to a per-case suppression.
    legacy_rule_ids: list[str] = Field(default_factory=list)
    gated: bool = True
    compile_status: str = "ok"
    compile_error: str | None = None
    warnings: list[str] = Field(default_factory=list)


class RuleDetail(RuleSummary):
    description: str = ""
    logic: str = ""
    yaml_source: str = ""
    logsource: str = ""
    unmapped_fields: list[str] = Field(default_factory=list)
    note: str = ""
    origin: str = ""
    source_builtin_id: str | None = None


class RuleListResponse(BaseModel):
    revision: int
    rules: list[RuleSummary]
    total: int
    builtin_total: int
    custom_total: int
    disabled_total: int
    ungated_total: int
    ungated_limit: int = limits.MAX_UNFILTERED_RULES


class BuiltinRuleUpdate(BaseModel):
    enabled: bool | None = None
    severity_override: Severity | None = None
    clear_severity: bool = False
    note: str | None = Field(default=None, max_length=limits.MAX_NOTE_LENGTH)


class CustomRuleCreate(BaseModel):
    yaml_source: str = Field(min_length=1, max_length=limits.MAX_YAML_BYTES)
    enabled: bool = True


class CustomRuleUpdate(BaseModel):
    yaml_source: str | None = Field(default=None, max_length=limits.MAX_YAML_BYTES)
    enabled: bool | None = None


class RuleValidateRequest(BaseModel):
    yaml_source: str = Field(min_length=1, max_length=limits.MAX_YAML_BYTES)


class RuleValidateResponse(BaseModel):
    ok: bool
    error: str | None = None
    title: str = ""
    severity: str = ""
    techniques: list[str] = Field(default_factory=list)
    logsource: str = ""
    literals: list[str] = Field(default_factory=list)
    gated: bool = False
    warnings: list[str] = Field(default_factory=list)
    unmapped_fields: list[str] = Field(default_factory=list)


class RuleImportResponse(BaseModel):
    imported: list[dict] = Field(default_factory=list)
    rejected: list[dict] = Field(default_factory=list)
    revision: int


class ForkRequest(BaseModel):
    disable_builtin: bool = True


class ForkResponse(BaseModel):
    id: str
    slug: str
    yaml_source: str
    revision: int


class MutationResponse(BaseModel):
    ok: bool = True
    revision: int
