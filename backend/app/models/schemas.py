"""Pydantic schemas for API requests and responses."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ProviderType = Literal["ollama", "openai", "openrouter", "gemini", "anthropic"]
Severity = Literal["info", "low", "medium", "high", "critical"]
CaseStatus = Literal["created", "ingesting", "analyzing", "ready", "error"]


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=20_000)


class CaseResponse(BaseModel):
    id: str
    name: str
    description: str
    status: CaseStatus
    created_at: datetime
    updated_at: datetime
    event_count: int = 0
    finding_count: int = 0
    active_finding_count: int = 0
    process_count: int = 0
    has_memory_dump: bool = False
    ai_summary: str | None = None


class UploadInit(BaseModel):
    filename: str
    total_size: int
    chunk_size: int = 5 * 1024 * 1024
    file_type: Literal["artifact", "memory"] = "artifact"


class IngestionProgress(BaseModel):
    case_id: str
    phase: str
    percent: float
    message: str
    done: bool = False
    error: str | None = None


class EventResponse(BaseModel):
    id: int
    timestamp: datetime | None
    host: str | None
    source: str
    category: str
    entity: str | None
    severity: Severity
    summary: str
    raw: dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    id: int
    start: datetime | None
    end: datetime | None
    content: str
    group: str
    severity: Severity
    source: str
    raw: dict[str, Any] = Field(default_factory=dict)


class FindingResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: Severity
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    source: str
    ai_verdict: str | None = None
    created_at: datetime
    suppressed: bool = False
    suppressed_reason: str | None = None
    suppression_details: dict[str, Any] | None = None


class ProcessNode(BaseModel):
    pid: int
    ppid: int | None
    name: str
    path: str | None = None
    cmdline: str | None = None
    start_time: datetime | None = None
    flags: list[str] = Field(default_factory=list)
    severity: Severity = "info"
    children: list["ProcessNode"] = Field(default_factory=list)


class ProcessTreeResponse(BaseModel):
    case_id: str
    session_id: str
    roots: list[ProcessNode]
    flat: list[dict[str, Any]] = Field(default_factory=list)


class MemoryResultResponse(BaseModel):
    id: int
    plugin: str
    pid: int | None
    process_name: str | None
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    severity: Severity = "info"


class ReportResponse(BaseModel):
    case_id: str
    summary: str
    timeline_narrative: str
    timeline_entries: list[dict[str, Any]] = Field(default_factory=list)
    findings_analysis: list[dict[str, Any]] = Field(default_factory=list)
    stale: bool = False
    generated_at: datetime


class LLMConfigUpdate(BaseModel):
    provider: ProviderType | None = None
    model: str | None = Field(default=None, min_length=1, max_length=256)
    ollama_base_url: str | None = Field(default=None, min_length=1, max_length=2048)
    openrouter_base_url: str | None = Field(default=None, min_length=1, max_length=2048)
    temperature: float | None = Field(default=None, ge=0, le=2, allow_inf_nan=False)
    max_tokens: int | None = Field(default=None, ge=1, le=131_072, strict=True)
    analysis_max_tool_calls: int | None = Field(default=None, ge=0, le=20)
    chat_max_tool_calls: int | None = Field(default=None, ge=0, le=20)
    entity_max_tool_calls: int | None = Field(default=None, ge=0, le=20)
    api_key: str | None = Field(default=None, max_length=4096)


class LLMConfigResponse(BaseModel):
    provider: ProviderType
    model: str
    ollama_base_url: str
    openrouter_base_url: str
    temperature: float
    max_tokens: int
    analysis_max_tool_calls: int
    chat_max_tool_calls: int
    entity_max_tool_calls: int
    has_api_key: bool
    available_models: list["ModelInfo"] = Field(default_factory=list)


class ModelInfo(BaseModel):
    id: str
    name: str
    provider: ProviderType


class ProviderTestResult(BaseModel):
    success: bool
    message: str
    models: list[ModelInfo] = Field(default_factory=list)


class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = Field(default_factory=list)


class AnalysisRequest(BaseModel):
    rerun: bool = False


class APIKeyUpdate(BaseModel):
    api_key: str = Field(min_length=1, max_length=4096)


class GeneralSettingsUpdate(BaseModel):
    yara_rules_dir: str | None = Field(default=None, max_length=4096)


class ChatCreate(BaseModel):
    title: str = Field(default="New chat", max_length=200)


class ChatTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=32_000)
    chat_id: str = Field(min_length=1, max_length=64)


class EntityInvestigation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entity_id: str = Field(min_length=1, max_length=4096)


class FindingBenignUpdate(BaseModel):
    benign: bool = Field(default=True, strict=True)
    rationale: str = Field(default="Analyst marked this finding benign", max_length=20_000)


class RuleDisabledUpdate(BaseModel):
    rule_id: str = Field(min_length=1, max_length=256)
    disabled: bool = Field(default=True, strict=True)


class ManualFindingCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    severity: Severity
    description: str = Field(default="", max_length=32_000)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=100)
    ref_type: Literal["event", "entity", ""] = ""
    ref_id: str = Field(default="", max_length=4096)
    ref_label: str = Field(default="", max_length=4096)
    entity_type: str = Field(default="", max_length=128)
    ref_entity: str = Field(default="", max_length=4096)


class VFSArchiveRequest(BaseModel):
    paths: list[Annotated[str, Field(min_length=1, max_length=4096)]] = Field(min_length=1, max_length=1000)
