"""Pydantic schemas for API requests and responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

ProviderType = Literal["ollama", "openai", "gemini", "anthropic"]
Severity = Literal["info", "low", "medium", "high", "critical"]
CaseStatus = Literal["created", "ingesting", "analyzing", "ready", "error"]


class CaseCreate(BaseModel):
    name: str
    description: str = ""


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
    findings_analysis: list[dict[str, Any]] = Field(default_factory=list)
    generated_at: datetime


class LLMConfigUpdate(BaseModel):
    provider: ProviderType | None = None
    model: str | None = None
    ollama_base_url: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    api_key: str | None = None


class LLMConfigResponse(BaseModel):
    provider: ProviderType
    model: str
    ollama_base_url: str
    temperature: float
    max_tokens: int
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
