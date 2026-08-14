"""Public request and response schemas for Reverse."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class ReverseProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=10_000)
    linked_case_id: str | None = None


class ReverseProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=10_000)
    linked_case_id: str | None = None
    clear_case_link: bool = False


class ReverseProjectResponse(BaseModel):
    id: str
    name: str
    description: str
    linked_case_id: str | None
    status: str
    active_run_id: str | None
    created_at: datetime
    updated_at: datetime
    artifact_count: int = 0
    latest_run_status: str | None = None
    analysis_note: str | None = None


class ReverseArtifactResponse(BaseModel):
    id: str
    project_id: str
    name: str
    artifact_type: str
    content_type: str
    file_size: int
    sha256: str
    source_case_id: str | None = None
    source_session_id: str | None = None
    source_pid: int | None = None
    source_process_name: str | None = None
    source_vfs_path: str | None = None
    source_kind: str | None = None
    source_hashes: dict[str, str] | None = None
    created_at: datetime


class ReverseProcessHandoffResponse(BaseModel):
    project_id: str
    status: Literal["ready"]
    artifact_ids: list[str]


class ReverseAnalysisRequest(BaseModel):
    notes: str = Field(default="", max_length=20_000)


class ReverseToolApprovalsUpdate(BaseModel):
    enabled_tools: list[str] = Field(max_length=32)


class ReverseRunResponse(BaseModel):
    id: str
    project_id: str
    status: str
    provider: str
    model: str
    temperature: float
    max_tokens: int
    max_turns: int
    turns_used: int
    awaiting_reason: str | None
    analysis_outcome: str | None = None
    analysis_state: dict[str, Any] = Field(default_factory=dict)
    error: str | None
    image_digest: str | None
    tool_versions: dict[str, Any]
    report_signature_status: str
    report_signature_error: str | None
    report_verification_status: str
    report_verification_summary: str | None
    report_verification_error: str | None
    report_review_status: str
    report_review_passes: int = 0
    report_review_details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None


class ReverseStatusResponse(BaseModel):
    project_id: str
    status: str
    run: ReverseRunResponse | None = None
    active: bool = False
    can_resume: bool = False
    can_recover_report: bool = False
    can_continue_investigation: bool = False


class ReverseReportResponse(BaseModel):
    project_id: str
    run_id: str
    content: str
    iocs: str | None = None
    structured_iocs: list[dict[str, Any]] = Field(default_factory=list)
    analysis_outcome: str | None = None
    analysis_state: dict[str, Any] = Field(default_factory=dict)
    signature_status: str
    signature_error: str | None = None
    verification_status: str
    verification_summary: str | None = None
    verification_error: str | None = None
    verification_details: dict[str, Any] = Field(default_factory=dict)
    review_status: str
    review_passes: int = 0
    review_history: list[dict[str, Any]] = Field(default_factory=list)


class ReverseEvidenceResponse(BaseModel):
    id: int
    project_id: str
    run_id: str
    tool: str | None = None
    target: Any = None
    success: bool | None = None
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    output_truncated: bool = False
    stdout_original_length: int | None = None
    stdout_returned_length: int | None = None
    stderr_original_length: int | None = None
    stderr_returned_length: int | None = None
    output_note: str | None = None
    output_sha256: str
    created_at: datetime


class ReverseChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=50_000)


class ReverseChatMessage(BaseModel):
    id: int
    role: Literal["user", "assistant", "system", "tool"]
    content: str
    phase: str
    metadata: dict[str, Any]
    created_at: datetime


class ReverseTraceEntry(BaseModel):
    id: int
    sequence: int
    event_type: str
    payload: dict[str, Any]
    previous_hash: str
    entry_hash: str
    signature: str | None
    created_at: datetime


class ReverseSettingsUpdate(BaseModel):
    sandbox_idle_ttl_minutes: int | None = Field(default=None, ge=5, le=1440)
    sandbox_memory_limit_mb: int | None = Field(default=None, ge=256, le=32768)
    sandbox_cpu_limit: float | None = Field(default=None, ge=0.25, le=16.0)
    sandbox_pids_limit: int | None = Field(default=None, ge=32, le=1024)
    analysis_max_turns: int | None = Field(default=None, ge=1, le=100)
    analysis_extension_turns: int | None = Field(default=None, ge=1, le=50)
    max_upload_bytes: int | None = Field(default=None, ge=1024, le=64 * 1024 ** 3)
    max_project_bytes: int | None = Field(default=None, ge=1024, le=256 * 1024 ** 3)
    max_tool_output_chars: int | None = Field(default=None, ge=1000, le=200_000)
    enabled_tools: list[str] | None = None
