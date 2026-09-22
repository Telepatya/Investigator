"""HTTP API for native Reverse workspaces."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from typing import Any

import aiofiles
from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import delete, func, select

from app.config import UPLOAD_STAGING_PREFIX, load_config

from .analysis import ACTIVE_STATUSES, analysis_manager, can_continue_investigation
from .database import (
    ReverseArtifact,
    ReverseAuditEvent,
    ReverseMessage,
    ReverseProject,
    ReverseProvenanceEntry,
    ReverseRun,
    ReverseToolApproval,
    get_reverse_session,
)
from .provenance import public_key_info, verify_bytes
from .sandbox import SandboxUnavailable, sandbox_manager
from .schemas import (
    ReverseAnalysisRequest,
    ReverseArtifactResponse,
    ReverseChatMessage,
    ReverseChatRequest,
    ReverseEvidenceResponse,
    ReverseProjectCreate,
    ReverseProjectResponse,
    ReverseProjectUpdate,
    ReverseReportResponse,
    ReverseRunResponse,
    ReverseStatusResponse,
    ReverseToolApprovalsUpdate,
    ReverseTraceEntry,
)
from .tools import TOOL_DESCRIPTIONS
from .store import (
    add_audit,
    append_provenance,
    contained_project_path,
    create_project,
    delete_project,
    get_project,
    list_projects,
    now,
    project_response,
    safe_filename,
    update_project,
    validate_project_id,
)

router = APIRouter(prefix="/api/reverse", tags=["reverse"])
_UPLOAD_LOCKS: dict[str, asyncio.Lock] = {}


def _project_or_404(project_id: str, db=None) -> ReverseProject:
    try:
        project = get_project(project_id, db=db)
    except ValueError as exc:
        raise HTTPException(404, "Reverse project not found") from exc
    if not project:
        raise HTTPException(404, "Reverse project not found")
    return project


def _run_response(run: ReverseRun) -> ReverseRunResponse:
    return ReverseRunResponse(
        id=run.id,
        project_id=run.project_id,
        status=run.status,
        provider=run.provider,
        model=run.model,
        temperature=run.temperature,
        max_tokens=run.max_tokens,
        max_turns=run.max_turns,
        turns_used=run.turns_used,
        awaiting_reason=run.awaiting_reason,
        analysis_outcome=run.analysis_outcome or ("legacy" if run.report_markdown else None),
        analysis_state=run.analysis_state or {},
        error=run.error,
        image_digest=run.image_digest,
        tool_versions=run.tool_versions or {},
        report_signature_status=run.report_signature_status,
        report_signature_error=run.report_signature_error,
        report_verification_status=_review_status(run.report_verification_status),
        report_verification_summary=run.report_verification_summary,
        report_verification_error=run.report_verification_error,
        report_review_status=_review_status(run.report_verification_status),
        report_review_passes=run.report_review_passes or 0,
        report_review_details=run.report_verification_details or {},
        created_at=run.created_at,
        updated_at=run.updated_at,
        completed_at=run.completed_at,
    )


@router.get("/health")
async def reverse_health() -> dict[str, Any]:
    return await asyncio.to_thread(sandbox_manager.health)


@router.get("/projects", response_model=list[ReverseProjectResponse])
async def get_projects(case_id: str | None = Query(default=None)) -> list[dict[str, Any]]:
    return list_projects(case_id)


@router.post("/projects", response_model=ReverseProjectResponse)
async def post_project(body: ReverseProjectCreate) -> dict[str, Any]:
    try:
        project = create_project(body.name, body.description, body.linked_case_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return project_response(project)


@router.get("/projects/{project_id}", response_model=ReverseProjectResponse)
async def get_project_endpoint(project_id: str) -> dict[str, Any]:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        count = db.scalar(select(func.count()).select_from(ReverseArtifact).where(
            ReverseArtifact.project_id == project.id
        )) or 0
        latest = db.scalar(select(ReverseRun).where(
            ReverseRun.project_id == project.id
        ).order_by(ReverseRun.created_at.desc()).limit(1))
        return project_response(project, int(count), latest.status if latest else None)


@router.patch("/projects/{project_id}", response_model=ReverseProjectResponse)
async def patch_project(project_id: str, body: ReverseProjectUpdate) -> dict[str, Any]:
    changes = body.model_dump(exclude_unset=True)
    clear = changes.pop("clear_case_link", False)
    if clear:
        changes["linked_case_id"] = None
    try:
        project = update_project(project_id, **changes)
    except KeyError as exc:
        raise HTTPException(404, "Reverse project not found") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return project_response(project)


def _tool_policy(project_id: str, db) -> dict[str, Any]:
    configured = [
        tool_id for tool_id in load_config().reverse.enabled_tools
        if tool_id in TOOL_DESCRIPTIONS
    ]
    approved = set(db.scalars(select(ReverseToolApproval.tool_id).where(
        ReverseToolApproval.project_id == project_id,
        ReverseToolApproval.approved.is_(True),
    )))
    return {
        "enabled_tools": [tool_id for tool_id in configured if tool_id in approved],
        "available_tools": [
            {"id": tool_id, "description": TOOL_DESCRIPTIONS[tool_id]}
            for tool_id in configured
        ],
    }


@router.get("/projects/{project_id}/tools")
async def get_project_tools(project_id: str) -> dict[str, Any]:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        return _tool_policy(project.id, db)


@router.put("/projects/{project_id}/tools")
async def put_project_tools(
    project_id: str, body: ReverseToolApprovalsUpdate
) -> dict[str, Any]:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        if project.status in ACTIVE_STATUSES | {"chatting"}:
            raise HTTPException(409, "Wait for the active Reverse operation before changing tools")
        configured = {
            tool_id for tool_id in load_config().reverse.enabled_tools
            if tool_id in TOOL_DESCRIPTIONS
        }
        requested = set(body.enabled_tools)
        invalid = sorted(requested - configured)
        if invalid:
            raise HTTPException(400, f"Tools are not installed and enabled: {', '.join(invalid)}")
        db.execute(delete(ReverseToolApproval).where(
            ReverseToolApproval.project_id == project.id
        ))
        for tool_id in sorted(requested):
            db.add(ReverseToolApproval(
                project_id=project.id, tool_id=tool_id, approved=True,
            ))
        add_audit(project.id, "tools.approvals_updated", {
            "enabled_tools": sorted(requested),
        }, db=db)
        append_provenance(project.id, "tools.approvals_updated", {
            "enabled_tools": sorted(requested),
        }, db=db)
        db.commit()
        return _tool_policy(project.id, db)


@router.delete("/projects/{project_id}")
async def remove_project(project_id: str) -> dict[str, bool]:
    try:
        validate_project_id(project_id)
    except ValueError as exc:
        raise HTTPException(404, "Reverse project not found") from exc
    project = _project_or_404(project_id)
    if project.status == "chatting":
        raise HTTPException(409, "Wait for the active Reverse LLM action before deleting")
    await analysis_manager.stop(project_id)
    await asyncio.to_thread(sandbox_manager.stop, project_id)
    try:
        removed = await asyncio.to_thread(delete_project, project_id)
    except OSError as exc:
        raise HTTPException(500, "Could not remove Reverse project files") from exc
    if not removed:
        raise HTTPException(404, "Reverse project not found")
    _UPLOAD_LOCKS.pop(project_id.lower(), None)
    return {"ok": True}


def _artifact_response(row: ReverseArtifact) -> ReverseArtifactResponse:
    return ReverseArtifactResponse(
        id=row.id, project_id=row.project_id, name=row.name,
        artifact_type=row.artifact_type, content_type=row.content_type,
        file_size=row.file_size, sha256=row.sha256,
        source_case_id=row.source_case_id, source_session_id=row.source_session_id,
        source_pid=row.source_pid, source_process_name=row.source_process_name,
        source_vfs_path=row.source_vfs_path, source_kind=row.source_kind,
        source_hashes=row.source_hashes, created_at=row.created_at,
    )


def _review_status(status: str | None) -> str:
    return {
        "verified": "passed",
        "needs_review": "passed_with_warnings",
    }.get(status or "pending", status or "pending")


@router.get("/projects/{project_id}/artifacts", response_model=list[ReverseArtifactResponse])
async def list_artifacts(project_id: str) -> list[ReverseArtifactResponse]:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        rows = list(db.scalars(select(ReverseArtifact).where(
            ReverseArtifact.project_id == project.id
        ).order_by(ReverseArtifact.created_at.desc())))
        return [_artifact_response(row) for row in rows]


@router.post("/projects/{project_id}/artifacts", response_model=ReverseArtifactResponse)
async def upload_artifact(project_id: str, file: UploadFile = File(...)) -> ReverseArtifactResponse:
    try:
        lock_id = validate_project_id(project_id)
    except ValueError as exc:
        raise HTTPException(404, "Reverse project not found") from exc
    lock = _UPLOAD_LOCKS.setdefault(lock_id, asyncio.Lock())
    async with lock:
        return await _upload_artifact(project_id, file)


async def _upload_artifact(project_id: str, file: UploadFile) -> ReverseArtifactResponse:
    project = _project_or_404(project_id)
    if project.status in ACTIVE_STATUSES | {"chatting"}:
        await file.close()
        raise HTTPException(409, "Wait for the active Reverse operation before uploading")
    try:
        name = safe_filename(file.filename)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    cfg = load_config().reverse
    artifact_id = str(uuid.uuid4())
    relative = f"uploads/{artifact_id}"
    target = contained_project_path(project.id, relative)
    staging = contained_project_path(
        project.id, f"staging/{UPLOAD_STAGING_PREFIX}{uuid.uuid4().hex}"
    )
    with get_reverse_session() as db:
        current_bytes = db.scalar(select(func.coalesce(func.sum(ReverseArtifact.file_size), 0)).where(
            ReverseArtifact.project_id == project.id
        )) or 0
    written = 0
    digest = hashlib.sha256()
    try:
        async with aiofiles.open(staging, "xb") as output:
            while True:
                chunk = await file.read(4 * 1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > cfg.max_upload_bytes:
                    raise HTTPException(413, "Upload exceeds the Reverse per-file limit")
                if int(current_bytes) + written > cfg.max_project_bytes:
                    raise HTTPException(413, "Upload exceeds the Reverse project size limit")
                digest.update(chunk)
                await output.write(chunk)
        if written == 0:
            raise HTTPException(400, "File is empty")
        os.replace(staging, target)
        row = ReverseArtifact(
            id=artifact_id,
            project_id=project.id,
            name=name,
            relative_path=relative,
            artifact_type="upload",
            content_type=file.content_type or "application/octet-stream",
            file_size=written,
            sha256=digest.hexdigest(),
        )
        with get_reverse_session() as db:
            db.add(row)
            project_row = db.get(ReverseProject, project.id)
            if project_row:
                project_row.updated_at = now()
            add_audit(project.id, "artifact.uploaded", {
                "artifact_id": artifact_id, "name": name,
                "size": written, "sha256": row.sha256,
            }, db=db)
            append_provenance(project.id, "artifact.uploaded", {
                "artifact_id": artifact_id, "name": name,
                "size": written, "sha256": row.sha256,
            }, db=db)
            db.commit()
            db.refresh(row)
        await asyncio.to_thread(sandbox_manager.stop, project.id)
        return _artifact_response(row)
    except HTTPException:
        staging.unlink(missing_ok=True)
        target.unlink(missing_ok=True)
        raise
    except Exception as exc:
        staging.unlink(missing_ok=True)
        target.unlink(missing_ok=True)
        raise HTTPException(500, "Upload failed") from exc
    finally:
        await file.close()


@router.get("/projects/{project_id}/artifacts/{artifact_id}/download")
async def download_artifact(project_id: str, artifact_id: str) -> FileResponse:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        row = db.get(ReverseArtifact, artifact_id)
        if not row or row.project_id != project.id:
            raise HTTPException(404, "Reverse artifact not found")
        try:
            path = contained_project_path(project.id, row.relative_path, must_exist=True)
        except (ValueError, OSError) as exc:
            raise HTTPException(404, "Reverse artifact file not found") from exc
        if not path.is_file():
            raise HTTPException(404, "Reverse artifact file not found")
        return FileResponse(path, media_type=row.content_type, filename=row.name)


@router.delete("/projects/{project_id}/artifacts/{artifact_id}")
async def delete_artifact(project_id: str, artifact_id: str) -> dict[str, bool]:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        if project.status in ACTIVE_STATUSES | {"chatting"}:
            raise HTTPException(409, "Stop Reverse analysis before deleting artifacts")
        row = db.get(ReverseArtifact, artifact_id)
        if not row or row.project_id != project.id:
            raise HTTPException(404, "Reverse artifact not found")
        path = contained_project_path(project.id, row.relative_path)
        db.delete(row)
        add_audit(project.id, "artifact.deleted", {
            "artifact_id": artifact_id, "sha256": row.sha256,
        }, db=db)
        db.commit()
    path.unlink(missing_ok=True)
    await asyncio.to_thread(sandbox_manager.stop, project.id)
    return {"ok": True}


@router.post("/projects/{project_id}/analysis/start", response_model=ReverseRunResponse)
async def start_analysis(project_id: str, body: ReverseAnalysisRequest) -> ReverseRunResponse:
    _project_or_404(project_id)
    try:
        return _run_response(await analysis_manager.start(project_id, body.notes))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except SandboxUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc


@router.get("/projects/{project_id}/analysis/status", response_model=ReverseStatusResponse)
async def analysis_status(project_id: str) -> ReverseStatusResponse:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        run = db.get(ReverseRun, project.active_run_id) if project.active_run_id else None
        final_message = None
        if run and run.status == "failed" and not run.report_markdown:
            final_message = db.scalar(select(ReverseMessage).where(
                ReverseMessage.run_id == run.id,
                ReverseMessage.phase == "analysis",
                ReverseMessage.role == "assistant",
            ).order_by(ReverseMessage.id.desc()).limit(1))
        return ReverseStatusResponse(
            project_id=project.id,
            status=(
                run.status
                if run and run.status in {"completed", "failed", "stopped"}
                else project.status
            ),
            run=_run_response(run) if run else None,
            active=analysis_manager.is_active(project.id),
            can_resume=bool(run and run.status in {"stopped", "failed", "awaiting_turn_approval"}),
            can_recover_report=bool(
                final_message
                and (final_message.metadata_json or {}).get("tool_request") is False
            ),
            can_continue_investigation=can_continue_investigation(run),
        )


@router.post("/projects/{project_id}/analysis/stop")
async def stop_analysis(project_id: str) -> dict[str, bool]:
    _project_or_404(project_id)
    return {"ok": await analysis_manager.stop(project_id)}


@router.post("/projects/{project_id}/analysis/resume", response_model=ReverseRunResponse)
async def resume_analysis(project_id: str) -> ReverseRunResponse:
    _project_or_404(project_id)
    try:
        return _run_response(await analysis_manager.resume(project_id))
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(409, str(exc)) from exc
    except SandboxUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc


@router.post(
    "/projects/{project_id}/analysis/continue",
    response_model=ReverseRunResponse,
)
async def continue_analysis(project_id: str) -> ReverseRunResponse:
    _project_or_404(project_id)
    try:
        return _run_response(await analysis_manager.continue_investigation(project_id))
    except SandboxUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/projects/{project_id}/analysis/turn-extension/approve", response_model=ReverseRunResponse)
async def approve_extension(project_id: str) -> ReverseRunResponse:
    _project_or_404(project_id)
    try:
        return _run_response(await analysis_manager.approve_extension(project_id))
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/projects/{project_id}/analysis/turn-extension/deny", response_model=ReverseRunResponse)
async def deny_extension(project_id: str) -> ReverseRunResponse:
    _project_or_404(project_id)
    try:
        return _run_response(await analysis_manager.deny_extension(project_id))
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/projects/{project_id}/analysis/replay", response_model=ReverseRunResponse)
async def replay_analysis(project_id: str) -> ReverseRunResponse:
    _project_or_404(project_id)
    try:
        return _run_response(await analysis_manager.replay(project_id))
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(409, str(exc)) from exc
    except SandboxUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc


@router.get("/projects/{project_id}/report", response_model=ReverseReportResponse)
async def get_report(project_id: str) -> ReverseReportResponse:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        run = db.scalar(select(ReverseRun).where(
            ReverseRun.project_id == project.id,
            ReverseRun.report_markdown.is_not(None),
        ).order_by(ReverseRun.created_at.desc()).limit(1))
        if not run or not run.report_markdown:
            raise HTTPException(404, "Reverse report not found")
        review_rows = list(db.scalars(select(ReverseMessage).where(
            ReverseMessage.project_id == project.id,
            ReverseMessage.run_id == run.id,
            ReverseMessage.phase == "verification",
            ReverseMessage.role == "assistant",
        ).order_by(ReverseMessage.id)))
        return ReverseReportResponse(
            project_id=project.id, run_id=run.id,
            content=run.report_markdown, iocs=run.iocs_markdown,
            structured_iocs=run.structured_iocs or [],
            analysis_outcome=run.analysis_outcome or "legacy",
            analysis_state=run.analysis_state or {},
            signature_status=run.report_signature_status,
            signature_error=run.report_signature_error,
            verification_status=_review_status(run.report_verification_status),
            verification_summary=run.report_verification_summary,
            verification_error=run.report_verification_error,
            verification_details=run.report_verification_details or {},
            review_status=_review_status(run.report_verification_status),
            review_passes=run.report_review_passes or 0,
            review_history=[row.metadata_json or {} for row in review_rows],
        )


@router.post("/projects/{project_id}/report/sign", response_model=ReverseRunResponse)
async def retry_report_signature(project_id: str) -> ReverseRunResponse:
    _project_or_404(project_id)
    try:
        return _run_response(await analysis_manager.retry_report_signature(project_id))
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/projects/{project_id}/report/verify", response_model=ReverseRunResponse)
async def retry_report_verification(project_id: str) -> ReverseRunResponse:
    _project_or_404(project_id)
    try:
        return _run_response(await analysis_manager.retry_report_verification(project_id))
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/projects/{project_id}/report/review", response_model=ReverseRunResponse)
async def retry_report_review(project_id: str) -> ReverseRunResponse:
    """Preferred evidence-aware review route; /verify remains a compatibility alias."""
    return await retry_report_verification(project_id)


@router.get(
    "/projects/{project_id}/evidence/{message_id}",
    response_model=ReverseEvidenceResponse,
)
async def get_report_evidence(project_id: str, message_id: int) -> ReverseEvidenceResponse:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        row = db.get(ReverseMessage, message_id)
        if (
            not row
            or row.project_id != project.id
            or row.phase != "analysis"
            or row.role != "tool"
            or not row.run_id
        ):
            raise HTTPException(404, "Reverse evidence reference not found")
        try:
            result = json.loads(row.content)
        except (json.JSONDecodeError, TypeError):
            result = {}
        if isinstance(result, list) and result:
            result = result[0]
        if not isinstance(result, dict):
            result = {}
        metadata = row.metadata_json or {}
        return ReverseEvidenceResponse(
            id=row.id,
            project_id=project.id,
            run_id=row.run_id,
            tool=metadata.get("tool"),
            target=metadata.get("target"),
            success=result.get("success"),
            returncode=result.get("returncode"),
            stdout=str(result.get("stdout") or ""),
            stderr=str(result.get("stderr") or ""),
            error=str(result.get("error") or "") or None,
            output_truncated=bool(result.get("output_truncated") or result.get("truncated")),
            stdout_original_length=result.get("stdout_original_length"),
            stdout_returned_length=result.get("stdout_returned_length"),
            stderr_original_length=result.get("stderr_original_length"),
            stderr_returned_length=result.get("stderr_returned_length"),
            output_note=str(result.get("output_note") or "") or None,
            output_sha256=hashlib.sha256(row.content.encode()).hexdigest(),
            created_at=row.created_at,
        )


@router.post("/projects/{project_id}/report/recover", response_model=ReverseRunResponse)
async def recover_completed_report(project_id: str) -> ReverseRunResponse:
    _project_or_404(project_id)
    try:
        return _run_response(await analysis_manager.recover_completed_report(project_id))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/projects/{project_id}/report/iocs")
async def regenerate_iocs(project_id: str) -> dict[str, str]:
    _project_or_404(project_id)
    try:
        return {"iocs": await analysis_manager.regenerate_iocs(project_id)}
    except KeyError as exc:
        raise HTTPException(404, "Reverse project not found") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/projects/{project_id}/messages", response_model=list[ReverseChatMessage])
async def get_messages(project_id: str) -> list[dict[str, Any]]:
    _project_or_404(project_id)
    return analysis_manager.chat_messages(project_id)


@router.post("/projects/{project_id}/messages", response_model=ReverseChatMessage)
async def send_message(project_id: str, body: ReverseChatRequest) -> dict[str, Any]:
    _project_or_404(project_id)
    try:
        row = await analysis_manager.chat(project_id, body.message)
    except KeyError as exc:
        raise HTTPException(404, "Reverse project not found") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {
        "id": row.id, "role": row.role, "content": row.content,
        "phase": row.phase, "metadata": row.metadata_json or {}, "created_at": row.created_at,
    }


@router.post("/projects/{project_id}/chat/pause")
async def pause_chat(project_id: str) -> dict[str, bool]:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        if analysis_manager.is_active(project.id) or project.status == "chatting":
            raise HTTPException(409, "A Reverse operation is active")
        project.status = "chat_paused"
        project.updated_at = now()
        add_audit(project.id, "chat.paused", {}, db=db)
        db.commit()
    return {"ok": True}


@router.post("/projects/{project_id}/chat/resume")
async def resume_chat(project_id: str) -> dict[str, bool]:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        if project.status == "chat_paused":
            project.status = "completed"
            project.updated_at = now()
            add_audit(project.id, "chat.resumed", {}, db=db)
            db.commit()
    return {"ok": True}


@router.delete("/projects/{project_id}/messages")
async def clear_chat(project_id: str) -> dict[str, bool]:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        if analysis_manager.is_active(project.id) or project.status == "chatting":
            raise HTTPException(409, "A Reverse operation is active")
        rows = list(db.scalars(select(ReverseMessage).where(
            ReverseMessage.project_id == project.id,
            ReverseMessage.phase == "chat",
        )))
        for row in rows:
            db.delete(row)
        add_audit(project.id, "chat.cleared", {"message_count": len(rows)}, db=db)
        db.commit()
    return {"ok": True}


@router.get("/projects/{project_id}/trace", response_model=list[ReverseTraceEntry])
async def get_trace(project_id: str) -> list[ReverseProvenanceEntry]:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        return list(db.scalars(select(ReverseProvenanceEntry).where(
            ReverseProvenanceEntry.project_id == project.id
        ).order_by(ReverseProvenanceEntry.sequence)))


@router.get("/projects/{project_id}/trace/verify")
async def verify_trace(project_id: str) -> dict[str, Any]:
    entries = await get_trace(project_id)
    previous = "0" * 64
    failures: list[int] = []
    signature_failures: list[int] = []
    for entry in entries:
        canonical = json.dumps({
            "sequence": entry.sequence,
            "event_type": entry.event_type,
            "payload": entry.payload,
            "previous_hash": previous,
        }, sort_keys=True, separators=(",", ":"), default=str).encode()
        expected = hashlib.sha256(canonical).hexdigest()
        if entry.previous_hash != previous or entry.entry_hash != expected:
            failures.append(entry.sequence)
        if entry.signature:
            run_id = str((entry.payload or {}).get("run_id") or "")
            public_pem = (entry.payload or {}).get("public_key_pem")
            with get_reverse_session() as db:
                run = db.get(ReverseRun, run_id)
                report = run.report_markdown if run else None
            if (
                not report
                or hashlib.sha256(report.encode()).hexdigest()
                != (entry.payload or {}).get("report_sha256")
                or not await asyncio.to_thread(
                    verify_bytes, report.encode(), entry.signature, public_pem
                )
            ):
                signature_failures.append(entry.sequence)
        previous = entry.entry_hash
    return {
        "valid": not failures and not signature_failures,
        "entries": len(entries),
        "failed_sequences": failures,
        "failed_signature_sequences": signature_failures,
    }


@router.get("/projects/{project_id}/audit")
async def get_audit(project_id: str, limit: int = Query(default=250, ge=1, le=2000)) -> list[dict[str, Any]]:
    with get_reverse_session() as db:
        project = _project_or_404(project_id, db)
        rows = list(db.scalars(select(ReverseAuditEvent).where(
            ReverseAuditEvent.project_id == project.id
        ).order_by(ReverseAuditEvent.id.desc()).limit(limit)))
        return [{
            "id": row.id, "event_type": row.event_type,
            "details": row.details or {}, "created_at": row.created_at,
        } for row in reversed(rows)]


@router.get("/provenance/public-key")
async def provenance_public_key() -> dict[str, str]:
    try:
        return await asyncio.to_thread(public_key_info)
    except Exception as exc:
        raise HTTPException(503, "OS keyring is unavailable for provenance signing") from exc
