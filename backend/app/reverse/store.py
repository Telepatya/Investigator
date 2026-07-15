"""Reverse project, artifact, audit, and lifecycle operations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from app.config import UPLOAD_STAGING_PREFIX, get_reverse_dir, load_config
from app.store import cases as case_store

from .database import (
    ReverseArtifact,
    ReverseAuditEvent,
    ReverseProject,
    ReverseProvenanceEntry,
    ReverseRun,
    ReverseToolApproval,
    get_reverse_session,
)

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ ()%+@-]{0,254}$")


def now() -> datetime:
    return datetime.now(timezone.utc)


def validate_project_id(project_id: str) -> str:
    if not _UUID_RE.fullmatch(str(project_id or "")):
        raise ValueError("Invalid Reverse project id")
    return project_id.lower()


def safe_filename(filename: str | None) -> str:
    name = os.path.basename(str(filename or "").replace("\\", "/"))
    if name in {"", ".", ".."} or not _SAFE_NAME_RE.fullmatch(name):
        raise ValueError("Invalid filename")
    return name


def project_dir(project_id: str) -> Path:
    project_id = validate_project_id(project_id)
    root = (get_reverse_dir() / "projects").resolve()
    root.mkdir(parents=True, exist_ok=True)
    target = (root / project_id).resolve()
    if target.parent != root:
        raise ValueError("Invalid Reverse project path")
    return target


def ensure_project_dirs(project_id: str) -> Path:
    root = project_dir(project_id)
    for name in ("uploads", "outputs", "logs", "staging"):
        (root / name).mkdir(parents=True, exist_ok=True)
    return root


def contained_project_path(project_id: str, relative_path: str, *, must_exist: bool = False) -> Path:
    root = project_dir(project_id).resolve()
    candidate = (root / relative_path).resolve(strict=must_exist)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("Path escapes Reverse project") from exc
    return candidate


def create_project(name: str, description: str = "", linked_case_id: str | None = None) -> ReverseProject:
    if linked_case_id and not case_store.case_exists(linked_case_id):
        raise ValueError("Linked case does not exist")
    project_id = str(uuid.uuid4())
    ensure_project_dirs(project_id)
    with get_reverse_session() as db:
        project = ReverseProject(
            id=project_id,
            name=name.strip(),
            description=description,
            linked_case_id=linked_case_id,
        )
        db.add(project)
        for tool_id in load_config().reverse.enabled_tools:
            db.add(ReverseToolApproval(
                project_id=project_id, tool_id=tool_id, approved=True,
            ))
        db.commit()
        db.refresh(project)
        add_audit(project_id, "project.created", {"linked_case_id": linked_case_id}, db=db)
        db.commit()
        return project


def get_project(project_id: str, db=None) -> ReverseProject | None:
    project_id = validate_project_id(project_id)
    if db is not None:
        return db.get(ReverseProject, project_id)
    with get_reverse_session() as own:
        return own.get(ReverseProject, project_id)


def list_projects(linked_case_id: str | None = None) -> list[dict[str, Any]]:
    with get_reverse_session() as db:
        stmt = select(ReverseProject).order_by(ReverseProject.updated_at.desc())
        if linked_case_id is not None:
            stmt = stmt.where(ReverseProject.linked_case_id == linked_case_id)
        projects = list(db.scalars(stmt))
        rows: list[dict[str, Any]] = []
        for project in projects:
            artifact_count = db.scalar(
                select(func.count()).select_from(ReverseArtifact).where(
                    ReverseArtifact.project_id == project.id
                )
            ) or 0
            latest = db.scalar(
                select(ReverseRun).where(ReverseRun.project_id == project.id).order_by(
                    ReverseRun.created_at.desc()
                ).limit(1)
            )
            rows.append(project_response(project, int(artifact_count), latest.status if latest else None))
        return rows


def project_response(project: ReverseProject, artifact_count: int = 0, latest_run_status: str | None = None) -> dict[str, Any]:
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "linked_case_id": project.linked_case_id,
        "status": project.status,
        "active_run_id": project.active_run_id,
        "created_at": project.created_at,
        "updated_at": project.updated_at,
        "artifact_count": artifact_count,
        "latest_run_status": latest_run_status,
    }


def update_project(project_id: str, **changes) -> ReverseProject:
    with get_reverse_session() as db:
        project = db.get(ReverseProject, validate_project_id(project_id))
        if not project:
            raise KeyError(project_id)
        if "linked_case_id" in changes:
            linked = changes["linked_case_id"]
            if linked and not case_store.case_exists(linked):
                raise ValueError("Linked case does not exist")
        before_link = project.linked_case_id
        for key in ("name", "description", "linked_case_id"):
            if key in changes:
                setattr(project, key, changes[key])
        project.updated_at = now()
        add_audit(
            project.id,
            "project.updated",
            {"changed": sorted(changes), "previous_linked_case_id": before_link},
            db=db,
        )
        db.commit()
        db.refresh(project)
        return project


def delete_project(project_id: str) -> bool:
    project_id = validate_project_id(project_id)
    with get_reverse_session() as db:
        project = db.get(ReverseProject, project_id)
        if not project:
            return False
        db.delete(project)
        db.commit()
    root = project_dir(project_id)
    if root.exists():
        shutil.rmtree(root)
    return True


def unlink_deleted_case(case_id: str) -> int:
    with get_reverse_session() as db:
        projects = list(db.scalars(select(ReverseProject).where(ReverseProject.linked_case_id == case_id)))
        for project in projects:
            project.linked_case_id = None
            project.updated_at = now()
            add_audit(project.id, "case.unlinked", {"deleted_case_id": case_id}, db=db)
        db.commit()
        return len(projects)


def repair_case_links() -> list[str]:
    repaired: list[str] = []
    with get_reverse_session() as db:
        projects = list(db.scalars(select(ReverseProject).where(ReverseProject.linked_case_id.is_not(None))))
        for project in projects:
            if project.linked_case_id and not case_store.case_exists(project.linked_case_id):
                old = project.linked_case_id
                project.linked_case_id = None
                project.updated_at = now()
                add_audit(project.id, "case.link_repaired", {"missing_case_id": old}, db=db)
                repaired.append(project.id)
        db.commit()
    return repaired


def recover_interrupted_runs() -> list[str]:
    recovered: list[str] = []
    with get_reverse_session() as db:
        runs = list(db.scalars(select(ReverseRun).where(
            ReverseRun.status.in_(("queued", "running", "verifying", "stopping"))
        )))
        for run in runs:
            run.status = "stopped"
            run.error = "Investigator stopped while this analysis was active"
            run.updated_at = now()
            project = db.get(ReverseProject, run.project_id)
            if project:
                project.status = "stopped"
                project.active_run_id = run.id
                project.updated_at = now()
            add_audit(run.project_id, "analysis.recovered", {"run_id": run.id}, db=db)
            recovered.append(run.id)
        db.commit()
    return recovered


def add_audit(project_id: str, event_type: str, details: dict[str, Any], *, db=None) -> None:
    owns = db is None
    session = db or get_reverse_session()
    try:
        session.add(ReverseAuditEvent(project_id=project_id, event_type=event_type, details=details))
        if owns:
            session.commit()
    finally:
        if owns:
            session.close()


def append_provenance(
    project_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    signature: str | None = None,
    db=None,
) -> ReverseProvenanceEntry:
    owns = db is None
    session = db or get_reverse_session()
    try:
        last = session.scalar(
            select(ReverseProvenanceEntry).where(
                ReverseProvenanceEntry.project_id == project_id
            ).order_by(ReverseProvenanceEntry.sequence.desc()).limit(1)
        )
        sequence = (last.sequence + 1) if last else 1
        previous = last.entry_hash if last else "0" * 64
        canonical = json.dumps(
            {"sequence": sequence, "event_type": event_type, "payload": payload, "previous_hash": previous},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
        entry = ReverseProvenanceEntry(
            project_id=project_id,
            sequence=sequence,
            event_type=event_type,
            payload=payload,
            previous_hash=previous,
            entry_hash=hashlib.sha256(canonical).hexdigest(),
            signature=signature,
        )
        session.add(entry)
        if owns:
            session.commit()
            session.refresh(entry)
        return entry
    finally:
        if owns:
            session.close()


def cleanup_staging_files() -> int:
    root = get_reverse_dir() / "projects"
    if not root.exists():
        return 0
    removed = 0
    for path in root.glob(f"*/staging/{UPLOAD_STAGING_PREFIX}*"):
        if path.is_file():
            path.unlink(missing_ok=True)
            removed += 1
    return removed
