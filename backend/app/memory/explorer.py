"""On-demand MemProcFS browsing and extraction helpers."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.config import case_uploads_path
from app.memory.forensics import memprocfs_artifact_dir
from app.memory.memprocfs_runner import (
    VFS_CHUNK_SIZE,
    _VMM_LOCK,
    _dict_get,
    _entry_name,
    _entry_size,
    is_memprocfs_available,
)

MEMORY_EXTENSIONS = {".raw", ".dmp", ".mem", ".vmem", ".bin", ".img", ".lime", ".dd"}
MAX_ARCHIVE_DEPTH = 6
MAX_ARCHIVE_FILES = 1000
MAX_MODULE_HASH_BYTES = 512 * 1024 * 1024
logger = logging.getLogger(__name__)


class MemoryExplorerError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class MemoryDumpRef:
    session_id: str
    dump_stem: str
    filename: str
    path: Path
    size: int


def list_memory_dumps(case_id: str) -> list[dict[str, Any]]:
    uploads = case_uploads_path(case_id)
    dumps: list[dict[str, Any]] = []
    for path in sorted(uploads.iterdir()):
        if path.is_file() and _looks_like_memory_dump(path):
            stat = path.stat()
            dumps.append({
                "session_id": f"mem-{path.stem}",
                "dump_stem": path.stem,
                "filename": path.name,
                "size": stat.st_size,
            })
    return dumps


def memory_process_candidates(session, entity_value: str) -> list[dict[str, Any]]:
    from app.store.database import MemoryResult, Process
    from sqlalchemy import select

    wanted = _basename(entity_value).lower()
    out: list[dict[str, Any]] = []
    for proc in session.scalars(select(Process).where(Process.session_id.like("mem-%"))):
        if _basename(proc.name).lower() != wanted and _basename(proc.path or "").lower() != wanted:
            continue
        mem_rows = [
            row for row in session.scalars(select(MemoryResult).where(MemoryResult.pid == proc.pid))
            if _memory_result_matches_process(row, proc)
        ]
        out.append({
            "session_id": proc.session_id,
            "pid": proc.pid,
            "ppid": proc.ppid,
            "name": proc.name,
            "path": proc.path,
            "cmdline": proc.cmdline,
            "start_time": proc.start_time.isoformat() if proc.start_time else None,
            "flags": proc.flags or [],
            "severity": proc.severity,
            "extra": proc.extra or {},
            "memory_results": [
                {
                    "id": m.id,
                    "plugin": m.plugin,
                    "summary": m.summary,
                    "severity": m.severity,
                    "data": m.data,
                }
                for m in mem_rows[:50]
            ],
            "handles": [],
            "handle_counts": {},
            "cross_process_activity": [],
            "handles_on_demand": True,
            "downloads": {
                "image": True,
                "minidump": True,
                "modules": True,
            },
        })
    return out


def list_process_handles(
    case_id: str,
    session_id: str,
    pid: int,
    handle_type: str | None = None,
    limit: int = 300,
    offset: int = 0,
) -> dict[str, Any]:
    from app.store import cases as case_store
    from app.store.database import Process
    from sqlalchemy import select

    limit = max(1, min(int(limit or 300), 1000))
    offset = max(0, int(offset or 0))
    session = case_store.get_session(case_id)
    try:
        proc = session.scalars(
            select(Process).where(Process.session_id == session_id, Process.pid == int(pid))
        ).first()
        if not proc:
            raise MemoryExplorerError("Memory-backed process not found", 404)
        events = _handle_events_for_process(session, proc)
        if not events:
            _collect_and_cache_process_handles(case_id, session, proc)
            session.commit()
            events = _handle_events_for_process(session, proc)
        rows = _process_handle_rows(proc, events, handle_type=handle_type)[0]
        return {
            "session_id": session_id,
            "pid": pid,
            "type": handle_type,
            "total": len(rows),
            "offset": offset,
            "limit": limit,
            "handles": rows[offset:offset + limit],
        }
    finally:
        session.close()


def _collect_and_cache_process_handles(case_id: str, session, proc) -> None:
    from app.store import cases as case_store
    from app.memory.pipeline import _grade_handle

    dump = resolve_memory_dump(case_id, proc.session_id)
    with _open_vmm(dump.path) as vmm:
        mem_proc = _process(vmm, proc.pid)
        proc_name = _proc_name(mem_proc, proc.pid) or proc.name
        try:
            handles = mem_proc.maps.handle() or []
        except Exception as exc:
            raise MemoryExplorerError(f"Could not collect process handles: {exc}", 500) from exc

    for handle in handles:
        row = {
            "PID": proc.pid,
            "Process": proc.name or proc_name,
            "Handle": _dict_get(handle, "handle", "Handle"),
            "Type": _dict_get(handle, "type", "Type"),
            "Name": _dict_get(handle, "name", "Name", "tag", "Tag", "path", "Path"),
            "Access": _dict_get(handle, "access", "Access", "dwGrantedAccess", "GrantedAccess"),
            "Object": _dict_get(handle, "va-object", "object", "Object", "ptr", "Pointer"),
            "TargetPID": _dict_get(handle, "pid", "target_pid", "TargetPID", "process_id"),
            "TargetProcess": _dict_get(handle, "process", "target", "Target", "target_process"),
        }
        if str(row["Type"] or "").lower() == "process":
            target_match = re.search(
                r"\bPID\s+(\d+)\s*(?:-\s*(.+))?",
                str(row["Name"] or ""),
                re.IGNORECASE,
            )
            parsed_target_pid = _to_int(row["TargetPID"])
            if target_match and (parsed_target_pid is None or parsed_target_pid == proc.pid):
                row["TargetPID"] = int(target_match.group(1))
                row["TargetProcess"] = (
                    (target_match.group(2) or str(row["TargetProcess"] or "")).strip() or None
                )
        severity, risk, reasons = _grade_handle(
            proc.pid,
            str(row["Type"] or "unknown"),
            str(row["Name"] or ""),
            _to_int(row["TargetPID"]),
            str(row["TargetProcess"] or ""),
            row["Access"],
        )
        raw = {
            "plugin": "handles",
            "session_id": proc.session_id,
            **row,
            "risk": risk,
            "risk_reasons": reasons,
            "on_demand": True,
        }
        target = str(row["TargetProcess"] or row["Name"] or "unnamed")
        case_store.add_event(
            session,
            timestamp=None,
            host=None,
            source="memory:handles",
            category="handle",
            entity=proc.name,
            severity=severity,
            summary=(
                f"{proc.name} (pid {proc.pid}) handle {row['Type'] or 'unknown'} -> {target}"
                + (f" access {row['Access']}" if row["Access"] not in (None, "") else "")
            ),
            raw=raw,
        )


def _handle_events_for_process(session, proc):
    from app.store.database import Event
    from sqlalchemy import select

    # Narrow by the event entity first so opening a process drawer does not scan
    # every file handle in a handle-heavy case.
    return list(session.scalars(
        select(Event).where(
            Event.category == "handle",
            Event.source == "memory:handles",
            Event.entity == proc.name,
        )
    ))


def _process_handle_rows(
    proc,
    events,
    handle_type: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    wanted = (handle_type or "").lower()
    for event in events:
        raw = event.raw or {}
        if raw.get("session_id") != proc.session_id:
            continue
        if _to_int(raw.get("PID")) != proc.pid:
            continue
        kind = str(raw.get("Type") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
        if wanted and kind.lower() != wanted:
            continue
        row = {
            "event_id": event.id,
            "type": kind,
            "name": raw.get("Name"),
            "target_pid": raw.get("TargetPID"),
            "target_process": raw.get("TargetProcess"),
            "access": raw.get("Access"),
            "handle": raw.get("Handle"),
            "risk": raw.get("risk") or "none",
            "risk_reasons": raw.get("risk_reasons") or [],
            "summary": event.summary,
            "severity": event.severity,
        }
        rows.append(row)
    rows.sort(key=lambda r: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "info": 5}.get(str(r["risk"]), 6),
        str(r["type"]).lower(),
        str(r.get("name") or r.get("target_process") or ""),
    ))
    cross = [r for r in rows if str(r.get("risk") or "").lower() in {"critical", "high", "medium"}]
    return rows, counts, cross


def list_vfs(case_id: str, session_id: str, vfs_path: str) -> dict[str, Any]:
    dump = resolve_memory_dump(case_id, session_id)
    path = sanitize_vfs_path(vfs_path)
    with _open_vmm(dump.path) as vmm:
        entries = _vfs_list(vmm, path)
    rows = []
    for name, entry in sorted(entries.items(), key=lambda item: (not _entry_is_dir(item[1]), item[0].lower())):
        child_path = _join_vfs(path, name)
        rows.append({
            "name": name,
            "path": child_path,
            "is_dir": _entry_is_dir(entry),
            "size": _entry_size(entry) or 0,
        })
    return {"session_id": session_id, "path": path, "entries": rows}


def extract_vfs_file(case_id: str, session_id: str, vfs_path: str) -> Path:
    dump = resolve_memory_dump(case_id, session_id)
    source = sanitize_vfs_path(vfs_path)
    with _open_vmm(dump.path) as vmm:
        entry = _vfs_entry(vmm, source)
        if entry is None:
            raise MemoryExplorerError(f"VFS path not found: {source}", 404)
        if entry is not None and _entry_is_dir(entry):
            raise MemoryExplorerError("VFS path is a directory; use archive download for folders")
        output = _cache_path(case_id, dump.dump_stem, "vfs", f"{_safe_filename(_basename(source))}.extracted")
        info = _copy_vfs_file(vmm, source, output, entry)
    _record_manifest(case_id, dump.dump_stem, info)
    return output


def archive_vfs_selection(case_id: str, session_id: str, paths: list[str]) -> Path:
    if not paths:
        raise MemoryExplorerError("No VFS paths selected")
    dump = resolve_memory_dump(case_id, session_id)
    safe_paths = list(dict.fromkeys(sanitize_vfs_path(p) for p in paths))
    archive_name = f"memprocfs-selection-{int(time.time())}.zip"
    output = _cache_path(case_id, dump.dump_stem, "vfs", archive_name)
    manifest: list[dict[str, Any]] = []
    count = 0

    with _open_vmm(dump.path) as vmm, zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for source in safe_paths:
            for file_path, entry in _walk_vfs(vmm, source):
                if count >= MAX_ARCHIVE_FILES:
                    manifest.append({"source": file_path, "status": "skipped", "error": "archive file limit reached"})
                    break
                arcname = _archive_name(file_path)
                try:
                    size, digest = _write_vfs_to_zip(vmm, zf, file_path, entry, arcname)
                    manifest.append({
                        "source": file_path,
                        "archive_path": arcname,
                        "size": size,
                        "sha256": digest,
                        "status": "ok",
                    })
                    count += 1
                except Exception as exc:
                    manifest.append({"source": file_path, "archive_path": arcname, "status": "failed", "error": str(exc)})
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    _record_manifest(case_id, dump.dump_stem, {
        "kind": "vfs_archive",
        "source": safe_paths,
        "local_path": str(output),
        "filename": output.name,
        "size": output.stat().st_size,
        "sha256": _hash_file(output),
        "status": "ok",
    })
    return output


def list_process_modules(case_id: str, session_id: str, pid: int) -> dict[str, Any]:
    dump = resolve_memory_dump(case_id, session_id)
    with _open_vmm(dump.path) as vmm:
        proc = _process(vmm, pid)
        process_info = _process_info(proc, pid)
        modules = _modules_for_process(proc)
    return {"session_id": session_id, "pid": pid, "process": process_info, "modules": modules}


def extract_process_image(case_id: str, session_id: str, pid: int, kind: str = "image") -> Path:
    dump = resolve_memory_dump(case_id, session_id)
    if kind not in {"image", "minidump"}:
        raise MemoryExplorerError("Unsupported process download kind")
    with _open_vmm(dump.path) as vmm:
        proc = _process(vmm, pid)
        if kind == "minidump":
            source = f"/pid/{pid}/minidump/minidump.dmp"
            entry = _vfs_entry(vmm, source)
            if entry is None:
                # `/pid` and `/name` are aliases in MemProcFS. Prefer the stable
                # PID path, but tolerate builds/dumps that expose only `/name`.
                try:
                    name_entries = _vfs_list(vmm, "/name")
                except MemoryExplorerError:
                    name_entries = {}
                for directory, candidate in name_entries.items():
                    if not _entry_is_dir(candidate) or not directory.endswith(f"-{pid}"):
                        continue
                    candidate_source = f"/name/{directory}/minidump/minidump.dmp"
                    candidate_entry = _vfs_entry(vmm, candidate_source)
                    if candidate_entry is not None:
                        source, entry = candidate_source, candidate_entry
                        break
            if entry is None:
                raise MemoryExplorerError(
                    "A full process minidump is unavailable. MemProcFS only generates it "
                    "for supported active user-mode processes.",
                    404,
                )
            output = _cache_path(
                case_id,
                dump.dump_stem,
                "processes",
                f"{_safe_filename(_proc_name(proc, pid))}_{pid}.minidump.dmp",
            )
            info = {
                **_copy_vfs_file(vmm, source, output, entry),
                "kind": "process_minidump",
                "pid": pid,
                "process": _proc_name(proc, pid),
            }
        else:
            module = _main_module(proc)
            if not module:
                raise MemoryExplorerError("Could not identify the process image in memory", 404)
            output = _module_output_path(case_id, dump.dump_stem, proc, pid, module, process_image=True)
            info = _copy_process_range(proc, module["base"], module["size"], output, {
                "kind": "process_image",
                "pid": pid,
                "process": _proc_name(proc, pid),
                "module": module,
            })
    _record_manifest(case_id, dump.dump_stem, info)
    return output


def extract_process_module(case_id: str, session_id: str, pid: int, base: str | None = None, name: str | None = None) -> Path:
    dump = resolve_memory_dump(case_id, session_id)
    with _open_vmm(dump.path) as vmm:
        proc = _process(vmm, pid)
        module = _find_module(proc, base, name)
        if not module:
            raise MemoryExplorerError("Module not found in process memory", 404)
        output = _module_output_path(case_id, dump.dump_stem, proc, pid, module, process_image=False)
        info = _copy_process_range(proc, module["base"], module["size"], output, {
            "kind": "module",
            "pid": pid,
            "process": _proc_name(proc, pid),
            "module": module,
        })
    _record_manifest(case_id, dump.dump_stem, info)
    return output


def resolve_memory_dump(case_id: str, session_id: str) -> MemoryDumpRef:
    if not session_id.startswith("mem-"):
        raise MemoryExplorerError("Not a memory-backed session")
    dump_stem = session_id[4:]
    uploads = case_uploads_path(case_id)
    for path in uploads.iterdir():
        if path.is_file() and path.stem == dump_stem and _looks_like_memory_dump(path):
            return MemoryDumpRef(session_id, dump_stem, path.name, path, path.stat().st_size)
    raise MemoryExplorerError("Original memory dump is unavailable", 404)


def _looks_like_memory_dump(path: Path) -> bool:
    if path.suffix.lower() in MEMORY_EXTENSIONS:
        return True
    # Velociraptor/collector outputs may retain a dump as "PhysicalMemory"
    # without an extension; the session id is still mem-PhysicalMemory.
    return path.suffix == "" and path.name.lower() in {"physicalmemory", "memory", "ram"}


def sanitize_vfs_path(raw_path: str | None) -> str:
    path = (raw_path or "/").replace("\\", "/").strip()
    if not path:
        path = "/"
    if "\x00" in path or re.match(r"^[a-zA-Z]:", path):
        raise MemoryExplorerError("Unsafe VFS path")
    if not path.startswith("/"):
        path = "/" + path
    parts = [p for p in path.split("/") if p]
    if any(p in {".", ".."} for p in parts):
        raise MemoryExplorerError("Unsafe VFS path")
    return "/" + "/".join(parts) if parts else "/"


class _open_vmm:
    def __init__(self, dump_path: Path):
        self.dump_path = dump_path
        self.vmm = None

    def __enter__(self):
        if not is_memprocfs_available():
            raise MemoryExplorerError("MemProcFS is not installed", 503)
        import memprocfs

        _VMM_LOCK.acquire()
        try:
            self.vmm = memprocfs.Vmm(["-device", str(self.dump_path)])
            return self.vmm
        except Exception:
            _VMM_LOCK.release()
            raise

    def __exit__(self, _exc_type, _exc, _tb):
        try:
            if self.vmm is not None:
                self.vmm.close()
        finally:
            self.vmm = None
            _VMM_LOCK.release()


def _process(vmm, pid: int):
    try:
        return vmm.process(int(pid))
    except Exception as exc:
        raise MemoryExplorerError(f"Process {pid} is unavailable in this memory image", 404) from exc


def _process_info(proc, pid: int) -> dict[str, Any]:
    return {
        "pid": _attr(proc, "pid", pid),
        "ppid": _attr(proc, "ppid"),
        "name": _proc_name(proc, pid),
        "path": _attr(proc, "pathuser") or _attr(proc, "pathkernel"),
        "cmdline": _attr(proc, "cmdline"),
        "user": _attr(proc, "username") or _attr(proc, "user"),
        "sid": _attr(proc, "sid"),
        "session": _attr(proc, "session"),
        "integrity": _attr(proc, "integrity"),
        "created": str(_attr(proc, "time_create") or ""),
    }


def _modules_for_process(proc) -> list[dict[str, Any]]:
    modules: list[dict[str, Any]] = []
    seen: set[int] = set()
    try:
        raw_modules = proc.module_list() or []
    except Exception:
        raw_modules = []
    for mod in raw_modules:
        row = _module_row(mod, "loaded")
        if row["base"] is None or row["size"] <= 0:
            continue
        row["sha256"] = _hash_process_range(proc, row["base"], row["size"])
        modules.append(row)
        seen.add(int(row["base"]))

    try:
        vads = proc.maps.vad(True) or []
    except Exception:
        vads = []
    for vad in vads:
        path = str(_dict_get(vad, "file", "path", "name", default="") or "")
        if not path.lower().endswith((".dll", ".exe", ".sys")):
            continue
        start = _to_int(_dict_get(vad, "start", "va"))
        end = _to_int(_dict_get(vad, "end"))
        size = _to_int(_dict_get(vad, "size"))
        if start is None or start in seen:
            continue
        if size is None and end is not None:
            size = max(0, end - start + 1)
        if not size:
            continue
        row = {
            "name": _basename(path),
            "path": path,
            "base": start,
            "base_hex": hex(start),
            "size": size,
            "status": "mapped-image",
            "sha256": _hash_process_range(proc, start, size),
        }
        modules.append(row)
        seen.add(start)
    modules.sort(key=lambda m: int(m.get("base") or 0))
    return modules


def _module_row(module, status: str) -> dict[str, Any]:
    name = _attr(module, "name") or _basename(str(_attr(module, "fullname", "")))
    path = _attr(module, "fullname") or name
    base = _to_int(_attr(module, "base"))
    size = _to_int(_attr(module, "image_size") or _attr(module, "file_size") or _attr(module, "size")) or 0
    return {
        "name": name or "module",
        "path": path,
        "base": base,
        "base_hex": hex(base) if base is not None else None,
        "size": size,
        "status": status,
        "sha256": None,
    }


def _main_module(proc) -> dict[str, Any] | None:
    modules = _modules_for_process(proc)
    proc_name = _basename(_proc_name(proc, 0)).lower()
    proc_path = _basename(_attr(proc, "pathuser") or _attr(proc, "pathkernel") or "").lower()
    for mod in modules:
        base = _basename(mod.get("path") or mod.get("name") or "").lower()
        if base and base in {proc_name, proc_path}:
            return mod
    for mod in modules:
        if str(mod.get("name") or "").lower().endswith(".exe"):
            return mod
    return modules[0] if modules else None


def _find_module(proc, base: str | None, name: str | None) -> dict[str, Any] | None:
    wanted_base = _to_int(base)
    wanted_name = _basename(name or "").lower()
    for mod in _modules_for_process(proc):
        if wanted_base is not None and _to_int(mod.get("base")) == wanted_base:
            return mod
        if wanted_name and _basename(str(mod.get("name") or mod.get("path") or "")).lower() == wanted_name:
            return mod
    return None


def _copy_process_range(proc, base: int, size: int, output: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    copied = 0
    try:
        with open(output, "wb") as dst:
            while copied < size:
                length = min(VFS_CHUNK_SIZE, size - copied)
                data = proc.memory.read(base + copied, length)
                if not data:
                    break
                if isinstance(data, str):
                    data = data.encode("utf-8", errors="replace")
                dst.write(data)
                hasher.update(data)
                copied += len(data)
                if len(data) < length:
                    break
        return {
            **metadata,
            "local_path": str(output),
            "filename": output.name,
            "size": copied,
            "sha256": hasher.hexdigest(),
            "status": "ok",
        }
    except Exception as exc:
        try:
            output.unlink(missing_ok=True)
        except OSError:
            logger.warning(
                "Could not remove partial memory-range extraction %s",
                _sanitize_for_log(output),
                exc_info=True,
            )
        raise MemoryExplorerError(f"Could not extract memory range: {exc}", 500) from exc


def _copy_vfs_file(vmm, source: str, output: Path, entry: Any | None) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    copied = 0
    size_hint = _entry_size(entry)
    try:
        with open(output, "wb") as dst:
            while size_hint is None or copied < size_hint:
                length = VFS_CHUNK_SIZE if size_hint is None else min(VFS_CHUNK_SIZE, size_hint - copied)
                if length <= 0:
                    break
                data = vmm.vfs.read(source, length, copied)
                if not data:
                    break
                if isinstance(data, str):
                    data = data.encode("utf-8", errors="replace")
                dst.write(data)
                hasher.update(data)
                copied += len(data)
                if size_hint is None and len(data) < length:
                    break
    except Exception as exc:
        try:
            output.unlink(missing_ok=True)
        except OSError:
            logger.warning(
                "Could not remove partial VFS extraction %s",
                _sanitize_for_log(output),
                exc_info=True,
            )
        raise MemoryExplorerError(f"Could not extract VFS file {source}: {exc}", 500) from exc
    return {
        "kind": "vfs_file",
        "source": source,
        "local_path": str(output),
        "filename": output.name,
        "size": copied,
        "sha256": hasher.hexdigest(),
        "status": "ok",
    }


def _write_vfs_to_zip(vmm, zf: zipfile.ZipFile, source: str, entry: Any | None, arcname: str) -> tuple[int, str]:
    hasher = hashlib.sha256()
    copied = 0
    size_hint = _entry_size(entry)
    with zf.open(arcname, "w") as dst:
        while size_hint is None or copied < size_hint:
            length = VFS_CHUNK_SIZE if size_hint is None else min(VFS_CHUNK_SIZE, size_hint - copied)
            if length <= 0:
                break
            data = vmm.vfs.read(source, length, copied)
            if not data:
                break
            if isinstance(data, str):
                data = data.encode("utf-8", errors="replace")
            dst.write(data)
            hasher.update(data)
            copied += len(data)
            if size_hint is None and len(data) < length:
                break
    return copied, hasher.hexdigest()


def _hash_process_range(proc, base: int, size: int) -> str | None:
    if size <= 0 or size > MAX_MODULE_HASH_BYTES:
        return None
    hasher = hashlib.sha256()
    copied = 0
    try:
        while copied < size:
            length = min(VFS_CHUNK_SIZE, size - copied)
            data = proc.memory.read(base + copied, length)
            if not data:
                break
            if isinstance(data, str):
                data = data.encode("utf-8", errors="replace")
            hasher.update(data)
            copied += len(data)
            if len(data) < length:
                break
        return hasher.hexdigest() if copied else None
    except Exception:
        return None


def _walk_vfs(vmm, source: str, depth: int = 0):
    if depth > MAX_ARCHIVE_DEPTH:
        return
    entry = _vfs_entry(vmm, source)
    if entry is not None and not _entry_is_dir(entry):
        yield source, entry
        return
    if entry is None and source != "/":
        yield source, None
        return
    for name, child in _vfs_list(vmm, source).items():
        child_path = _join_vfs(source, name)
        if _entry_is_dir(child):
            yield from _walk_vfs(vmm, child_path, depth + 1)
        else:
            yield child_path, child


def _vfs_list(vmm, path: str) -> dict[str, Any]:
    try:
        entries = vmm.vfs.list(path) or {}
    except Exception as exc:
        raise MemoryExplorerError(f"Could not list MemProcFS path {path}: {exc}", 404) from exc
    if isinstance(entries, dict):
        return {str(name): entry for name, entry in entries.items()}
    out: dict[str, Any] = {}
    for entry in entries:
        name = _entry_name(entry)
        if name:
            out[name] = entry
    return out


def _vfs_entry(vmm, path: str) -> Any | None:
    if path == "/":
        return {"name": "/", "f_isdir": True, "size": 0}
    parent = "/" + "/".join(path.strip("/").split("/")[:-1])
    if parent == "/":
        parent = "/"
    name = path.rstrip("/").split("/")[-1]
    return _vfs_list(vmm, parent).get(name)


def _record_manifest(case_id: str, dump_stem: str, entry: dict[str, Any]) -> None:
    manifest_path = memprocfs_artifact_dir(case_id, dump_stem) / "extracted" / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {"artifacts": []}
    except json.JSONDecodeError:
        manifest = {"artifacts": []}
    entry = {**entry, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    manifest.setdefault("artifacts", []).append(entry)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _cache_path(case_id: str, dump_stem: str, group: str, filename: str) -> Path:
    artifact_root = memprocfs_artifact_dir(case_id, dump_stem).resolve()
    artifact_root_real = os.path.realpath(artifact_root)
    root = (artifact_root / "extracted" / _safe_filename(group)).resolve()
    if not os.path.realpath(root).startswith(artifact_root_real + os.sep):
        raise MemoryExplorerError("Unsafe extraction directory", 500)
    root.mkdir(parents=True, exist_ok=True)
    root_real = os.path.realpath(root)
    output = (root / _safe_filename(filename)).resolve()
    if not os.path.realpath(output).startswith(root_real + os.sep):
        raise MemoryExplorerError("Unsafe extraction filename", 500)
    return output


def _module_output_path(case_id: str, dump_stem: str, proc, pid: int, module: dict[str, Any], process_image: bool) -> Path:
    name = _safe_filename(_basename(str(module.get("name") or module.get("path") or "module")))
    suffix = Path(name).suffix or (".exe" if process_image else ".bin")
    stem = Path(name).stem or ("process" if process_image else "module")
    base = module.get("base_hex") or hex(int(module.get("base") or 0))
    proc_name = _safe_filename(_basename(_proc_name(proc, pid)))
    if process_image:
        filename = f"{proc_name}_{pid}{suffix}.extracted"
        return _cache_path(case_id, dump_stem, "processes", filename)
    filename = f"{stem}_{base.replace('0x', '')}{suffix}.extracted"
    return _cache_path(case_id, dump_stem, f"modules/{proc_name}_{pid}", filename)


def _hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(VFS_CHUNK_SIZE), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _join_vfs(parent: str, name: str) -> str:
    return sanitize_vfs_path(f"{parent.rstrip('/')}/{name}")


def _archive_name(path: str) -> str:
    return "/".join(_safe_filename(p) for p in path.strip("/").split("/") if p) or "root"


def _entry_is_dir(entry: Any) -> bool:
    if isinstance(entry, dict):
        return bool(_dict_get(entry, "f_isdir", "is_dir", "IsDir", default=False))
    for attr in ("f_isdir", "is_dir", "IsDir"):
        if hasattr(entry, attr):
            return bool(getattr(entry, attr))
    return False


def _memory_result_matches_process(result, proc) -> bool:
    data = result.data if isinstance(result.data, dict) else {}
    source = str(data.get("source") or "")
    result_session = str(data.get("session_id") or "")
    if result_session and result_session != proc.session_id:
        return False
    if source.startswith("mem-") and not source.startswith(f"{proc.session_id}:"):
        return False
    if result.process_name and _basename(result.process_name).lower() != _basename(proc.name).lower():
        return False
    return True


def _attr(obj, name: str, default=None):
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


def _to_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _proc_name(proc, pid: int) -> str:
    return str(_attr(proc, "fullname") or _attr(proc, "name") or f"pid-{pid}")


def _basename(path: str) -> str:
    text = str(path or "").replace("\\", "/").rstrip("/")
    return text.rsplit("/", 1)[-1] if text else ""


def _sanitize_for_log(value: Any) -> str:
    return (
        str(value)
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(name or "").strip())
    cleaned = cleaned.strip("._")
    return cleaned[:180] or "artifact"
