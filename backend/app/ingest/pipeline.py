"""Ingestion pipeline: processes uploaded files into normalized events + processes."""

from __future__ import annotations

import asyncio
import os
import traceback
from pathlib import Path
from typing import Any, Callable

from app.ingest.normalize import parse_timestamp
from app.ingest.parsers import PARSABLE_EXTENSIONS, _basename, iter_zip_members, parse_file
from app.store import cases as case_store
from app.store.database import Process

MEMORY_EXTENSIONS = {".raw", ".dmp", ".mem", ".vmem", ".bin", ".img", ".lime", ".dd"}
DEFAULT_INGEST_BATCH_SIZE = 10000
MIN_INGEST_BATCH_SIZE = 1000
MAX_INGEST_BATCH_SIZE = 50000

ProgressCallback = Callable[[str, float, str, bool, str | None], Any]


def _ingest_batch_size() -> int:
    raw = os.environ.get("INVESTIGATOR_INGEST_BATCH_SIZE", "").strip()
    if not raw:
        return DEFAULT_INGEST_BATCH_SIZE
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_INGEST_BATCH_SIZE
    return max(MIN_INGEST_BATCH_SIZE, min(MAX_INGEST_BATCH_SIZE, value))


def _is_process_source(source: str) -> bool:
    lower = source.lower()
    return any(x in lower for x in ("pslist", "processes", "pstree", "process_list"))


def _extract_process(row_raw: dict[str, Any]) -> dict[str, Any] | None:
    """Pull process fields out of a raw pslist-style row."""
    pid = row_raw.get("Pid") or row_raw.get("pid") or row_raw.get("PID") or row_raw.get("ProcessId")
    if pid is None:
        return None
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    ppid = row_raw.get("Ppid") or row_raw.get("ppid") or row_raw.get("PPID") or row_raw.get("ParentProcessId")
    try:
        ppid = int(ppid) if ppid is not None else None
    except (TypeError, ValueError):
        ppid = None
    name = str(row_raw.get("Name") or row_raw.get("name") or row_raw.get("ImageFileName") or f"pid-{pid}")
    return {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "path": row_raw.get("Exe") or row_raw.get("ImagePath") or row_raw.get("Path"),
        "cmdline": row_raw.get("CommandLine") or row_raw.get("Cmdline") or row_raw.get("cmdline"),
        "start_time": parse_timestamp(
            row_raw.get("CreateTime") or row_raw.get("StartTime") or row_raw.get("create_time")
        ),
        "session_id": "live",
        "extra": {},
    }


def _to_int(value: Any) -> int | None:
    """Parse decimal (Sysmon) or 0x-hex (Security 4688) numeric fields."""
    if value is None:
        return None
    try:
        s = str(value).strip()
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except (TypeError, ValueError):
        return None


def _evtx_process_creation(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Pull process fields out of a Sysmon EID-1 / Security 4688 event's raw data."""
    eid = str(raw.get("EventID") or "")
    channel = str(raw.get("Channel") or "")
    provider = str(raw.get("Provider") or "")
    if eid == "1" and ("sysmon" in channel.lower() or "sysmon" in provider.lower()):
        image = str(raw.get("Image") or "").strip()
        pid = _to_int(raw.get("ProcessId"))
        if pid is None or not image:
            return None
        return {
            "pid": pid,
            "ppid": _to_int(raw.get("ParentProcessId")),
            "name": _basename(image) or f"pid-{pid}",
            "path": image,
            "cmdline": raw.get("CommandLine"),
            "user": raw.get("User"),
            "parent_image": raw.get("ParentImage"),
            "parent_cmdline": raw.get("ParentCommandLine"),
            "origin": "sysmon-1",
        }
    if eid == "4688" and (
        channel == "Security" or provider == "Microsoft-Windows-Security-Auditing"
    ):
        image = str(raw.get("NewProcessName") or "").strip()
        pid = _to_int(raw.get("NewProcessId"))
        if pid is None or not image:
            return None
        return {
            "pid": pid,
            "ppid": _to_int(raw.get("ProcessId")),
            "name": _basename(image) or f"pid-{pid}",
            "path": image,
            "cmdline": raw.get("CommandLine"),
            "user": raw.get("SubjectUserName") or raw.get("TargetUserName"),
            "parent_image": raw.get("ParentProcessName"),
            "parent_cmdline": None,
            "origin": "security-4688",
        }
    return None


def ingest_file_sync(case_id: str, file_path: Path, progress: ProgressCallback) -> dict[str, int]:
    """Synchronous ingestion of one uploaded file. Returns counts."""
    session = case_store.get_session(case_id)
    stats = {"events": 0, "processes": 0, "files": 0}
    seen_pids: set[tuple[str, int]] = set()
    # EVTX process creations: dedupe on pid+start_time+name (PIDs get reused in a
    # long log); known_pids tracks which pids already have any row so parent stubs
    # are only synthesized for genuinely unseen parents.
    seen_evtx_procs: set[tuple[str, int, str | None, str]] = set()
    known_pids: set[tuple[str, int]] = set()

    def handle_evtx_process(event_kwargs: dict[str, Any], source: str) -> None:
        info = _evtx_process_creation(event_kwargs.get("raw") or {})
        if not info:
            return
        sid = f"evtx-{event_kwargs.get('host') or Path(source).stem}"
        start = event_kwargs.get("timestamp")
        key = (sid, info["pid"], start.isoformat() if start else None, info["name"].lower())
        if key in seen_evtx_procs:
            return
        seen_evtx_procs.add(key)
        known_pids.add((sid, info["pid"]))
        session.add(Process(
            pid=info["pid"],
            ppid=info["ppid"],
            name=info["name"],
            path=info["path"],
            cmdline=info["cmdline"],
            start_time=start,
            session_id=sid,
            extra={"source": info["origin"], "user": info["user"]},
        ))
        stats["processes"] += 1
        # Synthesize a stub for the parent when its own creation event predates the
        # log, so parent/child detection rules can still link the chain.
        if info["ppid"] is not None and info["parent_image"] and (sid, info["ppid"]) not in known_pids:
            known_pids.add((sid, info["ppid"]))
            session.add(Process(
                pid=info["ppid"],
                ppid=None,
                name=_basename(info["parent_image"]) or f"pid-{info['ppid']}",
                path=info["parent_image"],
                cmdline=info["parent_cmdline"],
                start_time=None,
                session_id=sid,
                extra={"synthesized_from": "parent-fields"},
            ))
            stats["processes"] += 1

    def handle_parsed_file(path: Path, source: str) -> None:
        batch = 0
        batch_size = _ingest_batch_size()
        pending_events: list[dict[str, Any]] = []

        def flush_batch() -> None:
            if not pending_events:
                return
            case_store.add_events_bulk(session, pending_events)
            pending_events.clear()
            session.commit()
            session.expunge_all()
            progress("parsing", -1, f"{stats['events']} events from {source}", False, None)

        for event_kwargs in parse_file(path, source):
            pending_events.append(event_kwargs)
            stats["events"] += 1
            batch += 1
            if _is_process_source(source):
                proc = _extract_process(event_kwargs["raw"])
                if proc and (proc["session_id"], proc["pid"]) not in seen_pids:
                    seen_pids.add((proc["session_id"], proc["pid"]))
                    session.add(Process(**proc))
                    stats["processes"] += 1
            else:
                # Sysmon-1 / Security-4688 rows appear in .evtx files and in
                # Velociraptor JSON exports alike; _evtx_process_creation is a
                # cheap no-op for anything else.
                handle_evtx_process(event_kwargs, source)
            if batch % batch_size == 0:
                flush_batch()
        flush_batch()

    try:
        suffix = file_path.suffix.lower()
        if suffix == ".zip":
            extract_dir = file_path.parent / f"{file_path.stem}_extracted"
            extract_dir.mkdir(exist_ok=True)
            members = list(iter_zip_members(file_path, extract_dir))
            total = max(len(members), 1)
            for idx, (member_path, source) in enumerate(members):
                progress("parsing", idx / total * 100, f"Parsing {source}", False, None)
                handle_parsed_file(member_path, source)
                stats["files"] += 1
        elif suffix in PARSABLE_EXTENSIONS:
            progress("parsing", 10.0, f"Parsing {file_path.name}", False, None)
            # use full filename as source so same-stem files (test.evtx / test.txt)
            # stay separately attributable and deletable
            handle_parsed_file(file_path, file_path.name)
            stats["files"] = 1
        else:
            progress("skipped", 100.0, f"Unsupported file type: {suffix}", False, None)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    return stats


class IngestionManager:
    """Tracks running ingestion jobs and broadcasts progress over WebSocket."""

    def __init__(self):
        self.jobs: dict[str, dict[str, Any]] = {}
        self.listeners: dict[str, list[asyncio.Queue]] = {}

    def subscribe(self, case_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self.listeners.setdefault(case_id, []).append(queue)
        return queue

    def unsubscribe(self, case_id: str, queue: asyncio.Queue) -> None:
        if case_id in self.listeners and queue in self.listeners[case_id]:
            self.listeners[case_id].remove(queue)

    def _broadcast(self, case_id: str, payload: dict[str, Any]) -> None:
        self.jobs[case_id] = payload
        for queue in self.listeners.get(case_id, []):
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    def get_status(self, case_id: str) -> dict[str, Any] | None:
        return self.jobs.get(case_id)

    async def run_ingestion(
        self,
        case_id: str,
        file_path: Path,
        file_type: str,
        memory_options: dict[str, Any] | None = None,
    ) -> None:
        loop = asyncio.get_running_loop()

        def progress(phase: str, percent: float, message: str, done: bool, error: str | None) -> None:
            payload = {
                "case_id": case_id,
                "phase": phase,
                "percent": percent,
                "message": message,
                "done": done,
                "error": error,
            }
            loop.call_soon_threadsafe(self._broadcast, case_id, payload)

        case_store.update_case_meta(case_id, include_stats=False, status="ingesting")
        try:
            if file_type == "memory" or file_path.suffix.lower() in MEMORY_EXTENSIONS:
                case_store.update_case_meta(case_id, include_stats=False, has_memory_dump=True)
                from app.memory.pipeline import analyze_memory_dump_sync
                await loop.run_in_executor(
                    None, analyze_memory_dump_sync, case_id, file_path, progress, memory_options or {}
                )
            else:
                stats = await loop.run_in_executor(
                    None, ingest_file_sync, case_id, file_path, progress
                )
                progress(
                    "detection", 90.0,
                    f"Ingested {stats['events']} events; running detections", False, None,
                )
                from app.detect.engine import run_detections_sync
                await loop.run_in_executor(None, run_detections_sync, case_id)

            case_store.update_case_meta(case_id, include_stats=False, status="ready")
            progress("done", 100.0, "Ingestion complete", True, None)
        except Exception as e:
            traceback.print_exc()
            case_store.update_case_meta(case_id, include_stats=False, status="error")
            progress("error", 100.0, f"Ingestion failed: {e}", True, str(e))


manager = IngestionManager()
