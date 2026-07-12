"""Ingest copied MemProcFS forensic artifacts into normalized case data."""

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import select

from app.config import get_cases_dir
from app.ingest.normalize import (
    extract_entity,
    extract_host,
    extract_timestamp,
    parse_timestamp,
    summarize_row,
    truncate,
)
from app.ingest.parsers import _basename, parse_file
from app.store import cases as case_store
from app.store.database import MemoryResult, Process


ProgressCallback = Callable[[str, float, str, bool, str | None], Any]
BATCH_SIZE = 2000


def memprocfs_artifact_dir(case_id: str, dump_stem: str) -> Path:
    return get_cases_dir() / case_id / "derived" / "memprocfs" / _safe_dir_name(dump_stem)


def reset_memprocfs_artifact_dir(case_id: str, dump_stem: str) -> Path:
    path = memprocfs_artifact_dir(case_id, dump_stem)
    if path.exists():
        shutil.rmtree(path, ignore_errors=False)
    path.mkdir(parents=True, exist_ok=True)
    return path


def remove_memprocfs_artifacts(case_id: str, dump_stem: str) -> None:
    path = memprocfs_artifact_dir(case_id, dump_stem)
    if path.exists():
        shutil.rmtree(path, ignore_errors=False)


def ingest_memprocfs_artifacts_sync(
    session,
    dump_stem: str,
    artifact_dir: Path,
    extraction_manifest: dict[str, Any] | None,
    progress: ProgressCallback,
) -> dict[str, int]:
    """Parse copied MemProcFS forensic CSV and EVTX artifacts after VMM close."""
    stats = {"events": 0, "memory_results": 0, "processes": 0, "files": 0}
    artifact_dir = Path(artifact_dir)
    if not artifact_dir.exists():
        return stats

    manifest = _load_manifest(artifact_dir, extraction_manifest)
    parse_status: dict[str, dict[str, Any]] = {}

    csv_files = _selected_csv_files(artifact_dir / "forensic" / "csv")
    evtx_files = sorted((artifact_dir / "eventlog").glob("*.evtx"))
    total_files = max(len(csv_files) + len(evtx_files), 1)
    file_index = 0

    known_pids = {
        int(pid) for pid in session.scalars(
            select(Process.pid).where(Process.session_id == f"mem-{dump_stem}")
        )
        if pid is not None
    }

    for path in csv_files:
        file_index += 1
        source = _artifact_source(dump_stem, "forensic/csv", path.name)
        progress("memory", 56.0 + file_index / total_files * 10.0, f"Parsing {path.name}", False, None)
        try:
            file_stats = _ingest_csv(session, path, source, dump_stem, known_pids)
            _merge_stats(stats, file_stats)
            parse_status[str(path)] = {"status": "ok", **file_stats}
        except Exception as exc:
            session.rollback()
            result = _add_diagnostic(
                session,
                "memprocfs_forensics",
                f"MemProcFS artifact parse failed for {path.name}: {exc}",
                {"path": str(path), "source": source},
                "low",
            )
            session.commit()
            stats["memory_results"] += 1
            parse_status[str(path)] = {"status": "failed", "error": str(exc), "memory_result_id": result.id}

    for path in evtx_files:
        file_index += 1
        source = _artifact_source(dump_stem, "eventlog", path.name)
        progress("memory", 56.0 + file_index / total_files * 10.0, f"Parsing event log {path.name}", False, None)
        file_stats = _ingest_evtx(session, path, source)
        _merge_stats(stats, file_stats)
        status: dict[str, Any] = {"status": "ok", **file_stats}
        if path.stat().st_size > 0 and file_stats["events"] == 0:
            result = _add_diagnostic(
                session,
                "memprocfs_eventlog",
                f"No events could be parsed from MemProcFS-extracted event log {path.name}. "
                "Memory-resident event logs can be partial or corrupt.",
                {"path": str(path), "source": source, "size": path.stat().st_size},
                "low",
            )
            session.commit()
            stats["memory_results"] += 1
            status["memory_result_id"] = result.id
        parse_status[str(path)] = status

    _update_manifest_parse_status(artifact_dir, manifest, parse_status)
    if not csv_files and not evtx_files:
        _add_diagnostic(
            session,
            "memprocfs_forensics",
            "MemProcFS forensic mode did not produce CSV or event-log artifacts to ingest.",
            {"manifest": manifest},
            "low",
        )
        session.commit()
        stats["memory_results"] += 1
    return stats


def _ingest_csv(session, path: Path, source: str, dump_stem: str, known_pids: set[int]) -> dict[str, int]:
    stats = {"events": 0, "memory_results": 0, "processes": 0, "files": 1}
    pending: list[dict[str, Any]] = []
    csv_name = path.name.lower()
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row:
                continue
            raw = _json_safe({str(k): v for k, v in row.items() if k is not None})
            event = _normalize_memprocfs_csv_event(raw, source, csv_name)
            pending.append(event)
            stats["events"] += 1

            if csv_name in ("process.csv", "timeline_process.csv"):
                if _upsert_process(session, raw, dump_stem, known_pids):
                    stats["processes"] += 1
            if csv_name in ("findevil.csv", "yara.csv"):
                _add_artifact_memory_result(session, csv_name, raw, source)
                stats["memory_results"] += 1

            if len(pending) >= BATCH_SIZE:
                case_store.add_events_bulk(session, pending)
                pending.clear()
                session.commit()
    if pending:
        case_store.add_events_bulk(session, pending)
    session.commit()
    return stats


def _ingest_evtx(session, path: Path, source: str) -> dict[str, int]:
    stats = {"events": 0, "memory_results": 0, "processes": 0, "files": 1}
    pending: list[dict[str, Any]] = []
    seen_evtx_procs: set[tuple[str, int, str | None, str]] = set()
    known_pids: set[tuple[str, int]] = set()
    for event in parse_file(path, source):
        pending.append(event)
        stats["events"] += 1
        proc = _evtx_process_creation(event)
        if proc:
            key = (
                proc["session_id"],
                proc["pid"],
                proc["start_time"].isoformat() if proc["start_time"] else None,
                proc["name"].lower(),
            )
            if key not in seen_evtx_procs:
                seen_evtx_procs.add(key)
                known_pids.add((proc["session_id"], proc["pid"]))
                session.add(Process(**proc))
                stats["processes"] += 1
        if len(pending) >= BATCH_SIZE:
            case_store.add_events_bulk(session, pending)
            pending.clear()
            session.commit()
    if pending:
        case_store.add_events_bulk(session, pending)
    session.commit()
    return stats


def _selected_csv_files(csv_dir: Path) -> list[Path]:
    if not csv_dir.is_dir():
        return []
    csvs = {p.name.lower(): p for p in csv_dir.glob("*.csv")}
    selected: list[Path] = []
    if "timeline_all.csv" in csvs:
        selected.append(csvs["timeline_all.csv"])
    else:
        selected.extend(path for name, path in sorted(csvs.items()) if name.startswith("timeline_"))
    selected.extend(path for name, path in sorted(csvs.items()) if not name.startswith("timeline_"))
    return selected


def _normalize_memprocfs_csv_event(row: dict[str, Any], source: str, csv_name: str) -> dict[str, Any]:
    category = _csv_category(csv_name, row)
    entity = _csv_entity(csv_name, row) or extract_entity(row)
    severity = _csv_severity(csv_name, row)
    return {
        "timestamp": extract_timestamp(row),
        "host": extract_host(row),
        "source": source,
        "category": category,
        "entity": entity,
        "severity": severity,
        "summary": _csv_summary(csv_name, row),
        "raw": {**row, "memprocfs_csv": csv_name},
    }


def _csv_category(csv_name: str, row: dict[str, Any]) -> str:
    name = csv_name.lower()
    row_kind = str(_row_get(row, "Type", "Action", "EventType", "Category", default="")).lower()
    if row_kind in {"reg", "registry", "shtask", "task"}:
        return "persistence"
    if any(token in row_kind for token in ("net", "dns", "tcp", "udp", "socket")):
        return "network"
    if any(token in row_kind for token in ("service", "task", "registry", "autorun", "runkey")):
        return "persistence"
    if any(token in row_kind for token in ("process", "thread", "module", "dll")):
        return "process"
    if any(token in row_kind for token in ("file", "ntfs", "mft", "usn")):
        return "filesystem"
    if "web" in row_kind or "browser" in row_kind:
        return "browser"
    if "net" in name or _has_any(row, "ip", "port", "protocol"):
        return "network"
    if "service" in name or "task" in name:
        return "persistence"
    if "registry" in name:
        return "persistence"
    if "file" in name or "ntfs" in name:
        return "filesystem"
    if "web" in name:
        return "browser"
    if "findevil" in name or "yara" in name:
        return "memory"
    if "driver" in name:
        return "driver"
    if "process" in name or "thread" in name or "module" in name:
        return "process"
    return "artifact"


def _csv_entity(csv_name: str, row: dict[str, Any]) -> str | None:
    for key in (
        "Text",
        "Process", "ProcessName", "Name", "ImageFileName", "Path", "FullPath",
        "FileName", "ServiceName", "TaskName", "Driver", "Module", "RemoteAddress",
        "dst-ip", "raddr", "QueryName", "KeyPath",
    ):
        value = _row_get(row, key)
        if value:
            return truncate(str(value), 500)
    return None


def _csv_severity(csv_name: str, row: dict[str, Any]) -> str:
    value = str(_row_get(row, "Severity", "Risk", "Level") or "").strip().lower()
    if value in {"critical", "high", "medium", "low", "info"}:
        return value
    if csv_name.lower() == "findevil.csv":
        return "high"
    if csv_name.lower() == "yara.csv":
        return "high"
    return "info"


def _csv_summary(csv_name: str, row: dict[str, Any]) -> str:
    stem = Path(csv_name).stem
    detail = summarize_row(row)
    if stem.startswith("timeline"):
        event_type = _row_get(row, "Type", "Action", "Event", "EventType", default="timeline")
        return f"MemProcFS {event_type}: {detail}"
    if csv_name.lower() == "findevil.csv":
        return f"MemProcFS findevil: {detail}"
    if csv_name.lower() == "yara.csv":
        return f"MemProcFS YARA: {detail}"
    return f"MemProcFS {stem}: {detail}"


def _upsert_process(session, row: dict[str, Any], dump_stem: str, known_pids: set[int]) -> bool:
    pid = _to_int(_row_get(row, "PID", "Pid", "pid"))
    if pid is None:
        return False
    session_id = f"mem-{dump_stem}"
    ppid = _to_int(_row_get(row, "PPID", "Ppid", "ParentPid", "ParentProcessId"))
    name = str(_row_get(row, "ShortName", "Name", "Process", "ImageFileName", "ProcessName", default=f"pid-{pid}"))
    path = _row_get(row, "UserPath", "Path", "FullPath", "ImagePath", "Exe", "KernelPath")
    cmdline = _row_get(row, "CommandLine", "Cmdline", "CmdLine", "Args")
    start_time = parse_timestamp(_row_get(row, "CreateTime", "TimeCreate", "StartTime", "Created"))
    existing = session.scalars(
        select(Process).where(Process.session_id == session_id, Process.pid == pid)
    ).first()
    if existing:
        if not existing.path and path:
            existing.path = str(path)
        if not existing.cmdline and cmdline:
            existing.cmdline = str(cmdline)
        if existing.start_time is None and start_time:
            existing.start_time = start_time
        extra = dict(existing.extra or {})
        extra.setdefault("memprocfs_forensic_csv", True)
        existing.extra = extra
        return False
    if pid in known_pids:
        return False
    known_pids.add(pid)
    session.add(Process(
        pid=pid,
        ppid=ppid,
        name=name,
        path=str(path) if path else None,
        cmdline=str(cmdline) if cmdline else None,
        start_time=start_time,
        session_id=session_id,
        flags=[],
        severity="info",
        extra={"source": "memprocfs.forensic.process"},
    ))
    return True


def _add_artifact_memory_result(session, csv_name: str, row: dict[str, Any], source: str) -> None:
    pid = _to_int(_row_get(row, "PID", "Pid", "pid"))
    proc_name = _row_get(row, "Process", "ProcessName", "Name", "ImageFileName")
    severity = _csv_severity(csv_name, row)
    session.add(MemoryResult(
        plugin=f"memprocfs_{Path(csv_name).stem}",
        pid=pid,
        process_name=str(proc_name) if proc_name else None,
        summary=_csv_summary(csv_name, row),
        data={"source": source, "row": row},
        severity=severity,
    ))


def _add_diagnostic(session, plugin: str, summary: str, data: dict[str, Any], severity: str) -> MemoryResult:
    result = MemoryResult(plugin=plugin, pid=None, process_name=None, summary=summary, data=data, severity=severity)
    session.add(result)
    return result


def _evtx_process_creation(event: dict[str, Any]) -> dict[str, Any] | None:
    raw = event.get("raw") or {}
    eid = str(raw.get("EventID") or "")
    channel = str(raw.get("Channel") or "")
    provider = str(raw.get("Provider") or "")
    image = ""
    pid = None
    ppid = None
    cmdline = raw.get("CommandLine")
    origin = ""
    if eid == "1" and ("sysmon" in channel.lower() or "sysmon" in provider.lower()):
        image = str(raw.get("Image") or "").strip()
        pid = _to_int(raw.get("ProcessId"))
        ppid = _to_int(raw.get("ParentProcessId"))
        origin = "memprocfs-sysmon-1"
    elif eid == "4688" and (
        channel == "Security" or provider == "Microsoft-Windows-Security-Auditing"
    ):
        image = str(raw.get("NewProcessName") or "").strip()
        pid = _to_int(raw.get("NewProcessId"))
        ppid = _to_int(raw.get("ProcessId"))
        origin = "memprocfs-security-4688"
    if pid is None or not image:
        return None
    host = event.get("host") or "memory"
    return {
        "pid": pid,
        "ppid": ppid,
        "name": _basename(image) or f"pid-{pid}",
        "path": image,
        "cmdline": cmdline,
        "start_time": event.get("timestamp"),
        "session_id": f"evtx-{host}",
        "extra": {"source": origin, "memprocfs_eventlog": True},
    }


def _artifact_source(dump_stem: str, kind: str, name: str) -> str:
    return f"mem-{dump_stem}:{kind}/{name}"


def _row_get(row: dict[str, Any], *keys: str, default=None):
    lowered = {str(k).lower(): v for k, v in row.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if value not in (None, ""):
            return value
    return default


def _has_any(row: dict[str, Any], *needles: str) -> bool:
    keys = " ".join(str(k).lower() for k in row)
    return any(needle in keys for needle in needles)


def _to_int(value) -> int | None:
    try:
        text_value = str(value).strip()
        return int(text_value, 16) if text_value.lower().startswith("0x") else int(text_value)
    except (TypeError, ValueError):
        return None


def _json_safe(obj: Any) -> Any:
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return json.loads(json.dumps(obj, default=str))


def _load_manifest(artifact_dir: Path, fallback: dict[str, Any] | None) -> dict[str, Any]:
    manifest_path = artifact_dir / "manifest.json"
    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return fallback or {"artifacts": []}
    return fallback or {"artifacts": []}


def _update_manifest_parse_status(
    artifact_dir: Path,
    manifest: dict[str, Any],
    parse_status: dict[str, dict[str, Any]],
) -> None:
    for artifact in manifest.get("artifacts", []):
        local_path = artifact.get("local_path")
        if local_path in parse_status:
            artifact.update({"parse_status": parse_status[local_path]["status"], "parse": parse_status[local_path]})
    (artifact_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _merge_stats(total: dict[str, int], added: dict[str, int]) -> None:
    for key, value in added.items():
        total[key] = total.get(key, 0) + int(value or 0)


def _safe_dir_name(value: str) -> str:
    safe = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in value)
    return safe.strip("._") or "memory"
