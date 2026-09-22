"""Collect memory-analysis tables and forensic VFS artifacts from MemProcFS."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from threading import Lock
from typing import Any

logger = logging.getLogger(__name__)


MEMPROCFS_CAPABILITIES = (
    "pslist",
    "psscan",
    "cmdline",
    "dlllist",
    "vadinfo",
    "threads",
    "suspicious_threads",
    "handles",
    "netscan",
    "svcscan",
    "modules",
    "modscan",
    "driverscan",
    "drivermodule",
    "malfind",
)

UNSUPPORTED_CAPABILITIES = (
    "ldrmodules",
    "callbacks",
    "ssdt",
    "skeleton_key_check",
)

_VMM_LOCK = Lock()
FORENSIC_MODE = "1"
VFS_CHUNK_SIZE = 8 * 1024 * 1024
MALFIND_YARA_SAMPLE_SIZE = 256 * 1024
FORENSIC_PROGRESS_PATH = "/forensic/progress_percent.txt"
FORENSIC_ENABLE_PATH = "/forensic/forensic_enable.txt"
FORENSIC_CSV_DIR = "/forensic/csv"
EVENTLOG_DIR = "/misc/eventlog"
DEEP_MAP_SKIP_PIDS = {0, 4}
DEEP_MAP_SKIP_NAMES = {
    "system",
    "secure system",
    "registry",
    "memory compression",
    "memcompression",
}


def is_memprocfs_available() -> bool:
    try:
        import memprocfs  # noqa: F401
        return True
    except ImportError:
        return False


class MemProcFSRunner:
    """Wrap a single MemProcFS Vmm object and normalize useful maps."""

    def __init__(self, dump_path: Path):
        self.dump_path = Path(dump_path)
        self._vmm = None
        self._failures: dict[str, str] = {}
        self._lock_acquired = False

    def __enter__(self) -> "MemProcFSRunner":
        import memprocfs

        _VMM_LOCK.acquire()
        self._lock_acquired = True
        try:
            self._vmm = memprocfs.Vmm(["-device", str(self.dump_path), "-forensic", FORENSIC_MODE])
        except BaseException:
            # A context manager whose __enter__ raises never receives __exit__.
            self._lock_acquired = False
            _VMM_LOCK.release()
            raise
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        try:
            if self._vmm is not None:
                self._vmm.close()
        finally:
            self._vmm = None
            if self._lock_acquired:
                self._lock_acquired = False
                _VMM_LOCK.release()

    def failures(self) -> dict[str, str]:
        return dict(self._failures)

    def unsupported_capabilities(self) -> list[str]:
        return list(UNSUPPORTED_CAPABILITIES)

    def collect(self, progress=None) -> dict[str, list[dict[str, Any]]]:
        if self._vmm is None:
            raise RuntimeError("MemProcFSRunner must be used as a context manager")

        results = {name: [] for name in MEMPROCFS_CAPABILITIES}
        results.update({name: [] for name in UNSUPPORTED_CAPABILITIES})

        processes = self._safe("process_list", self._vmm.process_list, default=[])
        total = len(processes or [])
        for index, proc in enumerate(processes or [], start=1):
            process_rows = self._collect_process(proc, progress=progress, index=index, total=total)
            for key, rows in process_rows.items():
                results[key].extend(rows)

        results["psscan"].extend(self._safe("vfs.psscan", lambda: self._collect_vfs_psscan(results["pslist"]), default=[]))
        results["netscan"] = self._safe("net", self._collect_net, default=[])
        results["svcscan"] = self._safe("service", self._collect_services, default=[])
        results["modules"] = self._safe("kdriver", self._collect_drivers, default=[])
        return results

    def extract_forensic_artifacts(
        self,
        output_dir: Path,
        progress=None,
        include_csv: bool = True,
        include_eventlogs: bool = True,
    ) -> dict[str, Any]:
        """Copy useful MemProcFS forensic VFS outputs to a case-owned directory."""
        if self._vmm is None:
            raise RuntimeError("MemProcFSRunner must be used as a context manager")

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest: dict[str, Any] = {
            "dump": str(self.dump_path),
            "forensic_mode": FORENSIC_MODE,
            "include_csv": include_csv,
            "include_eventlogs": include_eventlogs,
            "artifacts": [],
            "failures": [],
        }

        if not include_csv and not include_eventlogs:
            manifest["skipped"] = "forensic CSV and event-log extraction disabled by upload options"
            manifest_path = output_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            return manifest

        forensic_started = self._enable_forensic()
        self._wait_for_forensic(progress, wait_for_start=forensic_started)
        copy_specs = []
        if include_csv:
            copy_specs.append((FORENSIC_CSV_DIR, Path("forensic") / "csv", ".csv"))
        if include_eventlogs:
            copy_specs.append((EVENTLOG_DIR, Path("eventlog"), ".evtx"))
        for vfs_dir, relative_dir, suffix in copy_specs:
            entries = self._list_vfs_dir(vfs_dir)
            if not entries:
                manifest["failures"].append({
                    "source_dir": vfs_dir,
                    "error": self._failures.get(f"vfs.list:{vfs_dir}", "no files found"),
                })
                continue
            for name, entry in sorted(entries.items()):
                if not name.lower().endswith(suffix):
                    continue
                source_path = f"{vfs_dir.rstrip('/')}/{name}"
                target = output_dir / relative_dir / _safe_filename(name)
                if progress:
                    progress(f"Copying MemProcFS artifact {name}")
                manifest["artifacts"].append(self._copy_vfs_file(source_path, target, entry))

        manifest_path = output_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest

    def _safe(self, name: str, fn, default):
        try:
            return fn()
        except Exception as exc:
            self._failures[name] = str(exc)
            return default

    def _enable_forensic(self) -> bool:
        try:
            self._vmm.vfs.write(FORENSIC_ENABLE_PATH, FORENSIC_MODE.encode("ascii"), 0)
            return True
        except TypeError:
            try:
                self._vmm.vfs.write(FORENSIC_ENABLE_PATH, FORENSIC_MODE.encode("ascii"))
                return True
            except Exception as exc:
                self._failures["forensic.enable"] = str(exc)
                return False
        except Exception as exc:
            self._failures["forensic.enable"] = str(exc)
            return False

    def _wait_for_forensic(self, progress=None, timeout_seconds: float = 600.0, wait_for_start: bool = False) -> None:
        """Poll forensic progress when MemProcFS exposes it; otherwise continue best-effort."""
        start = time.monotonic()
        saw_progress = False
        while time.monotonic() - start < timeout_seconds:
            percent = self._read_progress_percent()
            if percent is None:
                if self._list_vfs_dir(FORENSIC_CSV_DIR):
                    return
                if not saw_progress and not wait_for_start:
                    return
            else:
                saw_progress = True
                if progress:
                    progress(f"MemProcFS forensic pass {percent:.0f}%")
                if percent >= 100:
                    return
            time.sleep(1.0)
        self._failures["forensic.progress"] = f"forensic mode did not report completion within {timeout_seconds:.0f}s"

    def _read_progress_percent(self) -> float | None:
        try:
            data = self._vmm.vfs.read(FORENSIC_PROGRESS_PATH, 128, 0)
        except Exception:
            return None
        try:
            text = bytes(data).decode("utf-8", errors="replace").strip().strip("%\x00")
            return float(text)
        except (TypeError, ValueError):
            return None

    def _list_vfs_dir(self, vfs_dir: str) -> dict[str, Any]:
        try:
            entries = self._vmm.vfs.list(vfs_dir) or {}
        except Exception as exc:
            self._failures[f"vfs.list:{vfs_dir}"] = str(exc)
            return {}
        if isinstance(entries, dict):
            return entries
        out: dict[str, Any] = {}
        for entry in entries:
            name = _entry_name(entry)
            if name:
                out[name] = entry
        return out

    def _copy_vfs_file(self, source_path: str, target: Path, entry: Any) -> dict[str, Any]:
        target.parent.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        size_hint = _entry_size(entry)
        copied = 0
        artifact = {
            "source_path": source_path,
            "local_path": str(target),
            "size": 0,
            "sha256": None,
            "status": "ok",
            "parse_status": "pending",
        }
        try:
            with open(target, "wb") as dst:
                if size_hint == 0:
                    pass
                else:
                    while size_hint is None or copied < size_hint:
                        length = VFS_CHUNK_SIZE
                        if size_hint is not None:
                            length = min(length, size_hint - copied)
                        if length <= 0:
                            break
                        data = self._vmm.vfs.read(source_path, length, copied)
                        if not data:
                            break
                        if isinstance(data, str):
                            data = data.encode("utf-8", errors="replace")
                        dst.write(data)
                        hasher.update(data)
                        copied += len(data)
                        if size_hint is None and len(data) < length:
                            break
            if size_hint is not None and copied != size_hint:
                raise ValueError(f"Incomplete VFS read: expected {size_hint} bytes, received {copied}")
            artifact["size"] = copied
            artifact["sha256"] = hasher.hexdigest()
        except Exception as exc:
            artifact["status"] = "failed"
            artifact["error"] = str(exc)
            self._failures[f"vfs.read:{source_path}"] = str(exc)
            try:
                target.unlink(missing_ok=True)
            except OSError as cleanup_exc:
                artifact["cleanup_error"] = str(cleanup_exc)
        return artifact

    def _collect_process(self, proc, progress=None, index: int = 0, total: int = 0) -> dict[str, list[dict[str, Any]]]:
        pid = _attr(proc, "pid")
        ppid = _attr(proc, "ppid")
        name = _attr(proc, "fullname") or _attr(proc, "name") or f"pid-{pid}"
        path = _attr(proc, "pathuser") or _attr(proc, "pathkernel")
        cmdline = _attr(proc, "cmdline")
        create_time = _attr(proc, "time_create") or _attr(proc, "time-create-str")

        out = {
            "pslist": [{
                "PID": pid,
                "PPID": ppid,
                "ImageFileName": name,
                "CreateTime": _format_time(create_time),
                "Path": path,
            }],
            "cmdline": [{"PID": pid, "Args": cmdline}] if cmdline else [],
            "dlllist": [],
            "vadinfo": [],
            "threads": [],
            "handles": [],
            "malfind": [],
        }

        label = f"{name} pid {pid}".strip()
        prefix = f"MemProcFS: process {index}/{total} {label}" if total else f"MemProcFS: {label}"
        if _skip_deep_maps(pid, name):
            if progress:
                progress(f"{prefix} inventory only; skipping fragile kernel/pseudo-process maps")
            return out

        if progress:
            progress(f"{prefix} modules")
        modules = self._safe(f"module_list:{pid}", proc.module_list, default=[])
        for module in modules or []:
            out["dlllist"].append({
                "PID": pid,
                "Name": _attr(module, "name"),
                "Path": _attr(module, "fullname") or _attr(module, "name"),
                "Base": _attr(module, "base"),
                "Size": _attr(module, "image_size") or _attr(module, "file_size"),
            })

        if progress:
            progress(f"{prefix} VADs")
        vads = self._safe(f"vad:{pid}", lambda: proc.maps.vad(False), default=[])
        for vad in vads or []:
            row = _vad_row(pid, vad)
            out["vadinfo"].append(row)
            if _is_executable_private(row):
                out["malfind"].append(_malfind_row(proc, row))

        if progress:
            progress(f"{prefix} threads")
        threads = self._safe(f"threads:{pid}", proc.maps.thread, default=[])
        for thread in threads or []:
            out["threads"].append({
                "PID": pid,
                "TID": _dict_get(thread, "tid"),
                "StartAddress": _dict_get(thread, "va-win32start", "va-start", "va_start"),
                "CreateTime": _format_time(_dict_get(thread, "time-create-str", "time-create")),
            })

        if progress and (index == total or index % 5 == 0):
            progress(f"MemProcFS: collected process maps {index}/{total}")
        return out

    def _collect_vfs_psscan(self, pslist_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Best-effort hidden-process cross view from MemProcFS /pid VFS.

        MemProcFS does not expose Volatility's psscan table. The /pid filesystem
        can still surface process directories from a different internal view;
        entries not present in process_list are fed to the existing graded
        hidden-process analyzer as psscan-compatible candidates.
        """
        live_pids = {_to_int(row.get("PID")) for row in pslist_rows}
        live_pids.discard(None)
        entries = self._list_vfs_dir("/pid")
        rows: list[dict[str, Any]] = []
        for name in sorted(entries):
            pid = _to_int(name)
            if pid is None or pid in live_pids:
                continue
            proc_name = self._read_vfs_text_first(
                f"/pid/{pid}/name.txt",
                f"/pid/{pid}/name",
                f"/pid/{pid}/procname.txt",
            ) or f"pid-{pid}"
            cmdline = self._read_vfs_text_first(f"/pid/{pid}/cmdline.txt", f"/pid/{pid}/cmdline")
            ppid = _to_int(self._read_vfs_text_first(f"/pid/{pid}/ppid.txt", f"/pid/{pid}/ppid"))
            rows.append({
                "PID": pid,
                "PPID": ppid,
                "ImageFileName": proc_name,
                "CreateTime": self._read_vfs_text_first(f"/pid/{pid}/time_create.txt", f"/pid/{pid}/create_time.txt"),
                "ExitTime": self._read_vfs_text_first(f"/pid/{pid}/time_exit.txt", f"/pid/{pid}/exit_time.txt"),
                "CommandLine": cmdline,
                "Source": "memprocfs.vfs.pid",
            })
        return rows

    def _read_vfs_text_first(self, *paths: str) -> str | None:
        for path in paths:
            try:
                data = self._vmm.vfs.read(path, 4096, 0)
            except TypeError:
                try:
                    data = self._vmm.vfs.read(path, 4096)
                except Exception:
                    continue
            except Exception:
                continue
            if isinstance(data, str):
                text = data
            else:
                text = bytes(data).decode("utf-8", errors="replace")
            text = text.strip("\x00\r\n\t ")
            if text:
                return text
        return None

    def _collect_net(self) -> list[dict[str, Any]]:
        rows = []
        for row in self._vmm.maps.net() or []:
            proto = _dict_get(row, "proto", "tp", default="")
            if not proto:
                proto = "TCP" if _dict_get(row, "state") is not None else ""
            rows.append({
                "PID": _dict_get(row, "pid"),
                "Owner": _dict_get(row, "process", "owner", default=""),
                "Proto": str(proto).upper(),
                "LocalAddr": _dict_get(row, "src-ip", "laddr", "local_ip", default=""),
                "LocalPort": _dict_get(row, "src-port", "lport", "local_port"),
                "ForeignAddr": _dict_get(row, "dst-ip", "raddr", "remote_ip", default=""),
                "ForeignPort": _dict_get(row, "dst-port", "rport", "remote_port"),
                "State": _dict_get(row, "state", "state-str", default=""),
            })
        return rows

    def _collect_services(self) -> list[dict[str, Any]]:
        services = self._vmm.maps.service() or {}
        if isinstance(services, dict):
            values = services.values()
        else:
            values = services
        rows = []
        for svc in values:
            rows.append({
                "Name": _dict_get(svc, "name"),
                "Binary": _dict_get(svc, "path-image", "path", default=""),
                "State": _dict_get(svc, "dwCurrentState", "state", default=""),
                "PID": _dict_get(svc, "pid"),
            })
        return rows

    def _collect_drivers(self) -> list[dict[str, Any]]:
        rows = []
        for drv in self._vmm.maps.kdriver() or []:
            rows.append({
                "Name": _dict_get(drv, "name"),
                "Path": _dict_get(drv, "path", default=""),
                "Base": _dict_get(drv, "va", "base"),
                "Size": _dict_get(drv, "size"),
            })
        return rows


def _attr(obj, name: str, default=None):
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


def _dict_get(row: dict[str, Any], *keys: str, default=None):
    for key in keys:
        if isinstance(row, dict) and key in row:
            return row[key]
    return default


def _entry_name(entry: Any) -> str | None:
    if isinstance(entry, dict):
        value = _dict_get(entry, "name", "Name", "filename", "FileName")
        return str(value) if value else None
    for attr in ("name", "Name", "filename", "FileName"):
        value = getattr(entry, attr, None)
        if value:
            return str(value)
    return None


def _entry_size(entry: Any) -> int | None:
    value = None
    if isinstance(entry, dict):
        value = _dict_get(entry, "size", "Size", "cb", "CB")
    else:
        for attr in ("size", "Size", "cb", "CB"):
            if hasattr(entry, attr):
                value = getattr(entry, attr)
                break
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _safe_filename(name: str) -> str:
    cleaned = Path(str(name).replace("\\", "/")).name
    return cleaned or "artifact.bin"


def _format_time(value) -> str | None:
    if value in (None, "", 0):
        return None
    text = str(value).strip()
    return None if text.strip("* ") == "" else text


def _skip_deep_maps(pid, name: str) -> bool:
    pid_int = _to_int(pid)
    short = Path(str(name or "").replace("\\", "/")).name.lower()
    return pid_int in DEEP_MAP_SKIP_PIDS or short in DEEP_MAP_SKIP_NAMES


def _to_int(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _vad_row(pid: int | None, vad: dict[str, Any]) -> dict[str, Any]:
    start = _dict_get(vad, "start", "va")
    end = _dict_get(vad, "end")
    if end is None and start is not None:
        size = _dict_get(vad, "size")
        pages = _dict_get(vad, "pages")
        if size is not None:
            end = int(start) + int(size) - 1
        elif pages is not None:
            end = int(start) + int(pages) * 4096 - 1
    return {
        "PID": pid,
        "Start": start,
        "End": end,
        "Protection": _dict_get(vad, "protection", "flags", default=""),
        "PrivateMemory": _dict_get(vad, "private", "mem_commit", default=True),
        "CommitCharge": _dict_get(vad, "commit_charge", "pages"),
        "File": _dict_get(vad, "file", "path", "name", default=""),
        "Tag": _dict_get(vad, "tag", "type", default=""),
    }


def _is_executable_private(row: dict[str, Any]) -> bool:
    prot = str(row.get("Protection") or "").upper()
    executable = "EXECUTE" in prot or "X" in prot
    writable = "WRITE" in prot or "W" in prot
    file_backed = bool(str(row.get("File") or "").strip())
    private = str(row.get("PrivateMemory")).lower() not in ("false", "0", "none", "")
    return executable and writable and private and not file_backed


def _malfind_row(proc, vad: dict[str, Any]) -> dict[str, Any]:
    pid = vad.get("PID")
    name = _attr(proc, "fullname") or _attr(proc, "name") or f"pid-{pid}"
    start = vad.get("Start")
    hexdump = ""
    sample = b""
    if start is not None:
        try:
            end = vad.get("End")
            size = MALFIND_YARA_SAMPLE_SIZE
            if end is not None:
                size = max(0, min(MALFIND_YARA_SAMPLE_SIZE, int(end) - int(start) + 1))
            sample = proc.memory.read(int(start), size)
            hexdump = sample[:64].hex(" ")
        except Exception:
            hexdump = ""
            sample = b""
    return {
        "PID": pid,
        "Process": name,
        "Start": start,
        "End": vad.get("End"),
        "Protection": vad.get("Protection"),
        "Hexdump": hexdump,
        "BytesSample": sample if isinstance(sample, bytes) else bytes(sample or b""),
        "Disasm": "",
    }
