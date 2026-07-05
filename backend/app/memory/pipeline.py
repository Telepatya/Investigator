"""Memory dump analysis pipeline. Runs MemProcFS collection, heuristics, and YARA.

Grading philosophy: a single anomalous view (pool scan hit, RWX page, unlinked
list entry) is a lead, not a verdict. Severity scales with the number of
INDEPENDENT corroborating artifacts, and the correlation basis is stored in
each MemoryResult's data dict so the analyst can see why. As a machine-wide
backstop, any anomaly class that fires across a large fraction of all scanned
processes is treated as an environmental/analyzer artifact and downgraded
(see _PrevalenceTracker) - deliberate evasion is rare per machine.
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import select

from app.ingest.normalize import parse_timestamp
from app.memory.forensics import (
    ingest_memprocfs_artifacts_sync,
    reset_memprocfs_artifact_dir,
)
from app.memory.memprocfs_runner import MemProcFSRunner, is_memprocfs_available
from app.memory.yara_scanner import get_scanner
from app.store import cases as case_store
from app.store.database import MemoryResult, Process

ProgressCallback = Callable[[str, float, str, bool, str | None], Any]

# Runtimes that JIT-compile into RWX private pages - the classic malfind false positive.
JIT_PROCESS_NAMES = {
    "powershell.exe", "pwsh.exe", "dotnet.exe", "w3wp.exe", "aspnet_wp.exe",
    "java.exe", "javaw.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "iexplore.exe", "node.exe", "msbuild.exe",
}

# Runtime engine DLLs whose presence in dlllist marks a process as JIT-capable,
# regardless of its name (e.g. .NET services, Electron/CEF hosts, embedded
# script engines). Exact basenames plus prefix families (native images such as
# mscorlib.ni.dll and System.Private.CoreLib.ni.dll count).
JIT_RUNTIME_DLLS = {
    "clr.dll", "coreclr.dll", "mscorwks.dll", "node.dll", "libcef.dll", "jvm.dll",
}
JIT_RUNTIME_DLL_PREFIXES = (
    "mscorlib", "system.private.corelib", "jscript", "chakra", "v8", "electron",
)

# Pseudo/system processes that map system images (ntdll.dll, vertdll.dll, ...)
# without maintaining user-mode loader lists; ldrmodules linkage checks do not
# apply to them.
PSEUDO_PROCESS_NAMES = {
    "system", "secure system", "registry", "memory compression", "memcompression",
}

# ldrmodules patterns that speak about the process MAIN EXE's identity (the
# hollowing signals) as opposed to a generic unlinked mapping. Only these may
# corroborate malfind, and only these earn the hollowing-suspect flag.
LDR_EXE_LEVEL_PATTERNS = {"exe-not-in-load-order", "exe-name-mismatch"}

# Legitimate homes for kernel drivers (module Path column, device-path style).
SYSTEM_DRIVER_PATH_FRAGMENTS = (
    "\\systemroot\\system32", "\\windows\\system32", "\\winnt\\system32",
    "\\systemroot\\winsxs", "\\windows\\winsxs",
)

# User-writable / staging directories that are odd homes for a service binary.
USER_WRITABLE_DIR_FRAGMENTS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\",
    "\\users\\public\\", "\\downloads\\", "\\perflogs\\", "\\recycle",
)

SENSITIVE_PROCESS_NAMES = {
    "lsass.exe", "lsaiso.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "samss.exe", "smss.exe", "securityhealthservice.exe", "msmpeng.exe",
    "windefend.exe", "senseir.exe", "sensece.exe", "chrome.exe", "msedge.exe",
    "firefox.exe", "powershell.exe", "pwsh.exe", "cmd.exe",
}

# Flags that count as independent suspicious indicators in the final cross-correlation.
# VAD-shape and thread-start evidence intentionally stay inside malfind's data
# (they qualify the same memory region, they are not a second artifact); the
# skeleton-key lsass patch is a genuinely independent kernel-view signal.
SUSPICIOUS_MEMORY_FLAGS = {
    "hidden", "hidden-candidate", "injected", "hollowing-suspect",
    "unlinked-module", "suspicious-network", "skeleton-key", "cross-process", "yara-hit",
}

_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _get(row: dict[str, Any], *keys: str, default=None):
    for k in keys:
        for actual in row:
            if actual.lower() == k.lower():
                return row[actual]
    return default


def _to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _falsey(v) -> bool:
    return str(v).lower() in ("false", "0", "none", "-", "")


def _parse_ts(value):
    if value in (None, "", "-", "N/A", "None"):
        return None
    try:
        return parse_timestamp(value)
    except Exception:
        return None


def _plausible_time(dt) -> bool:
    """Pool reuse / acquisition smear produces null, epoch-1970 or far-future stamps."""
    return dt is not None and 1990 <= dt.year <= datetime.now().year + 2


def _is_private_addr(addr: str) -> bool:
    a = (addr or "").strip().lower().strip("[]")
    if not a or a in ("*", "::", "::0", "0.0.0.0", "::1"):
        return True
    if a.startswith(("127.", "10.", "192.168.", "169.254.", "fe80", "::1")):
        return True
    if a.startswith("172."):
        try:
            return 16 <= int(a.split(".")[1]) <= 31
        except (ValueError, IndexError):
            return False
    return False


def _pids_from(rows: list[dict[str, Any]]) -> set[int]:
    pids: set[int] = set()
    for row in rows:
        pid = _to_int(_get(row, "PID", "Pid"))
        if pid is not None:
            pids.add(pid)
    return pids


def _augment_results_from_memprocfs_csv(results: dict[str, list[dict[str, Any]]], artifact_dir: Path) -> None:
    """Feed copied MemProcFS forensic CSV hints into legacy-shaped analyzers."""
    csv_dir = Path(artifact_dir) / "forensic" / "csv"
    if not csv_dir.is_dir():
        return
    for path in sorted(csv_dir.glob("*.csv")):
        name = path.name.lower()
        for row in _iter_csv_rows(path):
            if name == "findevil.csv":
                _augment_from_findevil(results, row)
            elif "driver" in name or "module" in name or "kernel" in name:
                _augment_driver_row(results, row, source=f"memprocfs.csv:{path.name}")
            elif "process" in name or name.startswith("ps"):
                _augment_process_row(results, row, source=f"memprocfs.csv:{path.name}")


def _iter_csv_rows(path: Path):
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            yield from csv.DictReader(fh)
    except OSError:
        return


def _augment_from_findevil(results: dict[str, list[dict[str, Any]]], row: dict[str, Any]) -> None:
    row_type = str(_get(row, "Type", "Rule", "Finding", default="") or "").upper()
    reason = str(_get(row, "Reason", "Description", "Info", "Details", default="") or "")
    text = f"{row_type} {reason}".lower()
    source = "memprocfs.findevil"
    pid = _to_int(_get(row, "PID", "Pid", "ProcessID"))
    proc_name = str(_get(row, "Process", "Name", "ProcessName", default=f"pid-{pid}" if pid is not None else "") or "")

    if pid is not None and (
        "hidden process" in text or "process hidden" in text or "dkom" in text
        or row_type in {"PROC_HIDE", "PROCESS_HIDE", "HIDDEN_PROCESS", "DKOM_PROCESS", "EPROCESS"}
    ):
        results.setdefault("psscan", []).append({
            "PID": pid,
            "PPID": _to_int(_get(row, "PPID", "Ppid", "ParentPID")),
            "ImageFileName": proc_name or f"pid-{pid}",
            "CreateTime": _get(row, "CreateTime", "Time"),
            "ExitTime": _get(row, "ExitTime"),
            "Source": source,
            "Reason": reason,
        })

    if pid is not None and ("thread" in row_type.lower() or "remote thread" in text):
        results.setdefault("suspicious_threads", []).append({
            "PID": pid,
            "TID": _to_int(_get(row, "TID", "Tid", "ThreadID")),
            "StartAddress": _get(row, "StartAddress", "Address", "VA"),
            "Reason": reason,
            "Source": source,
        })

    if "driver" in text or row_type.startswith("DRIVER") or row_type in {"DKOM_DRIVER", "HIDDEN_DRIVER"}:
        _augment_driver_row(results, row, source=source)


def _augment_process_row(results: dict[str, list[dict[str, Any]]], row: dict[str, Any], source: str) -> None:
    pid = _to_int(_get(row, "PID", "Pid", "ProcessID"))
    if pid is None:
        return
    existing = _pids_from(results.get("pslist", [])) | _pids_from(results.get("psscan", []))
    if pid in existing:
        return
    results.setdefault("psscan", []).append({
        "PID": pid,
        "PPID": _to_int(_get(row, "PPID", "Ppid", "ParentPID")),
        "ImageFileName": _get(row, "Name", "Process", "ImageFileName", default=f"pid-{pid}"),
        "CreateTime": _get(row, "CreateTime", "Time"),
        "ExitTime": _get(row, "ExitTime", "EndTime"),
        "Source": source,
    })


def _augment_driver_row(results: dict[str, list[dict[str, Any]]], row: dict[str, Any], source: str) -> None:
    name = str(_get(row, "Name", "Driver Name", "Driver", "Module", default="") or "").strip()
    path = str(_get(row, "Path", "File", "ImagePath", "MappedPath", default="") or "").strip()
    if not name and path:
        name = _basename(path)
    if not name and not path:
        return
    out = {
        "Name": name,
        "Driver Name": name,
        "Path": path,
        "Base": _get(row, "Base", "Start", "Address", "VA"),
        "Size": _get(row, "Size", "ImageSize"),
        "Source": source,
        "Reason": _get(row, "Reason", "Description", "Info", default=""),
    }
    lower = f"{source} {out['Reason']} {name} {path}".lower()
    if "hidden" in lower or "dkom" in lower:
        results.setdefault("drivermodule", []).append({**out, "Known Exception": False})
        results.setdefault("driverscan", []).append(out)
    elif source.endswith("findevil"):
        results.setdefault("driverscan", []).append(out)
    else:
        results.setdefault("modscan", []).append(out)


def _norm_driver_name(name: str) -> str:
    n = (name or "").strip().lower()
    if "\\" in n:
        n = n.rsplit("\\", 1)[-1]
    return n


def _name_variants(name: str) -> set[str]:
    n = _norm_driver_name(name)
    if not n:
        return set()
    variants = {n, n + ".sys"}
    if "." in n:
        variants.add(n.rsplit(".", 1)[0])
    return variants


def _module_lookup(known: dict[str, str], name: str) -> str | None:
    """Path of a loaded module matching name (extension optional); None if not loaded."""
    for variant in _name_variants(name):
        if variant in known:
            return known[variant]
    return None


def _system_path(path: str) -> bool:
    p = (path or "").lower().replace("/", "\\")
    if any(f in p for f in SYSTEM_DRIVER_PATH_FRAGMENTS):
        return True
    # Drivers commonly register as \SystemRoot\<name>.sys (or live directly
    # under \Windows) without a system32 segment; that still resolves inside
    # the system root and is not a non-standard location.
    for root in ("\\systemroot\\", "\\windows\\", "\\winnt\\"):
        idx = p.find(root)
        if idx != -1:
            rest = p[idx + len(root):]
            if rest.endswith(".sys") and "\\" not in rest:
                return True
    return False


def _jit_runtime_evidence(proc_name: str, dll_paths: list[str]) -> str | None:
    """Why a process counts as a JIT runtime, or None if it does not.

    Dynamic evidence first: a runtime engine DLL actually loaded per dlllist
    (works for any host process, e.g. .NET services). The static name list is
    the fallback for processes whose engine is statically linked (browsers) or
    when dlllist returned nothing for the process."""
    for p in dll_paths or []:
        base = _basename(p)
        if base in JIT_RUNTIME_DLLS:
            return f"runtime-dll:{base}"
        if base.endswith(".dll") and base.startswith(JIT_RUNTIME_DLL_PREFIXES):
            return f"runtime-dll:{base}"
    if (proc_name or "").lower() in JIT_PROCESS_NAMES:
        return "process-name"
    return None


def _malfind_content(hexdump: str, disasm: str) -> tuple[bool, bool]:
    """Return (has_mz_header, has_nonzero_content) for a malfind region.

    Hexdump may be raw bytes decoded to str, or a formatted hex dump,
    depending on the memory collector version.
    """
    blob = hexdump or ""
    has_mz = blob.startswith("MZ") or blob.replace(" ", "").lower().startswith("4d5a") or " MZ" in blob[:120]
    hex_only = "".join(c for c in blob if c in "0123456789abcdefABCDEF")
    formatted_all_zero = bool(hex_only) and set(hex_only) == {"0"}
    raw_all_zero = bool(blob) and all(c == "\x00" for c in blob)
    has_content = bool(blob or disasm) and not (raw_all_zero or formatted_all_zero)
    return has_mz, has_content


def _to_addr(value) -> int | None:
    """Parse an address that may arrive as int, '0x7ff...' hex string or decimal string."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    s = str(value).strip().lower()
    if not s or s in ("-", "n/a", "none"):
        return None
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except ValueError:
        return None


def _basename(path: str) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _proc_name_mismatch(module_path: str, proc_name: str) -> bool:
    """True if a module basename cannot be the process's main exe.

    pslist's ImageFileName is truncated to 14 chars, so long names only get a
    prefix comparison."""
    base = _basename(module_path)
    pl = (proc_name or "").lower()
    if not base or not pl or pl == "unknown":
        return False
    return (not base.startswith(pl[:14])) if len(pl) >= 14 else base != pl


def _clean_cell(value) -> str:
    s = "" if value is None else str(value).strip()
    return "" if s.lower() in ("-", "n/a", "none") else s


def _build_vad_map(rows: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    """pid -> compact VAD descriptors from vadinfo (or vadwalk fallback) rows.

    Only the fields the correlations need are kept - vadinfo over all processes
    is far too large to store per-row."""
    out: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        pid = _to_int(_get(row, "PID", "Pid"))
        start = _to_addr(_get(row, "Start VPN", "Start", "StartVPN"))
        end = _to_addr(_get(row, "End VPN", "End", "EndVPN"))
        if pid is None or start is None or end is None:
            continue
        private_raw = _get(row, "PrivateMemory", "Private")
        out.setdefault(pid, []).append({
            "start": start,
            "end": end,
            "protection": _clean_cell(_get(row, "Protection")),
            "private": None if private_raw is None else not _falsey(private_raw),
            "commit_charge": _get(row, "CommitCharge", "Commit Charge"),
            "file": _clean_cell(_get(row, "File", "MappedFile", "File Path", "FileName")),
            "tag": _clean_cell(_get(row, "Tag")),
        })
    return out


def _build_thread_map(rows: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    """pid -> thread start addresses (windows.threads rows)."""
    out: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        pid = _to_int(_get(row, "PID", "Pid"))
        start = _to_addr(_get(row, "StartAddress", "Start Address",
                              "Win32StartAddress", "Win32 Start Address"))
        if pid is None or start is None:
            continue
        out.setdefault(pid, []).append({
            "tid": _to_int(_get(row, "TID", "Tid")),
            "start": start,
            "create_time": _get(row, "CreateTime"),
        })
    return out


def _build_dll_map(rows: list[dict[str, Any]]) -> dict[int, list[str]]:
    """pid -> ordered lowercased module paths from dlllist (first entry is
    normally the main exe in InLoadOrder)."""
    out: dict[int, list[str]] = {}
    for row in rows:
        pid = _to_int(_get(row, "PID", "Pid"))
        path = _clean_cell(_get(row, "Path", "Name"))
        if pid is None or not path:
            continue
        out.setdefault(pid, []).append(path.lower())
    return out


def _find_vad(vads: list[dict[str, Any]], addr: int | None) -> dict[str, Any] | None:
    if addr is None:
        return None
    for v in vads:
        if v["start"] <= addr <= v["end"]:
            return v
    return None


def _threads_in_region(threads: list[dict[str, Any]],
                       start: int | None, end: int | None) -> list[dict[str, Any]]:
    if start is None or end is None:
        return []
    return [t for t in threads if start <= t["start"] <= end]


def _vad_shape(vad: dict[str, Any] | None) -> str:
    """Classify what a malfind region actually is according to its VAD."""
    if vad is None:
        return "unresolved"
    if vad["file"]:
        return "file-backed"
    prot = (vad["protection"] or "").upper()
    executable = "EXECUTE" in prot or "X" in prot
    writable = "WRITE" in prot or "W" in prot
    if executable and writable and vad["private"] is not False:
        return "private-rwx-unbacked"
    return "unbacked"


def _notch_down(severity: str) -> str:
    try:
        i = _SEVERITY_ORDER.index(severity)
    except ValueError:
        return severity
    return _SEVERITY_ORDER[max(i - 1, 0)]


def _max_severity(a: str, b: str) -> str:
    ranks = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    return a if ranks.get(a, 0) >= ranks.get(b, 0) else b


def _grade_malfind_vad(severity: str, has_mz: bool, jit: bool, vad_shape: str,
                       thread_tids: list[int]) -> tuple[str, list[str], list[str]]:
    """Adjust a malfind grade by VAD identity and thread-start evidence.

    Returns (severity, extra_corroborations, notes). Rules:
    - file-backed region -> one notch down (a mapped module quirk is far more
      likely than injection), except when an MZ header was dumped: MZ inside a
      file-backed mapping is just the module header, neither escalation nor proof
      of a benign mapping, so the grade is left alone.
    - thread start inside a non-file-backed region -> critical (high for JIT
      runtimes): a live thread executing from unbacked executable private memory
      has essentially no benign explanation outside JIT."""
    extra: list[str] = []
    notes: list[str] = []
    if vad_shape == "file-backed":
        if has_mz:
            notes.append("the region is file-backed, so the MZ header is consistent "
                         "with a mapped module image")
        else:
            severity = _notch_down(severity)
            notes.append("the region is file-backed, reducing the injection likelihood")
        if thread_tids:
            notes.append("threads start inside this file-backed region "
                         f"(TID {', '.join(map(str, thread_tids))}), which is normal for a mapped module")
    else:
        if vad_shape == "private-rwx-unbacked":
            notes.append("the VAD shows private, unbacked, writable+executable memory "
                         "- the classic injection shape")
        if thread_tids:
            extra.append("thread-start-in-region")
            severity = _max_severity(severity, "high" if jit else "critical")
            tids = ", ".join(map(str, thread_tids))
            if jit:
                notes.append(f"a thread starts inside the region (TID {tids}); for a JIT "
                             "runtime this can still be generated code, but it warrants review")
            else:
                notes.append(f"a thread starts inside the region (TID {tids}), which has "
                             "no benign explanation outside JIT runtimes")
    return severity, extra, notes


def _check_exe_vad(vads: list[dict[str, Any]], exe_base: str) -> tuple[bool, dict[str, Any]]:
    """Hollowed-image shape check: does the main exe's VAD look like a normal
    mapped image? Returns (anomalous, detail).

    Anomalous when no VAD maps the exe file at all (the image was unmapped or
    replaced with private memory) or the image region is writable+executable.
    Requires file information in the VAD data (vadinfo, not the vadwalk
    fallback) to make either claim."""
    if not vads or not exe_base:
        return False, {"status": "unresolved", "reason": "no VAD data for process"}
    file_backed = [v for v in vads if v["file"]]
    if not file_backed:
        return False, {"status": "unresolved",
                       "reason": "VAD data carries no mapped-file information"}
    matches = [v for v in file_backed if _basename(v["file"]) == exe_base]
    if not matches:
        return True, {"status": "no-file-backed-vad",
                      "reason": f"no VAD maps {exe_base}; the image region is private/unbacked"}
    for v in matches:
        prot = (v["protection"] or "").upper()
        if ("EXECUTE" in prot or "X" in prot) and ("WRITE" in prot or "W" in prot):
            return True, {"status": "writable-image", "protection": v["protection"],
                          "file": v["file"],
                          "reason": "the exe image region is writable+executable"}
    m = matches[0]
    return False, {"status": "image-vad-normal", "protection": m["protection"],
                   "file": m["file"]}


def _collect_connections(results: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Merge netscan + netstat rows, deduped on proto/laddr/lport/raddr/rport/pid.

    netscan is a pool scan and can resurface CLOSED/stale connections."""
    merged: dict[tuple, dict[str, Any]] = {}
    for plugin_name in ("netscan", "netstat"):
        for row in results.get(plugin_name, []):
            conn = {
                "proto": str(_get(row, "Proto", "Protocol", default="") or ""),
                "laddr": str(_get(row, "LocalAddr", "Laddr", default="") or ""),
                "lport": _get(row, "LocalPort", "Lport"),
                "raddr": str(_get(row, "ForeignAddr", "Raddr", default="") or ""),
                "rport": _get(row, "ForeignPort", "Rport"),
                "state": _get(row, "State"),
                "owner": _get(row, "Owner", "Process"),
                "pid": _to_int(_get(row, "PID", "Pid")),
                "plugins": [plugin_name],
            }
            key = (conn["proto"], conn["laddr"], str(conn["lport"]),
                   conn["raddr"], str(conn["rport"]), conn["pid"])
            existing = merged.get(key)
            if existing:
                if plugin_name not in existing["plugins"]:
                    existing["plugins"].append(plugin_name)
                if not existing["state"] and conn["state"]:
                    existing["state"] = conn["state"]
            else:
                merged[key] = conn
    return list(merged.values())


def _record_process_handles(
    session,
    session_id: str,
    handle_rows: list[dict[str, Any]],
    pslist_info: dict[int, dict[str, Any]],
) -> None:
    for row in handle_rows:
        pid = _to_int(_get(row, "PID", "Pid"))
        if pid is None:
            continue
        owner = str(_get(row, "Process", default="") or pslist_info.get(pid, {}).get("name") or f"pid-{pid}")
        kind = str(_get(row, "Type", default="unknown") or "unknown")
        name = str(_get(row, "Name", "Target", "Path", default="") or "")
        target_pid = _to_int(_get(row, "TargetPID", "TargetPid", "Target Process ID"))
        target_name = str(_get(row, "TargetProcess", "Target", default="") or "")
        access_raw = _get(row, "Access", "GrantedAccess", "AccessMask")
        severity, risk, reasons = _grade_handle(pid, kind, name, target_pid, target_name, access_raw)
        raw = {
            "plugin": "handles",
            "session_id": session_id,
            "PID": pid,
            "Process": owner,
            "Handle": _get(row, "Handle"),
            "Type": kind,
            "Name": name,
            "TargetPID": target_pid,
            "TargetProcess": target_name,
            "Access": access_raw,
            "Object": _get(row, "Object"),
            "risk": risk,
            "risk_reasons": reasons,
        }
        target = target_name or name
        _add_event(
            session, owner, "handle",
            f"{owner} (pid {pid}) handle {kind} -> {target or 'unnamed'}"
            + (f" access {access_raw}" if access_raw not in (None, "") else ""),
            severity,
            raw,
        )
        if risk in {"high", "critical"}:
            summary = (
                f"Suspicious cross-process handle: {owner} (pid {pid}) holds a {kind} "
                f"handle to {target or 'unknown target'}"
                + (f" with access {access_raw}" if access_raw not in (None, "") else "")
                + f". Reason: {'; '.join(reasons)}."
            )
            _add_memory_result(
                session, "handles", pid, owner, summary,
                {"pid": pid, "target_pid": target_pid, "target": target, "type": kind,
                 "access": access_raw, "risk_reasons": reasons},
                risk,
            )
            _mark_process(session, session_id, pid, "cross-process", risk)


def _grade_handle(
    owner_pid: int,
    kind: str,
    name: str,
    target_pid: int | None,
    target_name: str,
    access_raw,
) -> tuple[str, str, list[str]]:
    kind_l = (kind or "").lower()
    target_text = f"{name} {target_name}".lower()
    access = _parse_access_mask(access_raw)
    reasons: list[str] = []
    cross_process = target_pid is not None and target_pid != owner_pid
    sensitive = any(proc in target_text for proc in SENSITIVE_PROCESS_NAMES)

    if kind_l in {"process", "thread", "token"}:
        if cross_process:
            reasons.append(f"handle references another process pid {target_pid}")
        if sensitive:
            reasons.append("target appears sensitive")
        if _dangerous_process_access(access, kind_l):
            reasons.append("access mask permits injection, memory access, duplication, or token use")
        if reasons and (sensitive or _dangerous_process_access(access, kind_l)):
            return ("critical" if sensitive and _dangerous_process_access(access, kind_l) else "high",
                    "critical" if sensitive and _dangerous_process_access(access, kind_l) else "high",
                    reasons)
        if cross_process:
            return "low", "low", reasons or ["cross-process handle"]

    normalized = (name or "").lower().replace("/", "\\")
    if kind_l in {"file", "key", "registry"} and normalized:
        suspicious_path = any(fragment in normalized for fragment in USER_WRITABLE_DIR_FRAGMENTS)
        persistence_path = any(token in normalized for token in (
            "\\currentversion\\run", "\\services\\", "\\system32\\tasks\\", "\\startup\\"
        ))
        if persistence_path:
            return "medium", "medium", ["handle references a persistence-related path"]
        if suspicious_path:
            return "low", "low", ["handle references a user-writable/staging path"]

    return "info", "none", []


def _parse_access_mask(value) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None


def _dangerous_process_access(access: int | None, kind: str) -> bool:
    if access is None:
        return False
    if access in (0x1F0FFF, 0x1FFFFF, 0x143A, 0x1410, 0x1FFFF):
        return True
    if kind == "process":
        return bool(access & (0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0800))
    if kind == "thread":
        return bool(access & (0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040))
    if kind == "token":
        return bool(access & (0x0002 | 0x0004 | 0x0008 | 0x0020 | 0x0080 | 0x0200))
    return False


def _analyze_ldrmodules(rows: list[dict[str, Any]],
                        vad_by_pid: dict[int, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Return (suspicious ldrmodules findings, skipped-row counters).

    Real semantics: the process MAIN exe is legitimately absent from InInit,
    so that alone is never flagged. Files mapped as images WITHOUT being loaded
    as modules (LOAD_LIBRARY_AS_DATAFILE / IMAGE_RESOURCE: .mui, .mun, .winmd,
    .lex, fonts, ...) are legitimately absent from all three loader lists - the
    textbook ldrmodules false positive - so only .exe/.dll mappings are
    considered at all, and an all-lists-unlinked mapping is only reported when
    its VAD is actually EXECUTABLE (a data/resource-mapped DLL is not).
    Pseudo/system processes (System, Secure System, Registry, Memory
    Compression) map system DLLs without user-mode loader lists and are exempt.
    Suspicious: an exe unlinked from the load-order list, an executable image
    unlinked from all three lists, or the mapped exe's basename differing from
    the process name (hollowing indicator)."""
    findings: list[dict[str, Any]] = []
    skipped = {"non-code-mapping": 0, "pseudo-process": 0,
               "non-executable-mapping": 0, "vad-unresolved": 0}
    for row in rows:
        mapped = str(_get(row, "MappedPath", "Path", default="") or "")
        if not mapped:
            continue
        is_exe = mapped.lower().endswith(".exe")
        if not is_exe and not mapped.lower().endswith(".dll"):
            skipped["non-code-mapping"] += 1
            continue
        pid = _to_int(_get(row, "Pid", "PID"))
        proc_name = str(_get(row, "Process", default="unknown"))
        in_load = not _falsey(_get(row, "InLoad"))
        in_init = not _falsey(_get(row, "InInit"))
        in_mem = not _falsey(_get(row, "InMem"))
        pseudo = pid == 4 or proc_name.lower() in PSEUDO_PROCESS_NAMES

        patterns = []
        unlinked_vad = None
        if not in_load and not in_init and not in_mem:
            if pseudo:
                skipped["pseudo-process"] += 1
            else:
                base_addr = _to_addr(_get(row, "Base"))
                vad = _find_vad(vad_by_pid.get(pid, []) if pid is not None else [], base_addr)
                prot = ((vad["protection"] if vad else "") or "").upper()
                if vad is None or not prot:
                    skipped["vad-unresolved"] += 1
                elif "EXECUTE" not in prot:
                    skipped["non-executable-mapping"] += 1
                else:
                    patterns.append("unlinked-all-lists")
                    unlinked_vad = {
                        "protection": vad["protection"], "private": vad["private"],
                        "file": vad["file"],
                        "private_unbacked": bool(vad["private"]) and not vad["file"],
                    }
        elif is_exe and not in_load:
            patterns.append("exe-not-in-load-order")
        if is_exe and _proc_name_mismatch(mapped, proc_name):
            patterns.append("exe-name-mismatch")
        if patterns:
            findings.append({
                "pid": pid, "process": proc_name, "mapped": mapped, "patterns": patterns,
                "InLoad": in_load, "InInit": in_init, "InMem": in_mem,
                "unlinked_vad": unlinked_vad,
                "exe_level": bool(set(patterns) & LDR_EXE_LEVEL_PATTERNS),
            })
    return findings, skipped


def _grade_kernel_pointer(module: str, known: dict[str, str],
                          hidden_names: set[str], have_modules: bool) -> tuple[str, str]:
    """Grade a callback/SSDT handler by which module it points into.

    Returns (status_text, severity)."""
    mod_l = _norm_driver_name(module)
    if not mod_l or mod_l in ("unknown", "n/a"):
        # Symbol-resolution gaps land here far more often than true orphan
        # handlers; a pointer into a pool-scan-only module (the strong case)
        # is caught by the hidden_names check below and stays critical.
        return "handler not attributable to any module", "medium"
    if _name_variants(mod_l) & hidden_names:
        return "handler points into a pool-scan-only module (hidden driver candidate)", "critical"
    if not have_modules:
        return "modules list unavailable; could not correlate", "info"
    path = _module_lookup(known, mod_l)
    if path is None:
        return "handler module absent from the loaded-modules list", "high"
    if path and not _system_path(path):
        return (f"third-party driver callback ({path}) - common for AV/EDR/anticheat; "
                "review if unexpected"), "low"
    return "handler in a loaded module at a system path", "info"


def _grade_malfind_region(row: dict[str, Any], pid: int | None, jit: bool,
                          corroborated: list[str],
                          vad_by_pid: dict[int, list[dict[str, Any]]],
                          threads_by_pid: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    """Grade a single malfind region; returns a region descriptor.

    Severity model: an executable private region with content but NO MZ header,
    NO thread starting inside it and NO independent corroboration is a lead,
    not a verdict - medium by default, low for JIT runtimes. High requires at
    least one independent corroborating artifact; critical requires hard
    region evidence (an MZ header, or a thread start - the latter JIT-capped
    at high by _grade_malfind_vad)."""
    addr = _get(row, "Start VPN", "Start", "Address", default="")
    hexdump = str(_get(row, "Hexdump", default="") or "")
    disasm = str(_get(row, "Disasm", default="") or "")
    has_mz, has_content = _malfind_content(hexdump, disasm)

    if has_mz:
        severity = "critical"
        reason = "the region contains an MZ/PE header - an injected executable image"
    elif not has_content:
        severity = "low"
        reason = ("the region is committed RWX but all zeroes - often a JIT or "
                  "allocation artifact rather than injected code")
    elif corroborated:
        severity = "high"
        reason = f"corroborated by {', '.join(corroborated)}"
    elif jit:
        severity = "low"
        reason = ("the process hosts a JIT runtime that legitimately creates RWX "
                  "private pages; downgraded absent corroborating indicators")
    else:
        severity = "medium"
        reason = ("executable private memory with non-zero content - a lead worth "
                  "review, though a common shape absent corroborating evidence")

    # VAD identity + thread-start cross-view for this region.
    addr_int = _to_addr(addr)
    vad = _find_vad(vad_by_pid.get(pid, []) if pid is not None else [], addr_int)
    vad_shape = _vad_shape(vad)
    region_start = vad["start"] if vad else addr_int
    region_end = vad["end"] if vad else _to_addr(_get(row, "End VPN", "End"))
    thread_hits = _threads_in_region(
        threads_by_pid.get(pid, []) if pid is not None else [],
        region_start, region_end)
    thread_tids = [t["tid"] for t in thread_hits]
    severity, extra_corr, vad_notes = _grade_malfind_vad(
        severity, has_mz, jit, vad_shape, thread_tids)
    return {
        "address": str(addr), "severity": severity, "reason": reason,
        "mz_header": has_mz, "has_content": has_content, "vad_shape": vad_shape,
        "vad": vad and {
            "start": hex(vad["start"]), "end": hex(vad["end"]),
            "protection": vad["protection"], "private": vad["private"],
            "commit_charge": vad["commit_charge"], "file": vad["file"],
            "tag": vad["tag"],
        },
        "thread_starts_in_region": thread_tids,
        "extra_corroboration": extra_corr, "vad_notes": vad_notes,
        "disasm": disasm[:2000],
    }


class _PrevalenceTracker:
    """Machine-wide prevalence dampener.

    Deliberate evasion is rare per machine: an anomaly class that fires across
    a large fraction of ALL scanned processes is an environmental/analyzer
    artifact, not targeted tampering. Per-plugin passes register
    (class_name, pid) pairs together with their MemoryResult objects and the
    process flag they would apply; apply() then

    - downgrades every result of a widespread class to low,
    - applies the deferred process flags (at low severity for dampened
      classes), and
    - remembers which flags per pid the final cross-correlation must ignore,
      so machine-wide artifacts cannot compose into critical verdicts.

    Any future heuristic gets the same protection just by registering here
    instead of calling _mark_process directly."""

    FRACTION = 0.15
    MIN_PROCESSES = 10

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._class_pids: dict[str, set[int]] = {}
        self._dampened_flags: dict[int, set[str]] = {}
        self.widespread: dict[str, int] = {}

    def register(self, class_name: str, pid: int | None, severity: str,
                 results: list[MemoryResult] | None = None, flag: str | None = None) -> None:
        if pid is not None:
            self._class_pids.setdefault(class_name, set()).add(pid)
        self._entries.append({"class": class_name, "pid": pid, "severity": severity,
                              "results": list(results or []), "flag": flag})

    def apply(self, session, session_id: str, total_processes: int) -> None:
        from app.detect.engine import SEVERITY_RANK
        total = max(total_processes, 1)
        self.widespread = {
            cls: len(pids) for cls, pids in self._class_pids.items()
            if len(pids) > self.MIN_PROCESSES and len(pids) / total > self.FRACTION
        }
        for entry in self._entries:
            dampened = entry["class"] in self.widespread
            severity = entry["severity"]
            if dampened and SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK["low"]:
                severity = "low"
            if dampened:
                for result in entry["results"]:
                    if SEVERITY_RANK.get(result.severity, 0) > SEVERITY_RANK["low"]:
                        result.severity = "low"
                    result.data = {**(result.data or {}),
                                   "prevalence_downgraded": True,
                                   "prevalence_class": entry["class"]}
            if entry["flag"] and entry["pid"] is not None:
                _mark_process(session, session_id, entry["pid"], entry["flag"], severity)
                if dampened:
                    self._dampened_flags.setdefault(int(entry["pid"]), set()).add(entry["flag"])
        for cls, count in sorted(self.widespread.items()):
            _add_memory_result(
                session, "prevalence", None, None,
                f"pattern {cls} observed in {count}/{total_processes} processes - "
                "machine-wide prevalence indicates an environmental/analyzer artifact, "
                "not targeted evasion; individual results downgraded.",
                {"class": cls, "affected_processes": count,
                 "scanned_processes": total_processes,
                 "fraction": round(count / total, 3)},
                "low",
            )

    def flags_to_ignore(self, pid: int | None) -> set[str]:
        if pid is None:
            return set()
        return self._dampened_flags.get(int(pid), set())


def analyze_memory_dump_sync(
    case_id: str,
    dump_path: Path,
    progress: ProgressCallback,
    memory_options: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Full synchronous memory analysis. Writes processes, memory results, events."""
    session = case_store.get_session(case_id)
    stats = {"processes": 0, "memory_results": 0, "yara_hits": 0, "events": 0, "artifacts": 0}

    if not is_memprocfs_available():
        progress(
            "memory", 100.0,
            "MemProcFS is not installed; skipping raw memory analysis. "
            "Install with: pip install memprocfs",
            False, None,
        )
        session.close()
        return stats

    runner = MemProcFSRunner(dump_path)
    session_id = f"mem-{dump_path.stem}"
    unsupported_capabilities: list[str] = []
    artifact_dir = reset_memprocfs_artifact_dir(case_id, dump_path.stem)
    extraction_manifest: dict[str, Any] | None = None
    memory_options = memory_options or {}
    include_forensic_timeline = bool(memory_options.get("forensic_timeline"))
    include_eventlogs = bool(memory_options.get("eventlogs"))

    try:
        progress("memory", 5.0, "MemProcFS: opening memory image", False, None)
        with runner:
            progress("memory", 15.0, "MemProcFS: collecting process and system maps", False, None)
            results = runner.collect(
                lambda message: progress("memory", 15.0, message, False, None)
            )
            unsupported_capabilities = runner.unsupported_capabilities()
            if include_forensic_timeline or include_eventlogs:
                enabled = []
                if include_forensic_timeline:
                    enabled.append("forensic timeline/artifact CSV")
                if include_eventlogs:
                    enabled.append("event logs")
                progress("memory", 35.0, "MemProcFS: extracting " + " and ".join(enabled), False, None)
                extraction_manifest = runner.extract_forensic_artifacts(
                    artifact_dir,
                    lambda message: progress("memory", 35.0, message, False, None),
                    include_csv=include_forensic_timeline,
                    include_eventlogs=include_eventlogs,
                )
            else:
                progress("memory", 35.0, "MemProcFS: forensic timeline and event-log extraction disabled", False, None)
                extraction_manifest = runner.extract_forensic_artifacts(
                    artifact_dir,
                    include_csv=False,
                    include_eventlogs=False,
                )

        if include_forensic_timeline or include_eventlogs:
            progress("memory", 56.0, "Parsing MemProcFS forensic artifacts", False, None)
            artifact_stats = ingest_memprocfs_artifacts_sync(
                session, dump_path.stem, artifact_dir, extraction_manifest, progress
            )
            stats["events"] += artifact_stats.get("events", 0)
            stats["memory_results"] += artifact_stats.get("memory_results", 0)
            stats["processes"] += artifact_stats.get("processes", 0)
            stats["artifacts"] += artifact_stats.get("files", 0)
            _augment_results_from_memprocfs_csv(results, artifact_dir)

        # --- Processes from pslist ---
        pslist = results.get("pslist", [])
        cmdlines = {}
        for row in results.get("cmdline", []):
            pid = _to_int(_get(row, "PID", "Pid"))
            args = _get(row, "Args", "Cmd")
            if pid is not None:
                cmdlines[pid] = args
        for row in results.get("psscan", []):
            pid = _to_int(_get(row, "PID", "Pid"))
            args = _get(row, "CommandLine", "Args", "Cmd")
            if pid is not None and args and pid not in cmdlines:
                cmdlines[pid] = args
        pslist_pids: set[int] = set()
        pslist_info: dict[int, dict[str, Any]] = {}

        for row in pslist:
            pid = _to_int(_get(row, "PID", "Pid"))
            if pid is None:
                continue
            pslist_pids.add(pid)
            ppid = _to_int(_get(row, "PPID", "Ppid"))
            create_raw = _get(row, "CreateTime")
            name = str(_get(row, "ImageFileName", "Name", default=f"pid-{pid}"))
            start = _parse_ts(create_raw)
            pslist_info[pid] = {"name": name, "ppid": ppid, "start": start, "start_raw": create_raw}
            proc = Process(
                pid=pid,
                ppid=ppid,
                name=name,
                path=_get(row, "Path"),
                cmdline=cmdlines.get(pid),
                start_time=start,
                session_id=session_id,
                flags=[],
                severity="info",
                extra={"source": "memprocfs.pslist"},
            )
            session.add(proc)
            stats["processes"] += 1
        session.commit()

        # Network rows are parsed early so psscan/malfind can correlate against them.
        connections = _collect_connections(results)
        net_pids = {c["pid"] for c in connections if c["pid"] is not None}
        external_net_pids = {
            c["pid"] for c in connections
            if c["pid"] is not None and c["raddr"] and not _is_private_addr(c["raddr"])
        }

        # --- psscan vs pslist: graded hidden-process analysis ---
        # psscan pool-scans EPROCESS blocks, so it legitimately resurfaces terminated
        # processes, stale pool memory and acquisition smear. DKOM unlinking is only
        # claimed when independent live artifacts corroborate it.
        progress("memory", 71.0, "Correlating psscan against pslist", False, None)
        psscan_rows: dict[int, dict[str, Any]] = {}
        for row in results.get("psscan", []):
            pid = _to_int(_get(row, "PID", "Pid"))
            if pid is not None:
                psscan_rows[pid] = row

        parent_pids = {info["ppid"] for info in pslist_info.values() if info["ppid"] is not None}
        corroboration_sources = {
            "network-connections": net_pids,
            "cmdline": _pids_from(results.get("cmdline", [])),
            "handles": _pids_from(results.get("handles", [])),
            "envars": _pids_from(results.get("envars", [])),
            "privileges": _pids_from(results.get("privileges", [])),
            "getsids": _pids_from(results.get("getsids", [])),
            "suspicious-threads": _pids_from(results.get("suspicious_threads", [])),
            "parent-of-visible-process": parent_pids,
        }

        hidden_flag_pids: set[int] = set()
        for pid, row in sorted(psscan_rows.items()):
            name = str(_get(row, "ImageFileName", "Name", default=f"pid-{pid}"))
            create_raw = _get(row, "CreateTime")
            exit_raw = _get(row, "ExitTime")
            create_time = _parse_ts(create_raw)
            exit_time = _parse_ts(exit_raw)

            if pid in pslist_pids:
                live = pslist_info[pid]
                same_name = name.lower() == live["name"].lower()
                same_start = create_time is None or live["start"] is None or create_time == live["start"]
                if not (same_name and same_start):
                    # PID reuse of freed pool memory: the stale EPROCESS belongs to an
                    # earlier process that happened to share the PID. Not hiding.
                    _add_memory_result(
                        session, "psscan", pid, name,
                        f"psscan recovered a stale EPROCESS for pid {pid} ({name}) that differs "
                        f"from the live process {live['name']} - PID reuse of freed pool memory, "
                        "not process hiding.",
                        {"pid": pid, "psscan_name": name, "pslist_name": live["name"],
                         "create_time": str(create_raw), "pslist_create_time": str(live["start_raw"]),
                         "exit_time": str(exit_raw) if exit_raw is not None else None,
                         "pid_reuse": True, "corroborating": []},
                        "info",
                    )
                continue

            corroborating = sorted(
                src for src, pids in corroboration_sources.items() if pid in pids
            )
            data = {
                "pid": pid, "name": name,
                "create_time": str(create_raw) if create_raw is not None else None,
                "exit_time": str(exit_raw) if exit_raw is not None else None,
                "create_time_plausible": _plausible_time(create_time),
                "corroborating": corroborating,
                "pid_reuse": False,
                "source": str(_get(row, "Source", default="memprocfs.crossview") or "memprocfs.crossview"),
            }

            if exit_time is not None:
                severity, flag = "info", "terminated"
                summary = (
                    f"{name} (pid {pid}) recovered by psscan with ExitTime {exit_raw}: "
                    "terminated process remnant in unreused pool memory, not a hidden process."
                )
            elif not data["create_time_plausible"] and not corroborating:
                severity, flag = "low", "psscan-artifact"
                summary = (
                    f"cross-view-only entry {name} (pid {pid}) from {data['source']} has an implausible or missing "
                    f"CreateTime ({create_raw}) and no corroborating artifacts - probable pool "
                    "reuse or acquisition smear artifact rather than a hidden process."
                )
            elif corroborating:
                # Corroborated but with a damaged-looking timestamp is slightly less certain.
                severity = "critical" if data["create_time_plausible"] else "high"
                flag = "hidden"
                summary = (
                    f"MemProcFS cross-view candidate for {name} (pid {pid}) is absent from the active "
                    f"process list, has no ExitTime, and has corroborating live artifacts "
                    f"({', '.join(corroborating)}) - consistent with DKOM process unlinking. "
                    "Verify against acquisition smear before concluding."
                )
                hidden_flag_pids.add(pid)
            else:
                severity, flag = "medium", "hidden-candidate"
                summary = (
                    f"{name} (pid {pid}) found only by MemProcFS cross-view evidence with no ExitTime and a plausible "
                    "CreateTime, but zero corroborating artifacts. Could be DKOM unlinking, a "
                    "very recent termination (exit not yet stamped), or acquisition smear - "
                    "needs manual confirmation."
                )
                hidden_flag_pids.add(pid)

            proc = Process(
                pid=pid,
                ppid=_to_int(_get(row, "PPID", "Ppid")),
                name=name,
                cmdline=cmdlines.get(pid),
                start_time=create_time,
                session_id=session_id,
                flags=[flag],
                severity=severity,
                extra={"source": "memprocfs.psscan", **data},
            )
            session.add(proc)
            stats["processes"] += 1
            _add_memory_result(session, "psscan", pid, name, summary, data, severity)
            _add_event(
                session, name, "process", summary, severity,
                {"pid": pid, "plugin": "psscan", "flag": flag, "corroborating": corroborating},
            )
        session.commit()

        # --- Driver inventory + hidden-driver correlation (modules vs pool scans) ---
        progress("memory", 74.0, "Building driver inventory and hidden-driver diff", False, None)
        modules_rows = results.get("modules", [])
        have_modules = bool(modules_rows)
        known_driver_names: dict[str, str] = {}  # name / stem -> path
        known_driver_bases: set[int] = set()
        for row in modules_rows:
            name = str(_get(row, "Name", default="") or "").strip()
            path = str(_get(row, "Path", default="") or "").strip()
            base = _to_int(_get(row, "Base"))
            size = _get(row, "Size")
            if name:
                n = name.lower()
                known_driver_names[n] = path
                known_driver_names.setdefault(n.rsplit(".", 1)[0], path)
            if base is not None:
                known_driver_bases.add(base)
            _add_event(
                session, name or (hex(base) if base is not None else "?"), "driver",
                f"Loaded kernel driver: {name} base {hex(base) if base is not None else '?'} "
                f"size {size} path {path}",
                "info",
                {"name": name, "base": hex(base) if base is not None else None,
                 "size": size, "path": path, "plugin": "modules"},
            )

        callback_modules: set[str] = set()
        for row in results.get("callbacks", []):
            callback_modules |= _name_variants(str(_get(row, "Module", default="") or ""))
        ssdt_modules: set[str] = set()
        for row in results.get("ssdt", []):
            ssdt_modules |= _name_variants(str(_get(row, "Module", default="") or ""))

        # drivermodule's hidden flag is a corroboration signal, not a standalone verdict
        drivermodule_flagged: set[str] = set()
        for row in results.get("drivermodule", []):
            if _falsey(_get(row, "Known Exception", "KnownException")):
                for key in ("Driver Name", "Alternative Name", "Name"):
                    val = _get(row, key)
                    if val:
                        drivermodule_flagged |= _name_variants(str(val))

        # Diff pool scans against the linked-list view. Pool scans routinely resurface
        # legitimately unloaded drivers and freed pool memory, so grade by corroboration.
        pool_only: dict[str, dict[str, Any]] = {}
        if have_modules:
            for plugin_name in ("modscan", "driverscan"):
                for row in results.get(plugin_name, []):
                    name = str(_get(row, "Name", "Driver Name", default="") or "").strip()
                    base = _to_int(_get(row, "Base", "Start"))
                    path = str(_get(row, "Path", default="") or "").strip()
                    in_modules = bool(_name_variants(name) & set(known_driver_names)) or \
                        (base is not None and base in known_driver_bases)
                    if in_modules:
                        continue
                    key = _norm_driver_name(name) or (hex(base) if base is not None else "")
                    if not key:
                        continue
                    entry = pool_only.get(key)
                    if entry:
                        if plugin_name not in entry["found_by"]:
                            entry["found_by"].append(plugin_name)
                        if not entry["path"] and path:
                            entry["path"] = path
                    else:
                        pool_only[key] = {
                            "name": name, "base": base, "size": _get(row, "Size"),
                            "path": path, "found_by": [plugin_name],
                        }

        modscan_only_names: set[str] = set()
        for entry in pool_only.values():
            name = entry["name"] or (hex(entry["base"]) if entry["base"] is not None else "unknown")
            variants = _name_variants(entry["name"])
            modscan_only_names |= variants
            corroborated = []
            if variants & callback_modules:
                corroborated.append("callbacks")
            if variants & ssdt_modules:
                corroborated.append("ssdt")
            if variants & drivermodule_flagged:
                corroborated.append("drivermodule")
            path = entry["path"]
            found_by = "/".join(entry["found_by"])

            if "callbacks" in corroborated or "ssdt" in corroborated:
                severity = "critical"
                summary = (
                    f"Hidden driver (DKOM candidate): {name} found only by pool scan ({found_by}) "
                    f"yet referenced by active kernel hooks ({', '.join(corroborated)}). An "
                    "unloaded remnant should not own live callbacks/SSDT entries."
                )
            elif corroborated:
                severity = "high"
                summary = (
                    f"Pool-scan-only driver {name} ({found_by}) also flagged hidden by "
                    "drivermodule. Not linked in the loaded-modules list; candidate hidden "
                    "driver, though unloaded remnants can also trip this."
                )
            elif not path or not _system_path(path):
                severity = "medium"
                summary = (
                    f"Pool-scan-only driver {name} ({found_by}) with missing or non-standard "
                    f"path '{path or 'n/a'}'. Could be a hidden/unlinked driver, but also an "
                    "unloaded third-party driver remnant - review the path and signing."
                )
            else:
                severity = "low"
                summary = (
                    f"Driver {name} found only by pool scan ({found_by}) at a plausible system "
                    "path with no corroboration - likely an unloaded driver remnant or pool "
                    "scan artifact; verify manually."
                )
            data = {
                "in_modules": False, "corroborated_by": corroborated, "path": path,
                "base": hex(entry["base"]) if entry["base"] is not None else None,
                "size": entry["size"], "found_by": entry["found_by"],
            }
            _add_memory_result(session, "hidden-driver", None, name, summary, data, severity)
            if severity in ("high", "critical"):
                _add_event(session, name, "driver", summary, severity,
                           {"name": name, "plugin": "hidden-driver", "corroborated_by": corroborated})
        session.commit()

        # --- Kernel callbacks & SSDT, correlated against the known-modules set ---
        progress("memory", 78.0, "Correlating kernel callbacks and SSDT", False, None)
        for row in results.get("callbacks", []):
            module = str(_get(row, "Module", default="") or "").strip()
            status, severity = _grade_kernel_pointer(
                module, known_driver_names, modscan_only_names, have_modules)
            data = {k: str(v) for k, v in row.items() if k != "__depth__"}
            data["module_status"] = status
            if severity == "critical":
                data["related"] = "hidden-driver"
            _add_memory_result(
                session, "callbacks", None, module,
                f"Kernel callback: {_get(row, 'Type', default='')} in {module or 'unknown'} "
                f"-> {_get(row, 'Symbol', default='')} ({status})",
                data, severity,
            )
            if severity in ("high", "critical"):
                _add_event(
                    session, module or "unknown", "driver",
                    f"Kernel callback in suspicious module {module or 'unknown'}: {status}",
                    severity, {"module": module, "plugin": "callbacks", "status": status},
                )
        for row in results.get("ssdt", []):
            module = str(_get(row, "Module", default="") or "").strip()
            if have_modules:
                status, severity = _grade_kernel_pointer(
                    module, known_driver_names, modscan_only_names, have_modules)
            elif module and module.lower() not in ("ntoskrnl.exe", "win32k.sys", "ntoskrnl"):
                # no modules list to correlate against; fall back to the coarse whitelist
                status, severity = "uncorrelated (modules plugin unavailable)", "medium"
            else:
                continue
            if severity == "info":
                continue  # expected handlers (loaded system modules) would flood the results
            data = {k: str(v) for k, v in row.items() if k != "__depth__"}
            data["module_status"] = status
            if severity == "critical":
                data["related"] = "hidden-driver"
            _add_memory_result(
                session, "ssdt", None, module,
                f"SSDT entry handled by {module or 'unknown module'} "
                f"({_get(row, 'Symbol', default='')}): {status}",
                data, severity,
            )
            if severity in ("high", "critical"):
                _add_event(
                    session, module or "unknown", "driver",
                    f"SSDT handler in suspicious module {module or 'unknown'}: {status}",
                    severity, {"module": module, "plugin": "ssdt", "status": status},
                )
        session.commit()

        # --- Region/thread ground truth: VAD tree, thread starts, DLL load order ---
        # vadinfo/threads/vadwalk rows are reduced to lookup structures only; they are
        # never written per-row (vadinfo over every process is enormous). All three
        # degrade to empty maps when the plugin is absent, leaving grading unchanged.
        progress("memory", 79.0, "Building VAD and thread lookups", False, None)
        vad_by_pid = _build_vad_map(results.get("vadinfo", []))
        if not vad_by_pid:
            # vadwalk carries no protection/file columns, so it only ever supplies
            # region bounds for the thread-start check; shape stays "unbacked"/unresolved.
            vad_by_pid = _build_vad_map(results.get("vadwalk", []))
        threads_by_pid = _build_thread_map(results.get("threads", []))
        dll_paths_by_pid = _build_dll_map(results.get("dlllist", []))
        for bulky in ("vadinfo", "vadwalk", "threads"):
            results.pop(bulky, None)

        # ldrmodules findings are computed up front (against the VAD ground
        # truth) so malfind can use the EXE-LEVEL anomalies as corroboration.
        # Generic unlinked-DLL rows never corroborate malfind: they describe
        # the same kind of region-level quirk and the pairing would be circular.
        ldr_findings, ldr_skipped = _analyze_ldrmodules(results.get("ldrmodules", []), vad_by_pid)
        ldr_exe_level_pids = {f["pid"] for f in ldr_findings
                              if f["pid"] is not None and f["exe_level"]}

        # dlllist's first InLoadOrder entry is normally the main exe; a basename
        # mismatch with the pslist name is a second, independent hollowing view.
        dll_mismatch_pids: dict[int, str] = {}
        for pid, paths in dll_paths_by_pid.items():
            info = pslist_info.get(pid)
            if info and paths and _proc_name_mismatch(paths[0], info["name"]):
                dll_mismatch_pids[pid] = paths[0]

        # Prevalence dampener: per-process anomaly classes register here instead
        # of calling _mark_process directly; apply() runs before the final
        # cross-correlation so machine-wide artifacts cannot feed composites.
        prevalence = _PrevalenceTracker()

        # --- malfind: injected/executable private memory, aggregated per process ---
        # A JIT host or self-protecting AV produces hundreds of near-identical
        # RWX regions; per-region rows drown the queue without adding evidence.
        # One result/event per process, graded by its worst region.
        progress("memory", 80.0, "Analyzing injected code (malfind)", False, None)
        malfind_pids: set[int] = set()
        malfind_by_pid: dict[int | None, list[dict[str, Any]]] = {}
        for row in results.get("malfind", []):
            pid = _to_int(_get(row, "PID", "Pid"))
            if pid is not None:
                malfind_pids.add(pid)
            malfind_by_pid.setdefault(pid, []).append(row)

        severity_rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
        for pid, rows in sorted(malfind_by_pid.items(),
                                key=lambda kv: (kv[0] is None, kv[0] or 0)):
            name = str(_get(rows[0], "Process", "ImageFileName", default="unknown"))
            proc_corroborated: list[str] = []
            if pid is not None:
                if pid in hidden_flag_pids:
                    proc_corroborated.append("psscan-hidden")
                if pid in ldr_exe_level_pids:
                    proc_corroborated.append("ldrmodules")
                elif pid in dll_mismatch_pids:
                    proc_corroborated.append("dlllist-exe-mismatch")
                if pid in external_net_pids:
                    proc_corroborated.append("external-network")
            dll_paths = dll_paths_by_pid.get(pid, []) if pid is not None else []
            jit_evidence = _jit_runtime_evidence(name, dll_paths)
            jit = jit_evidence is not None

            regions = [_grade_malfind_region(row, pid, jit, proc_corroborated,
                                             vad_by_pid, threads_by_pid)
                       for row in rows]
            severity = "info"
            shape_hist: dict[str, int] = {}
            all_tids: list[int] = []
            extra_corr: list[str] = []
            any_mz = False
            for region in regions:
                severity = _max_severity(severity, region["severity"])
                shape_hist[region["vad_shape"]] = shape_hist.get(region["vad_shape"], 0) + 1
                any_mz = any_mz or region["mz_header"]
                for tid in region["thread_starts_in_region"]:
                    if tid not in all_tids:
                        all_tids.append(tid)
                for c in region["extra_corroboration"]:
                    if c not in extra_corr:
                        extra_corr.append(c)
            corroborated = proc_corroborated + extra_corr
            top_regions = sorted(
                regions, key=lambda r: -severity_rank.get(r["severity"], 0))[:3]
            worst = top_regions[0]

            # "injected" is only claimed on malfind's OWN strong evidence: an MZ
            # header, a thread starting in a region, or corroboration that is
            # not an exe-level loader anomaly (those carry hollowing-suspect
            # themselves - one region's evidence must not yield two flags).
            independent = [c for c in corroborated
                           if c not in ("ldrmodules", "dlllist-exe-mismatch")]
            strong_evidence = any_mz or bool(all_tids) or bool(independent)
            flag = "injected" if strong_evidence and severity in ("high", "critical") \
                else "rwx-anomaly"

            region_word = "region" if len(regions) == 1 else "regions"
            shape_desc = ", ".join(
                f"{count}x {shape}" for shape, count in
                sorted(shape_hist.items(), key=lambda kv: (-kv[1], kv[0])))
            summary = (
                f"{len(regions)} executable private memory {region_word} in {name} "
                f"(pid {pid}) ({shape_desc}). Worst region at {worst['address']}: "
                f"{worst['reason']}."
            )
            if worst["vad_notes"]:
                summary += " " + "; ".join(worst["vad_notes"]) + "."
            if jit_evidence and jit_evidence.startswith("runtime-dll:"):
                summary += (f" The process has {jit_evidence.split(':', 1)[1]} loaded, "
                            "so JIT-generated code is the expected explanation.")

            result = _add_memory_result(
                session, "malfind", pid, name, summary,
                {"pid": pid, "region_count": len(regions),
                 "vad_shape_histogram": shape_hist,
                 "top_regions": [{k: r[k] for k in
                                  ("address", "severity", "reason", "mz_header",
                                   "vad_shape", "vad", "thread_starts_in_region", "disasm")}
                                 for r in top_regions],
                 "mz_header": any_mz, "jit_process": jit, "jit_evidence": jit_evidence,
                 "thread_starts_in_region": all_tids,
                 "corroborated_by": corroborated},
                severity,
            )
            prevalence.register("malfind-region", pid, severity,
                                results=[result], flag=flag)
            _add_event(
                session, name, "process",
                f"{len(regions)} malfind {region_word} in {name} (pid {pid}); worst at "
                f"{worst['address']}: {worst['reason']}",
                severity, {"pid": pid, "plugin": "malfind", "region_count": len(regions),
                           "corroborated_by": corroborated,
                           "vad_shape_histogram": shape_hist,
                           "thread_starts_in_region": all_tids},
            )
        session.commit()

        # --- ldrmodules: unlinked / hollowing indicators ---
        # Exe-level findings (the hollowing signals) may exchange corroboration
        # with malfind and carry the hollowing-suspect flag. Generic unlinked-DLL
        # findings stay standalone leads: they neither take malfind corroboration
        # nor grant it (see the malfind pass), so one region's evidence can never
        # produce both the injected and hollowing-suspect flags.
        progress("memory", 83.0, "Checking module linkage (ldrmodules)", False, None)
        ldr_exe_finding_pids: set[int] = set()
        for f in ldr_findings:
            pid = f["pid"]
            mapped_base = _basename(f["mapped"])

            if not f["exe_level"]:
                detail = f["unlinked_vad"] or {}
                summary = (
                    f"Module linkage anomaly in {f['process']} (pid {f['pid']}): {f['mapped']} "
                    f"({', '.join(f['patterns'])}). The mapping is executable "
                    f"({detail.get('protection') or 'protection n/a'}"
                    + (", private/unbacked" if detail.get("private_unbacked") else "")
                    + "), so it is not a plain resource/data mapping, but a single "
                    "unlinked view without injection artifacts remains a lead - "
                    "review before concluding."
                )
                result = _add_memory_result(
                    session, "ldrmodules", pid, f["process"], summary,
                    {"pid": pid, "mapped": f["mapped"], "patterns": f["patterns"],
                     "InLoad": f["InLoad"], "InInit": f["InInit"], "InMem": f["InMem"],
                     "unlinked_vad": f["unlinked_vad"], "corroborated_by": []},
                    "medium",
                )
                prevalence.register("unlinked-module", pid, "medium",
                                    results=[result], flag="unlinked-module")
                continue

            if pid is not None:
                ldr_exe_finding_pids.add(pid)
            corroborated: list[str] = []
            if pid is not None and pid in malfind_pids:
                corroborated.append("malfind")
            if pid is not None and pid in dll_mismatch_pids:
                corroborated.append("dlllist-exe-mismatch")
            # An exe unlinked from the load-order list that dlllist (a different
            # walk of the same PEB lists) also cannot see is a stronger unlink claim.
            dll_paths = dll_paths_by_pid.get(pid, []) if pid is not None else []
            absent_from_dlllist = (
                "exe-not-in-load-order" in f["patterns"] and dll_paths
                and mapped_base not in {_basename(p) for p in dll_paths}
            )
            if absent_from_dlllist:
                corroborated.append("absent-from-dlllist")

            # Hollowed-image shape: what does the VAD mapping the main exe look like?
            exe_vad_detail = None
            hollowing_suspect = "exe-name-mismatch" in f["patterns"] or \
                (pid is not None and pid in dll_mismatch_pids)
            if hollowing_suspect:
                anomalous, exe_vad_detail = _check_exe_vad(
                    vad_by_pid.get(pid, []) if pid is not None else [], mapped_base)
                if anomalous:
                    corroborated.append("exe-vad-anomalous")

            if "exe-vad-anomalous" in corroborated:
                severity = "critical" if len(corroborated) > 1 else "high"
            elif corroborated:
                severity = "high"
            else:
                severity = "medium"
            summary = (
                f"Module linkage anomaly in {f['process']} (pid {f['pid']}): {f['mapped']} "
                f"({', '.join(f['patterns'])})."
            )
            if "malfind" in corroborated:
                summary += " Same process also has malfind-flagged memory - consistent with process hollowing."
            if "dlllist-exe-mismatch" in corroborated:
                summary += (f" dlllist's first load-order module ({dll_mismatch_pids[pid]}) also "
                            "disagrees with the process name - a second view supporting hollowing.")
            if absent_from_dlllist:
                summary += " The exe is additionally absent from the dlllist load-order view."
            if exe_vad_detail is not None:
                if "exe-vad-anomalous" in corroborated:
                    summary += (f" The main-exe VAD is anomalous ({exe_vad_detail['reason']}) - "
                                "the hollowed-image shape.")
                elif exe_vad_detail["status"] == "image-vad-normal":
                    summary += (f" The main-exe VAD looks normal (file-backed, "
                                f"{exe_vad_detail.get('protection') or 'protection n/a'}).")
            if not corroborated:
                summary += (" No corroborating injection artifacts; single-list mismatches can be "
                            "benign (unloaded module, mapping quirks) - review before concluding.")
            result = _add_memory_result(
                session, "ldrmodules", pid, f["process"], summary,
                {"pid": pid, "mapped": f["mapped"], "patterns": f["patterns"],
                 "InLoad": f["InLoad"], "InInit": f["InInit"], "InMem": f["InMem"],
                 "absent_from_dlllist": absent_from_dlllist, "exe_vad": exe_vad_detail,
                 "corroborated_by": corroborated},
                severity,
            )
            prevalence.register("exe-anomaly", pid, severity,
                                results=[result], flag="hollowing-suspect")
            if severity in ("high", "critical"):
                _add_event(
                    session, f["process"], "process", summary, severity,
                    {"pid": pid, "plugin": "ldrmodules", "patterns": f["patterns"],
                     "corroborated_by": corroborated},
                )

        # Rows not reported are counted for transparency: resource/data image
        # mappings, non-executable or unresolvable VADs, and pseudo-process
        # system mappings are all expected to be absent from loader lists.
        ldr_skipped_total = sum(ldr_skipped.values())
        if ldr_skipped_total:
            _add_memory_result(
                session, "ldrmodules", None, None,
                f"ldrmodules: {ldr_skipped_total} mapped-image rows not reported - "
                "resource/data mappings (.mui/.mun/.winmd/fonts), non-executable or "
                "unresolved VADs, and pseudo-process system mappings are legitimately "
                "absent from the loader lists.",
                {"skipped": ldr_skipped}, "info",
            )

        # dlllist exe mismatches that ldrmodules did not surface (e.g. ldrmodules
        # absent or the entry hidden from it entirely) still deserve a finding.
        for pid, first_module in sorted(dll_mismatch_pids.items()):
            if pid in ldr_exe_finding_pids:
                continue  # already folded into the exe-level ldrmodules finding above
            proc_name = pslist_info.get(pid, {}).get("name", "unknown")
            corroborated = ["malfind"] if pid in malfind_pids else []
            anomalous, exe_vad_detail = _check_exe_vad(
                vad_by_pid.get(pid, []), _basename(first_module))
            if anomalous:
                corroborated.append("exe-vad-anomalous")
            if "exe-vad-anomalous" in corroborated:
                severity = "critical" if len(corroborated) > 1 else "high"
            else:
                severity = "high" if corroborated else "medium"
            summary = (
                f"dlllist's first load-order module for {proc_name} (pid {pid}) is "
                f"{first_module}, which does not match the process name - a possible "
                "hollowing indicator."
            )
            if anomalous:
                summary += (f" The main-exe VAD is anomalous ({exe_vad_detail['reason']}) - "
                            "the hollowed-image shape.")
            elif exe_vad_detail["status"] == "image-vad-normal":
                summary += (f" The main-exe VAD looks normal (file-backed, "
                            f"{exe_vad_detail.get('protection') or 'protection n/a'}).")
            if not corroborated:
                summary += " No other injection artifacts corroborate it - review before concluding."
            result = _add_memory_result(
                session, "dlllist", pid, proc_name, summary,
                {"pid": pid, "first_module": first_module, "exe_vad": exe_vad_detail,
                 "corroborated_by": corroborated},
                severity,
            )
            prevalence.register("exe-anomaly", pid, severity,
                                results=[result], flag="hollowing-suspect")
            if severity in ("high", "critical"):
                _add_event(
                    session, proc_name, "process", summary, severity,
                    {"pid": pid, "plugin": "dlllist", "corroborated_by": corroborated},
                )
        session.commit()

        # --- skeleton_key_check: lsass authentication-package patch ---
        # A positive hit is inherently a strong single signal; no corroboration needed.
        progress("memory", 85.0, "Checking lsass for skeleton-key patch", False, None)
        for row in results.get("skeleton_key_check", []):
            found = _get(row, "Skeleton Key Found", "SkeletonKeyFound", "Skeleton Key", "Found")
            if found is None or _falsey(found):
                continue
            pid = _to_int(_get(row, "PID", "Pid"))
            proc_name = str(_get(row, "Process", default="lsass.exe"))
            summary = (
                f"Skeleton-key patch detected in {proc_name} (pid {pid}): the in-memory "
                "authentication package is modified to accept an attacker master password. "
                "This has no benign explanation."
            )
            _add_memory_result(
                session, "skeleton_key", pid, proc_name, summary,
                {"pid": pid, "raw": {k: str(v) for k, v in row.items() if k != "__depth__"}},
                "critical",
            )
            _mark_process(session, session_id, pid, "skeleton-key", "critical")
            _add_event(
                session, proc_name, "process", summary, "critical",
                {"pid": pid, "plugin": "skeleton_key"},
            )
        session.commit()

        # --- Network connections (deduped netscan/netstat) ---
        progress("memory", 86.0, "Extracting network connections", False, None)
        for conn in connections:
            pid = conn["pid"]
            owner = str(conn["owner"] or "")
            external = bool(conn["raddr"]) and not _is_private_addr(conn["raddr"])
            reasons = []
            if pid is not None and pid in hidden_flag_pids:
                reasons.append("owning process is a psscan-only hidden/hidden-candidate process")
            if pid is not None and pid in malfind_pids and external:
                reasons.append("owning process has malfind-flagged memory and a non-private remote address")
            severity = "high" if reasons else "info"
            raw = {
                "Laddr": conn["laddr"], "Lport": conn["lport"], "Raddr": conn["raddr"],
                "Rport": conn["rport"], "Proto": conn["proto"], "State": str(conn["state"]),
                "Owner": owner, "PID": pid, "plugin": conn["plugins"][0],
                "seen_by": conn["plugins"], "external": external,
            }
            if "netscan" in conn["plugins"]:
                raw["pool_scan_note"] = ("netscan is a pool scan and can resurface "
                                         "closed/stale connections")
            _add_event(
                session, owner, "network",
                f"{conn['proto']} {conn['laddr']}:{conn['lport']} -> "
                f"{conn['raddr']}:{conn['rport']} {conn['state'] or ''} ({owner} pid {pid})",
                severity, raw,
            )
            if reasons:
                _add_memory_result(
                    session, "netscan", pid, owner,
                    f"Suspicious connection {conn['proto']} {conn['laddr']}:{conn['lport']} -> "
                    f"{conn['raddr']}:{conn['rport']} ({owner} pid {pid}): " + "; ".join(reasons) + ".",
                    {"pid": pid, "conn": {k: v for k, v in raw.items() if k != "pool_scan_note"},
                     "corroborated_by": reasons},
                    "high",
                )
                _mark_process(session, session_id, pid, "suspicious-network", "high")
        session.commit()

        # --- Process handles and cross-process access ---
        # Handle maps can block in MemProcFS for ordinary processes. They are
        # collected and cached by the entity drawer's on-demand handle endpoint.
        if results.get("handles"):
            progress("memory", 87.0, "Recording process handles and cross-process access", False, None)
            _record_process_handles(session, session_id, results.get("handles", []), pslist_info)
            session.commit()

        # --- Services ---
        progress("memory", 88.0, "Recording services", False, None)
        for row in results.get("svcscan", []):
            name = str(_get(row, "Name", default=""))
            binary = str(_get(row, "Binary", "Binary Path", default=""))
            state = str(_get(row, "State", default=""))
            b = binary.lower().replace("/", "\\")
            susp_dirs = sorted({d for d in USER_WRITABLE_DIR_FRAGMENTS if d in b})
            severity = "medium" if susp_dirs else "info"
            _add_event(
                session, name, "persistence",
                f"Service: {name} [{state}] -> {binary}",
                severity, {"service": name, "binary": binary, "state": state, "plugin": "svcscan"},
            )
            if susp_dirs:
                _add_memory_result(
                    session, "svcscan", None, name,
                    f"Service {name} [{state}] runs from a user-writable/staging path: {binary}. "
                    "Legitimate services rarely live there; common malware persistence pattern.",
                    {"service": name, "binary": binary, "state": state,
                     "suspicious_path_fragments": susp_dirs},
                    "medium",
                )
        session.commit()

        # --- Prevalence dampener: machine-wide patterns are artifacts, not evasion ---
        # Applies the deferred process flags and downgrades any anomaly class
        # that fired across a large fraction of processes; must run before the
        # cross-correlation below so dampened flags cannot feed composites.
        progress("memory", 89.0, "Applying prevalence dampener", False, None)
        prevalence.apply(session, session_id, len(pslist_pids))
        session.commit()

        # --- Final cross-correlation: multiple independent indicators on one PID ---
        progress("memory", 90.0, "Cross-correlating memory indicators", False, None)
        from app.detect.engine import SEVERITY_RANK
        for proc in session.scalars(select(Process).where(Process.session_id == session_id)):
            hits = sorted((set(proc.flags or []) & SUSPICIOUS_MEMORY_FLAGS)
                          - prevalence.flags_to_ignore(proc.pid))
            if len(hits) < 2:
                continue
            _add_memory_result(
                session, "correlation", proc.pid, proc.name,
                f"Multiple independent memory indicators for {proc.name} (pid {proc.pid}): "
                f"{', '.join(hits)}. Independent artifacts reinforcing each other make a "
                "benign explanation unlikely.",
                {"pid": proc.pid, "flags": hits}, "critical",
            )
            if SEVERITY_RANK.get(proc.severity, 0) < SEVERITY_RANK["critical"]:
                proc.severity = "critical"
            _add_event(
                session, proc.name, "process",
                f"Multiple independent memory indicators: {proc.name} (pid {proc.pid}) - "
                f"{', '.join(hits)}",
                "critical", {"pid": proc.pid, "flags": hits, "plugin": "correlation"},
            )
        session.commit()

        # --- YARA scan of process memory ---
        progress("memory", 92.0, "YARA scanning process memory for APT indicators", False, None)
        scanner = get_scanner()
        if scanner.available():
            _yara_scan_processes(session, dump_path, session_id, stats, progress, results)
        else:
            progress("memory", 94.0, "YARA not available; skipping signature scan", False, None)
        session.commit()

        # persist plugin failures for transparency
        failures = runner.failures()
        if failures:
            _add_memory_result(
                session, "diagnostics", None, None,
                f"{len(failures)} MemProcFS map(s) could not be collected: " +
                ", ".join(f"{k.split('.')[-1]}" for k in failures),
                {"failures": failures}, "info",
            )
        if unsupported_capabilities:
            _add_memory_result(
                session, "diagnostics", None, None,
                "MemProcFS migration: unsupported legacy memory views were skipped: "
                + ", ".join(unsupported_capabilities),
                {"unsupported_capabilities": unsupported_capabilities},
                "low",
            )
        session.commit()

        # run detections over the memory-derived processes/events too
        progress("detection", 96.0, "Running detections over memory artifacts", False, None)
        from app.detect.engine import run_detections_sync
        run_detections_sync(case_id)

        stats["memory_results"] = session.query(MemoryResult).count()
        return stats
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _yara_scan_processes(session, dump_path, session_id, stats, progress, results: dict[str, list[dict[str, Any]]]) -> None:
    """Dump each process's memory via vaddump-like approach is heavy; instead scan
    the whole dump file with YARA which still surfaces in-memory signatures, and
    additionally attribute suspicious MemProcFS regions when possible."""
    scanner = get_scanner()
    attributed_rules: set[str] = set()
    seen_regions: set[tuple[str, int | None, str]] = set()

    for row in results.get("malfind", []):
        sample = row.get("BytesSample")
        if not isinstance(sample, (bytes, bytearray)) or not sample:
            continue
        pid = _to_int(_get(row, "PID", "Pid"))
        process_name = str(_get(row, "Process", "ImageFileName", default=f"pid-{pid}" if pid is not None else "unknown"))
        start = _get(row, "Start", "Start VPN", "Address")
        end = _get(row, "End", "End VPN")
        for hit in scanner.scan_bytes(bytes(sample)):
            rule = hit.get("rule")
            key = (str(rule), pid, str(start))
            if key in seen_regions:
                continue
            seen_regions.add(key)
            attributed_rules.add(str(rule))
            meta = hit.get("meta", {})
            severity = meta.get("severity", "high")
            stats["yara_hits"] += 1
            summary = (
                f"YARA match in {process_name} (pid {pid}) at memory region {start}-{end}: "
                f"{rule} - {meta.get('description', '')}"
            )
            data = {
                "rule": rule,
                "meta": meta,
                "tags": hit.get("tags", []),
                "strings": hit.get("strings", []),
                "attribution": {
                    "type": "process_memory_region",
                    "session_id": session_id,
                    "pid": pid,
                    "process": process_name,
                    "start": str(start) if start is not None else None,
                    "end": str(end) if end is not None else None,
                    "protection": _get(row, "Protection"),
                    "source": "memprocfs.malfind",
                },
            }
            _add_memory_result(session, "yara", pid, process_name, summary, data, severity)
            _mark_process(session, session_id, pid, "yara-hit", severity)
            _add_event(
                session, process_name, "process", summary, severity,
                {"pid": pid, "rule": rule, "attck": meta.get("attck"), "plugin": "yara",
                 "attribution": data["attribution"]},
            )

    # Scan raw dump file as fallback; it gives presence when no process/region
    # attribution was possible for a rule.
    hits = scanner.scan_file(dump_path)
    for hit in hits:
        if str(hit.get("rule")) in attributed_rules:
            continue
        meta = hit.get("meta", {})
        stats["yara_hits"] += 1
        _add_memory_result(
            session, "yara", None, None,
            f"YARA match: {hit['rule']} - {meta.get('description', '')}",
            {"rule": hit["rule"], "meta": meta, "tags": hit.get("tags", []),
             "attribution": {"type": "raw_memory_dump", "session_id": session_id,
                             "path": str(dump_path), "note": "no process/region attribution available"}},
            meta.get("severity", "high"),
        )
        _add_event(
            session, hit["rule"], "memory",
            f"YARA signature '{hit['rule']}' matched in memory: {meta.get('description', '')}",
            meta.get("severity", "high"),
            {"rule": hit["rule"], "attck": meta.get("attck"), "plugin": "yara",
             "attribution": {"type": "raw_memory_dump", "session_id": session_id,
                             "path": str(dump_path), "note": "no process/region attribution available"}},
        )


def _add_memory_result(session, plugin, pid, process_name, summary, data, severity) -> MemoryResult:
    result = MemoryResult(
        plugin=plugin, pid=pid, process_name=process_name,
        summary=summary, data=data, severity=severity,
    )
    session.add(result)
    return result


def _add_event(session, entity, category, summary, severity, raw) -> None:
    case_store.add_event(
        session,
        timestamp=None, host=None, source=f"memory:{raw.get('plugin', 'memprocfs')}",
        category=category, entity=entity, severity=severity, summary=summary, raw=raw,
    )


def _mark_process(session, session_id, pid, flag, severity) -> None:
    if pid is None:
        return
    proc = session.scalars(
        select(Process).where(Process.session_id == session_id, Process.pid == int(pid))
    ).first()
    if proc:
        flags = set(proc.flags or [])
        flags.add(flag)
        proc.flags = sorted(flags)
        from app.detect.engine import SEVERITY_RANK
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(proc.severity, 0):
            proc.severity = severity
