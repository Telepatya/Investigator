"""Linux log parsing: syslog / auth.log (RFC3164, RFC5424, ISO rsyslog), auditd
audit.log, and journald JSON export.

All three sources normalize onto the same unified Event schema as the Windows
parsers, and every emitted event stamps raw["linux_log"] = True plus a small,
stable vocabulary of raw keys (AuthProto/AuthOutcome/SrcIp/AuthUser,
LinuxAccountAction, CommandLine, ...) so the detection engine has a single Linux
code path regardless of how the record arrived (raw file vs Sentinel Syslog
table vs journald)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.ingest.normalize import parse_timestamp, truncate

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# RFC3164: "Jul 12 05:03:22 host ident[pid]: message" (no year, single-digit day
# may be space-padded). Optional <PRI> prefix.
_RFC3164_RE = re.compile(
    r"^(?:<\d+>)?(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)
# ISO-prefixed rsyslog (RSYSLOG_FileFormat): "2026-07-12T05:03:22.123456+00:00 host rest".
_ISO_SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$"
)
# RFC5424: "<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG".
_RFC5424_RE = re.compile(
    r"^<\d+>1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+(?P<rest>.*)$"
)
# "ident[pid]: message" tail shared by RFC3164 / ISO forms. ident may contain
# '/', '.', '-' (e.g. postfix/smtpd, systemd-logind).
_IDENT_RE = re.compile(r"^(?P<ident>[\w./@-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
# Leading RFC5424 structured-data block ("[sd ...]" or "-").
_RFC5424_SD_RE = re.compile(r"^(?:-|\[(?:[^\]\\]|\\.)*\])\s*")


def _infer_year(mon: int, day: int, time_str: str, hint_dt: datetime) -> datetime | None:
    """Build a tz-aware datetime for an RFC3164 line (no year). Uses hint_dt.year;
    if the result lands more than ~2 days after the hint (a log written in Jan
    referencing a Dec event), roll back one year."""
    try:
        hh, mm, ss = (int(x) for x in time_str.split(":"))
        dt = datetime(hint_dt.year, mon, day, hh, mm, ss, tzinfo=timezone.utc)
    except ValueError:
        return None
    if dt > hint_dt + timedelta(days=2):
        try:
            dt = dt.replace(year=hint_dt.year - 1)
        except ValueError:
            return None
    return dt


def parse_syslog_line(line: str, hint_dt: datetime) -> dict[str, Any] | None:
    """Parse one syslog line into {ts, host, ident, pid, message}, or None."""
    m = _RFC3164_RE.match(line)
    if m:
        ts = _infer_year(_MONTHS.get(m.group("mon"), 0), int(m.group("day")),
                         m.group("time"), hint_dt)
        return _split_ident(ts, m.group("host"), m.group("rest"))
    m = _ISO_SYSLOG_RE.match(line)
    if m:
        return _split_ident(parse_timestamp(m.group("ts")), m.group("host"), m.group("rest"))
    m = _RFC5424_RE.match(line)
    if m:
        rest = _RFC5424_SD_RE.sub("", m.group("rest"))
        app = m.group("app")
        pid = m.group("pid")
        return {
            "ts": parse_timestamp(m.group("ts")),
            "host": _dash_none(m.group("host")),
            "ident": _dash_none(app) or "",
            "pid": _dash_none(pid) or "",
            "message": rest,
        }
    return None


def _dash_none(val: str | None) -> str | None:
    return None if val in (None, "-") else val


def _split_ident(ts: datetime | None, host: str, rest: str) -> dict[str, Any]:
    m = _IDENT_RE.match(rest)
    if m:
        return {"ts": ts, "host": _dash_none(host), "ident": m.group("ident"),
                "pid": m.group("pid") or "", "message": m.group("msg")}
    return {"ts": ts, "host": _dash_none(host), "ident": "", "pid": "", "message": rest}


# ---------------------------------------------------------------------------
# Message classification (shared by raw syslog, Sentinel Syslog table, journald)
# ---------------------------------------------------------------------------

_SSH_FAILED_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/\S+) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE)
_SSH_INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE)
_SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE)
_PAM_AUTHFAIL_RE = re.compile(
    r"authentication failure;.*?(?:rhost=(?P<ip>\S+))?(?:\s+user=(?P<user>\S+))?\s*$",
    re.IGNORECASE)
_SUDO_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:.*?(?:USER=(?P<runas>\S+))?\s*;\s*COMMAND=(?P<cmd>.+)$")
_USERADD_RE = re.compile(r"new user:\s*name=(?P<name>[^\s,]+)", re.IGNORECASE)
_GROUPADD_RE = re.compile(r"new group:\s*name=(?P<name>[^\s,]+)", re.IGNORECASE)
_USERMOD_ADD_RE = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'", re.IGNORECASE)
_GPASSWD_RE = re.compile(r"user (?P<user>\S+) added by \S+ to group (?P<group>\S+)", re.IGNORECASE)
_USERDEL_RE = re.compile(r"(?:delete|remove(?:d)?) user '?(?P<user>[^'\s]+)", re.IGNORECASE)
_CRON_CMD_RE = re.compile(r"^\((?P<user>[^)]+)\)\s+CMD\s+\((?P<cmd>.*)\)\s*$")
_CRONTAB_RE = re.compile(r"^\((?P<user>[^)]+)\)\s+(?P<action>REPLACE|EDIT|DELETE|LIST)\b")

def classify_syslog_event(
    rec: dict[str, Any], source: str, extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Turn a parsed syslog record into a unified Event dict, classifying by the
    program (ident) and message text. `extra` seeds additional raw keys (e.g. the
    Facility/SeverityLevel columns of the Sentinel Syslog table)."""
    ident = (rec.get("ident") or "").lower()
    msg = rec.get("message") or ""
    raw: dict[str, Any] = {"linux_log": True, "log_line": truncate(_reassemble(rec), 1000)}
    if extra:
        raw.update({k: v for k, v in extra.items() if v not in (None, "")})
    if rec.get("ident"):
        raw["Ident"] = rec["ident"]
    if rec.get("pid"):
        raw["ProcessId"] = rec["pid"]

    category = "log"
    entity: str | None = rec.get("host")
    summary = truncate(msg or _reassemble(rec), 400)

    base_ident = ident.split("/", 1)[0]  # postfix/smtpd -> postfix

    if base_ident == "sshd" or "sshd" in ident:
        category, entity, summary = _classify_ssh(msg, raw, entity, summary)
    elif base_ident == "sudo":
        category, entity, summary = _classify_sudo(msg, raw, entity, summary)
    elif base_ident in ("useradd", "groupadd", "usermod", "gpasswd", "userdel", "chpasswd"):
        category, entity, summary = _classify_account(base_ident, msg, raw, entity, summary)
    elif base_ident in ("cron", "cronie") or ident == "crond":
        category, entity, summary = _classify_cron(msg, raw, entity, summary)
    elif base_ident == "crontab":
        m = _CRONTAB_RE.match(msg)
        if m:
            category = "persistence"
            raw["CronAction"] = m.group("action")
            raw["CronUser"] = m.group("user")
            summary = f"crontab {m.group('action')} by {m.group('user')}"
    elif base_ident in ("su", "login") or "pam_unix" in msg.lower():
        category, entity, summary = _classify_pam(msg, raw, entity, summary, category)

    if category == "log" and _source_is_auth(source):
        category = "auth"

    return {
        "timestamp": rec.get("ts"),
        "host": rec.get("host"),
        "source": source,
        "category": category,
        "entity": entity,
        "severity": "info",
        "summary": summary,
        "raw": raw,
    }


def _reassemble(rec: dict[str, Any]) -> str:
    ident = rec.get("ident") or ""
    pid = rec.get("pid") or ""
    head = f"{ident}[{pid}]" if ident and pid else ident
    msg = rec.get("message") or ""
    return f"{head}: {msg}" if head else msg


def _source_is_auth(source: str) -> bool:
    low = (source or "").lower()
    return "auth" in low or "secure" in low


def _classify_ssh(msg, raw, entity, summary):
    raw["AuthProto"] = "ssh"
    m = _SSH_FAILED_RE.search(msg)
    if m:
        raw["AuthOutcome"] = "failure"
        raw["AuthUser"] = m.group("user")
        raw["SrcIp"] = m.group("ip")
        if m.group("invalid"):
            raw["InvalidUser"] = True
        return "auth", m.group("user"), f"SSH failed login: {m.group('user')} from {m.group('ip')}"
    m = _SSH_INVALID_RE.search(msg)
    if m:
        raw["AuthOutcome"] = "failure"
        raw["AuthUser"] = m.group("user")
        raw["SrcIp"] = m.group("ip")
        raw["InvalidUser"] = True
        return "auth", m.group("user"), f"SSH invalid user {m.group('user')} from {m.group('ip')}"
    m = _SSH_ACCEPTED_RE.search(msg)
    if m:
        user = m.group("user")
        raw["AuthOutcome"] = "success"
        raw["AuthUser"] = user
        raw["SrcIp"] = m.group("ip")
        raw["AuthMethod"] = m.group("method")
        if user == "root":
            raw["RootLogin"] = True
        return "auth", user, f"SSH accepted {m.group('method')}: {user} from {m.group('ip')}"
    return "auth", entity, summary


def _classify_sudo(msg, raw, entity, summary):
    m = _SUDO_RE.match(msg)
    if m:
        raw["SudoUser"] = m.group("user")
        raw["CommandLine"] = m.group("cmd").strip()
        if m.group("runas"):
            raw["RunAsUser"] = m.group("runas")
        return "auth", m.group("user"), f"sudo: {m.group('user')} ran {truncate(m.group('cmd').strip(), 200)}"
    return "auth", entity, summary


def _classify_account(base_ident, msg, raw, entity, summary):
    m = _USERADD_RE.search(msg)
    if m:
        raw["LinuxAccountAction"] = "new_user"
        raw["AccountName"] = m.group("name")
        muid = re.search(r"UID=(\d+)", msg)
        if muid:
            raw["AccountUid"] = muid.group(1)
        return "account", m.group("name"), f"Linux user created: {m.group('name')}"
    m = _GROUPADD_RE.search(msg)
    if m:
        raw["LinuxAccountAction"] = "new_group"
        raw["GroupName"] = m.group("name")
        return "account", m.group("name"), f"Linux group created: {m.group('name')}"
    m = _USERMOD_ADD_RE.search(msg) or _GPASSWD_RE.search(msg)
    if m:
        raw["LinuxAccountAction"] = "group_add"
        raw["AccountName"] = m.group("user")
        raw["GroupName"] = m.group("group")
        return "account", m.group("user"), f"User {m.group('user')} added to group {m.group('group')}"
    m = _USERDEL_RE.search(msg)
    if m:
        raw["LinuxAccountAction"] = "user_del"
        raw["AccountName"] = m.group("user")
        return "account", m.group("user"), f"Linux user deleted: {m.group('user')}"
    return "account", entity, summary


def _classify_cron(msg, raw, entity, summary):
    m = _CRON_CMD_RE.match(msg)
    if m:
        raw["CronUser"] = m.group("user")
        raw["CommandLine"] = m.group("cmd").strip()
        return "process", "cron", f"cron ({m.group('user')}): {truncate(m.group('cmd').strip(), 200)}"
    return "process", entity, summary


def _classify_pam(msg, raw, entity, summary, category):
    low = msg.lower()
    if "authentication failure" in low or "failed" in low:
        raw["AuthProto"] = raw.get("AuthProto", "pam")
        raw["AuthOutcome"] = "failure"
        m = _PAM_AUTHFAIL_RE.search(msg)
        if m:
            if m.group("ip"):
                raw["SrcIp"] = m.group("ip")
            if m.group("user"):
                raw["AuthUser"] = m.group("user")
        return "auth", entity, summary
    if "session opened" in low or "accepted" in low:
        raw["AuthProto"] = raw.get("AuthProto", "pam")
        raw["AuthOutcome"] = "success"
        muser = re.search(r"for (?:user )?(\S+)", msg)
        if muser:
            raw["AuthUser"] = muser.group(1).rstrip(":")
            if raw["AuthUser"] == "root":
                raw["RootLogin"] = True
        return "auth", raw.get("AuthUser", entity), summary
    return ("auth" if category == "log" else category), entity, summary


# ---------------------------------------------------------------------------
# auditd (audit.log)
# ---------------------------------------------------------------------------

_AUDIT_LINE_RE = re.compile(
    r"^(?:node=(?P<node>\S+)\s+)?type=(?P<type>\w+)\s+"
    r"msg=audit\((?P<ts>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s*(?P<body>.*)$")
_AUDIT_KV_RE = re.compile(r"(?P<k>\w+(?:\[\d+\])?)=(?P<v>\"[^\"]*\"|\([^)]*\)|\S+)")
# USER_* / CRED_* records nest their real key=values inside a single-quoted
# msg='op=... acct=... res=success' field; unwrap it before key=value parsing.
_AUDIT_NESTED_MSG_RE = re.compile(r"msg='([^']*)'")
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
_ARGV_KEY_RE = re.compile(r"^a(?P<n>\d+)(?:\[(?P<c>\d+)\])?$")

_AUDIT_PROC_TYPES = {"SYSCALL", "EXECVE"}
_AUDIT_AUTH_TYPES = {
    "USER_LOGIN", "USER_AUTH", "USER_ACCT", "USER_START", "USER_END",
    "CRED_ACQ", "CRED_DISP", "LOGIN", "USER_CMD", "ADD_USER", "ADD_GROUP",
    "USER_MGMT", "GRP_MGMT", "ACCT_LOCK",
}


def _audit_decode(val: str) -> str:
    """Decode an auditd field value: quoted -> literal; even-length hex -> bytes."""
    if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
        return val[1:-1]
    if val in ("(null)", "?"):
        return ""
    if len(val) >= 2 and len(val) % 2 == 0 and _HEX_RE.match(val):
        try:
            return bytes.fromhex(val).decode("utf-8", "replace")
        except ValueError:
            return val
    return val


def _reconstruct_argv(fields: dict[str, str]) -> str:
    """Rebuild a command line from EXECVE a0/a1/... (numeric order, chunked
    aN[M] continuations concatenated, hex-decoded)."""
    chunks: dict[int, dict[int, str]] = {}
    for key, val in fields.items():
        m = _ARGV_KEY_RE.match(key)
        if not m:
            continue
        n = int(m.group("n"))
        c = int(m.group("c")) if m.group("c") is not None else -1
        chunks.setdefault(n, {})[c] = val
    args: list[str] = []
    for n in sorted(chunks):
        parts = chunks[n]
        if -1 in parts and len(parts) == 1:
            args.append(_audit_decode(parts[-1]))
        else:
            joined = "".join(parts[c] for c in sorted(k for k in parts if k >= 0))
            args.append(_audit_decode(joined))
    return " ".join(a for a in args if a)


def _finalize_audit_event(records: list[tuple[str, dict[str, str]]], source: str) -> dict[str, Any] | None:
    """Merge the buffered records of one audit event id into a single Event."""
    if not records:
        return None
    by_type: dict[str, dict[str, str]] = {}
    paths: list[dict[str, str]] = []
    ts_val = None
    for rtype, fields in records:
        if ts_val is None and "_ts" in fields:
            ts_val = fields["_ts"]
        if rtype == "PATH":
            paths.append({
                "name": _audit_decode(fields.get("name", "")),
                "nametype": fields.get("nametype", ""),
            })
        else:
            by_type.setdefault(rtype, fields)

    syscall = by_type.get("SYSCALL", {})
    execve = by_type.get("EXECVE", {})
    proctitle = by_type.get("PROCTITLE", {})
    cwd = by_type.get("CWD", {})

    types = {rtype for rtype, _ in records}
    raw: dict[str, Any] = {"linux_log": True, "AuditType": next(iter(types), "")}

    cmdline = ""
    if execve:
        cmdline = _reconstruct_argv(execve)
    if not cmdline and proctitle.get("proctitle"):
        decoded = _audit_decode(proctitle["proctitle"])
        cmdline = decoded.replace("\x00", " ").strip()
    if cmdline:
        raw["CommandLine"] = truncate(cmdline, 1000)

    exe = _audit_decode(syscall.get("exe", "")) if syscall else ""
    comm = _audit_decode(syscall.get("comm", "")) if syscall else ""
    if exe:
        raw["Exe"] = exe
    if comm:
        raw["Comm"] = comm
    if cwd.get("cwd"):
        raw["Cwd"] = _audit_decode(cwd["cwd"])
    for src_key, dst_key in (("uid", "Uid"), ("auid", "Auid"), ("ses", "Ses"),
                             ("success", "Success"), ("syscall", "Syscall"),
                             ("key", "Key"), ("exit", "Exit")):
        val = syscall.get(src_key)
        if val not in (None, "", "(null)"):
            raw[dst_key] = _audit_decode(val)
    if paths:
        raw["Paths"] = paths

    category = "log"
    entity = None
    if types & _AUDIT_PROC_TYPES:
        category = "process"
        entity = comm or (exe.rsplit("/", 1)[-1] if exe else None)
        summary = f"Exec: {truncate(cmdline or exe or comm or '<unknown>', 300)}"
    elif types & _AUDIT_AUTH_TYPES:
        category = "auth"
        primary = next((f for t, f in records if t in _AUDIT_AUTH_TYPES), {})
        acct = _audit_decode(primary.get("acct", "")) or _audit_decode(primary.get("user", ""))
        addr = primary.get("addr", "") or primary.get("hostname", "")
        res = primary.get("res", "")
        op = _audit_decode(primary.get("op", "")).lower()
        group = _audit_decode(primary.get("grp", "")) or _audit_decode(primary.get("group", ""))
        raw["AuthProto"] = "auditd"
        raw["AuthOutcome"] = "success" if res == "success" else ("failure" if res else "")
        if acct:
            raw["AuthUser"] = acct
        if addr and addr not in ("?", "(null)"):
            raw["SrcIp"] = addr
        if acct == "root" and raw["AuthOutcome"] == "success":
            raw["RootLogin"] = True
        # Promote native audit account-management records onto the same stable
        # vocabulary used by useradd/usermod syslog messages, so the detection
        # engine does not depend on a duplicate prose log being present.
        if "ADD_USER" in types or op in ("add-user", "create-user"):
            raw["LinuxAccountAction"] = "new_user"
            if acct:
                raw["AccountName"] = acct
        elif "ADD_GROUP" in types or op in ("add-group", "create-group"):
            raw["LinuxAccountAction"] = "new_group"
            if group or acct:
                raw["GroupName"] = group or acct
        elif group and "add" in op and acct:
            raw["LinuxAccountAction"] = "group_add"
            raw["AccountName"] = acct
            raw["GroupName"] = group
        entity = acct or None
        summary = f"auditd {raw['AuditType']}: {acct or '<unknown>'} ({res or 'n/a'})"
    else:
        summary = f"auditd {raw['AuditType']}"

    return {
        "timestamp": parse_timestamp(float(ts_val)) if ts_val else None,
        "host": records[0][1].get("_node"),
        "source": source,
        "category": category,
        "entity": entity,
        "severity": "info",
        "summary": summary,
        "raw": raw,
    }


def is_auditd_line(line: str) -> bool:
    return bool(_AUDIT_LINE_RE.match(line.strip()))


def parse_auditd(path: Path, source: str) -> Iterator[dict[str, Any]]:
    """Parse an auditd audit.log, merging the contiguous records that share an
    audit event id (ts:serial) into one Event."""
    buffer: list[tuple[str, dict[str, str]]] = []
    current_serial: str | None = None
    MAX_RECORDS = 64

    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = _AUDIT_LINE_RE.match(line)
            if not m:
                continue
            rtype = m.group("type")
            serial = m.group("serial")
            fields: dict[str, str] = {"_ts": m.group("ts")}
            if m.group("node"):
                fields["_node"] = m.group("node")
            body = _AUDIT_NESTED_MSG_RE.sub(lambda mm: " " + mm.group(1) + " ", m.group("body"))
            for kv in _AUDIT_KV_RE.finditer(body):
                fields[kv.group("k")] = kv.group("v")

            if rtype == "EOE":
                if buffer:
                    ev = _finalize_audit_event(buffer, source)
                    if ev:
                        yield ev
                buffer = []
                current_serial = None
                continue

            if serial != current_serial or len(buffer) >= MAX_RECORDS:
                if buffer:
                    ev = _finalize_audit_event(buffer, source)
                    if ev:
                        yield ev
                buffer = []
                current_serial = serial
            buffer.append((rtype, fields))

    if buffer:
        ev = _finalize_audit_event(buffer, source)
        if ev:
            yield ev


# ---------------------------------------------------------------------------
# journald JSON export (journalctl -o json -> one JSON object per line)
# ---------------------------------------------------------------------------

def is_journald_row(row: dict[str, Any]) -> bool:
    if "__REALTIME_TIMESTAMP" in row:
        return True
    return "MESSAGE" in row and "_HOSTNAME" in row


def normalize_journald_row(row: dict[str, Any], source: str) -> dict[str, Any]:
    ts = None
    rt = row.get("__REALTIME_TIMESTAMP")
    if rt not in (None, ""):
        try:
            ts = parse_timestamp(int(rt))  # microseconds since epoch
        except (ValueError, TypeError):
            ts = parse_timestamp(rt)
    host = row.get("_HOSTNAME")
    ident = row.get("SYSLOG_IDENTIFIER") or row.get("_COMM") or ""
    pid = row.get("_PID") or row.get("SYSLOG_PID") or ""
    message = _as_text(row.get("MESSAGE"))

    rec = {"ts": ts, "host": host, "ident": ident, "pid": str(pid) if pid else "",
           "message": message}
    event = classify_syslog_event(rec, source)
    raw = event["raw"]
    # journald carries the resolved executable / command line directly.
    if row.get("_CMDLINE") and "CommandLine" not in raw:
        raw["CommandLine"] = truncate(_as_text(row.get("_CMDLINE")), 1000)
    if row.get("_EXE"):
        raw["Exe"] = _as_text(row.get("_EXE"))
    if row.get("_UID"):
        raw["Uid"] = str(row.get("_UID"))
    unit = row.get("_SYSTEMD_UNIT") or row.get("UNIT")
    if unit:
        raw["Unit"] = _as_text(unit)
    return event


def _as_text(val: Any) -> str:
    """journald MESSAGE/_CMDLINE can be a string or an array of byte values."""
    if isinstance(val, str):
        return val
    if isinstance(val, list):
        try:
            return bytes(int(b) for b in val).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return " ".join(str(v) for v in val)
    return "" if val is None else str(val)
