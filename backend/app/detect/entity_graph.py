"""Entity-action graph: extract actors (users, IPs, hosts, processes, services, accounts)
and the labeled actions between them from all ingested evidence.

This powers the Entity Action Map and dynamic per-entity investigation. Instead of
only showing a process tree, it reconstructs *who did what to what* across event logs,
web logs, process listings, network connections and memory analysis.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select

from app.memory.explorer import memory_process_candidates
from app.store import cases as case_store
from app.store.database import Event, Finding, Process

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Process flags that mean the process is no longer running.
_DEAD_PROCESS_FLAGS = {"terminated", "exited"}
# Service states (lowercased) that mean the service is not currently running.
_DEAD_SERVICE_STATES = {"stopped", "inactive", "disabled", "stop pending", "stopping"}

ENTITY_TYPES = (
    "user", "account", "host", "ip", "process", "service", "file", "url", "registry", "domain"
)

# Human-friendly verbs per Windows Event ID
EVENTID_VERB = {
    "4624": "logged on",
    "4625": "failed logon",
    "4634": "logged off",
    "4647": "logged off",
    "4648": "explicit-cred logon",
    "4672": "assigned admin rights",
    "4688": "executed",
    "4689": "exited process",
    "4720": "created account",
    "4722": "enabled account",
    "4724": "reset password",
    "4725": "disabled account",
    "4726": "deleted account",
    "4728": "added to global group",
    "4732": "added to local group",
    "4756": "added to universal group",
    "4697": "installed service",
    "7045": "installed service",
    "7036": "changed service state",
    "4698": "created scheduled task",
    "4702": "updated scheduled task",
    "1102": "cleared event log",
    "4826": "changed boot config",
    "1": "executed",
    "3": "network connection",
    "11": "created file",
    "13": "modified registry",
    "7": "loaded image",
}


def _norm(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s or s in ("-", "N/A", "?", "%%1843"):
        return None
    return s


def _basename(path: str) -> str:
    p = path.replace("\\", "/").rstrip("/")
    base = p.split("/")[-1]
    return base or path


def _looks_like_ip(v: str) -> bool:
    if v in ("::1", "127.0.0.1", "0.0.0.0", "::"):
        return True
    parts = v.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in v and any(c in "0123456789abcdefABCDEF" for c in v)


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}

    def node(self, etype: str, value: str) -> str | None:
        value = (value or "").strip()
        if not value:
            return None
        nid = f"{etype}::{value}"
        if nid not in self.nodes:
            self.nodes[nid] = {
                "id": nid,
                "type": etype,
                "value": value,
                "label": _basename(value) if etype in ("process", "file") else value,
                "severity": "info",
                "action_count": 0,
                "first_seen": None,
                "last_seen": None,
                "findings": [],
                "_event_severity": "info",
                "_process_severity": "info",
                "_finding_severity": "info",
                "meta": {},
            }
        return nid

    def mark_severity(self, nid: str | None, severity: str, source: str) -> None:
        if not nid or nid not in self.nodes:
            return
        n = self.nodes[nid]
        bucket = f"_{source}_severity"
        if bucket in n and SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(n[bucket], 0):
            n[bucket] = severity
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(n["severity"], 0):
            n["severity"] = severity

    def bump(self, nid: str | None, severity: str, ts: datetime | None, source: str = "event") -> None:
        if not nid or nid not in self.nodes:
            return
        n = self.nodes[nid]
        n["action_count"] += 1
        self.mark_severity(nid, severity, source)
        if ts:
            iso = ts.isoformat()
            if not n["first_seen"] or iso < n["first_seen"]:
                n["first_seen"] = iso
            if not n["last_seen"] or iso > n["last_seen"]:
                n["last_seen"] = iso

    def edge(
        self,
        src: str | None,
        dst: str | None,
        verb: str,
        severity: str,
        ts: datetime | None,
        summary: str,
    ) -> None:
        if not src or not dst or src == dst:
            return
        eid = f"{src}|{verb}|{dst}"
        if eid not in self.edges:
            self.edges[eid] = {
                "id": eid,
                "source": src,
                "target": dst,
                "verb": verb,
                "severity": "info",
                "count": 0,
                "last_seen": None,
                "samples": [],
            }
        e = self.edges[eid]
        e["count"] += 1
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(e["severity"], 0):
            e["severity"] = severity
        if ts:
            iso = ts.isoformat()
            if not e["last_seen"] or iso > e["last_seen"]:
                e["last_seen"] = iso
        if summary and len(e["samples"]) < 3:
            e["samples"].append(summary[:200])


def _extract_from_event(
    g: _Graph,
    ev: Event,
    suppressed_event_ids: set[int] | None = None,
    suppressed_propagation_entities: set[str] | None = None,
) -> None:
    raw = ev.raw or {}
    sev = ev.severity
    if suppressed_event_ids and ev.id in suppressed_event_ids:
        sev = "info"
    elif _is_suppressed_propagation(ev, suppressed_propagation_entities):
        sev = "info"
    ts = ev.timestamp
    cat = ev.category
    summary = ev.summary or ""

    if cat == "weblog":
        ip = _norm(raw.get("client_ip"))
        user = _norm(raw.get("user"))
        src = _norm(ev.source) or "web service"
        ip_node = g.node("ip", ip) if ip else None
        svc_node = g.node("host", f"web:{src}")
        if svc_node:
            g.nodes[svc_node]["label"] = f"Web service ({src})"
            g.nodes[svc_node]["meta"]["kind"] = "webservice"
        g.bump(ip_node, sev, ts)
        g.bump(svc_node, sev, ts)
        g.edge(ip_node, svc_node, "requested", sev, ts, summary)
        if user:
            status = str(raw.get("status") or "")
            acct = g.node("account", user)
            g.bump(acct, sev, ts)
            if status in ("200", "302"):
                g.edge(ip_node, acct, "authenticated as", "high" if sev == "info" else sev, ts, summary)
        return

    # Windows event log & process telemetry
    eid = str(raw.get("EventID") or "")
    verb = EVENTID_VERB.get(eid, None)
    host = _norm(raw.get("Computer") or raw.get("Hostname") or ev.host)
    actor = _norm(raw.get("SubjectUserName") or raw.get("User") or raw.get("AccountName"))
    target_user = _norm(raw.get("TargetUserName"))
    proc = _norm(raw.get("NewProcessName") or raw.get("Image") or raw.get("ProcessName"))
    parent = _norm(raw.get("ParentProcessName") or raw.get("ParentImage"))
    # EVTX 7045/4697/7036 service events (CamelCase keys) create a service node
    # just as before. Memory svcscan rows (lowercase "service" key) list *every*
    # service on the host -- surfacing all of them floods the map, so only bring
    # in svcscan services that were flagged suspicious (non-info severity), and
    # only those carry state / dead / binary detail.
    service = _norm(raw.get("ServiceName") or raw.get("Service Name") or raw.get("ServiceFileName"))
    svcscan_service = _norm(raw.get("service")) if raw.get("plugin") == "svcscan" else None
    if not service and svcscan_service and sev != "info":
        service = svcscan_service
    service_state = _norm(raw.get("state") or raw.get("State")) if svcscan_service else None
    service_binary = _norm(raw.get("binary") or raw.get("Binary")) if svcscan_service else None
    ip = _norm(raw.get("IpAddress") or raw.get("SourceIp") or raw.get("Raddr") or raw.get("DestinationIp"))
    if ip and not _looks_like_ip(ip):
        ip = None

    host_node = g.node("host", host) if host else None
    actor_node = g.node("user", actor) if actor else None
    proc_node = g.node("process", proc) if proc else None
    parent_node = g.node("process", parent) if parent else None
    ip_node = g.node("ip", ip) if ip else None

    for n in (host_node, actor_node, proc_node, parent_node, ip_node):
        g.bump(n, sev, ts)

    if parent_node and proc_node:
        g.edge(parent_node, proc_node, "spawned", sev, ts, summary)
    if actor_node and proc_node:
        g.edge(actor_node, proc_node, "executed", sev, ts, summary)
    if ip_node and host_node:
        g.edge(ip_node, host_node, verb or "connected to", sev, ts, summary)
    if actor_node and host_node and not proc_node:
        g.edge(actor_node, host_node, verb or "activity on", sev, ts, summary)

    if target_user:
        tgt = g.node("account", target_user)
        g.bump(tgt, sev, ts)
        g.edge(actor_node or host_node, tgt, verb or "modified account", sev, ts, summary)

    if service:
        svc = g.node("service", service)
        if svc:
            smeta = g.nodes[svc]["meta"]
            if service_state:
                smeta["state"] = service_state
                smeta["dead"] = service_state.lower() in _DEAD_SERVICE_STATES
            if service_binary:
                # a suspicious service's on-disk image, so a stopped service still
                # shows what it would run when revealed via the terminated toggle.
                fnode = g.node("file", service_binary)
                g.bump(fnode, sev, ts)
                g.edge(svc, fnode, "runs", sev, ts, summary)
        g.bump(svc, sev, ts)
        g.edge(actor_node or host_node, svc, verb or "installed service", sev, ts, summary)

    if eid in ("1102", "4826") and host_node:
        # host-scoped defense-evasion action
        g.edge(actor_node or host_node, host_node, verb or "modified host", sev, ts, summary)

    # network connections (memory netscan, sysmon 3, or Defender DeviceNetworkEvents)
    if cat == "network":
        # The initiating process lives under different keys per source: Owner
        # (netscan), Image (sysmon 3), InitiatingProcessFileName (Defender). Fall
        # back to the event entity, which the parsers set to the process basename.
        owner_raw = (
            raw.get("Owner") or raw.get("Process")
            or raw.get("InitiatingProcessFileName") or raw.get("Image")
            or raw.get("ProcessName") or ev.entity
        )
        owner = _basename(owner_raw) if owner_raw else None
        raddr = _norm(
            raw.get("Raddr") or raw.get("ForeignAddr")
            or raw.get("DestinationIp") or raw.get("RemoteIP")
        )
        oproc = g.node("process", owner) if owner else None
        rip = g.node("ip", raddr) if raddr and _looks_like_ip(raddr) else None
        g.bump(oproc, sev, ts)
        g.bump(rip, sev, ts)
        if oproc and rip:
            g.edge(oproc, rip, "connected to", sev, ts, summary)


def _extract_from_processes(g: _Graph, procs: list[Process]) -> None:
    by_pid: dict[int, Process] = {p.pid: p for p in procs}
    # nid -> [alive instances, dead instances, union of flags] so a process-name
    # node is marked dead only when every contributing process has exited.
    liveness: dict[str, list[Any]] = {}
    for p in procs:
        name = _basename(p.name or f"pid-{p.pid}")
        pnode = g.node("process", name)
        if pnode:
            g.nodes[pnode]["meta"].setdefault("pids", [])
            if p.pid not in g.nodes[pnode]["meta"]["pids"]:
                g.nodes[pnode]["meta"]["pids"].append(p.pid)
            if p.cmdline and not g.nodes[pnode]["meta"].get("cmdline"):
                g.nodes[pnode]["meta"]["cmdline"] = p.cmdline[:400]
            pflags = set(p.flags or [])
            agg = liveness.setdefault(pnode, [0, 0, set()])
            agg[2].update(pflags)
            if pflags & _DEAD_PROCESS_FLAGS:
                agg[1] += 1
            else:
                agg[0] += 1
        g.bump(pnode, p.severity, p.start_time, source="process")
        parent = by_pid.get(p.ppid) if p.ppid else None
        if parent:
            parent_name = _basename(parent.name or f"pid-{parent.ppid}")
            pn = g.node("process", parent_name)
            g.edge(pn, pnode, "spawned", "info", p.start_time,
                   f"{parent_name} -> {name} (pid {p.pid})")
        # owner user from extra if present
        owner = None
        if isinstance(p.extra, dict):
            owner = _norm(p.extra.get("user") or p.extra.get("Username") or p.extra.get("owner"))
        if owner:
            un = g.node("user", owner)
            g.bump(un, p.severity, p.start_time, source="process")
            g.edge(un, pnode, "ran", "info", p.start_time, f"{owner} ran {name}")

    # Finalize per-node liveness: surface the union of process flags and mark the
    # node dead only when it has no live instance. Consumed by the entity-map
    # "show terminated" toggle and the terminated badge.
    for nid, (alive, dead, flags) in liveness.items():
        meta = g.nodes[nid]["meta"]
        if flags:
            meta["flags"] = sorted(flags)
        meta["dead"] = alive == 0 and dead > 0


def _attach_findings(g: _Graph, findings: list[Finding]) -> None:
    # index nodes by lowercase value and basename for matching
    by_value: dict[str, list[str]] = {}
    for nid, n in g.nodes.items():
        by_value.setdefault(n["value"].lower(), []).append(nid)
        if n["type"] in ("process", "file"):
            by_value.setdefault(_basename(n["value"]).lower(), []).append(nid)

    for f in findings:
        ev = f.evidence or {}
        # Manual findings materialise their own node via _attach_manual_nodes so
        # they can create one that does not exist yet; skip them here to avoid
        # double-attaching the finding to a same-named node.
        if ev.get("manual"):
            continue
        candidates: set[str] = set()
        for key in ("entity", "client_ip", "parent", "process", "path", "name", "service"):
            val = ev.get(key)
            if isinstance(val, str) and val.strip():
                candidates.add(val.strip().lower())
                candidates.add(_basename(val).lower())
        matched_nodes: set[str] = set()
        for c in candidates:
            for nid in by_value.get(c, []):
                matched_nodes.add(nid)
        for nid in matched_nodes:
            n = g.nodes[nid]
            n["findings"].append({
                "id": f.id, "title": f.title, "severity": f.severity,
                "techniques": f.mitre_techniques,
            })
            g.mark_severity(nid, f.severity, source="finding")


def _attach_chain_edges(g: _Graph, findings: list[Finding]) -> None:
    """Materialize correlation chains (e.g. download -> service provenance) as
    first-class graph edges so relationships surface in the entity map/dossier."""
    for f in findings:
        for edge in (f.evidence or {}).get("chain_edges") or []:
            if not isinstance(edge, dict):
                continue
            src_type = str(edge.get("src_type") or "")
            dst_type = str(edge.get("dst_type") or "")
            if src_type not in ENTITY_TYPES or dst_type not in ENTITY_TYPES:
                continue
            src = g.node(src_type, str(edge.get("src") or ""))
            dst = g.node(dst_type, str(edge.get("dst") or ""))
            if not src or not dst:
                continue
            g.bump(src, f.severity, None, source="finding")
            g.bump(dst, f.severity, None, source="finding")
            g.edge(src, dst, str(edge.get("verb") or "correlated with"),
                   f.severity, None, f.title)


def _attach_manual_nodes(g: _Graph, findings: list[Finding]) -> None:
    """Materialize analyst-created findings onto the map.

    Unlike detector findings (which only colour entities already present),
    a manual finding creates its node when it does not exist yet and draws
    correlation edges to the related entities captured when it was raised, so a
    freshly flagged item is not left floating.
    """
    for f in findings:
        ev = f.evidence or {}
        if not ev.get("manual"):
            continue
        ntype = str(ev.get("node_type") or "")
        nval = str(ev.get("node_value") or "")
        if ntype not in ENTITY_TYPES or not nval:
            continue
        nid = g.node(ntype, nval)
        if not nid:
            continue
        node = g.nodes[nid]
        node["meta"]["manual"] = True
        g.bump(nid, f.severity, None, source="finding")
        g.mark_severity(nid, f.severity, source="finding")
        if not any(x.get("id") == f.id for x in node["findings"]):
            node["findings"].append({
                "id": f.id, "title": f.title, "severity": f.severity,
                "techniques": f.mitre_techniques,
            })
        for link in ev.get("links") or []:
            if not isinstance(link, dict):
                continue
            lt = str(link.get("type") or "")
            lv = str(link.get("value") or "")
            if lt not in ENTITY_TYPES or not lv:
                continue
            lid = g.node(lt, lv)
            if not lid:
                continue
            # Keep the linked node visible without recolouring it: the edge, not
            # the neighbour, carries the manual finding's severity.
            g.bump(lid, "info", None)
            g.edge(nid, lid, str(link.get("verb") or "connected to"), f.severity, None, f.title)


def _suppression_tokens(evidence: dict) -> set[str]:
    tokens: set[str] = set()
    for key in ("entity", "client_ip", "parent", "process", "path", "name", "service", "source_image"):
        val = evidence.get(key)
        if isinstance(val, str) and val.strip():
            tokens.add(val.strip().lower())
            tokens.add(_basename(val).lower())
    return tokens


def _suppressed_graph_signals(findings: list[Finding]) -> tuple[set[int], set[str]]:
    suppressed: set[int] = set()
    active: set[int] = set()
    suppressed_entities: set[str] = set()
    active_entities: set[str] = set()
    for f in findings:
        ev = f.evidence or {}
        event_id = ev.get("event_id")
        if ev.get("suppressed_from") and f.severity == "info":
            if isinstance(event_id, int):
                suppressed.add(event_id)
            suppressed_entities.update(_suppression_tokens(ev))
        elif SEVERITY_RANK.get(f.severity, 0) > 0:
            if isinstance(event_id, int):
                active.add(event_id)
            active_entities.update(_suppression_tokens(ev))
    return suppressed - active, suppressed_entities - active_entities


def _is_suppressed_propagation(ev: Event, suppressed_entities: set[str] | None) -> bool:
    if not suppressed_entities:
        return False
    reason = (ev.severity_reason or "").lower()
    if not reason.startswith("flagged-entity match:"):
        return False
    return any(token and token in reason for token in suppressed_entities)


def _max_severity(*severities: str) -> str:
    return max(severities or ("info",), key=lambda sev: SEVERITY_RANK.get(sev, 0))


def _finalize_node_severities(g: _Graph) -> None:
    for n in g.nodes.values():
        event_sev = n.get("_event_severity", "info")
        process_sev = n.get("_process_severity", "info")
        finding_sev = n.get("_finding_severity", "info")
        if n["findings"]:
            # Process.severity is detector-maintained and can outlive a user's
            # finding override. For entities with attached findings, make the
            # effective findings authoritative while preserving independent
            # event severity from logs or memory artifacts.
            n["severity"] = _max_severity(event_sev, finding_sev)
        else:
            n["severity"] = _max_severity(event_sev, process_sev, finding_sev)


def _public_graph_node(node: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in node.items() if not k.startswith("_")}


def build_entity_graph(
    case_id: str,
    entity_types: list[str] | None = None,
    min_severity: str = "info",
    max_nodes: int = 300,
) -> dict[str, Any]:
    session = case_store.get_session(case_id)
    try:
        g = _Graph()
        procs = list(session.scalars(select(Process)))
        findings = list(session.scalars(select(Finding)))
        suppressed_event_ids, suppressed_entities = _suppressed_graph_signals(findings)
        _extract_from_processes(g, procs)

        for ev in session.scalars(select(Event)):
            _extract_from_event(g, ev, suppressed_event_ids, suppressed_entities)

        _attach_chain_edges(g, findings)
        _attach_findings(g, findings)
        _attach_manual_nodes(g, findings)
        _finalize_node_severities(g)

        min_rank = SEVERITY_RANK.get(min_severity, 0)
        nodes = [
            _public_graph_node(n) for n in g.nodes.values()
            if SEVERITY_RANK.get(n["severity"], 0) >= min_rank
            and (not entity_types or n["type"] in entity_types)
        ]
        # rank by severity then activity, cap to keep the map readable
        nodes.sort(key=lambda n: (SEVERITY_RANK.get(n["severity"], 0), n["action_count"]), reverse=True)
        nodes = nodes[:max_nodes]
        keep = {n["id"] for n in nodes}
        edges = [
            e for e in g.edges.values()
            if e["source"] in keep and e["target"] in keep
        ]

        type_counts: dict[str, int] = {}
        for n in g.nodes.values():
            type_counts[n["type"]] = type_counts.get(n["type"], 0) + 1

        return {
            "case_id": case_id,
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(g.nodes),
            "total_edges": len(g.edges),
            "type_counts": type_counts,
        }
    finally:
        session.close()


def entity_dossier(case_id: str, entity_id: str, action_limit: int = 500) -> dict[str, Any]:
    """Dynamic investigation of one entity: its chronological action trace, the
    entities it interacted with, and the findings that reference it."""
    session = case_store.get_session(case_id)
    try:
        g = _Graph()
        procs = list(session.scalars(select(Process)))
        findings = list(session.scalars(select(Finding)))
        suppressed_event_ids, suppressed_entities = _suppressed_graph_signals(findings)
        _extract_from_processes(g, procs)
        all_events = list(session.scalars(select(Event)))
        for ev in all_events:
            _extract_from_event(g, ev, suppressed_event_ids, suppressed_entities)
        _attach_chain_edges(g, findings)
        _attach_findings(g, findings)
        _attach_manual_nodes(g, findings)
        _finalize_node_severities(g)

        node = g.nodes.get(entity_id)
        if not node:
            return {}

        # neighbors via edges
        neighbors: list[dict[str, Any]] = []
        for e in g.edges.values():
            if e["source"] == entity_id and e["target"] in g.nodes:
                other = g.nodes[e["target"]]
                neighbors.append({
                    "direction": "out", "verb": e["verb"], "entity": _public(other),
                    "count": e["count"], "severity": e["severity"],
                })
            elif e["target"] == entity_id and e["source"] in g.nodes:
                other = g.nodes[e["source"]]
                neighbors.append({
                    "direction": "in", "verb": e["verb"], "entity": _public(other),
                    "count": e["count"], "severity": e["severity"],
                })

        # action trace: raw events referencing this entity's value
        trace = _action_trace(node, all_events, procs, action_limit)

        result = {
            "entity": _public(node),
            "neighbors": sorted(neighbors, key=lambda x: SEVERITY_RANK.get(x["severity"], 0), reverse=True),
            "findings": node["findings"],
            "actions": trace,
            "action_total": len(trace),
        }
        if node["type"] == "process":
            result["memory_processes"] = memory_process_candidates(session, node["value"])
        return result
    finally:
        session.close()


def _public(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": node["id"], "type": node["type"], "value": node["value"],
        "label": node["label"], "severity": node["severity"],
        "action_count": node["action_count"], "first_seen": node["first_seen"],
        "last_seen": node["last_seen"], "meta": node["meta"],
        "finding_count": len(node["findings"]),
    }


def _event_mentions(node: dict[str, Any], ev: Event) -> bool:
    val = node["value"].lower()
    base = _basename(node["value"]).lower()
    raw = ev.raw or {}
    if node["type"] == "ip":
        for k in ("client_ip", "IpAddress", "SourceIp", "Raddr", "ForeignAddr", "DestinationIp"):
            if str(raw.get(k, "")).lower() == val:
                return True
        return False
    if node["type"] in ("user", "account"):
        for k in ("user", "SubjectUserName", "TargetUserName", "User", "AccountName"):
            if str(raw.get(k, "")).lower() == val:
                return True
        return False
    if node["type"] == "process":
        for k in ("NewProcessName", "Image", "ProcessName", "ParentProcessName", "ParentImage", "Owner", "Process"):
            rv = str(raw.get(k, "")).lower()
            if rv and (rv == val or _basename(rv).lower() == base):
                return True
        return False
    if node["type"] == "service":
        for k in ("ServiceName", "Service Name", "ServiceFileName"):
            if str(raw.get(k, "")).lower() == val:
                return True
        return False
    if node["type"] == "host":
        if node["meta"].get("kind") == "webservice":
            return ev.category == "weblog" and (node["value"] == f"web:{ev.source}")
        for k in ("Computer", "Hostname"):
            if str(raw.get(k, "")).lower() == val:
                return True
        return (ev.host or "").lower() == val
    # fallback substring match on summary
    return val in (ev.summary or "").lower()


def _action_trace(node, events, procs, limit) -> list[dict[str, Any]]:
    trace: list[dict[str, Any]] = []
    for ev in events:
        if _event_mentions(node, ev):
            trace.append({
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                "category": ev.category,
                "severity": ev.severity,
                "summary": ev.summary,
                "source": ev.source,
                "event_id": ev.id,
            })
    # include process rows for process entities
    if node["type"] == "process":
        for p in procs:
            if _basename(p.name or "").lower() == _basename(node["value"]).lower():
                trace.append({
                    "timestamp": p.start_time.isoformat() if p.start_time else None,
                    "category": "process",
                    "severity": p.severity,
                    "summary": f"Process {p.name} (pid {p.pid}, ppid {p.ppid}) "
                               + (f"cmd: {p.cmdline}" if p.cmdline else ""),
                    "source": "process-table",
                    "event_id": None,
                })
    trace.sort(key=lambda a: (a["timestamp"] or ""))
    return trace[:limit]
