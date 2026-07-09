import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Sparkles,
  ArrowRight,
  ArrowLeft,
  Loader2,
  Activity,
  AlertTriangle,
  Download,
  Cpu,
  Database,
  Crosshair,
} from "lucide-react";
import { api, memoryModuleDownloadUrl, memoryProcessDownloadUrl, wsUrl } from "../lib/api";
import { DetailDrawer, SeverityBadge, Spinner, CodeBlock } from "./common";
import { fmtTime, SEVERITY_COLORS } from "../lib/ui";
import type { EntityDossier, MemoryModule, MemoryProcessCandidate, MemoryProcessHandle, Severity } from "../lib/types";

export function EntityDossierPanel({
  caseId,
  entityId,
  onClose,
  onFocus,
  focused = false,
}: {
  caseId: string;
  entityId: string;
  onClose: () => void;
  onFocus?: (entityId: string) => void;
  focused?: boolean;
}) {
  const [tab, setTab] = useState<"trace" | "relations" | "memory" | "ai">("trace");
  const { data, isLoading } = useQuery({
    queryKey: ["entity-dossier", caseId, entityId],
    queryFn: () => api.getEntityDossier(caseId, entityId),
  });
  const hasMemoryProcesses = Boolean(data?.memory_processes?.length);
  const tabs: Array<"trace" | "relations" | "memory" | "ai"> = [
    "trace",
    "relations",
    ...(hasMemoryProcesses ? (["memory"] as const) : []),
    "ai",
  ];
  useEffect(() => {
    if (tab === "memory" && !hasMemoryProcesses) setTab("trace");
  }, [entityId, tab, hasMemoryProcesses]);

  return (
    <DetailDrawer
      eyebrow={`${data?.entity.type ?? "entity"} investigation`}
      title={data?.entity.value ?? "..."}
      onClose={onClose}
      ariaLabel="Entity investigation details"
    >
      <div className="hidden">
          <div className="min-w-0">
            <div className="text-xs font-semibold uppercase tracking-wider text-ink-400">
              {data?.entity.type ?? "entity"} investigation
            </div>
            <div className="text-lg font-semibold text-ink-50 mt-1 truncate" title={data?.entity.value}>
              {data?.entity.value ?? "…"}
            </div>
          </div>
        </div>
        {data && (
          <div className="flex items-center gap-2 mt-3 flex-wrap">
            <SeverityBadge severity={data.entity.severity} />
            <span className="chip bg-white/5 text-ink-300">
              <Activity size={11} /> {data.entity.action_count} actions
            </span>
            {data.entity.finding_count > 0 && (
              <span className="chip bg-sev-high/15 text-sev-high">
                <AlertTriangle size={11} /> {data.entity.finding_count} findings
              </span>
            )}
            {data.entity.first_seen && (
              <span className="text-[11px] text-ink-500">
                {fmtTime(data.entity.first_seen)} → {fmtTime(data.entity.last_seen)}
              </span>
            )}
          </div>
        )}
        {data && onFocus && (
          <button
            type="button"
            className={`btn-ghost mt-4 w-full justify-center text-xs ${
              focused ? "bg-accent-blue/10 text-accent-blue" : ""
            }`}
            onClick={() => onFocus(entityId)}
            title="Show only this entity and everything connected to it on the map"
          >
            <Crosshair size={14} />
            {focused ? "Focused on map" : "Focus on map"}
          </button>
        )}
        <div className="flex items-center gap-1 mt-4 flex-wrap">
          {tabs.map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`btn text-xs ${
                tab === t
                  ? "bg-accent-blue/10 text-accent-blue"
                  : "text-ink-300 hover:bg-[rgb(var(--panel-muted)/0.8)]"
              }`}
            >
              {t === "trace"
                ? "Action trace"
                : t === "relations"
                  ? "Relationships"
                  : t === "memory"
                    ? "Memory"
                    : "AI investigate"}
            </button>
          ))}
        </div>

      <div className="mt-4">
        {isLoading ? (
          <Spinner label="Loading entity…" />
        ) : !data ? (
          <div className="text-sm text-ink-400">Entity not found.</div>
        ) : tab === "trace" ? (
          <ActionTrace data={data} />
        ) : tab === "relations" ? (
          <Relationships data={data} />
        ) : tab === "memory" ? (
          <MemoryProcessDetails caseId={caseId} processes={data.memory_processes ?? []} />
        ) : (
          <AiInvestigate caseId={caseId} entityId={entityId} />
        )}
      </div>
    </DetailDrawer>
  );
}

function MemoryProcessDetails({
  caseId,
  processes,
}: {
  caseId: string;
  processes: MemoryProcessCandidate[];
}) {
  const [index, setIndex] = useState(0);
  const [showHandles, setShowHandles] = useState(false);
  const proc = processes[index] ?? processes[0];
  const { data, isLoading, error } = useQuery({
    queryKey: ["memory-process-modules", caseId, proc?.session_id, proc?.pid],
    queryFn: () => api.getMemoryProcessModules(caseId, proc.session_id, proc.pid),
    enabled: !!proc,
    retry: false,
  });
  const handleQuery = useQuery({
    queryKey: ["memory-process-handles", caseId, proc?.session_id, proc?.pid],
    queryFn: () => api.getMemoryProcessHandles(caseId, proc.session_id, proc.pid, { limit: 300 }),
    enabled: !!proc && showHandles,
    retry: false,
  });

  useEffect(() => {
    setShowHandles(false);
  }, [proc?.session_id, proc?.pid]);

  if (!proc) return <div className="text-sm text-ink-400">No memory process details.</div>;

  return (
    <div className="space-y-4">
      {processes.length > 1 && (
        <div className="flex items-center gap-2 flex-wrap">
          {processes.map((p, i) => (
            <button
              key={`${p.session_id}-${p.pid}`}
              className={`chip ${i === index ? "bg-accent-cyan/15 text-accent-cyan" : "bg-white/5 text-ink-300"}`}
              onClick={() => {
                setIndex(i);
                setShowHandles(false);
              }}
            >
              pid {p.pid}
            </button>
          ))}
        </div>
      )}

      <div className="card p-4 space-y-3">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <div className="text-sm font-semibold text-ink-100 flex items-center gap-2">
              <Cpu size={15} className="text-accent-cyan" />
              {proc.name} <span className="text-ink-500 font-mono">pid {proc.pid}</span>
            </div>
            <div className="text-xs text-ink-500 font-mono mt-1 truncate" title={proc.path ?? ""}>
              {proc.path || "no image path"}
            </div>
          </div>
          <SeverityBadge severity={proc.severity} />
        </div>
        <Field label="Session" value={proc.session_id} mono />
        <Field label="Started" value={proc.start_time ? fmtTime(proc.start_time) : "unknown"} />
        {proc.cmdline && <Field label="Command line" value={proc.cmdline} mono />}
        {proc.flags.length > 0 && <Field label="Flags" value={proc.flags.join(", ")} />}
        <div className="flex gap-2 flex-wrap pt-1">
          <a className="btn-primary text-xs" href={memoryProcessDownloadUrl(caseId, proc.session_id, proc.pid, "image")}>
            <Download size={14} /> Process image
          </a>
          <button
            className="btn text-xs text-ink-300 hover:bg-white/5"
            onClick={() => {
              if (
                window.confirm(
                  "Full process memory can be very large or sparse and may be refused by the safety limit. Continue?",
                )
              ) {
                window.location.href = memoryProcessDownloadUrl(caseId, proc.session_id, proc.pid, "vmem");
              }
            }}
          >
            <Database size={14} /> Full memory
          </button>
        </div>
      </div>

      {proc.memory_results.length > 0 && (
        <div className="space-y-2">
          <div className="text-xs uppercase tracking-wider text-ink-400">Memory findings</div>
          {proc.memory_results.slice(0, 8).map((m) => (
            <div key={m.id} className="card p-3">
              <div className="flex items-center gap-2 mb-1">
                <SeverityBadge severity={m.severity} />
                <span className="chip bg-white/5 text-ink-300 font-mono">{m.plugin}</span>
              </div>
              <div className="text-sm text-ink-200">{m.summary}</div>
            </div>
          ))}
        </div>
      )}

      <HandleSection
        handles={handleQuery.data?.handles ?? []}
        total={handleQuery.data?.total ?? 0}
        loading={handleQuery.isLoading}
        error={handleQuery.error as Error | null}
        showHandles={showHandles}
        onShowHandles={() => setShowHandles(true)}
      />

      <div className="space-y-2">
        <div className="text-xs uppercase tracking-wider text-ink-400">Loaded modules</div>
        {isLoading ? (
          <Spinner label="Loading modules..." />
        ) : error ? (
          <div className="text-sm text-sev-high">Could not load modules: {(error as Error).message}</div>
        ) : data?.modules.length ? (
          <ModuleTable caseId={caseId} sessionId={proc.session_id} pid={proc.pid} modules={data.modules} />
        ) : (
          <div className="text-sm text-ink-400">No module list available.</div>
        )}
      </div>
    </div>
  );
}

function HandleSection({
  handles,
  total,
  loading,
  error,
  showHandles,
  onShowHandles,
}: {
  handles: MemoryProcessHandle[];
  total: number;
  loading: boolean;
  error: Error | null;
  showHandles: boolean;
  onShowHandles: () => void;
}) {
  const rows = handles.slice(0, 300);
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="text-xs uppercase tracking-wider text-ink-400">Handles</div>
        {showHandles && total > 0 && (
          <div className="text-[11px] text-ink-500">Showing {rows.length} of {total}</div>
        )}
      </div>
      {!showHandles && (
        <button className="btn text-xs text-ink-300 hover:bg-white/5" onClick={onShowHandles}>
          <Database size={14} /> Show handles
        </button>
      )}
      {showHandles && loading && <Spinner label="Loading handles..." />}
      {showHandles && error && (
        <div className="text-sm text-sev-high">Could not load handles: {error.message}</div>
      )}
      {showHandles && !loading && !error && rows.length === 0 && (
        <div className="text-sm text-ink-400">No handle list available.</div>
      )}
      {rows.map((h) => (
        <HandleRow key={h.event_id} handle={h} />
      ))}
    </div>
  );
}

function HandleRow({ handle: h }: { handle: MemoryProcessHandle }) {
  return (
    <div className="card p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-sm text-ink-100 font-medium flex items-center gap-2">
            <span>{h.type || "Handle"}</span>
            {h.risk && h.risk !== "none" && (
              <SeverityBadge severity={riskSeverity(h.risk)} />
            )}
          </div>
          <div className="text-[11px] text-ink-500 font-mono truncate" title={handleTarget(h)}>
            {handleTarget(h)}
          </div>
        </div>
        {h.access !== null && h.access !== undefined && (
          <span className="chip bg-white/5 text-ink-300 font-mono">{String(h.access)}</span>
        )}
      </div>
      {h.risk_reasons?.length > 0 && (
        <div className="text-xs text-ink-400 mt-2">{h.risk_reasons.join("; ")}</div>
      )}
    </div>
  );
}

function handleTarget(h: MemoryProcessHandle) {
  const target = h.target_process || h.name || "unnamed";
  return h.target_pid ? `${target} (pid ${h.target_pid})` : target;
}

function riskSeverity(risk: string): Severity {
  if (risk === "critical" || risk === "high" || risk === "medium" || risk === "low") return risk;
  return "info";
}

function ModuleTable({
  caseId,
  sessionId,
  pid,
  modules,
}: {
  caseId: string;
  sessionId: string;
  pid: number;
  modules: MemoryModule[];
}) {
  return (
    <div className="space-y-2">
      {modules.map((m, i) => (
        <div key={`${m.base_hex ?? m.name}-${i}`} className="card p-3">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <div className="text-sm text-ink-100 font-medium truncate" title={m.path ?? m.name}>
                {m.name}
              </div>
              <div className="text-[11px] text-ink-500 font-mono truncate" title={m.path ?? ""}>
                {m.path || "memory mapped"}
              </div>
            </div>
            <a className="btn-ghost" href={memoryModuleDownloadUrl(caseId, sessionId, pid, m)} title="Download module">
              <Download size={14} />
            </a>
          </div>
          <div className="flex items-center gap-2 flex-wrap mt-2 text-[11px] text-ink-400">
            <span className="chip bg-white/5 text-ink-300">{m.status}</span>
            {m.base_hex && <span className="font-mono">{m.base_hex}</span>}
            <span>{fmtBytes(m.size)}</span>
          </div>
          {m.sha256 && (
            <div className="mt-2">
              <CodeBlock>{m.sha256}</CodeBlock>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-[11px] text-ink-500 uppercase tracking-wider">{label}</div>
      <div className={`text-sm text-ink-200 break-words ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}

function fmtBytes(n: number) {
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(value >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function ActionTrace({ data }: { data: EntityDossier }) {
  if (data.actions.length === 0)
    return <div className="text-sm text-ink-400">No recorded actions for this entity.</div>;
  return (
    <div className="space-y-2">
      <div className="text-xs text-ink-400 mb-2">
        {data.action_total} chronological actions
      </div>
      <div className="relative pl-4 border-l border-white/10 space-y-3">
        {data.actions.map((a, i) => (
          <div key={i} className="relative">
            <span
              className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full border-2 border-base-900"
              style={{ background: SEVERITY_COLORS[a.severity] }}
            />
            <div className="flex items-center gap-2 mb-0.5">
              <SeverityBadge severity={a.severity} />
              <span className="text-[11px] text-ink-500 font-mono">{fmtTime(a.timestamp)}</span>
              <span className="text-[10px] text-accent-cyan/70">{a.category}</span>
            </div>
            <div className="text-sm text-ink-200 break-words">{a.summary}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Relationships({ data }: { data: EntityDossier }) {
  if (data.neighbors.length === 0)
    return <div className="text-sm text-ink-400">No related entities.</div>;
  return (
    <div className="space-y-2">
      {data.neighbors.map((n, i) => (
        <div key={i} className="card p-3 flex items-center gap-3">
          {n.direction === "out" ? (
            <ArrowRight size={16} className="text-accent-cyan shrink-0" />
          ) : (
            <ArrowLeft size={16} className="text-accent-violet shrink-0" />
          )}
          <div className="min-w-0 flex-1">
            <div className="text-sm text-ink-100">
              <span className="text-ink-400">{n.direction === "out" ? "this" : n.entity.value}</span>{" "}
              <span className="font-medium text-accent-cyan">{n.verb}</span>{" "}
              <span className="text-ink-400">{n.direction === "out" ? n.entity.value : "this"}</span>
            </div>
            <div className="text-[11px] text-ink-500">
              {n.entity.type} · {n.count} time{n.count > 1 ? "s" : ""}
            </div>
          </div>
          <SeverityBadge severity={n.severity} />
        </div>
      ))}
    </div>
  );
}

function AiInvestigate({ caseId, entityId }: { caseId: string; entityId: string }) {
  const [text, setText] = useState("");
  const [running, setRunning] = useState(false);
  const [started, setStarted] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const ws = new WebSocket(wsUrl(`/cases/${caseId}/investigate-entity-ws`));
    ws.onmessage = (ev) => {
      const d = JSON.parse(ev.data);
      if (d.type === "start") {
        setText("");
        setRunning(true);
      } else if (d.type === "chunk") {
        setText((t) => t + d.content);
      } else if (d.type === "done") {
        setRunning(false);
      } else if (d.type === "error") {
        setText((t) => t + `\n\nError: ${d.content}`);
        setRunning(false);
      }
    };
    wsRef.current = ws;
    return () => ws.close();
  }, [caseId]);

  function run() {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      setStarted(true);
      wsRef.current.send(JSON.stringify({ entity_id: entityId }));
    }
  }

  return (
    <div className="space-y-3">
      <button className="btn-primary" onClick={run} disabled={running}>
        {running ? <Loader2 size={16} className="animate-spin" /> : <Sparkles size={16} />}
        {running ? "Investigating…" : started ? "Re-investigate" : "Investigate this entity with AI"}
      </button>
      {text ? (
        <div className="text-sm text-ink-200 leading-relaxed whitespace-pre-wrap">
          {text}
          {running && <span className="animate-pulse">▋</span>}
        </div>
      ) : (
        !running && (
          <p className="text-xs text-ink-500">
            The AI reconstructs this entity's role and timeline using its action trace, relationships,
            and related findings.
          </p>
        )
      )}
    </div>
  );
}
