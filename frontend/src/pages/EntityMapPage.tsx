import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import ReactFlow, {
  Background,
  Controls,
  MarkerType,
  Handle,
  Position,
  type Edge,
  type Node,
  type ReactFlowInstance,
  useEdgesState,
  useNodesState,
} from "reactflow";
import {
  User,
  Users,
  Monitor,
  Globe,
  Cpu,
  Settings2,
  FileText,
  Link2,
  KeyRound,
  Network,
  Boxes,
  Crosshair,
  X,
} from "lucide-react";
import { api } from "../lib/api";
import { EmptyState, Spinner } from "../components/common";
import { SEVERITY_COLORS } from "../lib/ui";
import type { EntityGraph, EntityNode, EntityType, Severity } from "../lib/types";
import { EntityDossierPanel } from "../components/EntityDossierPanel";

const TYPE_ICON: Record<EntityType, React.ReactNode> = {
  user: <User size={14} />,
  account: <Users size={14} />,
  host: <Monitor size={14} />,
  ip: <Globe size={14} />,
  process: <Cpu size={14} />,
  service: <Settings2 size={14} />,
  file: <FileText size={14} />,
  url: <Link2 size={14} />,
  registry: <KeyRound size={14} />,
  domain: <Network size={14} />,
};

const ALL_TYPES: EntityType[] = [
  "user",
  "account",
  "host",
  "ip",
  "process",
  "service",
  "file",
  "url",
  "registry",
  "domain",
];

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function EntityNodeCard({ data }: { data: any }) {
  const sev = data.severity as Severity;
  const active = sev !== "info";
  const color = SEVERITY_COLORS[sev];
  const isFocusRoot = data.focused as boolean;
  const hidden = (data.hiddenNeighbors as number) ?? 0;
  return (
    <div
      className="rounded-lg px-3 py-2 border min-w-[150px] max-w-[220px]"
      style={{
        background: active ? `${color}18` : "#141821",
        borderColor: isFocusRoot ? "#22d3ee" : active ? `${color}80` : "rgba(255,255,255,0.08)",
        boxShadow: isFocusRoot
          ? "0 0 0 2px #22d3ee, 0 0 20px -4px #22d3ee"
          : sev === "critical" || sev === "high"
            ? `0 0 16px -4px ${color}`
            : "none",
      }}
    >
      <Handle type="target" position={Position.Top} className="!bg-ink-500" />
      <div className="flex items-center gap-1.5">
        <span style={{ color: active ? color : "#8b96b0" }}>{TYPE_ICON[data.type as EntityType]}</span>
        <span className="text-[9px] uppercase tracking-wider text-ink-400">{data.type}</span>
        {hidden > 0 && (
          <span
            className="ml-auto text-[9px] px-1 rounded bg-accent-cyan/20 text-accent-cyan"
            title={`${hidden} more connected ${hidden === 1 ? "entity" : "entities"} — click to reveal`}
          >
            +{hidden}
          </span>
        )}
        {data.finding_count > 0 && (
          <span
            className={`text-[9px] px-1 rounded ${hidden > 0 ? "" : "ml-auto"}`}
            style={{ background: `${color}30`, color }}
          >
            {data.finding_count} finding{data.finding_count > 1 ? "s" : ""}
          </span>
        )}
      </div>
      <div className="text-sm font-semibold text-ink-50 truncate mt-0.5" title={data.value}>
        {data.label}
      </div>
      <div className="flex items-center gap-1.5 mt-0.5">
        <span className="text-[10px] text-ink-500">{data.action_count} actions</span>
        {data.dead && (
          <span
            className="text-[9px] px-1 rounded bg-white/10 text-ink-300 uppercase tracking-wider"
            title={data.state ? `Service state: ${data.state}` : "Process has exited"}
          >
            {data.type === "service" ? data.state || "stopped" : "terminated"}
          </span>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} className="!bg-ink-500" />
    </div>
  );
}

const nodeTypes = { entity: EntityNodeCard };

export default function EntityMapPage() {
  const { caseId } = useParams();
  const [minSeverity, setMinSeverity] = useState<Severity>("info");
  const [activeTypes, setActiveTypes] = useState<Set<EntityType>>(new Set(ALL_TYPES));
  const [showTerminated, setShowTerminated] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  // Focus mode: collapse the map to one entity and everything connected to it.
  const [focusId, setFocusId] = useState<string | null>(null);
  // "Hub" nodes whose direct neighbors are also shown; lets focus expand outward
  // one hop at a time as the analyst clicks connected nodes.
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const focusActive = focusId !== null;

  // Load the broad graph once and apply severity locally so the dropdown feels
  // instant instead of waiting on a slow graph rebuild for each threshold.
  const maxNodes = focusActive ? 600 : 250;

  const { data, isLoading } = useQuery({
    queryKey: ["entities", caseId, maxNodes],
    queryFn: () => api.getEntities(caseId!, { min_severity: "info", max_nodes: maxNodes }),
    enabled: !!caseId,
    placeholderData: (prev) => prev,
  });

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const rfRef = useRef<ReactFlowInstance | null>(null);

  const deadCount = useMemo(
    () => (data ? data.nodes.filter((n) => n.meta?.dead).length : 0),
    [data],
  );

  // Undirected adjacency for the loaded graph; "connected" ignores edge direction.
  const adjacency = useMemo(() => {
    const adj = new Map<string, Set<string>>();
    if (!data) return adj;
    for (const e of data.edges) {
      (adj.get(e.source) ?? adj.set(e.source, new Set()).get(e.source)!).add(e.target);
      (adj.get(e.target) ?? adj.set(e.target, new Set()).get(e.target)!).add(e.source);
    }
    return adj;
  }, [data]);

  const focusView = useMemo(() => {
    if (!data || !focusId) return null;
    const visible = new Set<string>([focusId]);
    for (const hub of [focusId, ...expanded]) {
      visible.add(hub);
      for (const nb of adjacency.get(hub) ?? []) visible.add(nb);
    }
    // Count still-hidden neighbors per visible node to drive the "+N" expand chip.
    const hiddenNeighbors = new Map<string, number>();
    for (const id of visible) {
      let count = 0;
      for (const nb of adjacency.get(id) ?? []) if (!visible.has(nb)) count++;
      hiddenNeighbors.set(id, count);
    }
    return { visible, hiddenNeighbors };
  }, [data, focusId, expanded, adjacency]);

  const focusLabel = useMemo(
    () => (focusId ? data?.nodes.find((n) => n.id === focusId)?.label ?? focusId : null),
    [data, focusId],
  );

  const filtered = useMemo(() => {
    if (!data) return null;
    if (focusView) {
      const keep = focusView.visible;
      const keepNodes = data.nodes.filter((n) => keep.has(n.id));
      const keepEdges = data.edges.filter((e) => keep.has(e.source) && keep.has(e.target));
      return { nodes: keepNodes, edges: keepEdges };
    }
    const minRank = SEVERITY_RANK[minSeverity];
    const keepNodes = data.nodes.filter(
      (n) =>
        SEVERITY_RANK[n.severity] >= minRank &&
        activeTypes.has(n.type) &&
        (showTerminated || !n.meta?.dead),
    );
    const keep = new Set(keepNodes.map((n) => n.id));
    const keepEdges = data.edges.filter((e) => keep.has(e.source) && keep.has(e.target));
    return { nodes: keepNodes, edges: keepEdges };
  }, [data, activeTypes, showTerminated, focusView, minSeverity]);

  useEffect(() => {
    if (!filtered) return;
    const { nodes: n, edges: e } = layoutGraph(filtered.nodes, filtered.edges, {
      focusId,
      hiddenNeighbors: focusView?.hiddenNeighbors,
    });
    setNodes(n);
    setEdges(e);
    // Reframe after positions apply so the focused subgraph re-centers.
    requestAnimationFrame(() => rfRef.current?.fitView({ padding: 0.2, duration: 300 }));
  }, [filtered, focusId, focusView, setNodes, setEdges]);

  const clearFocus = useCallback(() => {
    setFocusId(null);
    setExpanded(new Set());
  }, []);

  const onNodeClick = useCallback(
    (_: unknown, node: Node) => {
      setSelected(node.id);
      // In focus mode, clicking a node expands its connections (reveals its neighbors).
      if (focusActive) setExpanded((prev) => new Set(prev).add(node.id));
    },
    [focusActive],
  );

  function toggleType(t: EntityType) {
    setActiveTypes((prev) => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t);
      else next.add(t);
      return next;
    });
  }

  if (isLoading) return <Spinner label="Building entity action map…" />;
  if (!data || data.nodes.length === 0)
    return (
      <EmptyState
        icon={<Boxes size={40} />}
        title="No entities yet"
        hint="Upload Velociraptor artifacts, event logs, web logs, or a memory dump. The map reconstructs users, IPs, hosts, processes and services and the actions between them."
      />
    );

  return (
    <div className="space-y-4">
      {focusActive ? (
        <div className="card p-3 flex items-center justify-between flex-wrap gap-3 border-accent-cyan/40">
          <div className="flex items-center gap-2 flex-wrap min-w-0">
            <Crosshair size={16} className="text-accent-cyan shrink-0" />
            <span className="text-sm text-ink-200">
              Focused on <span className="font-semibold text-ink-50">{focusLabel}</span>
            </span>
            <span className="text-xs text-ink-500">
              · showing {filtered?.nodes.length ?? 0} connected entities · click a node to reveal its connections
            </span>
          </div>
          <button className="chip bg-accent-cyan/15 text-accent-cyan transition" onClick={clearFocus}>
            <X size={12} /> Clear focus
          </button>
        </div>
      ) : (
        <div className="card p-3 flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-2 flex-wrap">
            <Boxes size={16} className="text-accent-cyan" />
            <span className="text-sm text-ink-300">
              {data.total_nodes} entities · {data.total_edges} actions
            </span>
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            {ALL_TYPES.filter((t) => (data.type_counts[t] ?? 0) > 0).map((t) => (
              <button
                key={t}
                onClick={() => toggleType(t)}
                className={`chip transition ${
                  activeTypes.has(t)
                    ? "bg-accent-cyan/15 text-accent-cyan"
                    : "bg-white/5 text-ink-500"
                }`}
              >
                {TYPE_ICON[t]} {t} ({data.type_counts[t]})
              </button>
            ))}
            <button
              onClick={() => deadCount > 0 && setShowTerminated((v) => !v)}
              disabled={deadCount === 0}
              title={
                deadCount === 0
                  ? "No terminated processes or stopped services in this case (dead entities come from memory images, process-exit events, or svcscan)."
                  : "Show terminated processes and stopped services and their relationships"
              }
              className={`chip transition ${
                deadCount === 0
                  ? "bg-white/5 text-ink-600 cursor-not-allowed opacity-60"
                  : showTerminated
                    ? "bg-accent-cyan/15 text-accent-cyan"
                    : "bg-white/5 text-ink-500"
              }`}
            >
              {showTerminated && deadCount > 0 ? "showing terminated" : "show terminated"} ({deadCount})
            </button>
            <select
              className="input w-auto py-1 ml-2"
              value={minSeverity}
              onChange={(e) => setMinSeverity(e.target.value as Severity)}
            >
              {(["info", "low", "medium", "high", "critical"] as Severity[]).map((s) => (
                <option key={s} value={s}>
                  min: {s}
                </option>
              ))}
            </select>
          </div>
        </div>
      )}

      <div className="card p-0 overflow-hidden" style={{ height: 640 }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          onInit={(inst) => (rfRef.current = inst)}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.1}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#232a38" gap={20} />
          <Controls className="!bg-base-800 !border-white/10 [&_button]:!bg-base-700 [&_button]:!border-white/10 [&_button]:!fill-ink-200" />
        </ReactFlow>
      </div>

      {selected && caseId && (
        <EntityDossierPanel
          caseId={caseId}
          entityId={selected}
          onClose={() => setSelected(null)}
          onFocus={(id) => {
            setFocusId(id);
            setExpanded(new Set());
          }}
          focused={focusId === selected}
        />
      )}
    </div>
  );
}

function layoutGraph(
  nodes: EntityNode[],
  edges: { source: string; target: string; verb: string; severity: Severity; count: number }[],
  focus?: { focusId: string | null; hiddenNeighbors?: Map<string, number> },
) {
  // Group by type into columns; lay out vertically within each column.
  const columns: EntityType[] = ["ip", "user", "account", "host", "process", "service", "file", "url", "registry", "domain"];
  const byType: Record<string, EntityNode[]> = {};
  for (const n of nodes) (byType[n.type] ??= []).push(n);

  const COL_W = 280;
  const ROW_H = 96;
  const flowNodes: Node[] = [];
  let colIdx = 0;
  for (const t of columns) {
    const group = byType[t];
    if (!group?.length) continue;
    group.forEach((n, i) => {
      flowNodes.push({
        id: n.id,
        type: "entity",
        position: { x: colIdx * COL_W, y: i * ROW_H },
        data: {
          type: n.type,
          label: n.label,
          value: n.value,
          severity: n.severity,
          action_count: n.action_count,
          finding_count: n.findings.length,
          dead: n.meta?.dead ?? false,
          state: n.meta?.state,
          focused: focus?.focusId === n.id,
          hiddenNeighbors: focus?.hiddenNeighbors?.get(n.id) ?? 0,
        },
      });
    });
    colIdx++;
  }

  const flowEdges: Edge[] = edges.map((e, i) => {
    const active = e.severity !== "info";
    const color = SEVERITY_COLORS[e.severity];
    return {
      id: `${e.source}-${e.target}-${i}`,
      source: e.source,
      target: e.target,
      label: e.count > 1 ? `${e.verb} (${e.count})` : e.verb,
      type: "smoothstep",
      animated: e.severity === "critical" || e.severity === "high",
      labelStyle: { fill: "#8b96b0", fontSize: 10 },
      labelBgStyle: { fill: "#0f1218" },
      style: { stroke: active ? color : "#2e3646", strokeWidth: active ? 2 : 1 },
      markerEnd: { type: MarkerType.ArrowClosed, color: active ? color : "#2e3646" },
    };
  });

  return { nodes: flowNodes, edges: flowEdges };
}
