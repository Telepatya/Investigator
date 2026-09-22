import { memo, useCallback, useDeferredValue, useEffect, useMemo, useRef, useState, useTransition } from "react";
import type { ReactNode } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  MarkerType,
  Handle,
  Position,
  type Edge,
  type Node,
  type ReactFlowInstance,
  useEdgesState,
  useNodesState,
} from "reactflow";
import "reactflow/dist/style.css";
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
import { EmptyState, PageShell, PageTitle, Spinner } from "../components/common";
import { SEVERITY_COLORS } from "../lib/ui";
import type { EntityNode, EntityType, Severity } from "../lib/types";
import { EntityDossierPanel } from "../components/EntityDossierPanel";

const TYPE_ICON: Record<EntityType, ReactNode> = {
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

const EntityNodeCard = memo(function EntityNodeCard({ data }: { data: any }) {
  const sev = data.severity as Severity;
  const active = sev !== "info";
  const color = SEVERITY_COLORS[sev];
  const isFocusRoot = data.focused as boolean;
  const hidden = (data.hiddenNeighbors as number) ?? 0;
  return (
    <div
      className="min-w-[172px] max-w-[238px] rounded-2xl border px-4 py-3 shadow-sm transition-all duration-200 hover:-translate-y-0.5"
      style={{
        background: active
          ? `linear-gradient(145deg, ${color}16, rgb(var(--panel-strong) / 0.92))`
          : "rgb(var(--panel-strong) / 0.92)",
        borderColor: isFocusRoot ? "rgb(var(--accent-blue))" : active ? `${color}70` : "rgb(var(--border) / 0.72)",
        boxShadow: isFocusRoot
          ? "0 0 0 2px rgb(var(--accent-blue) / 0.42), 0 20px 38px -26px rgb(var(--accent-blue) / 0.9)"
          : sev === "critical" || sev === "high"
            ? `0 20px 36px -28px ${color}`
            : "0 16px 32px -28px rgb(var(--shadow) / 0.65)",
      }}
    >
      <Handle id="left" type="target" position={Position.Left} className="!h-2 !w-2 !border-0 !bg-ink-500" />
      <Handle id="right" type="source" position={Position.Right} className="!h-2 !w-2 !border-0 !bg-ink-500" />
      <div className="flex items-center gap-1.5">
        <span style={{ color: active ? color : "rgb(var(--ink-300))" }}>{TYPE_ICON[data.type as EntityType]}</span>
        <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-300">{data.type}</span>
        {data.manual && (
          <span
            className="text-[9px] px-1 rounded bg-accent-cyan/20 text-accent-cyan uppercase tracking-wider"
            title="Created from a manual finding"
          >
            manual
          </span>
        )}
        {hidden > 0 && (
          <span
            className="ml-auto text-[9px] px-1 rounded bg-accent-cyan/20 text-accent-cyan"
            title={`${hidden} more connected ${hidden === 1 ? "entity" : "entities"} - double-click to reveal`}
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
    </div>
  );
});

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
  // one hop at a time as the analyst double-clicks connected nodes.
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const focusActive = focusId !== null;

  // Load the broad graph once and apply severity locally so the dropdown feels
  // instant instead of waiting on a slow graph rebuild for each threshold.
  const maxNodes = focusActive ? 600 : 250;

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ["entities", caseId, maxNodes],
    queryFn: ({ signal }) => api.getEntities(caseId!, { min_severity: "info", max_nodes: maxNodes }, signal),
    enabled: !!caseId,
    placeholderData: (previousData, previousQuery) =>
      previousQuery?.queryKey[1] === caseId ? previousData : undefined,
  });

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [mapReady, setMapReady] = useState(false);
  const [, startLayoutTransition] = useTransition();
  const rfRef = useRef<ReactFlowInstance | null>(null);

  useEffect(() => {
    setMinSeverity("info");
    setActiveTypes(new Set(ALL_TYPES));
    setShowTerminated(false);
    setSelected(null);
    setFocusId(null);
    setExpanded(new Set());
    setNodes([]);
    setEdges([]);
    setMapReady(false);
  }, [caseId, setNodes, setEdges]);

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
  const layoutInput = useMemo(
    () => filtered ? { graph: filtered, focusId, hiddenNeighbors: focusView?.hiddenNeighbors } : null,
    [filtered, focusId, focusView],
  );
  const deferredLayoutInput = useDeferredValue(layoutInput);

  useEffect(() => {
    if (!deferredLayoutInput) return;
    setMapReady(false);
    let fitFrame = 0;
    const layoutFrame = requestAnimationFrame(() => {
      const { nodes: nextNodes, edges: nextEdges } = layoutGraph(
        deferredLayoutInput.graph.nodes,
        deferredLayoutInput.graph.edges,
        {
          focusId: deferredLayoutInput.focusId,
          hiddenNeighbors: deferredLayoutInput.hiddenNeighbors,
        },
      );
      startLayoutTransition(() => {
        setNodes(nextNodes);
        setEdges(nextEdges);
        setMapReady(true);
      });
      fitFrame = requestAnimationFrame(() =>
        rfRef.current?.fitView({ padding: 0.2, duration: nextNodes.length === 0 ? 0 : 180 }),
      );
    });
    return () => {
      cancelAnimationFrame(layoutFrame);
      cancelAnimationFrame(fitFrame);
    };
  }, [deferredLayoutInput, setNodes, setEdges, startLayoutTransition]);

  const clearFocus = useCallback(() => {
    setFocusId(null);
    setExpanded(new Set());
  }, []);

  const onNodeClick = useCallback(
    (_: unknown, node: Node) => {
      setSelected(node.id);
    },
    [],
  );

  const onNodeDoubleClick = useCallback(
    (_: unknown, node: Node) => {
      if (!focusActive || node.id === focusId) return;
      setExpanded((prev) => {
        const next = new Set(prev);
        if (next.has(node.id)) next.delete(node.id);
        else next.add(node.id);
        return next;
      });
    },
    [focusActive, focusId],
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
        hint="Upload logs, artifacts, event logs, web logs, Defender/Azure exports, or a memory dump. The map reconstructs users, IPs, hosts, processes and services and the actions between them."
      />
    );

  return (
    <PageShell>
      <PageTitle
        icon={<Boxes size={22} />}
        title="Entities"
        subtitle="Reconstructed users, hosts, IPs, processes, and services, and the actions between them."
      />
      {focusActive ? (
        <div className="card flex items-center justify-between gap-3 border-accent-blue/40 p-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap min-w-0">
            <Crosshair size={16} className="text-accent-blue shrink-0" />
            <span className="text-sm text-ink-200">
              Focused on <span className="font-semibold text-ink-50">{focusLabel}</span>
            </span>
            <span className="text-xs text-ink-500">
              · showing {filtered?.nodes.length ?? 0} connected entities · double-click a node to expand or compact its links
            </span>
          </div>
          <button className="chip bg-accent-blue/10 text-accent-blue transition" onClick={clearFocus}>
            <X size={12} /> Clear focus
          </button>
        </div>
      ) : (
        <div className="card flex items-center justify-between gap-3 p-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <Boxes size={16} className="text-accent-blue" />
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
                    ? "bg-accent-blue/10 text-accent-blue"
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
                    ? "bg-accent-blue/10 text-accent-blue"
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

      <div className="card relative overflow-hidden p-0" style={{ height: 680 }} aria-busy={!mapReady || isFetching}>
        {(!mapReady || isFetching) && (
          <div className="pointer-events-none absolute right-4 top-4 z-10 inline-flex items-center gap-2 rounded-full border border-[rgb(var(--border)/0.7)] bg-[rgb(var(--panel-strong)/0.88)] px-3 py-2 text-xs text-ink-300 shadow-sm backdrop-blur-xl">
            <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-accent-blue/25 border-t-accent-blue" />
            {mapReady ? "Updating map..." : "Arranging entities..."}
          </div>
        )}
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          onNodeDoubleClick={onNodeDoubleClick}
          onInit={(inst) => (rfRef.current = inst)}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.1}
          defaultEdgeOptions={{ type: "smoothstep" }}
          onlyRenderVisibleElements
          proOptions={{ hideAttribution: true }}
        >
          <Background color="rgb(var(--graph-grid))" gap={22} />
          <MiniMap
            pannable
            zoomable
            className="!rounded-3xl !border !border-[rgb(var(--border)/0.7)] !bg-[rgb(var(--panel)/0.76)]"
            nodeColor={(node) => node.data?.color ?? "rgb(var(--accent-blue))"}
            maskColor="rgb(var(--base-900) / 0.35)"
          />
          <Controls />
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
    </PageShell>
  );
}

function layoutGraph(
  nodes: EntityNode[],
  edges: { source: string; target: string; verb: string; severity: Severity; count: number }[],
  focus?: { focusId: string | null; hiddenNeighbors?: Map<string, number> },
) {
  const layerFor: Record<EntityType, number> = {
    ip: 0,
    domain: 0,
    url: 0,
    file: 0,
    user: 1,
    account: 1,
    host: 1,
    process: 2,
    service: 3,
    registry: 3,
  };
  const layers: Record<number, EntityNode[]> = {};
  for (const n of nodes) (layers[layerFor[n.type] ?? 2] ??= []).push(n);

  const COL_W = 340;
  const ROW_H = 118;

  // Columns are the semantic lanes (external -> identity -> process -> system),
  // ordered left to right. Empty lanes are skipped so there are no blank gaps.
  const colKeys = Object.keys(layers).map(Number).sort((a, b) => a - b);

  // Undirected adjacency restricted to nodes actually in this (filtered) view.
  const present = new Set(nodes.map((n) => n.id));
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    if (!present.has(e.source) || !present.has(e.target)) continue;
    (adj.get(e.source) ?? adj.set(e.source, []).get(e.source)!).push(e.target);
    (adj.get(e.target) ?? adj.set(e.target, []).get(e.target)!).push(e.source);
  }

  // Strongest signal first, so high-severity / findings-heavy hubs anchor the
  // top of their lane and ties are broken deterministically.
  const scoreOf = (n: EntityNode) =>
    SEVERITY_RANK[n.severity] * 1000 + n.findings.length * 100 + n.action_count;
  for (const key of colKeys) {
    layers[key].sort((a, b) => scoreOf(b) - scoreOf(a) || a.label.localeCompare(b.label));
  }

  // Barycenter ordering (Sugiyama): repeatedly reorder each lane by the mean row
  // of its connected neighbors so linked entities line up across columns and
  // edge crossings drop sharply. A handful of alternating passes converge for
  // graphs this size, replacing the old fixed stacking that let branches overlap.
  const rowOf = new Map<string, number>();
  for (const key of colKeys) layers[key].forEach((n, i) => rowOf.set(n.id, i));
  const barycenter = (n: EntityNode) => {
    const nb = adj.get(n.id);
    if (!nb || nb.length === 0) return rowOf.get(n.id)!;
    let sum = 0;
    for (const id of nb) sum += rowOf.get(id) ?? 0;
    return sum / nb.length;
  };
  const orderingPasses = nodes.length > 400 ? 3 : 4;
  for (let pass = 0; pass < orderingPasses; pass++) {
    const sweep = pass % 2 === 0 ? colKeys : [...colKeys].reverse();
    for (const key of sweep) {
      const col = layers[key];
      const bc = new Map(col.map((n) => [n.id, barycenter(n)] as const));
      col.sort((a, b) => bc.get(a.id)! - bc.get(b.id)! || scoreOf(b) - scoreOf(a));
      col.forEach((n, i) => rowOf.set(n.id, i));
    }
  }

  // Center each lane vertically around a shared axis so branches stay balanced.
  const tallest = Math.max(1, ...colKeys.map((k) => layers[k].length));
  const flowNodes: Node[] = [];
  colKeys.forEach((key, colIdx) => {
    const col = layers[key];
    const offset = ((tallest - col.length) * ROW_H) / 2;
    col.forEach((n, i) => {
      const color = SEVERITY_COLORS[n.severity];
      flowNodes.push({
        id: n.id,
        type: "entity",
        position: { x: colIdx * COL_W, y: offset + i * ROW_H },
        data: {
          type: n.type,
          label: n.label,
          value: n.value,
          severity: n.severity,
          action_count: n.action_count,
          finding_count: n.findings.length,
          dead: n.meta?.dead ?? false,
          state: n.meta?.state,
          manual: n.meta?.manual ?? false,
          focused: focus?.focusId === n.id,
          hiddenNeighbors: focus?.hiddenNeighbors?.get(n.id) ?? 0,
          color,
        },
      });
    });
  });

  const animateRiskEdges = edges.length <= 120;
  const showEdgeLabels = edges.length <= 180;
  const flowEdges: Edge[] = edges.map((e, i) => {
    const active = e.severity !== "info";
    const color = SEVERITY_COLORS[e.severity];
    return {
      id: `${e.source}-${e.target}-${i}`,
      source: e.source,
      target: e.target,
      sourceHandle: "right",
      targetHandle: "left",
      label: showEdgeLabels ? (e.count > 1 ? `${e.verb} (${e.count})` : e.verb) : undefined,
      type: "smoothstep",
      animated: animateRiskEdges && (e.severity === "critical" || e.severity === "high"),
      labelStyle: { fill: "rgb(var(--ink-300))", fontSize: 10, fontWeight: 600 },
      labelBgStyle: { fill: "rgb(var(--panel-strong))", fillOpacity: 0.88 },
      labelBgPadding: [8, 4],
      labelBgBorderRadius: 8,
      pathOptions: { borderRadius: 24, offset: 34 },
      style: { stroke: active ? color : "rgb(var(--border-strong))", strokeWidth: active ? 2.25 : 1.4 },
      markerEnd: { type: MarkerType.ArrowClosed, color: active ? color : "rgb(var(--border-strong))" },
    };
  });

  return { nodes: flowNodes, edges: flowEdges };
}
