import { useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { Timeline } from "vis-timeline/standalone";
import { DataSet } from "vis-data";
import "vis-timeline/styles/vis-timeline-graph2d.css";
import { api } from "../lib/api";
import { Spinner, EmptyState, SeverityBadge, CodeBlock } from "../components/common";
import { SEVERITY_COLORS, fmtTime } from "../lib/ui";
import type { Severity, TimelineEvt } from "../lib/types";
import { Clock, Filter, Search, X } from "lucide-react";

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export default function TimelinePage() {
  const { caseId } = useParams();
  const containerRef = useRef<HTMLDivElement>(null);
  const timelineRef = useRef<Timeline | null>(null);
  const [selected, setSelected] = useState<TimelineEvt | null>(null);
  const [minSeverity, setMinSeverity] = useState<Severity>("info");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [disabledSources, setDisabledSources] = useState<Set<string>>(new Set());
  const [showSources, setShowSources] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search.trim()), 400);
    return () => clearTimeout(t);
  }, [search]);

  // Latest known source list, readable inside queryFn without self-referencing
  // the query result.
  const sourcesRef = useRef<{ name: string; count: number }[]>([]);

  // All filtering is server-side, so the source list and counts cover the whole
  // case (not just the first page of events) and filters reveal capped events.
  const { data, isLoading, isFetching } = useQuery({
    queryKey: [
      "timeline",
      caseId,
      debouncedSearch,
      minSeverity,
      Array.from(disabledSources).sort().join("|"),
    ],
    queryFn: () =>
      api.getTimeline(caseId!, {
        ...(debouncedSearch ? { q: debouncedSearch } : {}),
        ...(minSeverity !== "info" ? { min_severity: minSeverity } : {}),
        ...(disabledSources.size > 0
          ? {
              sources: sourcesRef.current
                .map((s) => s.name)
                .filter((n) => !disabledSources.has(n))
                .join(","),
            }
          : {}),
      }),
    placeholderData: keepPreviousData,
  });

  useEffect(() => {
    if (data?.sources) sourcesRef.current = data.sources;
  }, [data]);

  const events = useMemo(() => data?.events ?? [], [data]);
  const sources = data?.sources ?? [];
  const total = data?.total ?? 0;
  const totalMatching = data?.total_matching ?? 0;
  const hasFilters =
    debouncedSearch !== "" || minSeverity !== "info" || disabledSources.size > 0;

  const toggleSource = (name: string) => {
    setDisabledSources((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  useEffect(() => {
    if (!containerRef.current || events.length === 0) return;

    const groups = new DataSet(
      Array.from(new Set(events.map((e) => e.group))).map((g) => ({
        id: g,
        content: g,
      })),
    );

    const items = new DataSet(
      events
        .filter((e) => e.start)
        .map((e) => ({
          id: e.id,
          content: e.content,
          title:
            `<b>[${e.severity.toUpperCase()}]</b> ${escapeHtml(e.content)}<br/>` +
            `<span>source: ${escapeHtml(e.source)}</span>` +
            (e.severity_reason ? `<br/><i>${escapeHtml(e.severity_reason)}</i>` : ""),
          start: e.start as string,
          group: e.group,
          style: `background-color: ${SEVERITY_COLORS[e.severity]}cc; color: #0a0c12; border-color:${SEVERITY_COLORS[e.severity]};`,
        })),
    );

    const timeline = new Timeline(containerRef.current, items, groups, {
      stack: true,
      maxHeight: 460,
      minHeight: 460,
      zoomKey: "ctrlKey",
      tooltip: { followMouse: true },
      orientation: "top",
    });

    timeline.on("select", (props) => {
      const id = props.items?.[0];
      const evt = events.find((e) => e.id === id);
      if (evt) setSelected(evt);
    });

    timelineRef.current = timeline;
    return () => {
      timeline.destroy();
      timelineRef.current = null;
    };
  }, [events]);

  if (isLoading) return <Spinner label="Building timeline…" />;
  if (total === 0 && !hasFilters)
    return (
      <EmptyState
        icon={<Clock size={40} />}
        title="No timestamped events"
        hint="Upload Velociraptor artifacts with timestamps (event logs, MFT, prefetch, etc.) to populate the machine timeline."
      />
    );

  return (
    <div className="space-y-4">
      <div className="card p-3 space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-2 text-sm text-ink-300">
            <Clock size={16} className="text-accent-cyan" />
            {events.length.toLocaleString()} shown of {totalMatching.toLocaleString()} matching
            ({total.toLocaleString()} total) · scroll to pan, Ctrl+scroll to zoom
            {isFetching && <span className="text-accent-cyan text-xs">updating…</span>}
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative">
              <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-400" />
              <input
                className="input w-64 py-1 pl-8"
                placeholder="Search events, entities, sources…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              {search && (
                <button
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-ink-400 hover:text-ink-100"
                  onClick={() => setSearch("")}
                >
                  <X size={13} />
                </button>
              )}
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-ink-400">Min severity</span>
              <select
                className="input w-auto py-1"
                value={minSeverity}
                onChange={(e) => setMinSeverity(e.target.value as Severity)}
              >
                {(["info", "low", "medium", "high", "critical"] as Severity[]).map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
            <button
              className={`chip cursor-pointer select-none ${
                disabledSources.size > 0 ? "text-accent-cyan border-accent-cyan/40" : "text-ink-300"
              }`}
              onClick={() => setShowSources((v) => !v)}
            >
              <Filter size={12} />
              Sources
              {disabledSources.size > 0 &&
                ` (${sources.length - disabledSources.size}/${sources.length})`}
            </button>
          </div>
        </div>

        {showSources && (
          <div className="border-t border-white/5 pt-3">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-xs uppercase tracking-wider text-ink-400">
                Evidence sources
              </span>
              <button
                className="text-xs text-accent-cyan hover:underline"
                onClick={() => setDisabledSources(new Set())}
              >
                all
              </button>
              <button
                className="text-xs text-accent-cyan hover:underline"
                onClick={() => setDisabledSources(new Set(sources.map((s) => s.name)))}
              >
                none
              </button>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-4 gap-y-1 max-h-48 overflow-y-auto pr-2">
              {sources.map((s) => (
                <label
                  key={s.name}
                  className="flex items-center gap-2 text-xs text-ink-200 cursor-pointer hover:text-ink-50"
                  title={s.name}
                >
                  <input
                    type="checkbox"
                    className="accent-cyan-400"
                    checked={!disabledSources.has(s.name)}
                    onChange={() => toggleSource(s.name)}
                  />
                  <span className="truncate font-mono">{s.name}</span>
                  <span className="text-ink-500 shrink-0">({s.count.toLocaleString()})</span>
                </label>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="card p-2">
        {events.length === 0 ? (
          <div className="p-10 text-center text-sm text-ink-400">
            No events match the current filters.
          </div>
        ) : (
          <div ref={containerRef} />
        )}
      </div>

      {selected && (
        <div className="fixed inset-y-0 right-0 z-50 w-full max-w-md glass border-l border-white/10 p-5 overflow-y-auto shadow-2xl">
          <div className="flex items-start justify-between mb-4">
            <div>
              <div className="text-xs uppercase tracking-wider text-ink-400">Event detail</div>
              <div className="text-lg font-semibold text-ink-50 mt-1">{selected.group}</div>
            </div>
            <button className="text-ink-400 hover:text-ink-100" onClick={() => setSelected(null)}>
              <X size={18} />
            </button>
          </div>
          <div className="space-y-3 text-sm">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={selected.severity} />
              <span className="text-ink-400">{fmtTime(selected.start)}</span>
            </div>
            <div>
              <div className="label">Severity origin</div>
              <div className="text-ink-200 text-xs">
                {selected.severity_reason ??
                  (selected.severity === "info"
                    ? "Default severity — no detection or flagged entity touched this event."
                    : "Base severity assigned by the evidence parser for this source.")}
              </div>
            </div>
            <div>
              <div className="label">Source</div>
              <div className="text-ink-200 font-mono text-xs">{selected.source}</div>
            </div>
            <div>
              <div className="label">Summary</div>
              <div className="text-ink-100">{selected.content}</div>
            </div>
            <div>
              <div className="label">Raw evidence</div>
              <CodeBlock>{JSON.stringify(selected.raw, null, 2)}</CodeBlock>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
