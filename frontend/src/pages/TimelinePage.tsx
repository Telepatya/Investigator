import { useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { Timeline } from "vis-timeline/standalone";
import { DataSet } from "vis-data";
import "vis-timeline/styles/vis-timeline-graph2d.css";
import { api } from "../lib/api";
import { EmptyState, PageShell, SeverityBadge, CodeBlock, Spinner } from "../components/common";
import { SEVERITY_COLORS, fmtTime } from "../lib/ui";
import type { Severity, TimelineEvt } from "../lib/types";
import { CalendarDays, Clock, Filter, Search, SlidersHorizontal, X, ZoomIn, ZoomOut } from "lucide-react";

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
  const [disabledCategories, setDisabledCategories] = useState<Set<string>>(new Set());
  const [showCategories, setShowCategories] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search.trim()), 400);
    return () => clearTimeout(t);
  }, [search]);

  // Latest known source list, readable inside queryFn without self-referencing
  // the query result.
  const sourcesRef = useRef<{ name: string; count: number }[]>([]);
  const categoriesRef = useRef<{ name: string; count: number }[]>([]);

  // All filtering is server-side, so the source list and counts cover the whole
  // case (not just the first page of events) and filters reveal capped events.
  const { data, isLoading, isFetching } = useQuery({
    queryKey: [
      "timeline",
      caseId,
      debouncedSearch,
      minSeverity,
      Array.from(disabledSources).sort().join("|"),
      Array.from(disabledCategories).sort().join("|"),
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
        ...(disabledCategories.size > 0
          ? {
              categories: categoriesRef.current
                .map((c) => c.name)
                .filter((n) => !disabledCategories.has(n))
                .join(","),
            }
          : {}),
      }),
    placeholderData: keepPreviousData,
  });

  useEffect(() => {
    if (data?.sources) sourcesRef.current = data.sources;
    if (data?.categories) categoriesRef.current = data.categories;
  }, [data]);

  const events = useMemo(() => data?.events ?? [], [data]);
  const sources = data?.sources ?? [];
  const categories = data?.categories ?? [];
  const total = data?.total ?? 0;
  const totalMatching = data?.total_matching ?? 0;
  const hasFilters =
    debouncedSearch !== "" ||
    minSeverity !== "info" ||
    disabledSources.size > 0 ||
    disabledCategories.size > 0;

  const toggleSource = (name: string) => {
    setDisabledSources((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const toggleCategory = (name: string) => {
    setDisabledCategories((prev) => {
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
          content: itemHtml(e),
          start: e.start as string,
          group: e.group,
          type: "box",
          style: `background-color: rgb(var(--panel-strong)); color: rgb(var(--ink-50)); border-color:${SEVERITY_COLORS[e.severity]}66;`,
        })),
    );

    const timeline = new Timeline(containerRef.current, items, groups, {
      stack: true,
      maxHeight: 460,
      minHeight: 460,
      margin: { item: { horizontal: 14, vertical: 12 } },
      zoomKey: "ctrlKey",
      orientation: "top",
    });

    timeline.on("doubleClick", (props) => {
      const id = props.item;
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
    <PageShell>
      <section className="surface overflow-hidden p-5">
        <div className="flex items-start gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-2xl bg-accent-blue/10 text-accent-blue ring-1 ring-accent-blue/20">
            <Clock size={22} />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-ink-50">Timeline</h1>
            <p className="mt-1 text-sm text-ink-300">
              Review events and evidence over time to understand the sequence of activity.
            </p>
          </div>
        </div>

      <div className="mt-5 space-y-3 rounded-3xl border border-[rgb(var(--border)/0.7)] bg-[rgb(var(--panel)/0.56)] p-3">
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
              <SlidersHorizontal size={12} />
              Sources
              {disabledSources.size > 0 &&
                ` (${sources.length - disabledSources.size}/${sources.length})`}
            </button>
            <button
              className={`chip cursor-pointer select-none ${
                disabledCategories.size > 0 ? "text-accent-cyan border-accent-cyan/40" : "text-ink-300"
              }`}
              onClick={() => setShowCategories((v) => !v)}
            >
              <Filter size={12} />
              Types
              {disabledCategories.size > 0 &&
                ` (${categories.length - disabledCategories.size}/${categories.length})`}
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

        {showCategories && (
          <div className="border-t border-white/5 pt-3">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-xs uppercase tracking-wider text-ink-400">
                Event types
              </span>
              <button
                className="text-xs text-accent-cyan hover:underline"
                onClick={() => setDisabledCategories(new Set())}
              >
                all
              </button>
              <button
                className="text-xs text-accent-cyan hover:underline"
                onClick={() => setDisabledCategories(new Set(categories.map((c) => c.name)))}
              >
                none
              </button>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-4 gap-y-1 max-h-48 overflow-y-auto pr-2">
              {categories.map((c) => (
                <label
                  key={c.name}
                  className="flex items-center gap-2 text-xs text-ink-200 cursor-pointer hover:text-ink-50"
                  title={c.name}
                >
                  <input
                    type="checkbox"
                    className="accent-cyan-400"
                    checked={!disabledCategories.has(c.name)}
                    onChange={() => toggleCategory(c.name)}
                  />
                  <span className="truncate font-mono">{c.name}</span>
                  <span className="text-ink-500 shrink-0">({c.count.toLocaleString()})</span>
                </label>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="timeline-board grid overflow-hidden rounded-3xl border border-[rgb(var(--border)/0.7)] bg-[rgb(var(--panel-strong)/0.5)] md:grid-cols-[190px_minmax(0,1fr)]">
        <TimelineRail events={events} />
        <div className="min-w-0 p-2">
        {events.length === 0 ? (
          <div className="p-10 text-center text-sm text-ink-400">
            No events match the current filters.
          </div>
        ) : (
          <div ref={containerRef} />
        )}
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="glass flex items-center overflow-hidden rounded-2xl">
          <button className="px-4 py-3 text-ink-200 hover:bg-white/40" onClick={() => timelineRef.current?.zoomIn(0.4)} title="Zoom in">
            <ZoomIn size={16} />
          </button>
          <button className="border-l border-[rgb(var(--border)/0.6)] px-4 py-3 text-ink-200 hover:bg-white/40" onClick={() => timelineRef.current?.zoomOut(0.4)} title="Zoom out">
            <ZoomOut size={16} />
          </button>
        </div>
        <div className="glass flex items-center gap-2 rounded-2xl px-4 py-3 text-sm text-ink-200">
          <CalendarDays size={16} className="text-accent-blue" />
          {events[0]?.start ? fmtTime(events[0].start) : "No range"} - {events[events.length - 1]?.start ? fmtTime(events[events.length - 1].start) : "No range"}
        </div>
      </div>
      </section>

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
    </PageShell>
  );
}

function TimelineRail({
  events,
}: {
  events: TimelineEvt[];
}) {
  const years = buildTimelineBuckets(events);

  return (
    <aside className="hidden border-r border-[rgb(var(--border)/0.65)] bg-[rgb(var(--panel-muted)/0.35)] md:block">
      <div className="max-h-[460px] overflow-y-auto">
        {years.length === 0 ? (
          <div className="text-sm text-ink-300">No event lanes</div>
        ) : (
          years.map((year) => (
            <section key={year.year} className="border-b border-[rgb(var(--border)/0.55)] last:border-b-0">
              <div className="px-5 py-4">
                <div className="flex items-center justify-between">
                  <div className="text-lg font-extrabold text-ink-50">{year.year}</div>
                  <div className="rounded-full bg-[rgb(var(--panel-strong))] px-2.5 py-1 text-xs font-bold text-ink-300">
                    {year.count}
                  </div>
                </div>
              </div>
              <div className="space-y-4 px-4 pb-5">
                {year.months.map((month) => (
                  <div key={`${year.year}-${month.month}`}>
                    <div className="mb-2 flex items-center justify-between text-sm font-bold text-ink-100">
                      <span>{month.label}</span>
                      <span className="text-xs text-ink-400">{month.count}</span>
                    </div>
                    <div className="space-y-1.5">
                      {month.groups.map((group) => (
                        <div key={group.name} className="flex items-center gap-2 pl-2 text-xs font-semibold text-ink-300">
                          <span className="h-2 w-2 rounded-full bg-accent-blue/70" />
                          <span className="min-w-0 flex-1 truncate">{laneLabel(group.name)}</span>
                          <span className="rounded-full bg-accent-blue/10 px-2 py-0.5 text-accent-blue">{group.count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          ))
        )}
      </div>
    </aside>
  );
}

function buildTimelineBuckets(events: TimelineEvt[]) {
  const yearMap = new Map<number, Map<number, Map<string, number>>>();
  for (const event of events) {
    if (!event.start) continue;
    const date = new Date(event.start);
    if (Number.isNaN(date.getTime())) continue;
    const year = date.getFullYear();
    const month = date.getMonth();
    const months = yearMap.get(year) ?? new Map<number, Map<string, number>>();
    const groups = months.get(month) ?? new Map<string, number>();
    groups.set(event.group, (groups.get(event.group) ?? 0) + 1);
    months.set(month, groups);
    yearMap.set(year, months);
  }

  return Array.from(yearMap.entries())
    .sort(([a], [b]) => a - b)
    .map(([year, months]) => {
      const monthRows = Array.from(months.entries())
        .sort(([a], [b]) => a - b)
        .map(([month, groups]) => {
          const groupRows = Array.from(groups.entries())
            .map(([name, count]) => ({ name, count }))
            .sort((a, b) => b.count - a.count || laneLabel(a.name).localeCompare(laneLabel(b.name)));
          const count = groupRows.reduce((sum, group) => sum + group.count, 0);
          return {
            month,
            label: new Date(year, month, 1).toLocaleString(undefined, { month: "short" }),
            count,
            groups: groupRows,
          };
        });
      return {
        year,
        count: monthRows.reduce((sum, month) => sum + month.count, 0),
        months: monthRows,
      };
    });
}

function timelineTitle(e: TimelineEvt): string {
  const content = e.content || "Timeline event";
  const pathMatch = /(?:DownloadedFilePath|TargetFilename|Image|Path)=([^;,]+)/i.exec(content);
  if (pathMatch?.[1]) {
    const path = pathMatch[1].trim();
    const name = path.split(/[\\/]/).filter(Boolean).pop() || path;
    return `${name} downloaded`;
  }
  return content.length > 72 ? `${content.slice(0, 72)}...` : content;
}

function timelineSubtext(e: TimelineEvt): string {
  const content = e.content || "";
  const pathMatch = /(?:DownloadedFilePath|TargetFilename|Image|Path)=([^;,]+)/i.exec(content);
  if (pathMatch?.[1]) return pathMatch[1].trim();
  return e.source;
}

function laneLabel(group: string): string {
  const lower = group.toLowerCase();
  if (lower.includes("file") || lower.includes("artifact") || lower.includes("filesystem")) return "File Activity";
  if (lower.includes("network")) return "Network Activity";
  if (lower.includes("process")) return "Process Activity";
  if (lower.includes("registry")) return "Registry Activity";
  return group.replace(/[_-]+/g, " ");
}

function itemHtml(e: TimelineEvt): string {
  return `
    <div class="timeline-card-item">
      <div class="timeline-card-title">${escapeHtml(timelineTitle(e))}</div>
      <div class="timeline-card-sub">${escapeHtml(timelineSubtext(e))}</div>
      <div class="timeline-card-time">${escapeHtml(fmtTime(e.start))}</div>
    </div>
  `;
}
