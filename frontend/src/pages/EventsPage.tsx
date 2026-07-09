import { useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { api } from "../lib/api";
import { DetailDrawer, EmptyState, PageShell, PageTitle, Spinner, SeverityBadge, CodeBlock } from "../components/common";
import { FlagAsFinding } from "../components/FlagAsFinding";
import { fmtTime } from "../lib/ui";
import { List, Search } from "lucide-react";
import type { EventRow, Severity } from "../lib/types";

export default function EventsPage() {
  const { caseId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialQuery = searchParams.get("q") ?? "";
  const [search, setSearch] = useState(initialQuery);
  const [query, setQuery] = useState(initialQuery);
  const [category, setCategory] = useState<string>("");
  const [severity, setSeverity] = useState<string>("");
  const [selected, setSelected] = useState<EventRow | null>(null);

  useEffect(() => {
    const q = searchParams.get("q") ?? "";
    setSearch(q);
    setQuery(q);
  }, [searchParams]);

  function submitSearch() {
    const q = search.trim();
    setQuery(q);
    const next = new URLSearchParams(searchParams);
    if (q) next.set("q", q);
    else next.delete("q");
    setSearchParams(next, { replace: true });
  }

  const { data: cats } = useQuery({
    queryKey: ["categories", caseId],
    queryFn: () => api.getCategories(caseId!),
  });

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ["events", caseId, query, category, severity],
    queryFn: () =>
      api.getEvents(caseId!, {
        limit: 300,
        ...(query ? { q: query } : {}),
        ...(category ? { category } : {}),
        ...(severity ? { severity } : {}),
      }),
    placeholderData: keepPreviousData,
  });

  const events = data?.events ?? [];

  return (
    <PageShell>
      <PageTitle
        icon={<List size={22} />}
        title="Events"
        subtitle="Search raw evidence rows and inspect normalized records."
      />
      <div className="card p-3 flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[220px]">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-400" />
          <input
            className="input pl-9"
            placeholder="Full-text search events…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submitSearch()}
          />
        </div>
        <button className="btn-ghost" onClick={submitSearch}>
          Search
        </button>
        <select className="input w-auto py-2" value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">All categories</option>
          {cats?.categories.map((c) => (
            <option key={c.name} value={c.name}>
              {c.name} ({c.count})
            </option>
          ))}
        </select>
        <select className="input w-auto py-2" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      {isLoading ? (
        <Spinner label="Loading events…" />
      ) : events.length === 0 ? (
        <EmptyState icon={<List size={40} />} title="No events" hint="Adjust filters or upload evidence." />
      ) : (
        <div className="card overflow-hidden">
          <div className="text-xs text-ink-400 px-4 py-2 border-b border-white/5 flex items-center justify-between">
            <span>
              Showing {events.length} of {data?.total.toLocaleString()} events
            </span>
            {isFetching && <span className="text-accent-cyan">updating…</span>}
          </div>
          <div className="divide-y divide-white/5 max-h-[65vh] overflow-y-auto">
            {events.map((e) => (
              <button
                key={e.id}
                onClick={() => setSelected(e)}
                className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-white/[0.03] transition"
              >
                <SeverityBadge severity={e.severity} />
                <span className="text-xs text-ink-400 font-mono w-40 shrink-0">
                  {fmtTime(e.timestamp)}
                </span>
                <span className="text-xs text-accent-cyan/80 font-mono w-32 shrink-0 truncate">
                  {e.category}
                </span>
                <span className="text-sm text-ink-200 truncate flex-1">{e.summary}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {selected && (
        <DetailDrawer eyebrow="Event detail" title={selected.category} onClose={() => setSelected(null)} ariaLabel="Event detail">
          <div className="space-y-3 text-sm">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={selected.severity} />
              <span className="text-ink-400">{fmtTime(selected.timestamp)}</span>
            </div>
            <Field
              label="Severity origin"
              value={
                selected.severity_reason ??
                (selected.severity === "info"
                  ? "Default severity — no detection or flagged entity touched this event."
                  : "Base severity assigned by the evidence parser for this source.")
              }
            />
            <Field label="Category" value={selected.category} />
            <Field label="Source" value={selected.source} mono />
            {selected.host && <Field label="Host" value={selected.host} />}
            {selected.entity && <Field label="Entity" value={selected.entity} mono />}
            <Field label="Summary" value={selected.summary} />
            <div>
              <div className="label">Raw</div>
              <CodeBlock>{JSON.stringify(selected.raw, null, 2)}</CodeBlock>
            </div>
            {caseId && (
              <div className="border-t border-[rgb(var(--border)/0.5)] pt-3">
                <FlagAsFinding
                  caseId={caseId}
                  refType="event"
                  refId={String(selected.id)}
                  refLabel={selected.summary}
                  entityHint={selected.entity ?? undefined}
                  defaultTitle={`Analyst-flagged event: ${selected.summary.slice(0, 140)}`}
                  defaultSeverity={selected.severity === "info" ? "medium" : selected.severity}
                />
              </div>
            )}
          </div>
        </DetailDrawer>
      )}
    </PageShell>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="label">{label}</div>
      <div className={`text-ink-100 break-words ${mono ? "font-mono text-xs" : ""}`}>{value}</div>
    </div>
  );
}
