import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Spinner, SeverityBadge, CodeBlock, EmptyState } from "../components/common";
import { fmtTime } from "../lib/ui";
import { List, Search, X } from "lucide-react";
import type { EventRow, Severity } from "../lib/types";

export default function EventsPage() {
  const { caseId } = useParams();
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<string>("");
  const [severity, setSeverity] = useState<string>("");
  const [selected, setSelected] = useState<EventRow | null>(null);

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
    <div className="space-y-4">
      <div className="card p-3 flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[220px]">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-400" />
          <input
            className="input pl-9"
            placeholder="Full-text search events…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && setQuery(search)}
          />
        </div>
        <button className="btn-ghost" onClick={() => setQuery(search)}>
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
        <div className="fixed inset-y-0 right-0 z-50 w-full max-w-md glass border-l border-white/10 p-5 overflow-y-auto shadow-2xl">
          <div className="flex items-start justify-between mb-4">
            <div className="text-xs uppercase tracking-wider text-ink-400">Event detail</div>
            <button className="text-ink-400 hover:text-ink-100" onClick={() => setSelected(null)}>
              <X size={18} />
            </button>
          </div>
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
          </div>
        </div>
      )}
    </div>
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
