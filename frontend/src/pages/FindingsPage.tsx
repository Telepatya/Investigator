import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { EmptyState, Spinner, SeverityBadge, CodeBlock } from "../components/common";
import { AlertTriangle, ChevronDown, ChevronRight, Sparkles, Shield } from "lucide-react";
import type { Finding, Severity } from "../lib/types";
import { SEVERITY_ORDER } from "../lib/ui";

export default function FindingsPage() {
  const { caseId } = useParams();
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");
  const { data, isLoading } = useQuery({
    queryKey: ["findings", caseId],
    queryFn: () => api.getFindings(caseId!),
  });

  if (isLoading) return <Spinner label="Loading findings…" />;
  const findings = data?.findings ?? [];
  if (findings.length === 0)
    return (
      <EmptyState
        icon={<Shield size={40} />}
        title="No findings yet"
        hint="The detection engine runs automatically after ingestion. Upload evidence to surface suspicious activity mapped to MITRE ATT&CK."
      />
    );

  const filtered =
    sevFilter === "all" ? findings : findings.filter((f) => f.severity === sevFilter);

  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

  return (
    <div className="space-y-4">
      <div className="card p-3 flex items-center gap-2 flex-wrap">
        <button
          className={`chip ${sevFilter === "all" ? "bg-accent-cyan/15 text-accent-cyan" : "bg-white/5 text-ink-300"}`}
          onClick={() => setSevFilter("all")}
        >
          all ({findings.length})
        </button>
        {(["critical", "high", "medium", "low", "info"] as Severity[])
          .filter((s) => counts[s])
          .map((s) => (
            <button
              key={s}
              className={`chip ${sevFilter === s ? "bg-accent-cyan/15 text-accent-cyan" : "bg-white/5 text-ink-300"}`}
              onClick={() => setSevFilter(s)}
            >
              {s} ({counts[s]})
            </button>
          ))}
      </div>

      <div className="space-y-2">
        {filtered
          .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity])
          .map((f) => (
            <FindingRow key={f.id} f={f} />
          ))}
      </div>
    </div>
  );
}

function FindingRow({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="card overflow-hidden">
      <button
        className="w-full flex items-start gap-3 p-4 text-left hover:bg-white/[0.02]"
        onClick={() => setOpen(!open)}
      >
        <div className="mt-0.5">
          {open ? (
            <ChevronDown size={16} className="text-ink-400" />
          ) : (
            <ChevronRight size={16} className="text-ink-400" />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <SeverityBadge severity={f.severity} />
            {f.mitre_techniques.map((t) => (
              <span key={t} className="chip bg-accent-violet/10 text-accent-violet font-mono">
                {t}
              </span>
            ))}
            <span className="text-[11px] text-ink-500 font-mono ml-auto">{f.source}</span>
          </div>
          <div className="text-sm font-medium text-ink-50">{f.title}</div>
          {!open && (
            <div className="text-xs text-ink-400 mt-0.5 line-clamp-1">{f.description}</div>
          )}
        </div>
      </button>
      {open && (
        <div className="px-4 pb-4 pl-11 space-y-3">
          <div className="text-sm text-ink-200">{f.description}</div>
          {f.ai_verdict && (
            <div className="bg-accent-violet/5 border border-accent-violet/20 rounded-lg p-3">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-accent-violet uppercase tracking-wider mb-1.5">
                <Sparkles size={12} /> AI verdict
              </div>
              <div className="text-sm text-ink-200 whitespace-pre-wrap">{f.ai_verdict}</div>
            </div>
          )}
          {f.evidence && Object.keys(f.evidence).length > 0 && (
            <div>
              <div className="label">Evidence</div>
              <CodeBlock>{JSON.stringify(f.evidence, null, 2)}</CodeBlock>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
