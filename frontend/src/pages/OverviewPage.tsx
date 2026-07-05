import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Cpu,
  ShieldAlert,
  Sparkles,
  HardDrive,
} from "lucide-react";
import { api } from "../lib/api";
import { StatCard, Section, Spinner } from "../components/common";
import { AttackMatrix } from "../components/AttackMatrix";
import { SEVERITY_ORDER } from "../lib/ui";
import type { Finding, Severity } from "../lib/types";

export default function OverviewPage() {
  const { caseId } = useParams();
  const { data: c } = useQuery({
    queryKey: ["case", caseId],
    queryFn: () => api.getCase(caseId!),
  });
  const { data: findingsData, isLoading } = useQuery({
    queryKey: ["findings", caseId],
    queryFn: () => api.getFindings(caseId!),
  });
  const { data: report } = useQuery({
    queryKey: ["report", caseId],
    queryFn: () => api.getReport(caseId!),
  });

  const findings = findingsData?.findings ?? [];
  const counts = countSeverities(findings);
  const worst = worstSeverity(findings);

  return (
    <div className="space-y-5">
      <VerdictBanner worst={worst} counts={counts} summary={report?.summary} />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Events"
          value={(c?.event_count ?? 0).toLocaleString()}
          icon={<Activity size={20} />}
          accent="#22d3ee"
        />
        <StatCard
          label="Findings"
          value={c?.finding_count ?? 0}
          icon={<AlertTriangle size={20} />}
          accent="#f97316"
        />
        <StatCard
          label="Processes"
          value={c?.process_count ?? 0}
          icon={<Cpu size={20} />}
          accent="#8b5cf6"
        />
        <StatCard
          label="Memory dump"
          value={c?.has_memory_dump ? "Yes" : "No"}
          icon={<HardDrive size={20} />}
          accent="#3b82f6"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
        <div className="lg:col-span-2 space-y-5">
          <Section title="Severity breakdown">
            <div className="space-y-2.5">
              {(["critical", "high", "medium", "low", "info"] as Severity[]).map((sev) => (
                <SeverityBar key={sev} sev={sev} count={counts[sev] ?? 0} total={findings.length} />
              ))}
            </div>
          </Section>
        </div>
        <div className="lg:col-span-3">
          <Section title="MITRE ATT&CK coverage">
            <AttackMatrix caseId={caseId!} />
          </Section>
        </div>
      </div>

      {isLoading && <Spinner label="Loading findings…" />}
    </div>
  );
}

function VerdictBanner({
  worst,
  counts,
  summary,
}: {
  worst: Severity | null;
  counts: Record<string, number>;
  summary?: string;
}) {
  const compromised = worst === "critical" || worst === "high";
  const label = !worst
    ? "No findings yet"
    : compromised
      ? "Likely compromised"
      : worst === "medium"
        ? "Suspicious activity"
        : "No strong indicators";
  const color = !worst
    ? "#64748b"
    : compromised
      ? "#ef4444"
      : worst === "medium"
        ? "#eab308"
        : "#10b981";

  return (
    <div
      className="card p-6 relative overflow-hidden"
      style={{ borderColor: `${color}40` }}
    >
      <div
        className="absolute inset-0 opacity-[0.07]"
        style={{ background: `radial-gradient(600px 200px at 0% 0%, ${color}, transparent)` }}
      />
      <div className="relative flex items-start gap-4">
        <div
          className="grid place-items-center w-12 h-12 rounded-xl shrink-0"
          style={{ background: `${color}20`, color }}
        >
          <ShieldAlert size={24} />
        </div>
        <div className="flex-1">
          <div className="text-xs uppercase tracking-widest text-ink-400">Verdict</div>
          <div className="text-2xl font-bold mt-0.5" style={{ color }}>
            {label}
          </div>
          {summary ? (
            <p className="text-sm text-ink-200 mt-3 leading-relaxed whitespace-pre-wrap">
              {summary.length > 600 ? summary.slice(0, 600) + "…" : summary}
            </p>
          ) : (
            <p className="text-sm text-ink-400 mt-3 flex items-center gap-2">
              <Sparkles size={14} /> Run AI analysis to generate an executive summary.
            </p>
          )}
          <div className="flex gap-2 mt-4 flex-wrap">
            {(["critical", "high", "medium"] as Severity[]).map(
              (s) =>
                (counts[s] ?? 0) > 0 && (
                  <span
                    key={s}
                    className="chip"
                    style={{
                      background: `${sevColor(s)}20`,
                      color: sevColor(s),
                    }}
                  >
                    {counts[s]} {s}
                  </span>
                ),
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function SeverityBar({ sev, count, total }: { sev: Severity; count: number; total: number }) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div>
      <div className="flex items-center justify-between text-xs mb-1">
        <span className="capitalize text-ink-200">{sev}</span>
        <span className="text-ink-400">{count}</span>
      </div>
      <div className="h-2 bg-base-900 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${pct}%`, background: sevColor(sev) }}
        />
      </div>
    </div>
  );
}

function sevColor(s: Severity): string {
  return { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#64748b" }[s];
}

function countSeverities(findings: Finding[]): Record<string, number> {
  const c: Record<string, number> = {};
  for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
  return c;
}

function worstSeverity(findings: Finding[]): Severity | null {
  let worst: Severity | null = null;
  for (const f of findings) {
    if (!worst || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst]) worst = f.severity;
  }
  return worst;
}
