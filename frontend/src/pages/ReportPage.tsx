import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { EmptyState, PageShell, PageTitle, Spinner, SeverityBadge } from "../components/common";
import { FileText, Download, Sparkles, Clock } from "lucide-react";
import type { Severity } from "../lib/types";
import { EvidenceLinkedText, EvidenceReference } from "../components/EvidenceReference";

export default function ReportPage() {
  const { caseId } = useParams();
  const { data: report, isLoading } = useQuery({
    queryKey: ["report", caseId],
    queryFn: () => api.getReport(caseId!),
  });
  const { data: c } = useQuery({
    queryKey: ["case", caseId],
    queryFn: () => api.getCase(caseId!),
  });

  if (isLoading) return <Spinner label="Loading report…" />;
  if (!report?.exists)
    return (
      <EmptyState
        icon={<FileText size={40} />}
        title="No report generated yet"
        hint="Click 'Run AI analysis' to correlate all evidence into an executive summary, timeline narrative, and per-finding verdicts."
      />
    );

  function exportReport() {
    const content = buildMarkdown();
    const blob = new Blob([content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `investigator-report-${caseId}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function buildMarkdown(): string {
    let md = `# Investigation Report: ${c?.name ?? caseId}\n\n`;
    md += `_Generated ${report?.generated_at}_\n\n`;
    md += `## Executive Summary\n\n${report?.summary ?? ""}\n\n`;
    if (report?.timeline_entries?.length) {
      md += `## Evidence-backed Timeline\n\n`;
      for (const entry of report.timeline_entries) {
        md += `### ${entry.start} — ${entry.title}\n\n${entry.description}\n\n`;
        md += `${entry.event_ids.map((id) => `Event #${id}`).join(", ")}`;
        if (entry.finding_ids.length) md += ` · ${entry.finding_ids.map((id) => `Finding #${id}`).join(", ")}`;
        md += `\n\n`;
      }
    } else if (report?.timeline_narrative) {
      md += `## Timeline Narrative\n\n${report.timeline_narrative}\n\n`;
    }
    md += `## Finding Coverage\n\n`;
    for (const f of report?.findings_analysis ?? []) {
      md += `### [${f.severity.toUpperCase()}] ${f.title}\n\n${f.verdict}\n\n`;
    }
    return md;
  }

  return (
    <PageShell className="max-w-5xl">
      <PageTitle
        icon={<FileText size={22} />}
        title="Report"
        subtitle="Executive summary, timeline narrative, and finding verdicts."
        right={
          <button className="btn-ghost" onClick={exportReport}>
            <Download size={16} /> Export Markdown
          </button>
        }
      />
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm text-ink-400">
          <Clock size={14} /> Generated {new Date(report.generated_at!).toLocaleString()}
        </div>
      </div>

      {report.stale && (
        <div className="rounded-xl border border-sev-medium/30 bg-sev-medium/10 px-4 py-3 text-sm text-sev-medium">
          Finding suppression changed after this report was generated. Run AI analysis again before relying on its conclusions.
        </div>
      )}

      <div className="card p-6">
        <h2 className="flex items-center gap-2 text-lg font-semibold text-ink-50 mb-3">
          <Sparkles size={18} className="text-accent-cyan" /> Executive Summary
        </h2>
        <p className="text-sm text-ink-200 leading-relaxed whitespace-pre-wrap">
          <EvidenceLinkedText caseId={caseId!} text={report.summary ?? ""} />
        </p>
      </div>

      {report.timeline_entries && report.timeline_entries.length > 0 ? (
        <div className="card p-6">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-ink-50 mb-4">
            <Clock size={18} className="text-accent-cyan" /> Evidence-backed Timeline
          </h2>
          <div className="space-y-4">
            {report.timeline_entries.map((entry) => (
              <article key={entry.id} className="relative border-l-2 border-accent-cyan/40 pl-5 pb-2">
                <div className="absolute -left-[5px] top-1.5 h-2 w-2 rounded-full bg-accent-cyan" />
                <div className="flex flex-wrap items-center gap-2">
                  <time className="font-mono text-xs text-ink-400">{new Date(entry.start).toLocaleString()}</time>
                  <span className="chip bg-white/5 text-ink-400">{entry.confidence} confidence</span>
                </div>
                <h3 className="mt-1 text-sm font-semibold text-ink-100">{entry.title}</h3>
                <p className="mt-1 text-sm leading-relaxed text-ink-300">
                  <EvidenceLinkedText caseId={caseId!} text={entry.description} />
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {entry.event_refs.map((ref) => (
                    <EvidenceReference key={`e-${ref.id}`} caseId={caseId!} kind="event" id={ref.id} label={ref.summary} />
                  ))}
                  {entry.finding_refs.map((ref) => (
                    <EvidenceReference
                      key={`f-${ref.id}`} caseId={caseId!} kind="finding" id={ref.id}
                      label={ref.title} suppressed={ref.suppressed}
                    />
                  ))}
                </div>
              </article>
            ))}
          </div>
        </div>
      ) : report.timeline_narrative ? (
        <div className="card p-6">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-ink-50 mb-3">
            <Clock size={18} className="text-accent-cyan" /> Timeline Narrative
          </h2>
          <p className="text-sm text-ink-200 leading-relaxed whitespace-pre-wrap">
            {report.timeline_narrative}
          </p>
        </div>
      ) : null}

      {report.findings_analysis && report.findings_analysis.length > 0 && (
        <div className="card p-6">
          <h2 className="text-lg font-semibold text-ink-50 mb-4">Finding Coverage</h2>
          <div className="space-y-4">
            {report.findings_analysis.map((f) => (
              <div key={f.id} className="border-l-2 pl-4 py-1" style={{ borderColor: sevColor(f.severity) }}>
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={f.severity} />
                  <span className="text-sm font-medium text-ink-100">{f.title}</span>
                  <span className="chip bg-white/5 text-ink-400">
                    {f.basis === "finding-evidence" ? "recorded evidence" : "AI assessment"}
                  </span>
                </div>
                <p className="text-sm text-ink-300 whitespace-pre-wrap">
                  <EvidenceLinkedText caseId={caseId!} text={f.verdict} />
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </PageShell>
  );
}

function sevColor(s: Severity): string {
  return { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#64748b" }[s];
}
