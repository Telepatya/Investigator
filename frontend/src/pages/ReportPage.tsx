import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { EmptyState, Spinner, SeverityBadge } from "../components/common";
import { FileText, Download, Sparkles, Clock } from "lucide-react";
import type { Severity } from "../lib/types";

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
    if (report?.timeline_narrative) {
      md += `## Timeline Narrative\n\n${report.timeline_narrative}\n\n`;
    }
    md += `## Finding Verdicts\n\n`;
    for (const f of report?.findings_analysis ?? []) {
      md += `### [${f.severity.toUpperCase()}] ${f.title}\n\n${f.verdict}\n\n`;
    }
    return md;
  }

  return (
    <div className="space-y-5 max-w-4xl">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm text-ink-400">
          <Clock size={14} /> Generated {new Date(report.generated_at!).toLocaleString()}
        </div>
        <button className="btn-ghost" onClick={exportReport}>
          <Download size={16} /> Export Markdown
        </button>
      </div>

      <div className="card p-6">
        <h2 className="flex items-center gap-2 text-lg font-semibold text-ink-50 mb-3">
          <Sparkles size={18} className="text-accent-cyan" /> Executive Summary
        </h2>
        <p className="text-sm text-ink-200 leading-relaxed whitespace-pre-wrap">
          {report.summary}
        </p>
      </div>

      {report.timeline_narrative && (
        <div className="card p-6">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-ink-50 mb-3">
            <Clock size={18} className="text-accent-cyan" /> Timeline Narrative
          </h2>
          <p className="text-sm text-ink-200 leading-relaxed whitespace-pre-wrap">
            {report.timeline_narrative}
          </p>
        </div>
      )}

      {report.findings_analysis && report.findings_analysis.length > 0 && (
        <div className="card p-6">
          <h2 className="text-lg font-semibold text-ink-50 mb-4">Finding Verdicts</h2>
          <div className="space-y-4">
            {report.findings_analysis.map((f) => (
              <div key={f.id} className="border-l-2 pl-4 py-1" style={{ borderColor: sevColor(f.severity) }}>
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={f.severity} />
                  <span className="text-sm font-medium text-ink-100">{f.title}</span>
                </div>
                <p className="text-sm text-ink-300 whitespace-pre-wrap">{f.verdict}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function sevColor(s: Severity): string {
  return { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#64748b" }[s];
}
