import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Cpu,
  FileText,
  FolderOpen,
  HardDrive,
  NotebookPen,
  Radar,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { api } from "../lib/api";
import { MetricCard, PageShell, Section, SeverityBadge, Spinner } from "../components/common";
import { AttackMatrix } from "../components/AttackMatrix";
import { SEVERITY_COLORS, SEVERITY_ORDER, fmtRelative, fmtTime } from "../lib/ui";
import type { EvidenceFile, Finding, Severity, TimelineEvt } from "../lib/types";

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
  const { data: evidenceData } = useQuery({
    queryKey: ["evidence", caseId],
    queryFn: () => api.listEvidence(caseId!),
  });
  const { data: timelineData } = useQuery({
    queryKey: ["timeline", caseId, "overview"],
    queryFn: () => api.getTimeline(caseId!, { limit: 6 }),
  });

  const findings = findingsData?.findings.filter((f) => !f.suppressed) ?? [];
  const evidence = evidenceData?.files ?? [];
  const counts = countSeverities(findings);

  return (
    <PageShell>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
        <MetricCard
          label="Events"
          value={(c?.event_count ?? 0).toLocaleString()}
          icon={<Activity size={23} />}
          accent="#3b82f6"
          trend={c ? `updated ${fmtRelative(c.updated_at)}` : "loading…"}
        />
        <MetricCard
          label="Findings"
          value={c?.active_finding_count ?? findings.length}
          icon={<FileText size={23} />}
          accent="#a855f7"
          trend={findings.length ? `${counts.high ?? 0} high priority` : "none active"}
        />
        <MetricCard label="Processes" value={(c?.process_count ?? 0).toLocaleString()} icon={<Cpu size={23} />} accent="#22c55e" trend="from process inventory" />
        <MetricCard label="Evidence Sources" value={evidence.length} icon={<FolderOpen size={23} />} accent="#38bdf8" trend={`${sumEvents(evidence).toLocaleString()} parsed events`} />
        <MetricCard label="Memory Artifacts" value={c?.has_memory_dump ? "Yes" : "No"} icon={<HardDrive size={23} />} accent="#a855f7" trend={c?.has_memory_dump ? "retained for review" : "not uploaded"} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_1fr_1fr]">
        <Section title="ATT&CK Coverage" className="xl:col-span-1" right={<CoverageScore findings={findings} />}>
          <AttackMatrix caseId={caseId!} />
        </Section>

        <Section title="Recent Activity">
          <ActivityList events={timelineData?.events ?? []} evidence={evidence} />
        </Section>

        <Section title="Top Findings" right={<span className="chip text-ink-300">{findings.length}</span>}>
          <TopFindings findings={findings} />
        </Section>
      </div>

      <div className="grid gap-5 xl:grid-cols-[0.9fr_1.8fr_1fr]">
        <Section title="Analyst Notes">
          <div className="flex gap-4">
            <div className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl bg-accent-violet/10 text-accent-violet">
              <NotebookPen size={22} />
            </div>
            <div className="text-sm leading-relaxed text-ink-200">
              {report?.summary
                ? truncate(report.summary, 260)
                : "Initial triage is waiting for AI analysis. Upload evidence and run analysis to generate a concise analyst summary."}
              <div className="mt-4 text-xs text-ink-400">
                AI-generated summary · {c ? fmtTime(c.updated_at) : "not available"}
              </div>
            </div>
          </div>
        </Section>

        <Section title="Case Timeline">
          <CompactTimeline events={timelineData?.events ?? []} />
        </Section>

        <Section title={`Evidence (${evidence.length})`}>
          <EvidenceList files={evidence} />
        </Section>
      </div>

      {isLoading && <Spinner label="Loading findings..." />}
    </PageShell>
  );
}

function CoverageScore({ findings }: { findings: Finding[] }) {
  const techniques = new Set(findings.flatMap((f) => f.mitre_techniques));
  return (
    <span className="chip text-accent-blue">
      {techniques.size} technique{techniques.size === 1 ? "" : "s"}
    </span>
  );
}

function ActivityList({ events, evidence }: { events: TimelineEvt[]; evidence: EvidenceFile[] }) {
  const rows = [
    ...evidence.slice(0, 2).map((f) => ({
      icon: <FolderOpen size={15} />,
      title: `Evidence uploaded: ${f.name}`,
      sub: `${f.kind} - ${fmtRelative(f.uploaded_at)}`,
      sev: "info" as Severity,
    })),
    ...events.slice(0, 3).map((e) => ({
      icon: <Radar size={15} />,
      title: e.content,
      sub: `${e.group} - ${fmtRelative(e.start)}`,
      sev: e.severity,
    })),
  ].slice(0, 5);

  if (!rows.length) return <div className="py-8 text-center text-sm text-ink-300">No recent activity yet.</div>;

  return (
    <div className="space-y-3">
      {rows.map((row, i) => (
        <div key={i} className="flex items-start gap-3">
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-2xl bg-[rgb(var(--panel-muted)/0.9)] text-accent-blue">
            {row.icon}
          </div>
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-semibold text-ink-100" title={row.title}>{row.title}</div>
            <div className="text-xs text-ink-300">{row.sub}</div>
          </div>
          <span className="mt-3 h-2 w-2 rounded-full" style={{ background: SEVERITY_COLORS[row.sev] }} />
        </div>
      ))}
    </div>
  );
}

function TopFindings({ findings }: { findings: Finding[] }) {
  const top = [...findings].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]).slice(0, 5);
  if (!top.length) return <div className="py-8 text-center text-sm text-ink-300">No findings detected.</div>;
  return (
    <div className="space-y-3">
      {top.map((f) => (
        <div key={f.id} className="grid grid-cols-[1fr_auto] items-center gap-3">
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold text-ink-100" title={f.title}>{f.title}</div>
            <div className="text-xs text-ink-300">{f.mitre_techniques.slice(0, 2).join(", ") || f.source}</div>
          </div>
          <SeverityBadge severity={f.severity} />
        </div>
      ))}
    </div>
  );
}

function CompactTimeline({ events }: { events: TimelineEvt[] }) {
  const rows = events.slice(0, 6);
  if (!rows.length) return <div className="py-8 text-center text-sm text-ink-300">Timeline appears after timestamped events are parsed.</div>;
  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
      {rows.map((event, i) => (
        <div key={event.id} className="relative text-center">
          {i < rows.length - 1 && <div className="absolute left-1/2 top-6 hidden h-px w-full bg-[rgb(var(--border)/0.85)] md:block" />}
          <div className="relative mx-auto grid h-12 w-12 place-items-center rounded-2xl bg-[rgb(var(--panel-strong))] text-accent-blue shadow-sm ring-1 ring-[rgb(var(--border)/0.7)]">
            {event.severity === "info" ? <ShieldCheck size={20} /> : <Zap size={20} />}
          </div>
          <div className="mt-3 text-xs text-ink-300">{event.start ? new Date(event.start).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "No date"}</div>
          <div className="mt-1 line-clamp-2 text-sm font-semibold text-ink-100">{event.content}</div>
        </div>
      ))}
    </div>
  );
}

function EvidenceList({ files }: { files: EvidenceFile[] }) {
  if (!files.length) return <div className="py-8 text-center text-sm text-ink-300">No evidence uploaded.</div>;
  return (
    <div className="space-y-3">
      {files.slice(0, 5).map((f) => (
        <div key={f.name} className="flex items-center gap-3">
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-2xl bg-accent-blue/10 text-accent-blue">
            <FolderOpen size={16} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-semibold text-ink-100" title={f.name}>{f.name}</div>
            <div className="text-xs text-ink-300">{f.kind} - {fmtBytes(f.size)}</div>
          </div>
          <div className="text-xs text-ink-300">{fmtRelative(f.uploaded_at)}</div>
        </div>
      ))}
    </div>
  );
}

function countSeverities(findings: Finding[]): Record<string, number> {
  const c: Record<string, number> = {};
  for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
  return c;
}

function sumEvents(files: EvidenceFile[]) {
  return files.reduce((sum, file) => sum + file.event_count, 0);
}

function truncate(text: string, max: number) {
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

function fmtBytes(n: number) {
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(value >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}
