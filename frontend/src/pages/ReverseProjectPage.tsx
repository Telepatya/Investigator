import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Binary, CheckCircle2, Download, FileCode2, Link2, Loader2, Play, RefreshCw, ShieldCheck, Square, Trash2, Upload, XCircle } from "lucide-react";
import { api, reverseArtifactDownloadUrl } from "../lib/api";
import type { ReverseArtifact } from "../lib/types";
import { CodeBlock, ConfirmDialog, EmptyState, PageShell, PageTitle, Section, Spinner } from "../components/common";
import { ReverseChat } from "../components/ReverseChat";
import { ReverseMarkdown } from "../components/ReverseMarkdown";

type View = "workspace" | "report" | "chat" | "provenance" | "activity";

export default function ReverseProjectPage() {
  const { projectId = "" } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [view, setView] = useState<View>("workspace");
  const [notes, setNotes] = useState("");
  const [pendingArtifact, setPendingArtifact] = useState<ReverseArtifact | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [evidenceId, setEvidenceId] = useState<number | null>(null);

  const project = useQuery({ queryKey: ["reverse-project", projectId], queryFn: () => api.getReverseProject(projectId), refetchInterval: 4000 });
  const access = useQuery({ queryKey: ["settings-access"], queryFn: api.getSettingsAccess });
  const deleteRestricted = access.data?.admin_required === true && !access.data.can_manage_shared_state;
  const artifacts = useQuery({ queryKey: ["reverse-artifacts", projectId], queryFn: () => api.listReverseArtifacts(projectId), refetchInterval: 5000 });
  const status = useQuery({ queryKey: ["reverse-status", projectId], queryFn: () => api.getReverseStatus(projectId), refetchInterval: 2500 });
  const report = useQuery({ queryKey: ["reverse-report", projectId], queryFn: () => api.getReverseReport(projectId), retry: false, enabled: view === "report" || view === "chat" || project.data?.status === "completed" });
  const trace = useQuery({ queryKey: ["reverse-trace", projectId], queryFn: () => api.getReverseTrace(projectId), enabled: view === "provenance" });
  const audit = useQuery({ queryKey: ["reverse-audit", projectId], queryFn: () => api.getReverseAudit(projectId), enabled: view === "activity", refetchInterval: view === "activity" ? 3000 : false });
  const llm = useQuery({ queryKey: ["llm-config"], queryFn: api.getLLMConfig });
  const health = useQuery({ queryKey: ["reverse-health"], queryFn: api.getReverseHealth });
  const cases = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const tools = useQuery({ queryKey: ["reverse-project-tools", projectId], queryFn: () => api.getReverseProjectTools(projectId) });
  const verify = useQuery({ queryKey: ["reverse-trace-verify", projectId], queryFn: () => api.verifyReverseTrace(projectId), enabled: view === "provenance" && Boolean(trace.data?.length) });
  const evidence = useQuery({ queryKey: ["reverse-evidence", projectId, evidenceId], queryFn: () => api.getReverseEvidence(projectId, evidenceId as number), enabled: evidenceId !== null });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["reverse-project", projectId] });
    qc.invalidateQueries({ queryKey: ["reverse-status", projectId] });
    qc.invalidateQueries({ queryKey: ["reverse-artifacts", projectId] });
    qc.invalidateQueries({ queryKey: ["reverse-report", projectId] });
    qc.invalidateQueries({ queryKey: ["reverse-audit", projectId] });
  };
  const action = useMutation({ mutationFn: async (kind: string) => {
    if (kind === "start") return api.startReverseAnalysis(projectId, notes);
    if (kind === "stop") return api.stopReverseAnalysis(projectId);
    if (kind === "resume") return api.resumeReverseAnalysis(projectId);
    if (kind === "continue") return api.continueReverseInvestigation(projectId);
    if (kind === "replay") return api.replayReverseAnalysis(projectId);
    if (kind === "recover") return api.recoverReverseReport(projectId);
    if (kind === "approve" || kind === "deny") return api.decideReverseExtension(projectId, kind);
    throw new Error("Unknown action");
  }, onSuccess: invalidate });
  const upload = useMutation({ mutationFn: (file: File) => api.uploadReverseArtifact(projectId, file), onSuccess: invalidate });
  const removeArtifact = useMutation({ mutationFn: (id: string) => api.deleteReverseArtifact(projectId, id), onSuccess: () => { setPendingArtifact(null); invalidate(); } });
  const removeProject = useMutation({ mutationFn: () => api.deleteReverseProject(projectId), onSuccess: () => navigate("/reverse") });
  const link = useMutation({ mutationFn: (caseId: string) => api.updateReverseProject(projectId, caseId ? { linked_case_id: caseId } : { clear_case_link: true }), onSuccess: invalidate });
  const iocs = useMutation({ mutationFn: () => api.regenerateReverseIocs(projectId), onSuccess: () => qc.invalidateQueries({ queryKey: ["reverse-report", projectId] }) });
  const reportSign = useMutation({ mutationFn: () => api.retryReverseReportSignature(projectId), onSuccess: invalidate });
  const reportVerify = useMutation({ mutationFn: () => api.reviewReverseReport(projectId), onSuccess: invalidate });
  const updateTools = useMutation({
    mutationFn: (enabled: string[]) => api.updateReverseProjectTools(projectId, enabled),
    onSuccess: (policy) => qc.setQueryData(["reverse-project-tools", projectId], policy),
  });

  useEffect(() => {
    if (!status.data?.run && project.data?.analysis_note) {
      setNotes((current) => current || project.data?.analysis_note || "");
    }
  }, [project.data?.analysis_note, status.data?.run]);

  const busy = Boolean(status.data?.active || ["queued", "running", "verifying", "stopping"].includes(status.data?.status ?? ""));
  const uploaded = useMemo(() => artifacts.data?.filter((item) => item.artifact_type === "upload") ?? [], [artifacts.data]);
  const coverage = report.data?.analysis_state.coverage ?? report.data?.analysis_state.objectives ?? [];
  const progress = status.data?.run?.analysis_state.progress_controller;

  if (project.isLoading) return <Spinner label="Loading Reverse workspace…" />;
  if (!project.data) return <EmptyState icon={<XCircle size={40} />} title="Reverse workspace not found" action={<Link className="btn-primary" to="/reverse">Back to Reverse</Link>} />;

  return (
    <PageShell>
      <PageTitle icon={<Binary size={22} />} title={project.data.name} subtitle={<span className="flex flex-wrap items-center gap-2"><span>{project.data.description || "Static reverse-engineering workspace"}</span>{project.data.linked_case_id && <Link className="chip bg-accent-blue/10 text-accent-blue" to={`/cases/${project.data.linked_case_id}/reverse`}><Link2 size={11} /> Case {project.data.linked_case_id}</Link>}</span>} right={<button className="btn-ghost text-sev-critical" disabled={deleteRestricted} title={deleteRestricted ? "An SSO administrator is required to delete shared workspaces" : "Delete workspace"} onClick={() => setConfirmDelete(true)}><Trash2 size={15} /> Delete</button>} />

      <div className="glass flex max-w-full gap-1 overflow-x-auto rounded-full p-1.5">
        {(["workspace", "report", "chat", "provenance", "activity"] as View[]).map((item) => <button key={item} className={`btn whitespace-nowrap rounded-full px-4 py-2 text-sm capitalize ${view === item ? "bg-[rgb(var(--panel-strong))] text-accent-blue shadow-sm" : "text-ink-300"}`} onClick={() => setView(item)}>{item}</button>)}
      </div>

      {view === "workspace" && <>
        <div className="grid gap-4 lg:grid-cols-3">
          <Section title="Shared AI settings"><div className="space-y-2 text-sm"><div className="flex justify-between"><span className="text-ink-400">Provider</span><span className="font-semibold text-ink-100">{llm.data?.provider ?? "…"}</span></div><div className="flex justify-between"><span className="text-ink-400">Model</span><span className="max-w-[65%] truncate font-mono text-xs text-ink-100">{llm.data?.model ?? "…"}</span></div><Link className="mt-3 inline-flex text-xs text-accent-blue hover:underline" to="/settings">Change in Settings</Link></div></Section>
          <Section title="Sandbox"><div className="flex items-start gap-3 text-sm">{health.data?.image_available ? <CheckCircle2 className="text-emerald-400" size={18} /> : <XCircle className="text-amber-400" size={18} />}<div><div className="font-semibold text-ink-100">{health.data?.image_available ? "Ready" : "Unavailable"}</div><div className="mt-1 text-xs text-ink-400">{health.data?.message ?? "Checking Docker…"}</div></div></div></Section>
          <Section title="Case association"><select className="input" value={project.data.linked_case_id ?? ""} onChange={(e) => link.mutate(e.target.value)} disabled={link.isPending}><option value="">Standalone workspace</option>{cases.data?.map((item) => <option key={item.id} value={item.id}>{item.name} ({item.id})</option>)}</select></Section>
          <Section title="Project static tools"><div className="space-y-2">{tools.data?.available_tools.map((tool) => { const checked = tools.data.enabled_tools.includes(tool.id); return <label key={tool.id} className="flex cursor-pointer items-start gap-2 text-xs text-ink-300"><input className="mt-0.5" type="checkbox" checked={checked} disabled={busy || updateTools.isPending} onChange={(event) => updateTools.mutate(event.target.checked ? [...tools.data.enabled_tools, tool.id] : tools.data.enabled_tools.filter((id) => id !== tool.id))} /><span><span className="font-mono text-ink-100">{tool.id}</span><span className="mt-0.5 block text-ink-500">{tool.description}</span></span></label>; })}{updateTools.error && <div className="text-sev-critical">{String(updateTools.error)}</div>}</div></Section>
        </div>

        <Section title="Artifacts" right={<><input ref={fileRef} className="hidden" type="file" multiple onChange={(event) => { Array.from(event.target.files ?? []).forEach((file) => upload.mutate(file)); event.target.value = ""; }} /><button className="btn-primary" disabled={busy || upload.isPending} onClick={() => fileRef.current?.click()}>{upload.isPending ? <Loader2 size={15} className="animate-spin" /> : <Upload size={15} />} Upload</button></>}>
          {!artifacts.data?.length ? <div className="py-8 text-center text-sm text-ink-400">Upload a suspicious artifact. It is stored locally and never executed.</div> : <div className="divide-y divide-white/5">{artifacts.data.map((item) => <div key={item.id} className="flex items-center gap-3 py-3"><FileCode2 size={17} className="text-accent-blue" /><div className="min-w-0 flex-1"><div className="truncate text-sm font-semibold text-ink-100">{item.name}</div><div className="truncate font-mono text-[10px] text-ink-500">{item.sha256} · {(item.file_size / 1024).toFixed(1)} KiB · {item.artifact_type}</div></div><a className="btn-ghost" href={reverseArtifactDownloadUrl(projectId, item.id)}><Download size={14} /></a>{item.artifact_type === "upload" && <button className="btn-ghost text-sev-critical" disabled={busy} onClick={() => setPendingArtifact(item)}><Trash2 size={14} /></button>}</div>)}</div>}
        </Section>

        <Section title="Static analysis">
          <textarea className="input min-h-24" placeholder="Optional analyst notes, suspected family, or questions for the model" value={notes} onChange={(e) => setNotes(e.target.value)} disabled={busy} />
          <div className="mt-4 flex flex-wrap gap-2">
            {!status.data?.run && <button className="btn-primary" disabled={!uploaded.length || !health.data?.image_available || action.isPending} onClick={() => action.mutate("start")}><Play size={15} /> Start analysis</button>}
            {busy && <button className="btn-ghost text-sev-critical" disabled={action.isPending} onClick={() => action.mutate("stop")}><Square size={14} /> Stop</button>}
            {status.data?.can_recover_report && <button className="btn-primary" disabled={action.isPending} onClick={() => action.mutate("recover")}><ShieldCheck size={15} /> Recover completed report</button>}
            {status.data?.can_continue_investigation && status.data.status !== "awaiting_turn_approval" && <button className="btn-primary" disabled={action.isPending || !health.data?.image_available} onClick={() => action.mutate("continue")}><Play size={15} /> {status.data.status === "stopped" || status.data.status === "failed" ? "Resume investigation" : "Continue investigation"}</button>}
            {status.data?.can_resume && !status.data.can_continue_investigation && !status.data.can_recover_report && status.data.status !== "awaiting_turn_approval" && <button className="btn-primary" disabled={action.isPending || !health.data?.image_available} onClick={() => action.mutate("resume")}><Play size={15} /> Resume</button>}
            {status.data?.run?.status === "completed" && <button className="btn-ghost" disabled={action.isPending} onClick={() => action.mutate("replay")}><RefreshCw size={14} /> Replay with captured settings</button>}
          </div>
          {status.data?.run && <div className="mt-4 rounded-2xl bg-[rgb(var(--panel-strong)/0.55)] p-4 text-sm"><div className="flex flex-wrap justify-between gap-2"><span className="font-semibold capitalize text-ink-100">{status.data.run.status.replace(/_/g, " ")}</span><span className="text-ink-400">Turns {status.data.run.turns_used} / {status.data.run.max_turns}</span></div><div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-ink-400"><span>{status.data.run.provider} · {status.data.run.model}</span>{status.data.run.analysis_outcome && <span className="chip bg-accent-blue/10 text-accent-blue">{status.data.run.analysis_outcome}</span>}</div>{status.data.run.error && <div className="mt-3 text-sev-critical">{status.data.run.error}</div>}</div>}
          {progress?.diagnostic.active && <div className="mt-4 rounded-2xl border border-amber-400/30 bg-amber-400/10 p-4 text-sm text-amber-200"><div className="font-semibold">Diagnostic pivot in progress</div><p className="mt-1">{progress.diagnostic.trigger}</p><p className="mt-2 text-xs opacity-90">{progress.diagnostic.required_pivot}</p>{progress.diagnostic.failure_fingerprint && <div className="mt-2 font-mono text-[10px] opacity-75">{progress.diagnostic.failure_fingerprint}</div>}<div className="mt-2 text-xs opacity-80">{progress.no_evidence_streak} consecutive operation{progress.no_evidence_streak === 1 ? "" : "s"} without new evidence.</div></div>}
          {status.data?.run?.analysis_state.latest_checkpoint_turn && busy && <div className="mt-3 text-xs text-ink-400">Substantive findings were checkpointed at turn {status.data.run.analysis_state.latest_checkpoint_turn}; investigation is continuing without sending that checkpoint through report review.</div>}
          {status.data?.status === "awaiting_turn_approval" && <div className="mt-4 rounded-2xl border border-amber-400/30 bg-amber-400/10 p-4 text-sm text-amber-300"><div className="font-semibold">More investigation turns requested</div><p className="mt-1">{status.data.run?.awaiting_reason}</p>{status.data.run?.analysis_state.next_steps?.length ? <ul className="mt-2 list-disc space-y-1 pl-5 text-xs">{status.data.run.analysis_state.next_steps.map((step) => <li key={step}>{step}</li>)}</ul> : null}<div className="mt-3 flex gap-2"><button className="btn-primary" onClick={() => action.mutate("approve")}>Allow more turns</button><button className="btn-ghost" onClick={() => action.mutate("deny")}>Finish report now</button></div></div>}
          {status.data?.can_continue_investigation && <div className="mt-3 text-xs text-ink-400">{status.data.run?.report_signature_status === "signed" ? "Continuing preserves the currently published and signed report as a downloadable snapshot until an updated report is ready." : "Continue from the same run, sandbox, saved evidence, checkpoints, and remaining objectives."}</div>}
          {action.error && <div className="mt-3 text-sm text-sev-critical">{String(action.error)}</div>}
        </Section>
      </>}

      {view === "report" && <div className="space-y-4">
        <Section title="Analysis report" right={report.data && <div className="flex flex-wrap items-center gap-2">{report.data.analysis_outcome && <span className={`chip ${report.data.analysis_outcome === "complete" ? "bg-emerald-400/10 text-emerald-400" : "bg-amber-400/10 text-amber-300"}`}>{report.data.analysis_outcome}</span>}<span className={`chip ${report.data.signature_status === "signed" ? "bg-emerald-400/10 text-emerald-400" : "bg-amber-400/10 text-amber-300"}`}><ShieldCheck size={12} /> {report.data.signature_status}</span>{status.data?.can_continue_investigation && <button className="btn-primary" disabled={action.isPending || !health.data?.image_available} onClick={() => action.mutate("continue")}><Play size={14} /> {status.data.status === "stopped" || status.data.status === "failed" ? "Resume investigation" : "Continue investigation"}</button>}{report.data.signature_status !== "signed" && <button className="btn-ghost" disabled={reportSign.isPending} onClick={() => reportSign.mutate()}><ShieldCheck size={14} /> Retry signing</button>}<button className="btn-ghost" disabled={iocs.isPending} onClick={() => iocs.mutate()}><RefreshCw size={14} /> Regenerate IOCs</button></div>}>{report.isLoading ? <Spinner label="Loading report…" /> : report.data ? <><ReverseMarkdown content={report.data.content} onTraceClick={setEvidenceId} />{report.data.signature_error && <div className="mt-4 rounded-xl border border-amber-400/30 bg-amber-400/10 p-3 text-xs text-amber-300">The report is safely stored but signing needs attention: {report.data.signature_error}</div>}{reportSign.error && <div className="mt-3 text-sm text-sev-critical">{String(reportSign.error)}</div>}</> : <div className="py-12 text-center text-sm text-ink-400">Complete an analysis to generate a report.</div>}</Section>
        {evidenceId !== null && <Section title={`Trace evidence ${evidenceId}`} right={<button className="btn-ghost" onClick={() => setEvidenceId(null)}>Close</button>}>{evidence.isLoading ? <Spinner label="Loading trace evidence…" /> : evidence.data ? <div className="space-y-3 text-sm"><div className="flex flex-wrap gap-2"><span className="chip bg-accent-blue/10 text-accent-blue">{evidence.data.tool ?? "tool"}</span><span className={`chip ${evidence.data.success ? "bg-emerald-400/10 text-emerald-400" : "bg-sev-critical/10 text-sev-critical"}`}>{evidence.data.success ? "succeeded" : "failed"}</span>{evidence.data.output_truncated && <span className="chip bg-amber-400/10 text-amber-300">truncated</span>}</div><CodeBlock>{JSON.stringify(evidence.data.target, null, 2)}</CodeBlock>{evidence.data.stdout && <CodeBlock>{evidence.data.stdout}</CodeBlock>}{evidence.data.stderr && <CodeBlock>{evidence.data.stderr}</CodeBlock>}{evidence.data.error && <div className="text-sev-critical">{evidence.data.error}</div>}<div className="break-all font-mono text-[10px] text-ink-500">SHA-256 {evidence.data.output_sha256}</div></div> : <div className="text-sev-critical">Evidence reference is unavailable for this project.</div>}</Section>}
        {report.data && coverage.length > 0 && <Section title="Investigation coverage"><div className="space-y-2">{coverage.map((item, index) => <div key={item.id ?? `${item.objective}-${index}`} className="rounded-xl bg-[rgb(var(--panel-strong)/0.55)] p-3 text-sm"><div className="flex items-start justify-between gap-3"><span className="font-semibold text-ink-100">{item.objective ?? item.text ?? `Objective ${index + 1}`}</span><span className="chip bg-accent-blue/10 text-accent-blue">{item.status}</span></div>{item.summary && <p className="mt-2 text-xs text-ink-400">{item.summary}</p>}</div>)}</div>{report.data.analysis_state.unresolved_items?.length ? <div className="mt-3 rounded-xl border border-amber-400/25 bg-amber-400/10 p-3 text-xs text-amber-200"><div className="font-semibold">Unresolved work</div><ul className="mt-2 list-disc space-y-1 pl-5">{report.data.analysis_state.unresolved_items.map((item) => <li key={item}>{item}</li>)}</ul></div> : null}</Section>}
        {report.data && <Section title="Independent evidence review" right={<span className={`chip ${report.data.review_status === "passed" ? "bg-emerald-400/10 text-emerald-400" : "bg-amber-400/10 text-amber-300"}`}><CheckCircle2 size={12} /> {report.data.review_status.replace(/_/g, " ")}</span>}><div className={`rounded-2xl border p-4 text-sm ${report.data.review_status === "passed" ? "border-emerald-400/25 bg-emerald-400/10 text-emerald-300" : "border-amber-400/25 bg-amber-400/10 text-amber-200"}`}><p>{report.data.verification_summary || "No reviewer summary is available."}</p><p className="mt-2 text-xs opacity-80">{report.data.review_passes} review pass{report.data.review_passes === 1 ? "" : "es"}; report integrity is signed independently.</p>{report.data.verification_error && <p className="mt-2 text-xs">{report.data.verification_error}</p>}</div>{(report.data.review_history.length > 0 || Object.keys(report.data.verification_details).length > 0) && <details className="mt-3 rounded-xl bg-[rgb(var(--panel-strong)/0.55)] p-3"><summary className="cursor-pointer text-xs font-semibold text-ink-300">Review findings and revision history</summary><div className="mt-3"><CodeBlock>{JSON.stringify({ latest: report.data.verification_details, history: report.data.review_history }, null, 2)}</CodeBlock></div></details>}<button className="btn-ghost mt-3" disabled={reportVerify.isPending} onClick={() => reportVerify.mutate()}><RefreshCw size={14} /> Review report again</button>{reportVerify.error && <div className="mt-3 text-sm text-sev-critical">{String(reportVerify.error)}</div>}</Section>}
        {report.data && <Section title="IOC inventory">{report.data.iocs ? <ReverseMarkdown content={report.data.iocs} onTraceClick={setEvidenceId} /> : <div className="py-6 text-sm text-ink-400">No defensible indicators were extracted from this report.</div>}{iocs.error && <div className="mt-3 text-sm text-sev-critical">{String(iocs.error)}</div>}</Section>}
      </div>}

      {view === "chat" && <ReverseChat projectId={projectId} hasReport={Boolean(report.data)} />}

      {view === "provenance" && <Section title="Security provenance" right={verify.data && <span className={`chip ${verify.data.valid ? "bg-emerald-400/10 text-emerald-400" : "bg-sev-critical/10 text-sev-critical"}`}><ShieldCheck size={12} /> {verify.data.valid ? "Chain valid" : "Chain invalid"}</span>}>{trace.isLoading ? <Spinner label="Verifying trace…" /> : !trace.data?.length ? <div className="py-10 text-center text-sm text-ink-400">No provenance entries yet.</div> : <div className="space-y-3">{trace.data.map((entry) => <details key={entry.id} className="rounded-2xl bg-[rgb(var(--panel-strong)/0.55)] p-3"><summary className="cursor-pointer text-sm font-semibold text-ink-100">#{entry.sequence} {entry.event_type}</summary><div className="mt-3"><CodeBlock>{JSON.stringify(entry.payload, null, 2)}</CodeBlock><div className="mt-2 break-all font-mono text-[10px] text-ink-500">{entry.entry_hash}</div></div></details>)}</div>}</Section>}

      {view === "activity" && <Section title="Audit activity">{!audit.data?.length ? <div className="py-10 text-center text-sm text-ink-400">No activity yet.</div> : <div className="space-y-2">{audit.data.map((entry) => <div key={entry.id} className="rounded-xl bg-[rgb(var(--panel-strong)/0.5)] p-3 text-sm"><div className="flex justify-between gap-3"><span className="font-semibold text-ink-100">{entry.event_type}</span><span className="text-xs text-ink-500">{new Date(entry.created_at).toLocaleString()}</span></div><div className="mt-1 truncate font-mono text-[10px] text-ink-500">{JSON.stringify(entry.details)}</div></div>)}</div>}</Section>}

      {pendingArtifact && <ConfirmDialog title="Delete uploaded artifact?" message={<>Remove <strong>{pendingArtifact.name}</strong> from this workspace?</>} danger busy={removeArtifact.isPending} onConfirm={() => removeArtifact.mutate(pendingArtifact.id)} onClose={() => setPendingArtifact(null)} />}
      {confirmDelete && <ConfirmDialog title="Delete Reverse workspace?" message="All local artifacts, reports, chat, and audit data will be permanently removed." danger busy={removeProject.isPending} confirmLabel="Delete workspace" onConfirm={() => removeProject.mutate()} onClose={() => setConfirmDelete(false)} />}
    </PageShell>
  );
}
