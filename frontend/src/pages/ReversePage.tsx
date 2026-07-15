import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Binary, Box, ExternalLink, Link2, Plus, ShieldAlert, Trash2, X } from "lucide-react";
import { api } from "../lib/api";
import type { ReverseProject } from "../lib/types";
import { ConfirmDialog, EmptyState, PageShell, PageTitle, Spinner } from "../components/common";
import { fmtRelative } from "../lib/ui";

const STATUS: Record<string, string> = {
  ready: "bg-ink-300/10 text-ink-300",
  queued: "bg-accent-blue/10 text-accent-blue",
  running: "bg-accent-violet/10 text-accent-violet",
  awaiting_turn_approval: "bg-amber-400/10 text-amber-400",
  completed: "bg-emerald-400/10 text-emerald-400",
  stopped: "bg-amber-400/10 text-amber-400",
  failed: "bg-sev-critical/10 text-sev-critical",
};

export default function ReversePage({ caseId: fixedCaseId }: { caseId?: string } = {}) {
  const params = useParams();
  const caseId = fixedCaseId ?? params.caseId;
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [linkedCaseId, setLinkedCaseId] = useState(caseId ?? "");
  const [pendingDelete, setPendingDelete] = useState<ReverseProject | null>(null);

  const projects = useQuery({
    queryKey: ["reverse-projects", caseId ?? "all"],
    queryFn: () => api.listReverseProjects(caseId),
    refetchInterval: 4000,
  });
  const cases = useQuery({ queryKey: ["cases"], queryFn: api.listCases, enabled: showCreate && !caseId });
  const health = useQuery({ queryKey: ["reverse-health"], queryFn: api.getReverseHealth, staleTime: 30_000 });
  const create = useMutation({
    mutationFn: () => api.createReverseProject({
      name: name.trim(), description, linked_case_id: (caseId ?? linkedCaseId) || null,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["reverse-projects"] });
      setShowCreate(false); setName(""); setDescription(""); setLinkedCaseId(caseId ?? "");
    },
  });
  const remove = useMutation({
    mutationFn: api.deleteReverseProject,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["reverse-projects"] }); setPendingDelete(null); },
  });

  return (
    <PageShell>
      <PageTitle
        icon={<Binary size={22} />}
        title={caseId ? "Reverse workspaces" : "Reverse"}
        subtitle={caseId ? "Static reverse-engineering workspaces linked to this case." : "Sandboxed static analysis for binaries and suspicious artifacts."}
        right={<button className="btn-primary" onClick={() => setShowCreate(true)}><Plus size={16} /> New workspace</button>}
      />

      {health.data && !health.data.image_available && (
        <div className="card flex items-start gap-3 border-amber-400/30 bg-amber-400/10 p-4 text-sm text-amber-300">
          <ShieldAlert size={18} className="mt-0.5 shrink-0" />
          <div><div className="font-semibold">Static sandbox is not ready</div><div className="mt-1 text-xs">{health.data.message}. Workspace management remains available.</div></div>
        </div>
      )}

      {projects.isLoading ? <Spinner label="Loading Reverse workspaces…" /> : !projects.data?.length ? (
        <EmptyState
          icon={<Binary size={40} />}
          title={caseId ? "No Reverse workspaces linked to this case" : "No Reverse workspaces yet"}
          hint="Create a workspace, upload a suspicious file, and run static analysis without executing the sample."
          action={<button className="btn-primary mt-2" onClick={() => setShowCreate(true)}><Plus size={16} /> Create workspace</button>}
        />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {projects.data.map((project) => (
            <div key={project.id} className="card interactive-lift group relative p-5 hover:border-accent-blue/30">
              <div className="flex items-start justify-between gap-3">
                <Link to={`/reverse/${project.id}`} className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`chip ${STATUS[project.status] ?? STATUS.ready}`}>{project.status.replace(/_/g, " ")}</span>
                    {project.linked_case_id && <span className="chip bg-accent-blue/10 text-accent-blue"><Link2 size={11} /> {project.linked_case_id}</span>}
                  </div>
                  <h3 className="mt-3 truncate text-lg font-semibold text-ink-50 transition group-hover:text-accent-blue">{project.name}</h3>
                  <p className="mt-1 min-h-[2.5rem] line-clamp-2 text-sm text-ink-400">{project.description || "No description"}</p>
                </Link>
                <button className="p-1 text-ink-500 opacity-0 transition hover:text-sev-critical group-hover:opacity-100" onClick={() => setPendingDelete(project)} title="Delete workspace"><Trash2 size={16} /></button>
              </div>
              <div className="mt-4 flex items-center justify-between border-t border-white/5 pt-4 text-xs text-ink-400">
                <span className="flex items-center gap-1.5"><Box size={13} /> {project.artifact_count} artifacts</span>
                <span>Updated {fmtRelative(project.updated_at)}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {pendingDelete && <ConfirmDialog title="Delete Reverse workspace?" danger busy={remove.isPending} confirmLabel="Delete workspace" message={<>All artifacts, reports, chat, and local audit data for <strong>{pendingDelete.name}</strong> will be removed.</>} onConfirm={() => remove.mutate(pendingDelete.id)} onClose={() => setPendingDelete(null)} />}

      {showCreate && (
        <div className="modal-backdrop fixed inset-0 z-50 grid place-items-center p-4">
          <div className="modal-panel w-full max-w-lg rounded-2xl p-6">
            <div className="mb-4 flex items-center justify-between"><h2 className="text-lg font-semibold text-ink-50">New Reverse workspace</h2><button className="text-ink-400" onClick={() => setShowCreate(false)}><X size={18} /></button></div>
            <div className="space-y-4">
              <div><label className="label">Workspace name</label><input className="input" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Suspicious loader triage" /></div>
              <div><label className="label">Description</label><textarea className="input min-h-20" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Sample source, scope, and analyst context" /></div>
              {caseId ? <div className="rounded-xl bg-accent-blue/10 p-3 text-sm text-accent-blue"><Link2 size={14} className="mr-2 inline" />Linked to case {caseId}</div> : (
                <div><label className="label">Linked case (optional)</label><select className="input" value={linkedCaseId} onChange={(e) => setLinkedCaseId(e.target.value)}><option value="">Standalone workspace</option>{cases.data?.map((item) => <option key={item.id} value={item.id}>{item.name} ({item.id})</option>)}</select></div>
              )}
              {create.error && <div className="text-sm text-sev-critical">{String(create.error)}</div>}
              <div className="flex justify-end gap-2"><button className="btn-ghost" onClick={() => setShowCreate(false)}>Cancel</button><button className="btn-primary" disabled={!name.trim() || create.isPending} onClick={() => create.mutate()}>{create.isPending ? "Creating…" : "Create workspace"}</button></div>
            </div>
          </div>
        </div>
      )}
    </PageShell>
  );
}

export function ReverseCasePage() {
  return <ReversePage />;
}
