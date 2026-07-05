import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Plus,
  FolderSearch,
  Trash2,
  Cpu,
  AlertTriangle,
  Activity,
  HardDrive,
  X,
} from "lucide-react";
import { api } from "../lib/api";
import type { Case } from "../lib/types";
import { EmptyState, Spinner } from "../components/common";
import { fmtRelative } from "../lib/ui";

const STATUS_STYLE: Record<string, string> = {
  created: "text-ink-300 bg-ink-300/10",
  ingesting: "text-accent-blue bg-accent-blue/10",
  analyzing: "text-accent-violet bg-accent-violet/10",
  ready: "text-emerald-400 bg-emerald-400/10",
  error: "text-sev-critical bg-sev-critical/10",
};

export default function CasesPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");

  const { data: cases, isLoading } = useQuery({
    queryKey: ["cases"],
    queryFn: api.listCases,
    refetchInterval: 4000,
  });

  const createMut = useMutation({
    mutationFn: () => api.createCase(name, desc),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cases"] });
      setShowCreate(false);
      setName("");
      setDesc("");
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => api.deleteCase(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cases"] }),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-ink-50">Investigations</h1>
          <p className="text-sm text-ink-400 mt-1">
            Ingest Velociraptor collections and memory dumps, then let the AI map the machine.
          </p>
        </div>
        <button className="btn-primary" onClick={() => setShowCreate(true)}>
          <Plus size={16} /> New Case
        </button>
      </div>

      {isLoading ? (
        <Spinner label="Loading cases…" />
      ) : !cases || cases.length === 0 ? (
        <EmptyState
          icon={<FolderSearch size={40} />}
          title="No investigations yet"
          hint="Create a case to upload Velociraptor output or a memory dump and start the AI-driven analysis."
          action={
            <button className="btn-primary mt-2" onClick={() => setShowCreate(true)}>
              <Plus size={16} /> Create your first case
            </button>
          }
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {cases.map((c) => (
            <CaseCard key={c.id} c={c} onDelete={() => deleteMut.mutate(c.id)} />
          ))}
        </div>
      )}

      {showCreate && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-sm p-4">
          <div className="card p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-ink-50">New investigation</h2>
              <button className="text-ink-400 hover:text-ink-100" onClick={() => setShowCreate(false)}>
                <X size={18} />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="label">Case name</label>
                <input
                  className="input"
                  placeholder="e.g. WORKSTATION-07 compromise"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  autoFocus
                />
              </div>
              <div>
                <label className="label">Description</label>
                <textarea
                  className="input min-h-[80px]"
                  placeholder="Context, ticket number, suspected activity…"
                  value={desc}
                  onChange={(e) => setDesc(e.target.value)}
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button className="btn-ghost" onClick={() => setShowCreate(false)}>
                  Cancel
                </button>
                <button
                  className="btn-primary"
                  disabled={!name.trim() || createMut.isPending}
                  onClick={() => createMut.mutate()}
                >
                  {createMut.isPending ? "Creating…" : "Create case"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function CaseCard({ c, onDelete }: { c: Case; onDelete: () => void }) {
  return (
    <div className="card p-5 hover:border-accent-cyan/30 transition group relative">
      <div className="flex items-start justify-between">
        <Link to={`/cases/${c.id}/overview`} className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className={`chip ${STATUS_STYLE[c.status] ?? STATUS_STYLE.created}`}>
              {c.status}
            </span>
            {c.has_memory_dump && (
              <span className="chip bg-accent-violet/10 text-accent-violet">
                <HardDrive size={11} /> memory
              </span>
            )}
          </div>
          <h3 className="text-lg font-semibold text-ink-50 mt-2 truncate group-hover:text-accent-cyan transition">
            {c.name}
          </h3>
          <p className="text-sm text-ink-400 line-clamp-2 mt-1 min-h-[2.5rem]">
            {c.description || "No description"}
          </p>
        </Link>
        <button
          className="text-ink-500 hover:text-sev-critical p-1 opacity-0 group-hover:opacity-100 transition"
          onClick={onDelete}
          title="Delete case"
        >
          <Trash2 size={16} />
        </button>
      </div>
      <div className="grid grid-cols-3 gap-2 mt-4 pt-4 border-t border-white/5">
        <Stat icon={<Activity size={14} />} label="events" value={c.event_count} />
        <Stat icon={<AlertTriangle size={14} />} label="findings" value={c.finding_count} />
        <Stat icon={<Cpu size={14} />} label="procs" value={c.process_count} />
      </div>
      <div className="text-[11px] text-ink-500 mt-3">Updated {fmtRelative(c.updated_at)}</div>
    </div>
  );
}

function Stat({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <div className="flex flex-col items-center">
      <div className="flex items-center gap-1 text-ink-200 font-semibold">
        {icon}
        {value.toLocaleString()}
      </div>
      <div className="text-[10px] uppercase tracking-wider text-ink-500">{label}</div>
    </div>
  );
}
