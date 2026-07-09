import { useState, type ReactNode } from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Archive,
  FileText,
  FolderOpen,
  HardDrive,
  Loader2,
  RefreshCw,
  ScrollText,
  Trash2,
  File,
} from "lucide-react";
import { api } from "../lib/api";
import { EmptyState, PageShell, PageTitle, Spinner } from "../components/common";
import { fmtTime } from "../lib/ui";
import type { EvidenceFile } from "../lib/types";

const KIND_META: Record<EvidenceFile["kind"], { icon: ReactNode; label: string; color: string }> = {
  memory: { icon: <HardDrive size={16} />, label: "Memory dump", color: "#a78bfa" },
  archive: { icon: <Archive size={16} />, label: "Collector archive", color: "#22d3ee" },
  eventlog: { icon: <ScrollText size={16} />, label: "Event log", color: "#f59e0b" },
  textlog: { icon: <FileText size={16} />, label: "Text log", color: "#34d399" },
  artifact: { icon: <File size={16} />, label: "Artifact", color: "#60a5fa" },
  other: { icon: <File size={16} />, label: "Other", color: "#8b96b0" },
};

function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

export default function EvidencePage() {
  const { caseId } = useParams();
  const qc = useQueryClient();
  const [confirming, setConfirming] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["evidence", caseId],
    queryFn: () => api.listEvidence(caseId!),
    enabled: !!caseId,
    refetchInterval: 5000,
  });

  const invalidateAll = () => {
    qc.invalidateQueries({ queryKey: ["evidence", caseId] });
    qc.invalidateQueries({ queryKey: ["case", caseId] });
    for (const key of ["events", "timeline", "findings", "entities", "categories", "attack-matrix", "memory"]) {
      qc.invalidateQueries({ queryKey: [key] });
    }
  };

  const del = useMutation({
    mutationFn: (name: string) => api.deleteEvidence(caseId!, name),
    onMutate: (name) => setBusy(name),
    onSettled: () => {
      setBusy(null);
      setConfirming(null);
      invalidateAll();
    },
  });

  const reingest = useMutation({
    mutationFn: (file: EvidenceFile) =>
      api.reingestEvidence(caseId!, file.name, file.kind === "memory" ? "memory" : "artifact"),
    onMutate: (file) => setBusy(file.name),
    onSettled: () => {
      setBusy(null);
      invalidateAll();
    },
  });

  if (isLoading) return <Spinner label="Loading evidence…" />;

  const files = data?.files ?? [];
  if (files.length === 0)
    return (
      <EmptyState
        icon={<FolderOpen size={40} />}
        title="No evidence uploaded"
        hint="Use the Upload evidence button to add Velociraptor collections, event logs, text logs, or memory dumps to this case."
      />
    );

  const totalSize = files.reduce((s, f) => s + f.size, 0);
  const totalEvents = files.reduce((s, f) => s + f.event_count, 0);

  return (
    <PageShell>
      <PageTitle
        icon={<FolderOpen size={22} />}
        title="Evidence"
        subtitle="Uploaded files, parsed sources, and re-ingestion controls."
      />
      <div className="card p-3 flex items-center gap-4 text-sm text-ink-300 flex-wrap">
        <span className="flex items-center gap-2">
          <FolderOpen size={16} className="text-accent-cyan" />
          {files.length} file{files.length > 1 ? "s" : ""}
        </span>
        <span>{fmtSize(totalSize)} total</span>
        <span>{totalEvents.toLocaleString()} events extracted</span>
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[11px] uppercase tracking-wider text-ink-400 border-b border-white/5">
              <th className="px-4 py-3">File</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Size</th>
              <th className="px-4 py-3">Uploaded</th>
              <th className="px-4 py-3">Extracted data</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {files.map((f) => {
              const meta = KIND_META[f.kind];
              const isBusy = busy === f.name;
              return (
                <tr key={f.name} className="border-b border-white/5 last:border-0 hover:bg-white/[0.02]">
                  <td className="px-4 py-3">
                    <div className="font-medium text-ink-100 break-all">{f.name}</div>
                    {f.sources.length > 1 && (
                      <div className="text-[11px] text-ink-500 mt-0.5">
                        {f.sources.length} artifact sources
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className="chip"
                      style={{ background: `${meta.color}18`, color: meta.color }}
                    >
                      {meta.icon} {meta.label}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-ink-300 whitespace-nowrap">{fmtSize(f.size)}</td>
                  <td className="px-4 py-3 text-ink-400 whitespace-nowrap">{fmtTime(f.uploaded_at)}</td>
                  <td className="px-4 py-3 text-ink-300">
                    {f.kind === "memory" ? (
                      <>
                        {f.process_count.toLocaleString()} processes ·{" "}
                        {f.memory_result_count.toLocaleString()} memory results
                      </>
                    ) : (
                      <>{f.event_count.toLocaleString()} events</>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      {confirming === f.name ? (
                        <>
                          <span className="text-xs text-ink-400 mr-1">Delete file + its data?</span>
                          <button
                            className="btn text-xs bg-sev-critical/20 text-sev-critical hover:bg-sev-critical/30"
                            disabled={isBusy}
                            onClick={() => del.mutate(f.name)}
                          >
                            {isBusy ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
                            Confirm
                          </button>
                          <button
                            className="btn text-xs text-ink-300 hover:bg-white/5"
                            disabled={isBusy}
                            onClick={() => setConfirming(null)}
                          >
                            Cancel
                          </button>
                        </>
                      ) : (
                        <>
                          <button
                            className="btn text-xs text-ink-300 hover:bg-white/5"
                            title="Purge this file's data and parse it again"
                            disabled={isBusy}
                            onClick={() => reingest.mutate(f)}
                          >
                            {isBusy ? (
                              <Loader2 size={13} className="animate-spin" />
                            ) : (
                              <RefreshCw size={13} />
                            )}
                            Re-ingest
                          </button>
                          <button
                            className="btn text-xs text-sev-critical/80 hover:bg-sev-critical/10 hover:text-sev-critical"
                            disabled={isBusy}
                            onClick={() => setConfirming(f.name)}
                          >
                            <Trash2 size={13} />
                            Delete
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-ink-500">
        Deleting evidence removes the file and all events, processes and memory results extracted
        from it, then re-runs detections so findings reflect the remaining evidence.
      </p>
    </PageShell>
  );
}
