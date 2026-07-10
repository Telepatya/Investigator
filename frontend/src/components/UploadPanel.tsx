import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Upload, HardDrive, FileArchive, Loader2, X } from "lucide-react";
import { uploadFile, wsUrl } from "../lib/api";
import type { CaseStatus, Progress } from "../lib/types";

export function UploadPanel({ caseId, status }: { caseId: string; status?: CaseStatus }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [uploadPct, setUploadPct] = useState<number | null>(null);
  const [fileType, setFileType] = useState<"artifact" | "memory">("artifact");
  const [memoryOptions, setMemoryOptions] = useState({
    forensicTimeline: false,
    eventlogs: false,
  });
  const [progress, setProgress] = useState<Progress | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState("");
  const wsRef = useRef<WebSocket | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const ws = new WebSocket(wsUrl(`/cases/${caseId}/ingestion-ws`));
    ws.onmessage = (ev) => {
      const p: Progress = JSON.parse(ev.data);
      setProgress(p);
      if (p.done) {
        qc.invalidateQueries({ queryKey: ["case", caseId] });
        qc.invalidateQueries({ queryKey: ["cases"] });
        setTimeout(() => setProgress(null), 4000);
      } else {
        qc.invalidateQueries({ queryKey: ["case", caseId] });
      }
    };
    wsRef.current = ws;
    return () => ws.close();
  }, [caseId, qc]);

  async function handleFiles(files: FileList | null) {
    if (!files || files.length === 0 || status === "ingesting" || status === "analyzing") return;
    setError("");
    let succeeded = true;
    for (const file of Array.from(files)) {
      const isMemory =
        fileType === "memory" ||
        /\.(raw|dmp|mem|vmem|lime|bin|img|dd)$/i.test(file.name);
      setUploadPct(0);
      try {
        await uploadFile(
          caseId,
          file,
          isMemory ? "memory" : "artifact",
          (pct) => setUploadPct(pct),
          isMemory ? memoryOptions : {},
        );
      } catch (err) {
        succeeded = false;
        setError(err instanceof Error ? err.message : "Upload failed");
        break;
      } finally {
        setUploadPct(null);
      }
    }
    if (succeeded) setOpen(false);
    qc.invalidateQueries({ queryKey: ["case", caseId] });
  }

  const busy =
    uploadPct !== null ||
    (progress && !progress.done && progress.phase !== "idle");
  const blocked = status === "ingesting" || status === "analyzing";

  return (
    <>
      <button
        className="btn-primary"
        onClick={() => setOpen(true)}
        disabled={blocked || Boolean(busy)}
        title={blocked ? "Wait for the current case operation to finish" : "Upload evidence"}
      >
        <Upload size={16} /> Upload evidence
      </button>

      {busy && progress && (
        <div className="fixed bottom-5 right-5 z-50 card p-4 w-80">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-ink-100 flex items-center gap-2">
              <Loader2 size={14} className="animate-spin text-accent-cyan" />
              {progress.phase}
            </span>
            <span className="text-xs text-ink-400">
              {progress.percent >= 0 ? `${Math.round(progress.percent)}%` : ""}
            </span>
          </div>
          <div className="text-xs text-ink-400 mb-2 truncate">{progress.message}</div>
          <div className="h-1.5 bg-base-900 rounded-full overflow-hidden">
            <div
              className="h-full bg-accent-cyan transition-all"
              style={{ width: `${progress.percent >= 0 ? progress.percent : 30}%` }}
            />
          </div>
        </div>
      )}

      {open && (
        <div className="modal-backdrop fixed inset-0 z-50 grid place-items-center p-4">
          <div className="modal-panel w-full max-w-md rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-ink-50">Upload evidence</h2>
              <button className="text-ink-400 transition hover:text-ink-100 active:scale-95" onClick={() => setOpen(false)}>
                <X size={18} />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-2 mb-4">
              <button
                onClick={() => setFileType("artifact")}
                className={`rounded-xl border p-3 text-left transition-all duration-200 active:scale-[0.98] ${
                  fileType === "artifact"
                    ? "border-accent-blue/55 bg-accent-blue/10 shadow-sm"
                    : "border-[rgb(var(--border)/0.62)] bg-[rgb(var(--panel-strong)/0.58)] hover:bg-[rgb(var(--panel-strong)/0.78)]"
                }`}
              >
                <FileArchive size={18} className="text-accent-blue" />
                <div className="text-sm font-medium text-ink-100 mt-1.5">Velociraptor</div>
                <div className="text-[11px] text-ink-500">ZIP, JSON, JSONL, CSV, EVTX</div>
              </button>
              <button
                onClick={() => setFileType("memory")}
                className={`rounded-xl border p-3 text-left transition-all duration-200 active:scale-[0.98] ${
                  fileType === "memory"
                    ? "border-accent-blue/55 bg-accent-blue/10 shadow-sm"
                    : "border-[rgb(var(--border)/0.62)] bg-[rgb(var(--panel-strong)/0.58)] hover:bg-[rgb(var(--panel-strong)/0.78)]"
                }`}
              >
                <HardDrive size={18} className="text-accent-blue" />
                <div className="text-sm font-medium text-ink-100 mt-1.5">Memory dump</div>
                <div className="text-[11px] text-ink-500">RAW, DMP, MEM, VMEM, LIME</div>
              </button>
            </div>

            {fileType === "memory" && (
              <div className="mb-4 space-y-2">
                <label className="flex items-start gap-3 rounded-xl border border-[rgb(var(--border)/0.62)] bg-[rgb(var(--panel-strong)/0.5)] p-3 cursor-pointer">
                  <input
                    type="checkbox"
                    className="mt-1 accent-cyan-400"
                    checked={memoryOptions.forensicTimeline}
                    onChange={(e) =>
                      setMemoryOptions((prev) => ({ ...prev, forensicTimeline: e.target.checked }))
                    }
                  />
                  <span className="min-w-0">
                    <span className="block text-sm text-ink-100">Parse forensic timeline</span>
                    <span className="block text-xs text-ink-500">
                      Copies MemProcFS forensic CSVs, including timeline rows.
                    </span>
                  </span>
                </label>
                <label className="flex items-start gap-3 rounded-xl border border-[rgb(var(--border)/0.62)] bg-[rgb(var(--panel-strong)/0.5)] p-3 cursor-pointer">
                  <input
                    type="checkbox"
                    className="mt-1 accent-cyan-400"
                    checked={memoryOptions.eventlogs}
                    onChange={(e) =>
                      setMemoryOptions((prev) => ({ ...prev, eventlogs: e.target.checked }))
                    }
                  />
                  <span className="min-w-0">
                    <span className="block text-sm text-ink-100">Extract event logs</span>
                    <span className="block text-xs text-ink-500">
                      Copies EVTX files exposed from memory.
                    </span>
                  </span>
                </label>
              </div>
            )}

            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragOver(false);
                handleFiles(e.dataTransfer.files);
              }}
              onClick={() => inputRef.current?.click()}
              className={`rounded-2xl border border-dashed p-8 text-center cursor-pointer transition-all duration-200 active:scale-[0.99] ${
                dragOver
                  ? "border-accent-blue bg-accent-blue/5"
                  : "border-[rgb(var(--border)/0.72)] bg-[rgb(var(--panel-strong)/0.36)] hover:border-accent-blue/45"
              }`}
            >
              <Upload size={28} className="mx-auto text-accent-blue" />
              <div className="text-sm text-ink-200 mt-3 font-medium">
                Drop files here or click to browse
              </div>
              <div className="text-xs text-ink-500 mt-1">
                {fileType === "memory"
                  ? "Large memory dumps are streamed to disk."
                  : "Multiple files supported."}
              </div>
              <input
                ref={inputRef}
                type="file"
                multiple
                className="hidden"
                onChange={(e) => handleFiles(e.target.files)}
              />
            </div>

            {uploadPct !== null && (
              <div className="mt-4">
                <div className="text-xs text-ink-400 mb-1">Uploading… {Math.round(uploadPct)}%</div>
                <div className="h-1.5 bg-base-900 rounded-full overflow-hidden">
                  <div className="h-full bg-accent-cyan transition-all" style={{ width: `${uploadPct}%` }} />
                </div>
              </div>
            )}
            {error && (
              <div className="mt-4 rounded-xl border border-sev-high/30 bg-sev-high/10 px-3 py-2 text-xs text-sev-high" role="alert">
                {error}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
