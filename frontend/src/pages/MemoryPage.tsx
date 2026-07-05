import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, downloadMemoryVfsArchive, memoryVfsDownloadUrl } from "../lib/api";
import { EmptyState, Spinner, SeverityBadge, CodeBlock } from "../components/common";
import {
  Archive,
  ArrowUp,
  ChevronDown,
  ChevronRight,
  Download,
  File,
  Folder,
  HardDrive,
} from "lucide-react";
import type { MemoryDump, MemoryResult, MemoryVfsEntry } from "../lib/types";
import { SEVERITY_ORDER } from "../lib/ui";

export default function MemoryPage() {
  const { caseId } = useParams();
  const [tab, setTab] = useState<"findings" | "filesystem">("findings");
  const [plugin, setPlugin] = useState<string | undefined>();
  const { data, isLoading } = useQuery({
    queryKey: ["memory", caseId, plugin],
    queryFn: () => api.getMemory(caseId!, plugin),
  });
  const { data: dumpsData, isLoading: dumpsLoading } = useQuery({
    queryKey: ["memory-dumps", caseId],
    queryFn: () => api.getMemoryDumps(caseId!),
    enabled: !!caseId,
  });

  if (isLoading) return <Spinner label="Loading memory analysis..." />;
  const dumps = dumpsData?.dumps ?? [];
  if ((!data || data.results.length === 0) && !dumps.length && !dumpsLoading)
    return (
      <EmptyState
        icon={<HardDrive size={40} />}
        title="No memory analysis yet"
        hint="Upload a raw memory dump (.raw, .dmp, .mem, .vmem). MemProcFS plus YARA APT scanning will populate this view."
      />
    );

  const results = [...(data?.results ?? [])].sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
  );

  return (
    <div className="space-y-4">
      <div className="glass rounded-xl p-1 flex items-center gap-1 w-fit">
        <button
          className={`btn ${tab === "findings" ? "bg-accent-cyan/15 text-accent-cyan" : "text-ink-300 hover:bg-white/5"}`}
          onClick={() => setTab("findings")}
        >
          Findings
        </button>
        <button
          className={`btn ${tab === "filesystem" ? "bg-accent-cyan/15 text-accent-cyan" : "text-ink-300 hover:bg-white/5"}`}
          onClick={() => setTab("filesystem")}
        >
          Filesystem
        </button>
      </div>

      {tab === "filesystem" ? (
        <MemoryFilesystem caseId={caseId!} dumps={dumps} loading={dumpsLoading} />
      ) : (
        <>
          {results.length === 0 ? (
            <EmptyState
              icon={<HardDrive size={36} />}
              title="No memory findings yet"
              hint="The retained dump can still be browsed from the Filesystem tab."
            />
          ) : (
            <>
              <div className="card p-3 flex items-center gap-2 flex-wrap">
                <button
                  className={`chip ${!plugin ? "bg-accent-cyan/15 text-accent-cyan" : "bg-white/5 text-ink-300"}`}
                  onClick={() => setPlugin(undefined)}
                >
                  all ({data?.results.length ?? 0})
                </button>
                {(data?.plugins ?? []).map((p) => (
                  <button
                    key={p.name}
                    className={`chip ${plugin === p.name ? "bg-accent-cyan/15 text-accent-cyan" : "bg-white/5 text-ink-300"}`}
                    onClick={() => setPlugin(p.name)}
                  >
                    {p.name} ({p.count})
                  </button>
                ))}
              </div>

              <div className="space-y-2">
                {results.map((r) => (
                  <MemoryRow key={r.id} r={r} />
                ))}
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}

function MemoryFilesystem({ caseId, dumps, loading }: { caseId: string; dumps: MemoryDump[]; loading: boolean }) {
  const [sessionId, setSessionId] = useState("");
  const [path, setPath] = useState("/");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [archiving, setArchiving] = useState(false);
  const [errorText, setErrorText] = useState("");

  useEffect(() => {
    if (!sessionId && dumps.length) setSessionId(dumps[0].session_id);
  }, [dumps, sessionId]);

  const { data, isLoading, error } = useQuery({
    queryKey: ["memory-vfs", caseId, sessionId, path],
    queryFn: () => api.getMemoryVfs(caseId, sessionId, path),
    enabled: !!sessionId,
  });

  useEffect(() => {
    setSelected(new Set());
    setErrorText("");
  }, [sessionId, path]);

  if (loading) return <Spinner label="Loading retained memory dumps..." />;
  if (!dumps.length) {
    return (
      <EmptyState
        icon={<HardDrive size={36} />}
        title="No retained memory dump"
        hint="The parsed memory results are still available, but the original dump is needed for browsing and extraction."
      />
    );
  }

  async function archiveSelection(paths: string[]) {
    if (!paths.length || !sessionId) return;
    setArchiving(true);
    setErrorText("");
    try {
      await downloadMemoryVfsArchive(caseId, sessionId, paths);
    } catch (err) {
      setErrorText((err as Error).message);
    } finally {
      setArchiving(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="card p-3 flex items-center gap-3 flex-wrap">
        <select
          value={sessionId}
          onChange={(e) => {
            setSessionId(e.target.value);
            setPath("/");
          }}
          className="bg-base-900 border border-white/10 rounded-lg px-3 py-2 text-sm text-ink-100"
        >
          {dumps.map((d) => (
            <option key={d.session_id} value={d.session_id}>
              {d.filename}
            </option>
          ))}
        </select>
        <Breadcrumb path={path} onNavigate={setPath} />
        <button
          className="btn text-ink-300 hover:bg-white/5"
          disabled={path === "/"}
          onClick={() => setPath(parentPath(path))}
        >
          <ArrowUp size={15} /> Up
        </button>
        <button
          className="btn-primary"
          disabled={selected.size === 0 || archiving}
          onClick={() => archiveSelection([...selected])}
        >
          <Archive size={15} /> {archiving ? "Preparing..." : `Download ${selected.size || ""}`}
        </button>
      </div>

      {errorText && <div className="text-sm text-sev-high">{errorText}</div>}
      {error ? (
        <div className="text-sm text-sev-high">Could not browse memory filesystem: {(error as Error).message}</div>
      ) : isLoading ? (
        <Spinner label="Opening MemProcFS filesystem..." />
      ) : (
        <VfsTable
          caseId={caseId}
          sessionId={sessionId}
          entries={data?.entries ?? []}
          selected={selected}
          setSelected={setSelected}
          onNavigate={setPath}
          onArchive={archiveSelection}
          archiving={archiving}
        />
      )}
    </div>
  );
}

function VfsTable({
  caseId,
  sessionId,
  entries,
  selected,
  setSelected,
  onNavigate,
  onArchive,
  archiving,
}: {
  caseId: string;
  sessionId: string;
  entries: MemoryVfsEntry[];
  selected: Set<string>;
  setSelected: (next: Set<string>) => void;
  onNavigate: (path: string) => void;
  onArchive: (paths: string[]) => void;
  archiving: boolean;
}) {
  if (!entries.length) return <div className="text-sm text-ink-400">This directory is empty.</div>;
  function toggle(path: string) {
    const next = new Set(selected);
    if (next.has(path)) next.delete(path);
    else next.add(path);
    setSelected(next);
  }
  return (
    <div className="card overflow-hidden">
      <div className="divide-y divide-white/5">
        {entries.map((entry) => (
          <div key={entry.path} className="grid grid-cols-[32px_1fr_auto_auto] gap-3 items-center p-3 hover:bg-white/[0.02]">
            <input
              type="checkbox"
              checked={selected.has(entry.path)}
              onChange={() => toggle(entry.path)}
              className="accent-cyan-400"
            />
            <button
              className="min-w-0 flex items-center gap-2 text-left"
              onClick={() => entry.is_dir && onNavigate(entry.path)}
            >
              {entry.is_dir ? (
                <Folder size={17} className="text-accent-cyan shrink-0" />
              ) : (
                <File size={17} className="text-ink-500 shrink-0" />
              )}
              <span className="text-sm text-ink-100 truncate" title={entry.name}>
                {entry.name}
              </span>
            </button>
            <span className="text-xs text-ink-500 font-mono">{entry.is_dir ? "folder" : fmtBytes(entry.size)}</span>
            {entry.is_dir ? (
              <button
                className="btn-ghost"
                disabled={archiving}
                title="Download folder as ZIP"
                onClick={() => onArchive([entry.path])}
              >
                <Archive size={15} />
              </button>
            ) : (
              <a className="btn-ghost" href={memoryVfsDownloadUrl(caseId, sessionId, entry.path)} title="Download file">
                <Download size={15} />
              </a>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function Breadcrumb({ path, onNavigate }: { path: string; onNavigate: (path: string) => void }) {
  const parts = path.split("/").filter(Boolean);
  return (
    <div className="flex items-center gap-1 text-sm min-w-0 flex-wrap">
      <button className="chip bg-white/5 text-ink-300" onClick={() => onNavigate("/")}>
        /
      </button>
      {parts.map((part, i) => {
        const target = "/" + parts.slice(0, i + 1).join("/");
        return (
          <button key={target} className="chip bg-white/5 text-ink-300" onClick={() => onNavigate(target)}>
            {part}
          </button>
        );
      })}
    </div>
  );
}

function parentPath(path: string) {
  const parts = path.split("/").filter(Boolean);
  parts.pop();
  return parts.length ? "/" + parts.join("/") : "/";
}

function MemoryRow({ r }: { r: MemoryResult }) {
  const [open, setOpen] = useState(false);
  const hasData = r.data && Object.keys(r.data).length > 0;
  return (
    <div className="card overflow-hidden">
      <button
        className="w-full flex items-start gap-3 p-4 text-left hover:bg-white/[0.02]"
        onClick={() => hasData && setOpen(!open)}
      >
        <div className="mt-0.5">
          {hasData ? (
            open ? (
              <ChevronDown size={16} className="text-ink-400" />
            ) : (
              <ChevronRight size={16} className="text-ink-400" />
            )
          ) : (
            <span className="w-4 inline-block" />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <SeverityBadge severity={r.severity} />
            <span className="chip bg-white/5 text-ink-300 font-mono">{r.plugin}</span>
            {r.pid != null && (
              <span className="chip bg-white/5 text-ink-400 font-mono">pid {r.pid}</span>
            )}
            {r.process_name && (
              <span className="text-xs text-ink-400">{r.process_name}</span>
            )}
          </div>
          <div className="text-sm text-ink-100">{r.summary}</div>
        </div>
      </button>
      {open && hasData && (
        <div className="px-4 pb-4 pl-11">
          <CodeBlock>{JSON.stringify(r.data, null, 2)}</CodeBlock>
        </div>
      )}
    </div>
  );
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
