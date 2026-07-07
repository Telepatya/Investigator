import type {
  AttackTechnique,
  Case,
  EntityDossier,
  EntityGraph,
  EventRow,
  EvidenceFile,
  Finding,
  FindingsResponse,
  LLMConfig,
  MemoryResult,
  MemoryDump,
  MemoryModule,
  MemoryProcessHandle,
  MemoryVfsEntry,
  ModelInfo,
  ProcessTree,
  Provider,
  ProviderTestResult,
  Report,
  TimelineEvt,
} from "./types";

const BASE = "/api";

async function req<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  // Cases
  listCases: () => req<Case[]>("/cases"),
  getCase: (id: string) => req<Case>(`/cases/${id}`),
  createCase: (name: string, description: string) =>
    req<Case>("/cases", { method: "POST", body: JSON.stringify({ name, description }) }),
  deleteCase: (id: string) => req<{ ok: boolean }>(`/cases/${id}`, { method: "DELETE" }),

  // Data
  getEvents: (id: string, params: Record<string, string | number> = {}) => {
    const qs = new URLSearchParams(
      Object.entries(params).map(([k, v]) => [k, String(v)]),
    ).toString();
    return req<{ total: number; events: EventRow[] }>(`/cases/${id}/events?${qs}`);
  },
  getTimeline: (
    id: string,
    params: { q?: string; min_severity?: string; sources?: string; limit?: number } = {},
  ) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => [k, String(v)]),
    ).toString();
    return req<{
      total: number;
      total_matching: number;
      sources: { name: string; count: number }[];
      events: TimelineEvt[];
    }>(`/cases/${id}/timeline${qs ? `?${qs}` : ""}`);
  },
  getCategories: (id: string) =>
    req<{ categories: { name: string; count: number }[] }>(`/cases/${id}/categories`),
  getFindings: (id: string) => req<FindingsResponse>(`/cases/${id}/findings`),
  setFindingBenign: (id: string, findingId: number, benign: boolean) =>
    req<{ ok: boolean }>(`/cases/${id}/findings/${findingId}/benign`, {
      method: "POST",
      body: JSON.stringify({ benign }),
    }),
  setRuleDisabled: (id: string, ruleId: string, disabled: boolean) =>
    req<{ ok: boolean; disabled_rules: string[] }>(`/cases/${id}/rules/disable`, {
      method: "POST",
      body: JSON.stringify({ rule_id: ruleId, disabled }),
    }),
  getAttackMatrix: (id: string) =>
    req<{ techniques: AttackTechnique[] }>(`/cases/${id}/attack-matrix`),
  getProcessSessions: (id: string) =>
    req<{ sessions: { session_id: string; process_count: number }[] }>(
      `/cases/${id}/processes/sessions`,
    ),
  getProcessTree: (id: string, sessionId?: string) =>
    req<ProcessTree>(
      `/cases/${id}/processes/tree${sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : ""}`,
    ),
  getProcessDossier: (id: string, sessionId: string, pid: number) =>
    req<{
      process: Record<string, unknown>;
      memory_results: MemoryResult[];
      events: EventRow[];
    }>(`/cases/${id}/processes/${encodeURIComponent(sessionId)}/${pid}`),
  getEntities: (
    id: string,
    params: { types?: string; min_severity?: string; max_nodes?: number } = {},
  ) => {
    const qs = new URLSearchParams(
      Object.entries(params).map(([k, v]) => [k, String(v)]),
    ).toString();
    return req<EntityGraph>(`/cases/${id}/entities${qs ? `?${qs}` : ""}`);
  },
  getEntityDossier: (id: string, entityId: string) =>
    req<EntityDossier>(`/cases/${id}/entity-dossier?entity_id=${encodeURIComponent(entityId)}`),

  // Evidence
  listEvidence: (id: string) => req<{ files: EvidenceFile[] }>(`/cases/${id}/evidence`),
  deleteEvidence: (id: string, name: string) =>
    req<{ ok: boolean; removed: Record<string, number> }>(
      `/cases/${id}/evidence/${encodeURIComponent(name)}`,
      { method: "DELETE" },
    ),
  reingestEvidence: (id: string, name: string, fileType: "artifact" | "memory" = "artifact") =>
    req<{ ok: boolean; filename: string }>(
      `/cases/${id}/evidence/${encodeURIComponent(name)}/reingest?file_type=${fileType}`,
      { method: "POST" },
    ),

  getMemory: (id: string, plugin?: string) =>
    req<{ plugins: { name: string; count: number }[]; results: MemoryResult[] }>(
      `/cases/${id}/memory${plugin ? `?plugin=${plugin}` : ""}`,
    ),
  getMemoryDumps: (id: string) =>
    req<{ dumps: MemoryDump[] }>(`/cases/${id}/memory/dumps`),
  getMemoryVfs: (id: string, sessionId: string, path = "/") =>
    req<{ session_id: string; path: string; entries: MemoryVfsEntry[] }>(
      `/cases/${id}/memory/${encodeURIComponent(sessionId)}/vfs?path=${encodeURIComponent(path)}`,
    ),
  getMemoryProcessModules: (id: string, sessionId: string, pid: number) =>
    req<{ session_id: string; pid: number; process: Record<string, unknown>; modules: MemoryModule[] }>(
      `/cases/${id}/memory/${encodeURIComponent(sessionId)}/processes/${pid}/modules`,
    ),
  getMemoryProcessHandles: (
    id: string,
    sessionId: string,
    pid: number,
    params: { type?: string; limit?: number; offset?: number } = {},
  ) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => [k, String(v)]),
    ).toString();
    return req<{
      session_id: string;
      pid: number;
      type: string | null;
      total: number;
      offset: number;
      limit: number;
      handles: MemoryProcessHandle[];
    }>(`/cases/${id}/memory/${encodeURIComponent(sessionId)}/processes/${pid}/handles${qs ? `?${qs}` : ""}`);
  },

  // Analysis
  startAnalysis: (id: string) =>
    req<{ ok: boolean }>(`/cases/${id}/analyze`, { method: "POST" }),
  getReport: (id: string) => req<Report>(`/cases/${id}/report`),

  // Settings
  getLLMConfig: () => req<LLMConfig>("/settings/llm"),
  updateLLMConfig: (body: Partial<LLMConfig> & { api_key?: string }) =>
    req<LLMConfig>("/settings/llm", { method: "PUT", body: JSON.stringify(body) }),
  getModels: (provider: Provider) => req<ModelInfo[]>(`/settings/llm/models/${provider}`),
  testProvider: (provider: Provider) =>
    req<ProviderTestResult>(`/settings/llm/test/${provider}`, { method: "POST" }),
  getGeneralSettings: () =>
    req<{ cases_dir: string; yara_rules_dir: string }>("/settings/general"),
  updateGeneralSettings: (body: { yara_rules_dir?: string }) =>
    req<{ cases_dir: string; yara_rules_dir: string }>("/settings/general", {
      method: "PUT",
      body: JSON.stringify(body),
    }),

  health: () =>
    req<{ status: string; brand: string; credit: string; memprocfs: boolean; yara: boolean }>(
      "/health",
    ),
};

export function downloadUrl(path: string): string {
  return `${BASE}${path}`;
}

export function memoryProcessDownloadUrl(
  caseId: string,
  sessionId: string,
  pid: number,
  kind: "image" | "vmem" = "image",
): string {
  return downloadUrl(
    `/cases/${caseId}/memory/${encodeURIComponent(sessionId)}/processes/${pid}/download?kind=${kind}`,
  );
}

export function memoryModuleDownloadUrl(
  caseId: string,
  sessionId: string,
  pid: number,
  module: { base_hex?: string | null; name?: string | null },
): string {
  const params = new URLSearchParams();
  if (module.base_hex) params.set("base", module.base_hex);
  else if (module.name) params.set("name", module.name);
  return downloadUrl(
    `/cases/${caseId}/memory/${encodeURIComponent(sessionId)}/processes/${pid}/modules/download?${params}`,
  );
}

export function memoryVfsDownloadUrl(caseId: string, sessionId: string, path: string): string {
  return downloadUrl(
    `/cases/${caseId}/memory/${encodeURIComponent(sessionId)}/vfs/download?path=${encodeURIComponent(path)}`,
  );
}

export async function downloadMemoryVfsArchive(caseId: string, sessionId: string, paths: string[]) {
  const res = await fetch(
    downloadUrl(`/cases/${caseId}/memory/${encodeURIComponent(sessionId)}/vfs/archive`),
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ paths }),
    },
  );
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  const disposition = res.headers.get("content-disposition") || "";
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  const filename = match?.[1] || "memprocfs-selection.zip";
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function uploadFile(
  caseId: string,
  file: File,
  fileType: "artifact" | "memory",
  onProgress?: (pct: number) => void,
  memoryOptions: { forensicTimeline?: boolean; eventlogs?: boolean } = {},
): Promise<{ ok: boolean; filename: string }> {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append("file", file);
    const xhr = new XMLHttpRequest();
    const params = new URLSearchParams({ file_type: fileType });
    if (fileType === "memory") {
      params.set("mem_forensic_timeline", String(Boolean(memoryOptions.forensicTimeline)));
      params.set("mem_eventlogs", String(Boolean(memoryOptions.eventlogs)));
    }
    xhr.open("POST", `${BASE}/cases/${caseId}/upload?${params.toString()}`);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress((e.loaded / e.total) * 100);
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve(JSON.parse(xhr.responseText));
      else reject(new Error(xhr.responseText || "Upload failed"));
    };
    xhr.onerror = () => reject(new Error("Upload failed"));
    xhr.send(form);
  });
}

export function wsUrl(path: string): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${BASE}${path}`;
}
