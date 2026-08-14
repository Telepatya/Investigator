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
  RuleDetail,
  RuleImportResponse,
  RuleListResponse,
  RuleValidateResponse,
  TimelineEvt,
} from "./types";

const BASE = "/api";

async function req<T>(path: string, opts?: RequestInit): Promise<T> {
  const contentHeaders = opts?.body instanceof FormData ? undefined : { "Content-Type": "application/json" };
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: opts?.headers ?? contentHeaders,
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
  getCase: (id: string, signal?: AbortSignal) => req<Case>(`/cases/${id}`, { signal }),
  createCase: (name: string, description: string) =>
    req<Case>("/cases", { method: "POST", body: JSON.stringify({ name, description }) }),
  deleteCase: (id: string) => req<{ ok: boolean }>(`/cases/${id}`, { method: "DELETE" }),

  // Data
  getEvents: (id: string, params: Record<string, string | number> = {}, signal?: AbortSignal) => {
    const qs = new URLSearchParams(
      Object.entries(params).map(([k, v]) => [k, String(v)]),
    ).toString();
    return req<{ total: number; events: EventRow[] }>(`/cases/${id}/events?${qs}`, { signal });
  },
  getEvent: (id: string, eventId: number, signal?: AbortSignal) =>
    req<EventRow>(`/cases/${id}/events/${eventId}`, { signal }),
  getTimeline: (
    id: string,
    params: {
      q?: string;
      min_severity?: string;
      sources?: string;
      categories?: string;
      limit?: number;
      include_facets?: boolean;
    } = {},
    signal?: AbortSignal,
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
      categories: { name: string; count: number }[];
      events: TimelineEvt[];
    }>(`/cases/${id}/timeline${qs ? `?${qs}` : ""}`, { signal });
  },
  getCategories: (id: string) =>
    req<{ categories: { name: string; count: number }[] }>(`/cases/${id}/categories`),
  getFindings: (id: string) => req<FindingsResponse>(`/cases/${id}/findings`),
  getFinding: (id: string, findingId: number, signal?: AbortSignal) =>
    req<Finding>(`/cases/${id}/findings/${findingId}`, { signal }),
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
  rebuildDetections: (id: string) =>
    req<{ ok: boolean; added: number; rebuild: boolean }>(`/cases/${id}/detections/run?rebuild=true`, {
      method: "POST",
    }),
  createManualFinding: (
    id: string,
    payload: {
      title: string;
      severity: string;
      description?: string;
      mitre_techniques?: string[];
      ref_type: "event" | "entity";
      ref_id: string;
      ref_label: string;
      ref_entity?: string;
      entity_type?: string;
    },
  ) =>
    req<{ ok: boolean; manual_id: string }>(`/cases/${id}/findings/manual`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteManualFinding: (id: string, manualId: string) =>
    req<{ ok: boolean; removed: boolean }>(`/cases/${id}/findings/manual/${manualId}`, {
      method: "DELETE",
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
    signal?: AbortSignal,
  ) => {
    const qs = new URLSearchParams(
      Object.entries(params).map(([k, v]) => [k, String(v)]),
    ).toString();
    return req<EntityGraph>(`/cases/${id}/entities${qs ? `?${qs}` : ""}`, { signal });
  },
  getEntityDossier: (id: string, entityId: string, signal?: AbortSignal) =>
    req<EntityDossier>(`/cases/${id}/entity-dossier?entity_id=${encodeURIComponent(entityId)}`, { signal }),
  sendMemoryProcessToReverse: (caseId: string, sessionId: string, pid: number) =>
    req<import("./types").ReverseProcessHandoff>(
      `/cases/${caseId}/memory/${encodeURIComponent(sessionId)}/processes/${pid}/reverse`,
      { method: "POST" },
    ),

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
  listChats: (id: string) => req<{
    chats: {
      id: string;
      title: string;
      message_count: number;
      preview: string;
      created_at: string;
      updated_at: string;
    }[];
  }>(`/cases/${id}/chats`),
  createChat: (id: string, title = "New chat") =>
    req<{ id: string; title: string; messages: []; memo: null }>(`/cases/${id}/chats`, {
      method: "POST",
      body: JSON.stringify({ title }),
    }),
  getChat: (id: string, chatId: string) => req<{
    id: string;
    title: string;
    memo: string | null;
    messages: { id: number; role: "user" | "assistant"; content: string; created_at: string }[];
  }>(`/cases/${id}/chats/${encodeURIComponent(chatId)}`),
  deleteChat: (id: string, chatId: string) =>
    req<{ ok: boolean }>(`/cases/${id}/chats/${encodeURIComponent(chatId)}`, {
      method: "DELETE",
    }),

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

  // Reverse workspaces
  listReverseProjects: (caseId?: string) =>
    req<import("./types").ReverseProject[]>(`/reverse/projects${caseId ? `?case_id=${encodeURIComponent(caseId)}` : ""}`),
  getReverseProject: (id: string) => req<import("./types").ReverseProject>(`/reverse/projects/${id}`),
  createReverseProject: (body: { name: string; description?: string; linked_case_id?: string | null }) =>
    req<import("./types").ReverseProject>("/reverse/projects", { method: "POST", body: JSON.stringify(body) }),
  updateReverseProject: (id: string, body: Record<string, unknown>) =>
    req<import("./types").ReverseProject>(`/reverse/projects/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteReverseProject: (id: string) => req<{ ok: boolean }>(`/reverse/projects/${id}`, { method: "DELETE" }),
  getReverseProjectTools: (id: string) =>
    req<import("./types").ReverseToolPolicy>(`/reverse/projects/${id}/tools`),
  updateReverseProjectTools: (id: string, enabledTools: string[]) =>
    req<import("./types").ReverseToolPolicy>(`/reverse/projects/${id}/tools`, {
      method: "PUT", body: JSON.stringify({ enabled_tools: enabledTools }),
    }),
  getReverseHealth: () => req<import("./types").ReverseHealth>("/reverse/health"),
  listReverseArtifacts: (id: string) =>
    req<import("./types").ReverseArtifact[]>(`/reverse/projects/${id}/artifacts`),
  uploadReverseArtifact: (id: string, file: File) => {
    const body = new FormData();
    body.append("file", file);
    return req<import("./types").ReverseArtifact>(`/reverse/projects/${id}/artifacts`, { method: "POST", body });
  },
  deleteReverseArtifact: (id: string, artifactId: string) =>
    req<{ ok: boolean }>(`/reverse/projects/${id}/artifacts/${artifactId}`, { method: "DELETE" }),
  startReverseAnalysis: (id: string, notes: string) =>
    req<import("./types").ReverseRun>(`/reverse/projects/${id}/analysis/start`, {
      method: "POST", body: JSON.stringify({ notes }),
    }),
  getReverseStatus: (id: string) =>
    req<import("./types").ReverseStatus>(`/reverse/projects/${id}/analysis/status`),
  stopReverseAnalysis: (id: string) =>
    req<{ ok: boolean }>(`/reverse/projects/${id}/analysis/stop`, { method: "POST" }),
  resumeReverseAnalysis: (id: string) =>
    req<import("./types").ReverseRun>(`/reverse/projects/${id}/analysis/resume`, { method: "POST" }),
  continueReverseInvestigation: (id: string) =>
    req<import("./types").ReverseRun>(`/reverse/projects/${id}/analysis/continue`, { method: "POST" }),
  decideReverseExtension: (id: string, decision: "approve" | "deny") =>
    req<import("./types").ReverseRun>(`/reverse/projects/${id}/analysis/turn-extension/${decision}`, { method: "POST" }),
  replayReverseAnalysis: (id: string) =>
    req<import("./types").ReverseRun>(`/reverse/projects/${id}/analysis/replay`, { method: "POST" }),
  getReverseReport: (id: string) =>
    req<import("./types").ReverseReport>(`/reverse/projects/${id}/report`),
  regenerateReverseIocs: (id: string) =>
    req<{ iocs: string }>(`/reverse/projects/${id}/report/iocs`, { method: "POST" }),
  retryReverseReportSignature: (id: string) =>
    req<import("./types").ReverseRun>(`/reverse/projects/${id}/report/sign`, { method: "POST" }),
  retryReverseReportVerification: (id: string) =>
    req<import("./types").ReverseRun>(`/reverse/projects/${id}/report/verify`, { method: "POST" }),
  reviewReverseReport: (id: string) =>
    req<import("./types").ReverseRun>(`/reverse/projects/${id}/report/review`, { method: "POST" }),
  getReverseEvidence: (id: string, messageId: number) =>
    req<import("./types").ReverseEvidence>(`/reverse/projects/${id}/evidence/${messageId}`),
  recoverReverseReport: (id: string) =>
    req<import("./types").ReverseRun>(`/reverse/projects/${id}/report/recover`, { method: "POST" }),
  getReverseMessages: (id: string) =>
    req<import("./types").ReverseChatMessage[]>(`/reverse/projects/${id}/messages`),
  sendReverseMessage: (id: string, message: string) =>
    req<import("./types").ReverseChatMessage>(`/reverse/projects/${id}/messages`, {
      method: "POST", body: JSON.stringify({ message }),
    }),
  clearReverseMessages: (id: string) =>
    req<{ ok: boolean }>(`/reverse/projects/${id}/messages`, { method: "DELETE" }),
  pauseReverseChat: (id: string) =>
    req<{ ok: boolean }>(`/reverse/projects/${id}/chat/pause`, { method: "POST" }),
  resumeReverseChat: (id: string) =>
    req<{ ok: boolean }>(`/reverse/projects/${id}/chat/resume`, { method: "POST" }),
  getReverseTrace: (id: string) =>
    req<import("./types").ReverseTraceEntry[]>(`/reverse/projects/${id}/trace`),
  verifyReverseTrace: (id: string) =>
    req<{ valid: boolean; entries: number; failed_sequences: number[]; failed_signature_sequences: number[] }>(`/reverse/projects/${id}/trace/verify`),
  getReverseAudit: (id: string) =>
    req<import("./types").ReverseAuditEvent[]>(`/reverse/projects/${id}/audit`),
  getReverseSettings: () => req<import("./types").ReverseSettings>("/settings/reverse"),
  updateReverseSettings: (body: Partial<import("./types").ReverseSettings>) =>
    req<import("./types").ReverseSettings>("/settings/reverse", { method: "PUT", body: JSON.stringify(body) }),

  health: () =>
    req<{
      status: string;
      brand: string;
      version: string;
      release_channel: string;
      credit: string;
      memprocfs: boolean;
      yara: boolean;
      reverse: import("./types").ReverseHealth & { store_ready: boolean };
    }>(
      "/health",
    ),
};

export function downloadUrl(path: string): string {
  return `${BASE}${path}`;
}

export function reverseArtifactDownloadUrl(projectId: string, artifactId: string): string {
  return downloadUrl(`/reverse/projects/${projectId}/artifacts/${artifactId}/download`);
}

export function memoryProcessDownloadUrl(
  caseId: string,
  sessionId: string,
  pid: number,
  kind: "image" | "minidump" = "image",
): string {
  return downloadUrl(
    `/cases/${caseId}/memory/${encodeURIComponent(sessionId)}/processes/${pid}/download?kind=${kind}`,
  );
}

async function saveDownloadResponse(res: Response, fallbackFilename: string) {
  if (!res.ok) {
    const text = await res.text();
    try {
      const parsed = JSON.parse(text) as { detail?: string };
      throw new Error(parsed.detail || text || `Download failed: ${res.status}`);
    } catch (error) {
      if (error instanceof SyntaxError) throw new Error(text || `Download failed: ${res.status}`);
      throw error;
    }
  }
  const blob = await res.blob();
  const disposition = res.headers.get("content-disposition") || "";
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  const filename = match?.[1] || fallbackFilename;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function downloadMemoryProcessMinidump(
  caseId: string,
  sessionId: string,
  pid: number,
) {
  const res = await fetch(memoryProcessDownloadUrl(caseId, sessionId, pid, "minidump"));
  await saveDownloadResponse(res, `process-${pid}.minidump.dmp`);
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
  await saveDownloadResponse(res, "memprocfs-selection.zip");
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

export const rulesApi = {
  list: (params: { q?: string; source?: string; kind?: string; platform?: string; severity?: string } = {}) => {
    const query = new URLSearchParams(
      Object.entries(params).filter(([, value]) => Boolean(value)) as [string, string][],
    ).toString();
    return req<RuleListResponse>(`/rules${query ? `?${query}` : ""}`);
  },
  get: (ruleId: string) => req<RuleDetail>(`/rules/${encodeURIComponent(ruleId)}`),
  updateBuiltin: (
    ruleId: string,
    body: { enabled?: boolean; severity_override?: string | null; clear_severity?: boolean; note?: string },
  ) =>
    req<{ ok: boolean; revision: number }>(`/rules/builtin/${encodeURIComponent(ruleId)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  createCustom: (yamlSource: string, enabled = true) =>
    req<{ ok: boolean; revision: number }>("/rules/custom", {
      method: "POST",
      body: JSON.stringify({ yaml_source: yamlSource, enabled }),
    }),
  updateCustom: (ruleId: string, body: { yaml_source?: string; enabled?: boolean }) =>
    req<{ ok: boolean; revision: number }>(`/rules/custom/${encodeURIComponent(ruleId)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteCustom: (ruleId: string) =>
    req<{ ok: boolean; revision: number }>(`/rules/custom/${encodeURIComponent(ruleId)}`, {
      method: "DELETE",
    }),
  validate: (yamlSource: string) =>
    req<RuleValidateResponse>("/rules/validate", {
      method: "POST",
      body: JSON.stringify({ yaml_source: yamlSource }),
    }),
  fork: (ruleId: string, disableBuiltin: boolean) =>
    req<{ id: string; slug: string; yaml_source: string; revision: number }>(
      `/rules/builtin/${encodeURIComponent(ruleId)}/fork`,
      { method: "POST", body: JSON.stringify({ disable_builtin: disableBuiltin }) },
    ),
  import: (yamlSource: string) =>
    req<RuleImportResponse>("/rules/import", {
      method: "POST",
      body: JSON.stringify({ yaml_source: yamlSource }),
    }),
};

export function rulesExportUrl(): string {
  return `${BASE}/rules/export/bundle`;
}

export function wsUrl(path: string): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${BASE}${path}`;
}
