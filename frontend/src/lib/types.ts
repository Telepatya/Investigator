export type Provider = "ollama" | "openai" | "gemini" | "anthropic";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type CaseStatus = "created" | "ingesting" | "analyzing" | "ready" | "error";

export interface Case {
  id: string;
  name: string;
  description: string;
  status: CaseStatus;
  created_at: string;
  updated_at: string;
  event_count: number;
  finding_count: number;
  active_finding_count: number;
  process_count: number;
  has_memory_dump: boolean;
  ai_summary: string | null;
}

export interface ModelInfo {
  id: string;
  name: string;
  provider: Provider;
}

export interface LLMConfig {
  provider: Provider;
  model: string;
  ollama_base_url: string;
  temperature: number;
  max_tokens: number;
  analysis_max_tool_calls: number;
  chat_max_tool_calls: number;
  entity_max_tool_calls: number;
  has_api_key: boolean;
  available_models: ModelInfo[];
}

export interface ProviderTestResult {
  success: boolean;
  message: string;
  models: ModelInfo[];
}

export interface EventRow {
  id: number;
  timestamp: string | null;
  host: string | null;
  source: string;
  category: string;
  entity: string | null;
  severity: Severity;
  severity_reason: string | null;
  summary: string;
  raw: Record<string, unknown>;
}

export interface TimelineEvt {
  id: number;
  start: string | null;
  content: string;
  group: string;
  severity: Severity;
  severity_reason: string | null;
  source: string;
  raw?: Record<string, unknown>;
}

export interface Finding {
  id: number;
  title: string;
  description: string;
  severity: Severity;
  mitre_techniques: string[];
  evidence: Record<string, unknown>;
  source: string;
  ai_verdict: string | null;
  created_at: string;
  rule_id: string;
  suppressed: boolean;
  suppressed_reason: string | null;
  suppression_details: {
    reason: string;
    actor: "analyst" | "ai" | "rule";
    rationale: string;
    confidence: string | null;
    evidence_refs: { type: "event" | "memory_result"; id: number }[];
    timestamp: string | null;
  } | null;
  benign: boolean;
  rule_disabled: boolean;
  manual: boolean;
  manual_id: string | null;
}

export interface FindingsResponse {
  findings: Finding[];
  disabled_rules: string[];
}

export interface AttackTechnique {
  technique: string;
  name: string;
  count: number;
  max_severity: Severity;
}

export interface ProcNode {
  pid: number;
  ppid: number | null;
  name: string;
  path: string | null;
  cmdline: string | null;
  start_time: string | null;
  flags: string[];
  severity: Severity;
  children: ProcNode[];
}

export interface ProcessTree {
  case_id: string;
  session_id: string;
  roots: ProcNode[];
  flat: Omit<ProcNode, "children">[];
}

export interface EvidenceFile {
  name: string;
  kind: "memory" | "archive" | "eventlog" | "textlog" | "artifact" | "other";
  size: number;
  uploaded_at: string;
  sources: string[];
  event_count: number;
  process_count: number;
  memory_result_count: number;
}

export type EntityType =
  | "user"
  | "account"
  | "host"
  | "ip"
  | "process"
  | "service"
  | "file"
  | "url"
  | "registry"
  | "domain";

export interface EntityNode {
  id: string;
  type: EntityType;
  value: string;
  label: string;
  severity: Severity;
  action_count: number;
  first_seen: string | null;
  last_seen: string | null;
  findings: { id: number; title: string; severity: Severity; techniques: string[] }[];
  meta: EntityNodeMeta;
}

export interface EntityNodeMeta extends Record<string, unknown> {
  // Present on process nodes: true when every contributing process has exited.
  dead?: boolean;
  // Union of process flags (e.g. "terminated", "hidden") or, for services,
  // the service state ("Stopped", "Running", …).
  flags?: string[];
  state?: string;
  pids?: number[];
  // True when an analyst raised this node via a manual finding.
  manual?: boolean;
  // On manual nodes: number of related entities correlated from event evidence.
  correlated?: number;
}

export interface EntityEdge {
  id: string;
  source: string;
  target: string;
  verb: string;
  severity: Severity;
  count: number;
  last_seen: string | null;
  samples: string[];
}

export interface EntityGraph {
  case_id: string;
  nodes: EntityNode[];
  edges: EntityEdge[];
  total_nodes: number;
  total_edges: number;
  type_counts: Record<string, number>;
}

export interface EntityAction {
  timestamp: string | null;
  category: string;
  severity: Severity;
  summary: string;
  source: string;
  event_id: number | null;
}

export interface EntityNeighbor {
  direction: "in" | "out";
  verb: string;
  entity: {
    id: string;
    type: EntityType;
    value: string;
    label: string;
    severity: Severity;
    finding_count: number;
  };
  count: number;
  severity: Severity;
}

export interface EntityDossier {
  entity: {
    id: string;
    type: EntityType;
    value: string;
    label: string;
    severity: Severity;
    action_count: number;
    first_seen: string | null;
    last_seen: string | null;
    meta: Record<string, unknown>;
    finding_count: number;
  };
  neighbors: EntityNeighbor[];
  findings: { id: number; title: string; severity: Severity; techniques: string[] }[];
  actions: EntityAction[];
  action_total: number;
  memory_processes?: MemoryProcessCandidate[];
}

export interface MemoryResult {
  id: number;
  plugin: string;
  pid: number | null;
  process_name: string | null;
  summary: string;
  data: Record<string, unknown>;
  severity: Severity;
}

export interface MemoryProcessCandidate {
  session_id: string;
  pid: number;
  ppid: number | null;
  name: string;
  path: string | null;
  cmdline: string | null;
  start_time: string | null;
  flags: string[];
  severity: Severity;
  extra: Record<string, unknown>;
  memory_results: {
    id: number;
    plugin: string;
    summary: string;
    severity: Severity;
    data: Record<string, unknown>;
  }[];
  handles: MemoryProcessHandle[];
  handle_counts: Record<string, number>;
  cross_process_activity: MemoryProcessHandle[];
  handles_on_demand?: boolean;
  downloads: {
    image: boolean;
    minidump: boolean;
    modules: boolean;
  };
}

export interface MemoryProcessHandle {
  event_id: number;
  type: string;
  name: string | null;
  target_pid: number | null;
  target_process: string | null;
  access: string | number | null;
  handle: string | number | null;
  risk: string;
  risk_reasons: string[];
  summary: string;
  severity: Severity;
}

export interface MemoryDump {
  session_id: string;
  dump_stem: string;
  filename: string;
  size: number;
}

export interface MemoryModule {
  name: string;
  path: string | null;
  base: number | null;
  base_hex: string | null;
  size: number;
  status: string;
  sha256: string | null;
}

export interface MemoryVfsEntry {
  name: string;
  path: string;
  is_dir: boolean;
  size: number;
}

export interface Report {
  exists: boolean;
  case_id?: string;
  summary?: string;
  timeline_narrative?: string;
  timeline_entries?: ReportTimelineEntry[];
  findings_analysis?: {
    id: number;
    title: string;
    severity: Severity;
    verdict: string;
    basis?: "ai-verdict" | "finding-evidence";
  }[];
  stale?: boolean;
  generated_at?: string;
}

export interface ReportTimelineEntry {
  id: string;
  title: string;
  description: string;
  confidence: "high" | "medium" | "low";
  start: string;
  end: string;
  event_ids: number[];
  finding_ids: number[];
  event_refs: { id: number; timestamp: string | null; summary: string; severity: Severity; source: string }[];
  finding_refs: { id: number; title: string; severity: Severity; suppressed: boolean }[];
}

export interface Progress {
  case_id: string;
  phase: string;
  percent: number;
  message: string;
  done: boolean;
  error?: string | null;
}

export interface ReverseProject {
  id: string;
  name: string;
  description: string;
  linked_case_id: string | null;
  status: string;
  active_run_id: string | null;
  created_at: string;
  updated_at: string;
  artifact_count: number;
  latest_run_status: string | null;
}

export interface ReverseArtifact {
  id: string;
  project_id: string;
  name: string;
  artifact_type: string;
  content_type: string;
  file_size: number;
  sha256: string;
  created_at: string;
}

export interface ReverseRun {
  id: string;
  project_id: string;
  status: string;
  provider: Provider;
  model: string;
  temperature: number;
  max_tokens: number;
  max_turns: number;
  turns_used: number;
  awaiting_reason: string | null;
  error: string | null;
  image_digest: string | null;
  tool_versions: Record<string, string>;
  report_signature_status: string;
  report_signature_error: string | null;
  report_verification_status: string;
  report_verification_summary: string | null;
  report_verification_error: string | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
}

export interface ReverseStatus {
  project_id: string;
  status: string;
  run: ReverseRun | null;
  active: boolean;
  can_resume: boolean;
  can_recover_report: boolean;
}

export interface ReverseReport {
  project_id: string;
  run_id: string;
  content: string;
  iocs: string | null;
  signature_status: string;
  signature_error: string | null;
  verification_status: string;
  verification_summary: string | null;
  verification_error: string | null;
  verification_details: Record<string, unknown>;
}

export interface ReverseTraceEntry {
  id: number;
  sequence: number;
  event_type: string;
  payload: Record<string, unknown>;
  previous_hash: string;
  entry_hash: string;
  signature: string | null;
  created_at: string;
}

export interface ReverseChatMessage {
  id: number;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  phase: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface ReverseAuditEvent {
  id: number;
  event_type: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface ReverseHealth {
  docker_available: boolean;
  image_available: boolean;
  image: string;
  image_digest: string | null;
  message: string;
}

export interface ReverseToolPolicy {
  enabled_tools: string[];
  available_tools: { id: string; description: string }[];
}

export interface ReverseSettings {
  sandbox_image: string;
  sandbox_idle_ttl_minutes: number;
  sandbox_memory_limit_mb: number;
  sandbox_cpu_limit: number;
  sandbox_pids_limit: number;
  analysis_max_turns: number;
  analysis_extension_turns: number;
  max_upload_bytes: number;
  max_project_bytes: number;
  max_tool_output_chars: number;
  enabled_tools: string[];
  available_tools: { id: string; description: string }[];
}
