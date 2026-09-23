import { useEffect, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Server,
  Cloud,
  KeyRound,
  CheckCircle2,
  XCircle,
  Loader2,
  Cpu,
  ShieldAlert,
  Binary,
  Box,
} from "lucide-react";
import { api } from "../lib/api";
import type { LLMConfig, ModelInfo, Provider } from "../lib/types";
import { PageShell, PageTitle, Section } from "../components/common";

const PROVIDERS: { id: Provider; name: string; icon: ReactNode; local: boolean }[] = [
  { id: "ollama", name: "Ollama (Local)", icon: <Server size={18} />, local: true },
  { id: "openai", name: "OpenAI (ChatGPT)", icon: <Cloud size={18} />, local: false },
  { id: "openrouter", name: "OpenRouter", icon: <Cloud size={18} />, local: false },
  { id: "anthropic", name: "Anthropic (Claude)", icon: <Cloud size={18} />, local: false },
  { id: "gemini", name: "Google (Gemini)", icon: <Cloud size={18} />, local: false },
];

export default function SettingsPage() {
  const [provider, setProvider] = useState<Provider>("ollama");
  const [model, setModel] = useState("");
  const [ollamaUrl, setOllamaUrl] = useState("http://localhost:11434");
  const [openRouterUrl, setOpenRouterUrl] = useState("https://openrouter.ai/api/v1");
  const [temperature, setTemperature] = useState(0.2);
  const [maxTokens, setMaxTokens] = useState(4096);
  const [analysisToolCalls, setAnalysisToolCalls] = useState(8);
  const [chatToolCalls, setChatToolCalls] = useState(4);
  const [entityToolCalls, setEntityToolCalls] = useState(5);
  const [apiKey, setApiKey] = useState("");
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [hasKey, setHasKey] = useState(false);
  const [loadingModels, setLoadingModels] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [saved, setSaved] = useState(false);
  const [yaraDir, setYaraDir] = useState("");

  const { data: health } = useQuery({ queryKey: ["health"], queryFn: api.health });
  const { data: access } = useQuery({ queryKey: ["settings-access"], queryFn: api.getSettingsAccess });
  const settingsLocked = !access || !access.can_manage_shared_state;
  const { data: general } = useQuery({
    queryKey: ["general-settings"],
    queryFn: api.getGeneralSettings,
  });

  useEffect(() => {
    api.getLLMConfig().then((cfg: LLMConfig) => {
      setProvider(cfg.provider);
      setModel(cfg.model);
      setOllamaUrl(cfg.ollama_base_url);
      setOpenRouterUrl(cfg.openrouter_base_url);
      setTemperature(cfg.temperature);
      setMaxTokens(cfg.max_tokens);
      setAnalysisToolCalls(cfg.analysis_max_tool_calls);
      setChatToolCalls(cfg.chat_max_tool_calls);
      setEntityToolCalls(cfg.entity_max_tool_calls);
      setHasKey(cfg.has_api_key);
      setModels(cfg.available_models);
    });
  }, []);

  useEffect(() => {
    if (general) setYaraDir(general.yara_rules_dir);
  }, [general]);

  async function loadModels(p: Provider) {
    setLoadingModels(true);
    try {
      const m = await api.getModels(p);
      setModels(m);
      if (m.length && !m.find((x) => x.id === model)) setModel(m[0].id);
    } catch {
      setModels([]);
    } finally {
      setLoadingModels(false);
    }
  }

  function switchProvider(p: Provider) {
    setProvider(p);
    setTestResult(null);
    setModels([]);
    loadModels(p);
  }

  async function test() {
    setTesting(true);
    setTestResult(null);
    try {
      // Persist provider-specific connection details before testing them.
      await api.updateLLMConfig({
        provider,
        ...(provider === "ollama" ? { ollama_base_url: ollamaUrl } : {}),
        ...(provider === "openrouter" ? { openrouter_base_url: openRouterUrl } : {}),
        ...(apiKey ? { api_key: apiKey } : {}),
      });
      if (apiKey) {
        setHasKey(true);
        setApiKey("");
      }
      const res = await api.testProvider(provider);
      setTestResult({ ok: res.success, msg: res.message });
      if (res.success && res.models.length) {
        setModels(res.models);
        if (!res.models.find((x) => x.id === model)) setModel(res.models[0].id);
      }
    } catch (e) {
      setTestResult({ ok: false, msg: String(e) });
    } finally {
      setTesting(false);
    }
  }

  async function save() {
    await api.updateLLMConfig({
      provider,
      model,
      ollama_base_url: ollamaUrl,
      openrouter_base_url: openRouterUrl,
      temperature,
      max_tokens: maxTokens,
      analysis_max_tool_calls: analysisToolCalls,
      chat_max_tool_calls: chatToolCalls,
      entity_max_tool_calls: entityToolCalls,
      ...(apiKey ? { api_key: apiKey } : {}),
    });
    await api.updateGeneralSettings({ yara_rules_dir: yaraDir });
    if (apiKey) {
      setHasKey(true);
      setApiKey("");
    }
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  const current = PROVIDERS.find((p) => p.id === provider)!;

  return (
    <PageShell className="max-w-4xl">
      <PageTitle
        icon={<Server size={22} />}
        title="Settings"
        subtitle="Configure AI providers, detection paths, and local forensic engines."
      />

      {access?.admin_required && !access.can_manage_shared_state && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-amber-400/30 bg-amber-400/10 p-3 text-sm text-amber-300">
          <ShieldAlert size={16} className="mt-0.5 shrink-0" />
          <div>Only users with the configured SSO administrator role can change shared provider credentials or deployment settings.</div>
        </div>
      )}

      <fieldset disabled={settingsLocked} className="contents">
      <Section title="AI Provider">
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 mb-5">
          {PROVIDERS.map((p) => (
            <button
              key={p.id}
              onClick={() => switchProvider(p.id)}
              className={`p-3 rounded-lg border text-left transition ${
                provider === p.id
                  ? "border-accent-cyan/50 bg-accent-cyan/10 shadow-glow"
                  : "border-white/5 bg-white/5 hover:bg-white/10"
              }`}
            >
              <div
                className={provider === p.id ? "text-accent-cyan" : "text-ink-300"}
              >
                {p.icon}
              </div>
              <div className="text-sm font-medium text-ink-100 mt-2">{p.name}</div>
              <div className="text-[10px] uppercase tracking-wider text-ink-500 mt-0.5">
                {p.local ? "on-device" : "remote api"}
              </div>
            </button>
          ))}
        </div>

        {!current.local && (
          <div className="mb-4 flex items-start gap-2 rounded-lg border border-amber-400/30 bg-amber-400/10 p-3 text-sm text-amber-300">
            <ShieldAlert size={16} className="mt-0.5 shrink-0" />
            <div>
              <span className="font-semibold">Evidence leaves your machine.</span>{" "}
              With a remote provider, the evidence excerpts placed in analysis and
              chat prompts — log lines, command lines, process and memory details —
              are transmitted to {current.name} for processing. Choose{" "}
              <span className="font-semibold">Ollama (Local)</span> to keep all case
              data on this machine.
            </div>
          </div>
        )}

        {provider === "ollama" && (
          <div className="mb-4">
            <label className="label">Ollama server URL</label>
            <input
              className="input"
              value={ollamaUrl}
              onChange={(e) => setOllamaUrl(e.target.value)}
              onBlur={() => loadModels("ollama")}
            />
          </div>
        )}

        {provider === "openrouter" && (
          <div className="mb-4">
            <label className="label">OpenRouter API URL</label>
            <input
              className="input"
              value={openRouterUrl}
              onChange={(e) => setOpenRouterUrl(e.target.value)}
              onBlur={() => loadModels("openrouter")}
            />
          </div>
        )}

        {!current.local && (
          <div className="mb-4">
            <label className="label flex items-center gap-1.5">
              <KeyRound size={12} /> API Key {hasKey && <span className="text-emerald-400 normal-case font-normal">· saved</span>}
            </label>
            <input
              className="input font-mono"
              type="password"
              placeholder={hasKey ? "•••••••••• (leave blank to keep)" : "Paste API key"}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
          </div>
        )}

        <div className="flex items-end gap-3 mb-4">
          <div className="flex-1">
            <label className="label flex items-center gap-1.5">
              <Cpu size={12} /> Model {loadingModels && <Loader2 size={12} className="animate-spin" />}
            </label>
            <select className="input" value={model} onChange={(e) => setModel(e.target.value)}>
              {models.length === 0 && <option value={model}>{model || "—"}</option>}
              {models.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name}
                </option>
              ))}
            </select>
          </div>
          <button className="btn-ghost" onClick={() => loadModels(provider)}>
            Refresh
          </button>
          <button className="btn-ghost" onClick={test} disabled={testing}>
            {testing ? <Loader2 size={16} className="animate-spin" /> : "Test"}
          </button>
        </div>

        {testResult && (
          <div
            className={`flex items-center gap-2 text-sm p-3 rounded-lg ${
              testResult.ok
                ? "bg-emerald-400/10 text-emerald-400"
                : "bg-sev-critical/10 text-sev-critical"
            }`}
          >
            {testResult.ok ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
            {testResult.msg}
          </div>
        )}

        <div className="grid grid-cols-2 gap-4 mt-4">
          <div>
            <label className="label">Temperature ({temperature.toFixed(2)})</label>
            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={temperature}
              onChange={(e) => setTemperature(parseFloat(e.target.value))}
              className="w-full accent-accent-cyan"
            />
          </div>
          <div>
            <label className="label">Max tokens</label>
            <input
              className="input"
              type="number"
              value={maxTokens}
              onChange={(e) => setMaxTokens(parseInt(e.target.value) || 4096)}
            />
          </div>
        </div>
        <div className="mt-5 border-t border-white/5 pt-4">
          <div className="label mb-2">Maximum AI database interactions</div>
          <p className="text-xs text-ink-500 mb-3">
            Each tool call usually adds a model round trip. Set a workflow to 0 to use only its compact initial context.
          </p>
          <div className="grid gap-3 sm:grid-cols-3">
            <ToolCallLimit label="Case analysis" value={analysisToolCalls} onChange={setAnalysisToolCalls} />
            <ToolCallLimit label="Chat turn" value={chatToolCalls} onChange={setChatToolCalls} />
            <ToolCallLimit label="Entity investigation" value={entityToolCalls} onChange={setEntityToolCalls} />
          </div>
        </div>
      </Section>

      <Section title="Detection Engine">
        <div>
          <label className="label flex items-center gap-1.5">
            <ShieldAlert size={12} /> Custom YARA rules directory
          </label>
          <input
            className="input font-mono"
            placeholder="C:\path\to\your\yara-rules (optional)"
            value={yaraDir}
            onChange={(e) => setYaraDir(e.target.value)}
          />
          <p className="text-xs text-ink-500 mt-1.5">
            Bundled APT/C2 rules always run. Point this at a folder of .yar/.yara files to add your own.
          </p>
        </div>
        <div className="flex gap-4 mt-4 text-sm">
          <EngineStatus label="MemProcFS" ok={health?.memprocfs} />
          <EngineStatus label="YARA engine" ok={health?.yara} />
        </div>
      </Section>

      <ReverseSandboxSettings />

      <div className="flex items-center gap-3">
        <button className="btn-primary" onClick={save}>
          Save settings
        </button>
        {saved && (
          <span className="text-emerald-400 text-sm flex items-center gap-1.5">
            <CheckCircle2 size={16} /> Saved
          </span>
        )}
      </div>
      </fieldset>
    </PageShell>
  );
}

function ReverseSandboxSettings() {
  const { data } = useQuery({ queryKey: ["reverse-settings"], queryFn: api.getReverseSettings });
  const { data: health } = useQuery({ queryKey: ["reverse-health"], queryFn: api.getReverseHealth });
  const [draft, setDraft] = useState<Awaited<ReturnType<typeof api.getReverseSettings>> | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => { if (data) setDraft(data); }, [data]);
  if (!draft) return <Section title="Reverse sandbox"><div className="text-sm text-ink-400">Loading sandbox settings…</div></Section>;

  const number = (key: keyof typeof draft, value: number) => setDraft({ ...draft, [key]: value });
  async function saveReverse() {
    setSaving(true); setError(""); setSaved(false);
    try {
      const updated = await api.updateReverseSettings({
        sandbox_idle_ttl_minutes: draft!.sandbox_idle_ttl_minutes,
        sandbox_memory_limit_mb: draft!.sandbox_memory_limit_mb,
        sandbox_cpu_limit: draft!.sandbox_cpu_limit,
        sandbox_pids_limit: draft!.sandbox_pids_limit,
        analysis_max_turns: draft!.analysis_max_turns,
        analysis_extension_turns: draft!.analysis_extension_turns,
        max_upload_bytes: draft!.max_upload_bytes,
        max_project_bytes: draft!.max_project_bytes,
        max_tool_output_chars: draft!.max_tool_output_chars,
        enabled_tools: draft!.enabled_tools,
      });
      setDraft(updated); setSaved(true); setTimeout(() => setSaved(false), 2000);
    } catch (e) { setError(String(e)); } finally { setSaving(false); }
  }

  return (
    <Section title="Reverse sandbox" right={<span className={`chip ${health?.image_available ? "bg-emerald-400/10 text-emerald-400" : "bg-amber-400/10 text-amber-400"}`}><Box size={12} /> {health?.image_available ? "ready" : "not built"}</span>}>
      <div className="mb-4 flex items-start gap-2 rounded-xl border border-accent-blue/20 bg-accent-blue/10 p-3 text-sm text-ink-200">
        <Binary size={17} className="mt-0.5 shrink-0 text-accent-blue" />
        <div>Reverse uses the AI provider above. Uploaded samples are inspected only by a network-isolated, non-root static-analysis container and are never intentionally executed.</div>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <ReverseNumber label="Idle TTL (minutes)" value={draft.sandbox_idle_ttl_minutes} min={5} max={1440} onChange={(v) => number("sandbox_idle_ttl_minutes", v)} />
        <ReverseNumber label="Memory limit (MB)" value={draft.sandbox_memory_limit_mb} min={256} max={32768} onChange={(v) => number("sandbox_memory_limit_mb", v)} />
        <ReverseNumber label="CPU limit" value={draft.sandbox_cpu_limit} min={0.25} max={16} step={0.25} onChange={(v) => number("sandbox_cpu_limit", v)} />
        <ReverseNumber label="PID limit" value={draft.sandbox_pids_limit} min={32} max={1024} onChange={(v) => number("sandbox_pids_limit", v)} />
        <ReverseNumber label="Analysis turns" value={draft.analysis_max_turns} min={1} max={100} onChange={(v) => number("analysis_max_turns", v)} />
        <ReverseNumber label="Extension turns" value={draft.analysis_extension_turns} min={1} max={50} onChange={(v) => number("analysis_extension_turns", v)} />
      </div>
      <div className="mt-5 border-t border-white/5 pt-4">
        <div className="label mb-2">Enabled static tools</div>
        <div className="grid gap-2 sm:grid-cols-2">
          {draft.available_tools.map((tool) => <label key={tool.id} className="flex cursor-pointer items-start gap-2 rounded-xl bg-[rgb(var(--panel-strong)/0.46)] p-3 text-sm"><input type="checkbox" className="mt-1 accent-accent-cyan" checked={draft.enabled_tools.includes(tool.id)} onChange={(event) => setDraft({ ...draft, enabled_tools: event.target.checked ? [...draft.enabled_tools, tool.id] : draft.enabled_tools.filter((id) => id !== tool.id) })} /><span><span className="font-mono text-xs font-semibold text-ink-100">{tool.id}</span><span className="mt-0.5 block text-xs text-ink-400">{tool.description}</span></span></label>)}
        </div>
      </div>
      <div className="mt-4 flex items-center gap-3"><button className="btn-primary" disabled={saving} onClick={saveReverse}>{saving ? <Loader2 size={15} className="animate-spin" /> : "Save Reverse settings"}</button>{saved && <span className="flex items-center gap-1 text-sm text-emerald-400"><CheckCircle2 size={15} /> Saved</span>}{error && <span className="text-sm text-sev-critical">{error}</span>}</div>
      {!health?.image_available && <div className="mt-3 font-mono text-xs text-ink-400">python run.py --build-reverse-sandbox</div>}
    </Section>
  );
}

function ReverseNumber({ label, value, min, max, step = 1, onChange }: { label: string; value: number; min: number; max: number; step?: number; onChange: (value: number) => void }) {
  return <div><label className="label">{label}</label><input className="input" type="number" value={value} min={min} max={max} step={step} onChange={(event) => onChange(Math.max(min, Math.min(max, Number(event.target.value) || min)))} /></div>;
}

function ToolCallLimit({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) {
  return (
    <div>
      <label className="text-xs text-ink-400">{label}</label>
      <input
        className="input mt-1"
        type="number"
        min={0}
        max={20}
        value={value}
        onChange={(e) => onChange(Math.max(0, Math.min(20, Number(e.target.value) || 0)))}
      />
    </div>
  );
}

function EngineStatus({ label, ok }: { label: string; ok?: boolean }) {
  return (
    <div className="flex items-center gap-1.5">
      {ok ? (
        <CheckCircle2 size={15} className="text-emerald-400" />
      ) : (
        <XCircle size={15} className="text-ink-500" />
      )}
      <span className={ok ? "text-ink-200" : "text-ink-500"}>{label}</span>
      <span className="text-ink-500 text-xs">{ok ? "ready" : "not installed"}</span>
    </div>
  );
}
