import { useEffect, useState } from "react";
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
} from "lucide-react";
import { api } from "../lib/api";
import type { LLMConfig, ModelInfo, Provider } from "../lib/types";
import { Section } from "../components/common";

const PROVIDERS: { id: Provider; name: string; icon: React.ReactNode; local: boolean }[] = [
  { id: "ollama", name: "Ollama (Local)", icon: <Server size={18} />, local: true },
  { id: "openai", name: "OpenAI (ChatGPT)", icon: <Cloud size={18} />, local: false },
  { id: "anthropic", name: "Anthropic (Claude)", icon: <Cloud size={18} />, local: false },
  { id: "gemini", name: "Google (Gemini)", icon: <Cloud size={18} />, local: false },
];

export default function SettingsPage() {
  const [provider, setProvider] = useState<Provider>("ollama");
  const [model, setModel] = useState("");
  const [ollamaUrl, setOllamaUrl] = useState("http://localhost:11434");
  const [temperature, setTemperature] = useState(0.2);
  const [maxTokens, setMaxTokens] = useState(4096);
  const [apiKey, setApiKey] = useState("");
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [hasKey, setHasKey] = useState(false);
  const [loadingModels, setLoadingModels] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [saved, setSaved] = useState(false);
  const [yaraDir, setYaraDir] = useState("");

  const { data: health } = useQuery({ queryKey: ["health"], queryFn: api.health });
  const { data: general } = useQuery({
    queryKey: ["general-settings"],
    queryFn: api.getGeneralSettings,
  });

  useEffect(() => {
    api.getLLMConfig().then((cfg: LLMConfig) => {
      setProvider(cfg.provider);
      setModel(cfg.model);
      setOllamaUrl(cfg.ollama_base_url);
      setTemperature(cfg.temperature);
      setMaxTokens(cfg.max_tokens);
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
      // save key first if provided so the test can use it
      if (apiKey) {
        await api.updateLLMConfig({ provider, api_key: apiKey });
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
      temperature,
      max_tokens: maxTokens,
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
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold text-ink-50">Settings</h1>
        <p className="text-sm text-ink-400 mt-1">
          Configure the AI backend. Everything runs locally; API keys are stored in your OS
          credential vault.
        </p>
      </div>

      <Section title="AI Provider">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-5">
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
