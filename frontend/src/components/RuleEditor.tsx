import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { CheckCircle2, Plus, X, XCircle } from "lucide-react";
import { rulesApi } from "../lib/api";
import type { RuleValidateResponse } from "../lib/types";
import { SegmentedControl, Spinner } from "./common";

type Mode = "form" | "yaml";

interface Condition {
  field: string;
  modifier: string;
  values: string;
}

const FIELDS = [
  "CommandLine",
  "Image",
  "ParentImage",
  "ParentCommandLine",
  "OriginalFileName",
  "TargetFilename",
  "TargetObject",
  "EventID",
  "User",
  "ServiceName",
  "DestinationIp",
  "DestinationHostname",
  "QueryName",
  "c-uri",
  "cs-user-agent",
];

const MODIFIERS = ["contains", "equals", "startswith", "endswith", "contains|all", "re", "cidr"];

const LOGSOURCES = [
  { label: "Windows process creation", value: "product: windows\n    category: process_creation" },
  { label: "Windows registry", value: "product: windows\n    category: registry_set" },
  { label: "Windows file event", value: "product: windows\n    category: file_event" },
  { label: "Windows (any)", value: "product: windows" },
  { label: "Linux (any)", value: "product: linux" },
  { label: "Web server logs", value: "category: webserver" },
  { label: "Network connection", value: "category: network_connection" },
];

const LEVELS = ["informational", "low", "medium", "high", "critical"];

function quote(value: string): string {
  // Single-quoted YAML performs no escape processing, so a backslash in a Windows
  // path stays a single backslash. Only the quote character itself needs doubling.
  return `'${value.replace(/'/g, "''")}'`;
}

function uuid(): string {
  return crypto.randomUUID();
}

function buildYaml(draft: {
  title: string;
  description: string;
  level: string;
  logsource: string;
  technique: string;
  conditions: Condition[];
  id: string;
}): string {
  const lines = [
    `title: ${quote(draft.title || "Untitled rule")}`,
    `id: ${draft.id}`,
    "status: experimental",
  ];
  if (draft.description.trim()) lines.push(`description: ${quote(draft.description.trim())}`);
  lines.push("logsource:", `    ${draft.logsource}`);
  lines.push("detection:", "    selection:");

  for (const condition of draft.conditions) {
    const values = condition.values
      .split("\n")
      .map((value) => value.trim())
      .filter(Boolean);
    if (!values.length) continue;
    const key =
      condition.modifier === "equals" ? condition.field : `${condition.field}|${condition.modifier}`;
    if (values.length === 1) {
      lines.push(`        ${key}: ${quote(values[0])}`);
    } else {
      lines.push(`        ${key}:`);
      values.forEach((value) => lines.push(`            - ${quote(value)}`));
    }
  }
  lines.push("    condition: selection");
  if (draft.technique.trim()) {
    lines.push("tags:", `    - attack.${draft.technique.trim().toLowerCase()}`);
  }
  lines.push(`level: ${draft.level}`);
  return lines.join("\n") + "\n";
}

export function RuleEditor({
  ruleId,
  onClose,
  onSaved,
}: {
  ruleId: string | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const editing = Boolean(ruleId);
  const existing = useQuery({
    queryKey: ["rule", ruleId],
    queryFn: () => rulesApi.get(ruleId as string),
    enabled: editing,
  });

  const [mode, setMode] = useState<Mode>("form");
  const [yaml, setYaml] = useState("");
  const [touchedYaml, setTouchedYaml] = useState(false);
  const [validation, setValidation] = useState<RuleValidateResponse | null>(null);
  const [draft, setDraft] = useState({
    title: "",
    description: "",
    level: "medium",
    logsource: LOGSOURCES[0].value,
    technique: "",
    id: uuid(),
    conditions: [{ field: "CommandLine", modifier: "contains", values: "" }] as Condition[],
  });

  // An existing rule opens as YAML: it may use constructs the form cannot express,
  // and silently dropping them on a round-trip would be worse than not offering the
  // form at all.
  useEffect(() => {
    if (existing.data) {
      setYaml(existing.data.yaml_source);
      setMode("yaml");
      setTouchedYaml(true);
    }
  }, [existing.data]);

  const generated = useMemo(() => buildYaml(draft), [draft]);
  const source = mode === "yaml" || touchedYaml ? yaml : generated;

  useEffect(() => {
    if (mode === "form" && !touchedYaml) setYaml(generated);
  }, [generated, mode, touchedYaml]);

  const validate = useMutation({
    mutationFn: () => rulesApi.validate(source),
    onSuccess: setValidation,
  });

  const save = useMutation({
    mutationFn: () =>
      editing
        ? rulesApi.updateCustom(ruleId as string, { yaml_source: source })
        : rulesApi.createCustom(source, true),
    onSuccess: onSaved,
  });

  const setCondition = (index: number, patch: Partial<Condition>) =>
    setDraft((current) => ({
      ...current,
      conditions: current.conditions.map((item, position) =>
        position === index ? { ...item, ...patch } : item,
      ),
    }));

  return (
    <div className="modal-backdrop fixed inset-0 z-50 grid place-items-center p-4">
      <div className="modal-panel flex max-h-[92vh] w-full max-w-3xl flex-col rounded-2xl p-6">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-ink-50">
            {editing ? "Edit Sigma rule" : "New Sigma rule"}
          </h2>
          <button className="text-ink-400" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        {editing && existing.isLoading ? (
          <Spinner label="Loading rule…" />
        ) : (
          <>
            <SegmentedControl<Mode>
              className="mb-4 self-start"
              value={mode}
              onChange={setMode}
              options={[
                { value: "form", label: "Form" },
                { value: "yaml", label: "YAML" },
              ]}
            />

            <div className="min-h-0 flex-1 overflow-y-auto pr-1">
              {mode === "form" ? (
                touchedYaml ? (
                  <div className="rounded-xl border border-amber-400/25 bg-amber-400/10 p-4 text-sm text-amber-200">
                    <div className="font-semibold">Editing as YAML</div>
                    <p className="mt-1 text-xs">
                      This rule has been edited directly, or uses Sigma features the form does
                      not cover — several selections, keyword searches, <code>1 of</code>{" "}
                      conditions, or negation. Switch to the YAML tab to continue. Nothing is
                      dropped by staying in YAML.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div>
                        <label className="label">Title</label>
                        <input
                          className="input"
                          autoFocus
                          value={draft.title}
                          onChange={(event) =>
                            setDraft({ ...draft, title: event.target.value })
                          }
                          placeholder="e.g. Certutil remote download"
                        />
                      </div>
                      <div>
                        <label className="label">Severity</label>
                        <select
                          className="input"
                          value={draft.level}
                          onChange={(event) => setDraft({ ...draft, level: event.target.value })}
                        >
                          {LEVELS.map((level) => (
                            <option key={level} value={level}>
                              {level}
                            </option>
                          ))}
                        </select>
                      </div>
                    </div>

                    <div>
                      <label className="label">Description</label>
                      <textarea
                        className="input min-h-16"
                        value={draft.description}
                        onChange={(event) =>
                          setDraft({ ...draft, description: event.target.value })
                        }
                        placeholder="What this rule detects, and what a true positive looks like"
                      />
                    </div>

                    <div className="grid gap-4 sm:grid-cols-2">
                      <div>
                        <label className="label">Log source</label>
                        <select
                          className="input"
                          value={draft.logsource}
                          onChange={(event) =>
                            setDraft({ ...draft, logsource: event.target.value })
                          }
                        >
                          {LOGSOURCES.map((item) => (
                            <option key={item.label} value={item.value}>
                              {item.label}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="label">ATT&CK technique (optional)</label>
                        <input
                          className="input"
                          value={draft.technique}
                          onChange={(event) =>
                            setDraft({ ...draft, technique: event.target.value })
                          }
                          placeholder="T1105"
                        />
                      </div>
                    </div>

                    <div>
                      <div className="mb-2 flex items-center justify-between">
                        <label className="label mb-0">Match conditions (all must hold)</label>
                        <button
                          className="btn-ghost text-xs"
                          onClick={() =>
                            setDraft({
                              ...draft,
                              conditions: [
                                ...draft.conditions,
                                { field: "CommandLine", modifier: "contains", values: "" },
                              ],
                            })
                          }
                        >
                          <Plus size={13} /> Add condition
                        </button>
                      </div>
                      <div className="space-y-3">
                        {draft.conditions.map((condition, index) => (
                          <div key={index} className="rounded-xl bg-[rgb(var(--panel-strong)/0.5)] p-3">
                            <div className="flex flex-wrap gap-2">
                              <select
                                className="input flex-1"
                                value={condition.field}
                                onChange={(event) =>
                                  setCondition(index, { field: event.target.value })
                                }
                              >
                                {FIELDS.map((field) => (
                                  <option key={field} value={field}>
                                    {field}
                                  </option>
                                ))}
                              </select>
                              <select
                                className="input flex-1"
                                value={condition.modifier}
                                onChange={(event) =>
                                  setCondition(index, { modifier: event.target.value })
                                }
                              >
                                {MODIFIERS.map((modifier) => (
                                  <option key={modifier} value={modifier}>
                                    {modifier}
                                  </option>
                                ))}
                              </select>
                              {draft.conditions.length > 1 && (
                                <button
                                  className="btn-ghost text-sev-critical"
                                  onClick={() =>
                                    setDraft({
                                      ...draft,
                                      conditions: draft.conditions.filter((_, p) => p !== index),
                                    })
                                  }
                                >
                                  <X size={14} />
                                </button>
                              )}
                            </div>
                            <textarea
                              className="input mt-2 min-h-16 font-mono text-xs"
                              spellCheck={false}
                              value={condition.values}
                              onChange={(event) =>
                                setCondition(index, { values: event.target.value })
                              }
                              placeholder="One value per line; any of them matches"
                            />
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )
              ) : (
                <textarea
                  className="input min-h-[420px] w-full font-mono text-xs"
                  spellCheck={false}
                  wrap="off"
                  value={yaml}
                  onChange={(event) => {
                    setYaml(event.target.value);
                    setTouchedYaml(true);
                  }}
                />
              )}

              {validation && (
                <div className="mt-4 space-y-2 text-xs">
                  {validation.ok ? (
                    <div className="flex items-start gap-2 rounded-xl border border-emerald-400/25 bg-emerald-400/10 p-3 text-emerald-300">
                      <CheckCircle2 size={15} className="mt-0.5 shrink-0" />
                      <div>
                        <div className="font-semibold">
                          Valid — {validation.title} ({validation.severity})
                        </div>
                        <div className="mt-1 opacity-90">
                          Log source {validation.logsource || "any"}.{" "}
                          {validation.gated
                            ? `Pre-filtered on ${validation.literals.length} literal(s), so it costs
                               almost nothing when it cannot match.`
                            : "No literal pre-filter could be derived, so it runs on every event."}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-start gap-2 rounded-xl border border-sev-critical/30 bg-sev-critical/10 p-3 text-sev-critical">
                      <XCircle size={15} className="mt-0.5 shrink-0" />
                      <div className="whitespace-pre-wrap break-words">{validation.error}</div>
                    </div>
                  )}
                  {validation.warnings.map((warning) => (
                    <div
                      key={warning}
                      className="rounded-xl border border-amber-400/25 bg-amber-400/10 p-3 text-amber-200"
                    >
                      {warning}
                    </div>
                  ))}
                </div>
              )}

              {save.error && (
                <div className="mt-3 whitespace-pre-wrap text-sm text-sev-critical">
                  {String(save.error)}
                </div>
              )}
            </div>

            <div className="mt-4 flex flex-wrap justify-end gap-2 border-t border-white/5 pt-4">
              <button className="btn-ghost" onClick={onClose}>
                Cancel
              </button>
              <button
                className="btn-ghost"
                disabled={validate.isPending || !source.trim()}
                onClick={() => validate.mutate()}
              >
                {validate.isPending ? "Checking…" : "Validate"}
              </button>
              <button
                className="btn-primary"
                disabled={save.isPending || !source.trim()}
                onClick={() => save.mutate()}
              >
                {save.isPending ? "Saving…" : editing ? "Save changes" : "Create rule"}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
