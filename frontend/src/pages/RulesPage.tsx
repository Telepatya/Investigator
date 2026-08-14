import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Download,
  FileCode2,
  GitFork,
  Plus,
  ScrollText,
  Trash2,
  Upload,
} from "lucide-react";
import { clsx } from "clsx";
import { rulesApi, rulesExportUrl } from "../lib/api";
import type { RuleDetail, RuleListResponse, RuleSummary } from "../lib/types";
import {
  ConfirmDialog,
  DetailDrawer,
  EmptyState,
  PageShell,
  PageTitle,
  SegmentedControl,
  SeverityBadge,
  Spinner,
} from "../components/common";
import { RuleEditor } from "../components/RuleEditor";

type SourceFilter = "all" | "builtin" | "custom";

const PAGE_SIZE = 50;
const PLATFORMS = ["windows", "linux", "web", "any"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export default function RulesPage() {
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  const [platform, setPlatform] = useState("");
  const [severity, setSeverity] = useState("");
  const [onlyDisabled, setOnlyDisabled] = useState(false);
  const [visible, setVisible] = useState(PAGE_SIZE);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<RuleSummary | null>(null);

  // The catalog is a few hundred rows and changes only when the analyst edits it,
  // so it is fetched once and filtered in the browser. That keeps typing in the
  // search box instant and avoids a request per keystroke.
  const rules = useQuery({
    queryKey: ["rules"],
    queryFn: () => rulesApi.list(),
    staleTime: 60_000,
  });

  const toggle = useMutation({
    mutationFn: (rule: RuleSummary) =>
      rule.source === "builtin"
        ? rulesApi.updateBuiltin(rule.id, { enabled: !rule.enabled })
        : rulesApi.updateCustom(rule.id, { enabled: !rule.enabled }),
    onMutate: async (rule) => {
      await qc.cancelQueries({ queryKey: ["rules"] });
      const previous = qc.getQueryData<RuleListResponse>(["rules"]);
      qc.setQueryData<RuleListResponse>(["rules"], (current) =>
        current
          ? {
              ...current,
              rules: current.rules.map((item) =>
                item.id === rule.id ? { ...item, enabled: !item.enabled } : item,
              ),
            }
          : current,
      );
      return { previous };
    },
    onError: (_error, _rule, context) => {
      if (context?.previous) qc.setQueryData(["rules"], context.previous);
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });

  const remove = useMutation({
    mutationFn: (rule: RuleSummary) => rulesApi.deleteCustom(rule.id),
    onSuccess: () => {
      setPendingDelete(null);
      setSelectedId(null);
      qc.invalidateQueries({ queryKey: ["rules"] });
    },
  });

  const filtered = useMemo(() => {
    const all = rules.data?.rules ?? [];
    const needle = search.trim().toLowerCase();
    return all.filter((rule) => {
      if (sourceFilter !== "all" && rule.source !== sourceFilter) return false;
      if (platform && rule.platform !== platform) return false;
      if (severity && rule.severity !== severity) return false;
      if (onlyDisabled && rule.enabled) return false;
      if (!needle) return true;
      return (
        rule.title.toLowerCase().includes(needle) ||
        rule.id.toLowerCase().includes(needle) ||
        rule.techniques.some((technique) => technique.toLowerCase().includes(needle))
      );
    });
  }, [rules.data, search, sourceFilter, platform, severity, onlyDisabled]);

  const shown = filtered.slice(0, visible);
  const summary = rules.data;

  return (
    <PageShell>
      <PageTitle
        icon={<ScrollText size={22} />}
        title="Detection rules"
        subtitle="Every rule the detection engine runs. Changes apply to new analyses; rebuild a case's detections to apply them to existing findings."
        right={
          <div className="flex flex-wrap gap-2">
            <a className="btn-ghost" href={rulesExportUrl()} title="Download custom rules as Sigma">
              <Download size={15} /> Export
            </a>
            <button className="btn-ghost" onClick={() => setImportOpen(true)}>
              <Upload size={15} /> Import
            </button>
            <button
              className="btn-primary"
              onClick={() => {
                setSelectedId(null);
                setEditorOpen(true);
              }}
            >
              <Plus size={16} /> New rule
            </button>
          </div>
        }
      />

      {summary && summary.ungated_total > 0 && (
        <div className="card flex items-start gap-3 border-amber-400/30 bg-amber-400/10 p-4 text-sm text-amber-300">
          <AlertTriangle size={18} className="mt-0.5 shrink-0" />
          <div>
            <div className="font-semibold">
              {summary.ungated_total} of {summary.ungated_limit} un-gated rule slots in use
            </div>
            <div className="mt-1 text-xs">
              These rules have no literal a cheap pre-check can look for, so they are
              evaluated against every process and event. Narrowing them keeps analysis fast.
            </div>
          </div>
        </div>
      )}

      <div className="card space-y-3 p-4">
        <div className="flex flex-wrap items-center gap-3">
          <input
            className="input max-w-sm flex-1"
            placeholder="Search rules by name, id, or ATT&CK technique…"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setVisible(PAGE_SIZE);
            }}
          />
          <SegmentedControl<SourceFilter>
            value={sourceFilter}
            onChange={(value) => {
              setSourceFilter(value);
              setVisible(PAGE_SIZE);
            }}
            options={[
              { value: "all", label: "All" },
              { value: "builtin", label: "Built-in" },
              { value: "custom", label: "Custom" },
            ]}
          />
          <label className="flex cursor-pointer items-center gap-2 text-xs text-ink-300">
            <input
              type="checkbox"
              checked={onlyDisabled}
              onChange={(event) => setOnlyDisabled(event.target.checked)}
            />
            Only disabled
          </label>
        </div>

        <div className="flex flex-wrap gap-1.5">
          <FilterChip label="Any platform" active={!platform} onClick={() => setPlatform("")} />
          {PLATFORMS.map((item) => (
            <FilterChip
              key={item}
              label={item}
              active={platform === item}
              onClick={() => setPlatform(platform === item ? "" : item)}
            />
          ))}
          <span className="mx-1 w-px bg-white/10" />
          <FilterChip label="Any severity" active={!severity} onClick={() => setSeverity("")} />
          {SEVERITIES.map((item) => (
            <FilterChip
              key={item}
              label={item}
              active={severity === item}
              onClick={() => setSeverity(severity === item ? "" : item)}
            />
          ))}
        </div>

        {summary && (
          <div className="text-xs text-ink-400">
            Showing {shown.length} of {filtered.length} matching · {summary.builtin_total} built-in,{" "}
            {summary.custom_total} custom, {summary.disabled_total} disabled
          </div>
        )}
      </div>

      {rules.isLoading ? (
        <Spinner label="Loading detection rules…" />
      ) : !filtered.length ? (
        <EmptyState
          icon={<ScrollText size={40} />}
          title="No rules match these filters"
          hint="Clear the search box or reset the platform and severity filters."
        />
      ) : (
        <>
          <div className="card overflow-hidden p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/5 text-left text-[11px] uppercase tracking-wider text-ink-400">
                  <th className="w-14 px-4 py-3">On</th>
                  <th className="px-4 py-3">Rule</th>
                  <th className="hidden px-4 py-3 md:table-cell">Type</th>
                  <th className="hidden px-4 py-3 lg:table-cell">Platform</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="hidden px-4 py-3 lg:table-cell">ATT&CK</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((rule) => (
                  <tr
                    key={rule.id}
                    className="cursor-pointer border-b border-white/5 last:border-0 hover:bg-white/[0.02]"
                    onClick={() => setSelectedId(rule.id)}
                  >
                    <td className="px-4 py-3" onClick={(event) => event.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        disabled={toggle.isPending}
                        onChange={() => toggle.mutate(rule)}
                        title={rule.enabled ? "Disable this rule" : "Enable this rule"}
                      />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={clsx(
                            "font-semibold",
                            rule.enabled ? "text-ink-100" : "text-ink-500 line-through",
                          )}
                        >
                          {rule.title}
                        </span>
                        {rule.source === "custom" && (
                          <span className="chip bg-accent-violet/10 text-accent-violet">Sigma</span>
                        )}
                        {rule.is_family && (
                          <span className="chip bg-accent-blue/10 text-accent-blue">group</span>
                        )}
                        {!rule.gated && (
                          <span className="chip bg-amber-400/10 text-amber-300" title="No literal pre-check could be derived; evaluated on every event">
                            un-gated
                          </span>
                        )}
                        {rule.compile_status !== "ok" && (
                          <span className="chip bg-sev-critical/10 text-sev-critical">error</span>
                        )}
                      </div>
                      <div className="mt-0.5 truncate font-mono text-[10px] text-ink-500">{rule.id}</div>
                    </td>
                    <td className="hidden px-4 py-3 text-xs text-ink-400 md:table-cell">{rule.kind}</td>
                    <td className="hidden px-4 py-3 text-xs text-ink-400 lg:table-cell">{rule.platform}</td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td className="hidden px-4 py-3 lg:table-cell">
                      <div className="flex flex-wrap gap-1">
                        {rule.techniques.slice(0, 2).map((technique) => (
                          <span key={technique} className="chip bg-accent-blue/10 text-accent-blue">
                            {technique}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {visible < filtered.length && (
            <button className="btn-ghost mx-auto" onClick={() => setVisible((count) => count + PAGE_SIZE)}>
              Load {Math.min(PAGE_SIZE, filtered.length - visible)} more
            </button>
          )}
        </>
      )}

      {selectedId && (
        <RuleDetailDrawer
          ruleId={selectedId}
          onClose={() => setSelectedId(null)}
          onEdit={() => setEditorOpen(true)}
          onDelete={(rule) => setPendingDelete(rule)}
        />
      )}

      {editorOpen && (
        <RuleEditor
          ruleId={selectedId && selectedId.includes("-") && selectedId.length === 36 ? selectedId : null}
          onClose={() => setEditorOpen(false)}
          onSaved={() => {
            setEditorOpen(false);
            qc.invalidateQueries({ queryKey: ["rules"] });
          }}
        />
      )}

      {importOpen && (
        <ImportDialog
          onClose={() => setImportOpen(false)}
          onDone={() => qc.invalidateQueries({ queryKey: ["rules"] })}
        />
      )}

      {pendingDelete && (
        <ConfirmDialog
          title="Delete this rule?"
          danger
          busy={remove.isPending}
          confirmLabel="Delete rule"
          message={
            <>
              <strong>{pendingDelete.title}</strong> will be removed. Findings it already
              produced stay until the affected cases are rebuilt.
            </>
          }
          onConfirm={() => remove.mutate(pendingDelete)}
          onClose={() => setPendingDelete(null)}
        />
      )}
    </PageShell>
  );
}

function FilterChip({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      className={clsx(
        "chip capitalize transition",
        active ? "bg-accent-blue/15 text-accent-blue" : "bg-white/5 text-ink-400 hover:text-ink-200",
      )}
      onClick={onClick}
    >
      {label}
    </button>
  );
}

function RuleDetailDrawer({
  ruleId,
  onClose,
  onEdit,
  onDelete,
}: {
  ruleId: string;
  onClose: () => void;
  onEdit: () => void;
  onDelete: (rule: RuleSummary) => void;
}) {
  const qc = useQueryClient();
  const [forkOpen, setForkOpen] = useState(false);
  const detail = useQuery({ queryKey: ["rule", ruleId], queryFn: () => rulesApi.get(ruleId) });

  const severity = useMutation({
    mutationFn: (value: string) =>
      rulesApi.updateBuiltin(ruleId, value ? { severity_override: value } : { clear_severity: true }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rules"] });
      qc.invalidateQueries({ queryKey: ["rule", ruleId] });
    },
  });

  const fork = useMutation({
    mutationFn: (disableBuiltin: boolean) => rulesApi.fork(ruleId, disableBuiltin),
    onSuccess: () => {
      setForkOpen(false);
      qc.invalidateQueries({ queryKey: ["rules"] });
      onClose();
    },
  });

  const rule = detail.data as RuleDetail | undefined;

  return (
    <DetailDrawer eyebrow="Detection rule" title={rule?.title ?? "Loading…"} onClose={onClose} ariaLabel="Rule detail">
      {detail.isLoading || !rule ? (
        <Spinner label="Loading rule…" />
      ) : (
        <div className="space-y-4 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={rule.severity} />
            <span className="chip bg-white/5 text-ink-300">{rule.kind}</span>
            <span className="chip bg-white/5 text-ink-300">{rule.platform}</span>
            {rule.techniques.map((technique) => (
              <span key={technique} className="chip bg-accent-blue/10 text-accent-blue">
                {technique}
              </span>
            ))}
          </div>

          <div>
            <div className="label">Rule id</div>
            <div className="break-all font-mono text-xs text-ink-100">{rule.id}</div>
          </div>

          {rule.description && <p className="text-ink-300">{rule.description}</p>}

          {rule.compile_error && (
            <div className="rounded-xl border border-sev-critical/30 bg-sev-critical/10 p-3 text-xs text-sev-critical">
              {rule.compile_error}
            </div>
          )}

          {rule.warnings.map((warning) => (
            <div
              key={warning}
              className="rounded-xl border border-amber-400/25 bg-amber-400/10 p-3 text-xs text-amber-200"
            >
              {warning}
            </div>
          ))}

          {rule.source === "builtin" && rule.editable.includes("severity") && (
            <div>
              <label className="label">Severity</label>
              <select
                className="input"
                value={rule.severity_override ?? ""}
                disabled={severity.isPending}
                onChange={(event) => severity.mutate(event.target.value)}
              >
                <option value="">Default ({rule.severity})</option>
                {SEVERITIES.map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div>
            <div className="label">Logic</div>
            <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-[rgb(var(--panel-strong)/0.6)] p-3 font-mono text-[11px] text-ink-200">
              {rule.source === "custom" ? rule.yaml_source : rule.logic}
            </pre>
            {rule.source === "builtin" && (
              <p className="mt-2 text-xs text-ink-400">
                This rule is implemented in the detection engine. Its name and logic are fixed —
                existing cases identify it by its title, so renaming it would orphan the
                suppressions analysts have already set. Enable state and severity are editable
                here; to change the logic, fork it to a Sigma rule.
              </p>
            )}
          </div>

          {rule.legacy_rule_ids.length > 0 && (
            <div>
              <div className="label">Per-case suppression id</div>
              <div className="font-mono text-[11px] text-ink-400">
                {rule.legacy_rule_ids.join(", ")}
              </div>
            </div>
          )}

          <div className="flex flex-wrap gap-2 border-t border-white/5 pt-4">
            {rule.source === "custom" && (
              <>
                <button className="btn-primary" onClick={onEdit}>
                  <FileCode2 size={15} /> Edit
                </button>
                <button className="btn-ghost text-sev-critical" onClick={() => onDelete(rule)}>
                  <Trash2 size={15} /> Delete
                </button>
              </>
            )}
            {rule.source === "builtin" && rule.forkable && (
              <button className="btn-primary" onClick={() => setForkOpen(true)}>
                <GitFork size={15} /> Fork to Sigma
              </button>
            )}
            {rule.source === "builtin" && !rule.forkable && (
              <p className="text-xs text-ink-400">
                This detection is stateful — it correlates several signals or crosses a
                threshold — so it has no single-event Sigma equivalent and cannot be forked.
              </p>
            )}
          </div>

          {forkOpen && (
            <ConfirmDialog
              title="Fork this rule to Sigma?"
              confirmLabel={fork.isPending ? "Forking…" : "Create fork"}
              busy={fork.isPending}
              message={
                <>
                  A new Sigma rule approximating <strong>{rule.title}</strong> will be created,
                  disabled, so you can review it before turning it on. The built-in rule is
                  switched off at the same time. The fork is an approximation: the built-in uses
                  Python matching that Sigma cannot always express exactly, so check the
                  generated rule before relying on it.
                </>
              }
              onConfirm={() => fork.mutate(true)}
              onClose={() => setForkOpen(false)}
            />
          )}
          {fork.error && <div className="text-sm text-sev-critical">{String(fork.error)}</div>}
        </div>
      )}
    </DetailDrawer>
  );
}

function ImportDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [text, setText] = useState("");
  const importer = useMutation({
    mutationFn: () => rulesApi.import(text),
    onSuccess: onDone,
  });
  const result = importer.data;

  return (
    <div className="modal-backdrop fixed inset-0 z-50 grid place-items-center p-4">
      <div className="modal-panel w-full max-w-2xl rounded-2xl p-6">
        <h2 className="mb-1 text-lg font-semibold text-ink-50">Import Sigma rules</h2>
        <p className="mb-4 text-xs text-ink-400">
          Paste one or more Sigma rules separated by <code>---</code>. Rules are imported
          disabled so you can review them first, and each is reported on its own — one bad rule
          never blocks the rest.
        </p>
        <textarea
          className="input min-h-64 font-mono text-xs"
          spellCheck={false}
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder="title: ...&#10;logsource: ...&#10;detection: ..."
        />
        {result && (
          <div className="mt-3 space-y-2 text-xs">
            <div className="text-emerald-400">Imported {result.imported.length} rule(s).</div>
            {result.rejected.map((item) => (
              <div key={item.index} className="text-sev-critical">
                Rule #{item.index + 1}: {item.error}
              </div>
            ))}
          </div>
        )}
        {importer.error && (
          <div className="mt-3 text-sm text-sev-critical">{String(importer.error)}</div>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button className="btn-ghost" onClick={onClose}>
            Close
          </button>
          <button
            className="btn-primary"
            disabled={!text.trim() || importer.isPending}
            onClick={() => importer.mutate()}
          >
            {importer.isPending ? "Importing…" : "Import"}
          </button>
        </div>
      </div>
    </div>
  );
}
