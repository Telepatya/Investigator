import { useState, type ReactNode } from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { EmptyState, PageShell, PageTitle, Spinner, SeverityBadge, CodeBlock } from "../components/common";
import {
  ChevronDown,
  ChevronRight,
  Sparkles,
  Shield,
  EyeOff,
  Eye,
  Ban,
  Flag,
  RotateCcw,
  Trash2,
} from "lucide-react";
import type { Finding, Severity } from "../lib/types";
import { SEVERITY_ORDER } from "../lib/ui";

type BenignFn = (findingId: number, benign: boolean) => void;
type RuleFn = (ruleId: string, disabled: boolean) => void;
type DeleteManualFn = (manualId: string) => void;

export default function FindingsPage() {
  const { caseId } = useParams();
  const qc = useQueryClient();
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");
  const [showSuppressed, setShowSuppressed] = useState(false);
  const { data, isLoading } = useQuery({
    queryKey: ["findings", caseId],
    queryFn: () => api.getFindings(caseId!),
  });
  const invalidateCaseViews = () => {
    for (const key of [
      "findings",
      "entities",
      "entity-dossier",
      "attack-matrix",
      "timeline",
      "events",
      "categories",
    ]) {
      qc.invalidateQueries({ queryKey: [key, caseId] });
    }
  };

  const benignMut = useMutation({
    mutationFn: ({ id, benign }: { id: number; benign: boolean }) =>
      api.setFindingBenign(caseId!, id, benign),
    onSuccess: invalidateCaseViews,
  });
  const ruleMut = useMutation({
    mutationFn: ({ ruleId, disabled }: { ruleId: string; disabled: boolean }) =>
      api.setRuleDisabled(caseId!, ruleId, disabled),
    onSuccess: invalidateCaseViews,
  });
  const deleteManualMut = useMutation({
    mutationFn: (manualId: string) => api.deleteManualFinding(caseId!, manualId),
    onSuccess: () => {
      invalidateCaseViews();
      qc.invalidateQueries({ queryKey: ["case", caseId] });
    },
  });
  const setBenign: BenignFn = (id, benign) => benignMut.mutate({ id, benign });
  const setRule: RuleFn = (ruleId, disabled) => ruleMut.mutate({ ruleId, disabled });
  const deleteManual: DeleteManualFn = (manualId) => deleteManualMut.mutate(manualId);

  if (isLoading) return <Spinner label="Loading findings…" />;
  const findings = data?.findings ?? [];
  const disabledRules = data?.disabled_rules ?? [];
  if (findings.length === 0)
    return (
      <EmptyState
        icon={<Shield size={40} />}
        title="No findings yet"
        hint="The detection engine runs automatically after ingestion. Upload evidence to surface suspicious activity mapped to MITRE ATT&CK."
      />
    );

  // A representative title for each disabled rule id, for the management panel.
  const ruleTitles: Record<string, string> = {};
  for (const f of findings) if (f.rule_disabled) ruleTitles[f.rule_id] ??= f.title;

  const visible = findings.filter((f) => showSuppressed || !f.suppressed);
  const filtered =
    sevFilter === "all" ? visible : visible.filter((f) => f.severity === sevFilter);

  const counts: Record<string, number> = {};
  for (const f of visible) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  const suppressedCount = findings.filter((f) => f.suppressed).length;

  return (
    <PageShell>
      <PageTitle
        icon={<Shield size={22} />}
        title="Findings"
        subtitle="Detections, analyst overrides, AI verdicts, and mapped evidence."
      />
      {disabledRules.length > 0 && (
        <div className="card p-3">
          <div className="flex items-center gap-2 mb-2 text-xs font-semibold uppercase tracking-wider text-ink-400">
            <Ban size={13} /> Disabled rules ({disabledRules.length})
          </div>
          <div className="flex flex-wrap gap-2">
            {disabledRules.map((rid) => (
              <span
                key={rid}
                className="chip bg-white/5 text-ink-300 flex items-center gap-1.5"
              >
                <span className="font-mono">{ruleTitles[rid] ?? rid}</span>
                <button
                  className="text-accent-cyan hover:underline flex items-center gap-0.5"
                  onClick={() => setRule(rid, false)}
                  title="Re-enable this rule"
                >
                  <RotateCcw size={11} /> enable
                </button>
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="card p-3 flex items-center gap-2 flex-wrap">
        <button
          className={`chip ${sevFilter === "all" ? "bg-accent-cyan/15 text-accent-cyan" : "bg-white/5 text-ink-300"}`}
          onClick={() => setSevFilter("all")}
        >
          all ({visible.length})
        </button>
        {(["critical", "high", "medium", "low", "info"] as Severity[])
          .filter((s) => counts[s])
          .map((s) => (
            <button
              key={s}
              className={`chip ${sevFilter === s ? "bg-accent-cyan/15 text-accent-cyan" : "bg-white/5 text-ink-300"}`}
              onClick={() => setSevFilter(s)}
            >
              {s} ({counts[s]})
            </button>
          ))}
        {suppressedCount > 0 && (
          <button
            className={`chip ml-auto ${showSuppressed ? "bg-accent-violet/15 text-accent-violet" : "bg-white/5 text-ink-400"}`}
            onClick={() => setShowSuppressed((v) => !v)}
            title="Benign / disabled-rule findings are hidden by default"
          >
            {showSuppressed ? <Eye size={12} /> : <EyeOff size={12} />} suppressed ({suppressedCount})
          </button>
        )}
      </div>

      <div className="space-y-2">
        {filtered
          .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity])
          .map((f) => (
            <FindingRow key={f.id} f={f} setBenign={setBenign} setRule={setRule} deleteManual={deleteManual} />
          ))}
      </div>
    </PageShell>
  );
}

function FindingRow({
  f,
  setBenign,
  setRule,
  deleteManual,
}: {
  f: Finding;
  setBenign: BenignFn;
  setRule: RuleFn;
  deleteManual: DeleteManualFn;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`card overflow-hidden ${f.suppressed ? "opacity-60" : ""}`}>
      <div className="flex items-start">
        <button
          className="flex-1 min-w-0 flex items-start gap-3 p-4 text-left hover:bg-white/[0.02]"
          onClick={() => setOpen(!open)}
        >
          <div className="mt-0.5">
            {open ? (
              <ChevronDown size={16} className="text-ink-400" />
            ) : (
              <ChevronRight size={16} className="text-ink-400" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <SeverityBadge severity={f.severity} />
              {f.manual && (
                <span className="chip bg-accent-cyan/15 text-accent-cyan">
                  <Flag size={11} /> Manual
                </span>
              )}
              {f.suppressed && (
                <span className="chip bg-white/10 text-ink-400">{f.suppressed_reason}</span>
              )}
              {f.mitre_techniques.map((t) => (
                <span key={t} className="chip bg-accent-violet/10 text-accent-violet font-mono">
                  {t}
                </span>
              ))}
              <span className="text-[11px] text-ink-500 font-mono ml-auto">{f.source}</span>
            </div>
            <div
              className={`text-sm font-medium ${f.suppressed ? "text-ink-400 line-through" : "text-ink-50"}`}
            >
              {f.title}
            </div>
            {!open && (
              <div className="text-xs text-ink-400 mt-0.5 line-clamp-1">{f.description}</div>
            )}
          </div>
        </button>
        <div className="flex items-center gap-1 p-2 shrink-0">
          <IconBtn
            active={f.benign}
            onClick={() => setBenign(f.id, !f.benign)}
            title={f.benign ? "Restore (un-mark benign)" : "Mark benign (set to informational)"}
          >
            {f.benign ? <Eye size={15} /> : <EyeOff size={15} />}
          </IconBtn>
          {f.manual && f.manual_id ? (
            <IconBtn
              active={false}
              onClick={() => deleteManual(f.manual_id!)}
              title="Delete this manual finding"
            >
              <Trash2 size={15} />
            </IconBtn>
          ) : (
            <IconBtn
              active={f.rule_disabled}
              onClick={() => setRule(f.rule_id, !f.rule_disabled)}
              title={
                f.rule_disabled
                  ? `Enable rule "${f.rule_id}"`
                  : `Disable rule "${f.rule_id}" (all its findings become informational)`
              }
            >
              {f.rule_disabled ? <RotateCcw size={15} /> : <Ban size={15} />}
            </IconBtn>
          )}
        </div>
      </div>
      {open && (
        <div className="px-4 pb-4 pl-11 space-y-3">
          <div className="text-sm text-ink-200">{f.description}</div>
          {f.suppressed && (
            <div className="text-xs text-ink-400">
              This finding is suppressed ({f.suppressed_reason}); it is shown as informational and
              excluded from severity counts. Use the buttons above to restore it.
            </div>
          )}
          {f.ai_verdict && (
            <div className="bg-accent-violet/5 border border-accent-violet/20 rounded-lg p-3">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-accent-violet uppercase tracking-wider mb-1.5">
                <Sparkles size={12} /> AI verdict
              </div>
              <div className="text-sm text-ink-200 whitespace-pre-wrap">{f.ai_verdict}</div>
            </div>
          )}
          {f.evidence && Object.keys(f.evidence).length > 0 && (
            <div>
              <div className="label">Evidence</div>
              <CodeBlock>{JSON.stringify(f.evidence, null, 2)}</CodeBlock>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function IconBtn({
  active,
  onClick,
  title,
  children,
}: {
  active: boolean;
  onClick: () => void;
  title: string;
  children: ReactNode;
}) {
  return (
    <button
      className={`p-1.5 rounded-lg transition-colors ${
        active
          ? "bg-accent-cyan/15 text-accent-cyan"
          : "text-ink-500 hover:text-ink-200 hover:bg-white/5"
      }`}
      onClick={onClick}
      title={title}
    >
      {children}
    </button>
  );
}
