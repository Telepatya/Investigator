import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { clsx } from "clsx";
import { Check, Flag } from "lucide-react";
import { api } from "../lib/api";
import { severityChip } from "../lib/ui";
import type { Severity } from "../lib/types";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

/**
 * Compact control to raise an analyst-created ("manual") finding from an event
 * or an entity. Pick a severity, optionally add a note, and it POSTs a finding
 * tagged manual that shows up in the Findings view and the case counts.
 */
export function FlagAsFinding({
  caseId,
  refType,
  refId,
  refLabel,
  defaultTitle,
  defaultSeverity = "medium",
}: {
  caseId: string;
  refType: "event" | "entity";
  refId: string;
  refLabel: string;
  defaultTitle: string;
  defaultSeverity?: Severity;
}) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [severity, setSeverity] = useState<Severity>(defaultSeverity);
  const [note, setNote] = useState("");

  const mut = useMutation({
    mutationFn: () =>
      api.createManualFinding(caseId, {
        title: defaultTitle,
        severity,
        description: note.trim() || `Manually flagged ${refType}: ${refLabel}`,
        ref_type: refType,
        ref_id: refId,
        ref_label: refLabel,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings", caseId] });
      qc.invalidateQueries({ queryKey: ["case", caseId] });
      qc.invalidateQueries({ queryKey: ["entities", caseId] });
      qc.invalidateQueries({ queryKey: ["entity-dossier", caseId] });
      setOpen(false);
    },
  });

  if (mut.isSuccess) {
    return (
      <div className="flex items-center gap-2 text-xs font-semibold text-emerald-500">
        <Check size={14} /> Flagged as finding — see the Findings tab
      </div>
    );
  }

  if (!open) {
    return (
      <button className="btn-ghost w-full justify-center text-xs" onClick={() => setOpen(true)}>
        <Flag size={14} /> Flag as finding
      </button>
    );
  }

  return (
    <div className="card space-y-3 p-3">
      <div className="text-xs font-semibold text-ink-200">Raise a manual finding</div>
      <div className="flex flex-wrap gap-1.5">
        {SEVERITIES.map((s) => (
          <button
            key={s}
            onClick={() => setSeverity(s)}
            className={clsx(
              "chip capitalize transition",
              severityChip(s),
              severity === s ? "ring-2 ring-accent-blue/60" : "opacity-60 hover:opacity-100",
            )}
          >
            {s}
          </button>
        ))}
      </div>
      <input
        className="input text-xs"
        placeholder="Optional note (why this matters)…"
        value={note}
        onChange={(e) => setNote(e.target.value)}
      />
      {mut.isError && (
        <div className="text-xs text-sev-critical">Could not create finding. Try again.</div>
      )}
      <div className="flex justify-end gap-2">
        <button className="btn-ghost text-xs" onClick={() => setOpen(false)} disabled={mut.isPending}>
          Cancel
        </button>
        <button className="btn-primary text-xs" onClick={() => mut.mutate()} disabled={mut.isPending}>
          {mut.isPending ? "Flagging…" : "Create finding"}
        </button>
      </div>
    </div>
  );
}
