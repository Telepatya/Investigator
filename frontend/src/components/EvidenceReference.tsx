import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { CodeBlock, DetailDrawer, SeverityBadge, Spinner } from "./common";
import { fmtTime } from "../lib/ui";

type RefKind = "event" | "finding";

export function EvidenceReference({
  caseId,
  kind,
  id,
  label,
  suppressed = false,
}: {
  caseId: string;
  kind: RefKind;
  id: number;
  label?: string;
  suppressed?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const eventQuery = useQuery({
    queryKey: ["event-detail", caseId, id],
    queryFn: ({ signal }) => api.getEvent(caseId, id, signal),
    enabled: open && kind === "event",
  });
  const findingQuery = useQuery({
    queryKey: ["finding-detail", caseId, id],
    queryFn: ({ signal }) => api.getFinding(caseId, id, signal),
    enabled: open && kind === "finding",
  });
  const loading = kind === "event" ? eventQuery.isLoading : findingQuery.isLoading;
  const error = kind === "event" ? eventQuery.error : findingQuery.error;
  const title = kind === "event"
    ? eventQuery.data?.category
    : findingQuery.data?.title;

  return (
    <>
      <button
        type="button"
        className={`chip max-w-full bg-accent-cyan/10 text-accent-cyan hover:bg-accent-cyan/20 ${
          suppressed ? "line-through opacity-60" : ""
        }`}
        title={label}
        onClick={() => setOpen(true)}
      >
        {kind === "event" ? `Event #${id}` : `Finding #${id}`}
        {label && <span className="max-w-48 truncate">{label}</span>}
      </button>
      {open && (
        <DetailDrawer
          eyebrow={`${kind} evidence`}
          title={title ?? `${kind} #${id}`}
          onClose={() => setOpen(false)}
          ariaLabel={`${kind} evidence detail`}
        >
          {loading ? (
            <Spinner label={`Loading ${kind}…`} />
          ) : error || (kind === "event" ? !eventQuery.data : !findingQuery.data) ? (
            <div className="text-sm text-sev-high">This referenced record is no longer available.</div>
          ) : kind === "event" && eventQuery.data ? (
            <div className="space-y-3 text-sm">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={eventQuery.data.severity} />
                <span className="text-ink-400">{fmtTime(eventQuery.data.timestamp)}</span>
              </div>
              <Field label="Source" value={eventQuery.data.source} />
              {eventQuery.data.host && <Field label="Host" value={eventQuery.data.host} />}
              {eventQuery.data.entity && <Field label="Entity" value={eventQuery.data.entity} />}
              <Field label="Summary" value={eventQuery.data.summary} />
              <div><div className="label">Raw event</div><CodeBlock>{JSON.stringify(eventQuery.data.raw, null, 2)}</CodeBlock></div>
            </div>
          ) : findingQuery.data ? (
            <div className="space-y-3 text-sm">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={findingQuery.data.severity} />
                {findingQuery.data.suppressed && <span className="chip bg-white/10 text-ink-400">{findingQuery.data.suppressed_reason}</span>}
              </div>
              <Field label="Description" value={findingQuery.data.description} />
              {findingQuery.data.mitre_techniques.length > 0 && <Field label="MITRE ATT&CK" value={findingQuery.data.mitre_techniques.join(", ")} />}
              {findingQuery.data.suppression_details?.rationale && (
                <Field
                  label={`Suppression rationale · ${findingQuery.data.suppression_details.actor}`}
                  value={findingQuery.data.suppression_details.rationale}
                />
              )}
              <div><div className="label">Finding evidence</div><CodeBlock>{JSON.stringify(findingQuery.data.evidence, null, 2)}</CodeBlock></div>
            </div>
          ) : null}
        </DetailDrawer>
      )}
    </>
  );
}

export function EvidenceLinkedText({ caseId, text }: { caseId: string; text: string }) {
  const parts = text.split(/(\[\[(?:event|finding):\d+\]\])/g);
  return (
    <span className="whitespace-pre-wrap">
      {parts.map((part, index) => {
        const match = part.match(/^\[\[(event|finding):(\d+)\]\]$/);
        if (!match) return <span key={index}>{part}</span>;
        return <EvidenceReference key={index} caseId={caseId} kind={match[1] as RefKind} id={Number(match[2])} />;
      })}
    </span>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return <div><div className="label">{label}</div><div className="break-words text-ink-100">{value}</div></div>;
}
