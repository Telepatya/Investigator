import { Fragment, type ReactNode, useState } from "react";
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
  const parts = text.split(/(\[{1,2}(?:event|finding):\d+\]{1,2})/g);
  return (
    <span className="whitespace-pre-wrap">
      {parts.map((part, index) => {
        const match = part.match(/^\[{1,2}(event|finding):(\d+)\]{1,2}$/);
        if (!match) return <span key={index}>{part}</span>;
        return <EvidenceReference key={index} caseId={caseId} kind={match[1] as RefKind} id={Number(match[2])} />;
      })}
    </span>
  );
}

/** Safe, deliberately small Markdown renderer for AI-authored case text.
 * Raw HTML is never interpreted. Evidence tokens become in-app detail links,
 * including grouped model output such as [[finding:10], [finding:15]]. */
export function EvidenceMarkdown({ caseId, text }: { caseId: string; text: string }) {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed) {
      i += 1;
      continue;
    }

    const fence = trimmed.match(/^```([\w-]*)\s*$/);
    if (fence) {
      const code: string[] = [];
      i += 1;
      while (i < lines.length && !/^```\s*$/.test(lines[i].trim())) {
        code.push(lines[i]);
        i += 1;
      }
      if (i < lines.length) i += 1;
      blocks.push(
        <pre key={`code-${i}`} className="overflow-x-auto rounded-lg border border-white/10 bg-black/25 p-3 text-xs text-ink-200">
          <code data-language={fence[1] || undefined}>{code.join("\n")}</code>
        </pre>,
      );
      continue;
    }

    const heading = trimmed.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      const level = heading[1].length;
      blocks.push(
        <div
          key={`heading-${i}`}
          role="heading"
          aria-level={level}
          className={level <= 2 ? "text-base font-semibold text-ink-50" : "font-semibold text-ink-100"}
        >
          {renderInline(caseId, heading[2], `heading-${i}`)}
        </div>,
      );
      i += 1;
      continue;
    }

    if (/^(?:---+|___+|\*\*\*+)\s*$/.test(trimmed)) {
      blocks.push(<hr key={`rule-${i}`} className="border-white/10" />);
      i += 1;
      continue;
    }

    if (/^>\s?/.test(trimmed)) {
      const quote: string[] = [];
      while (i < lines.length && /^>\s?/.test(lines[i].trim())) {
        quote.push(lines[i].trim().replace(/^>\s?/, ""));
        i += 1;
      }
      blocks.push(
        <blockquote key={`quote-${i}`} className="border-l-2 border-accent-cyan/50 pl-3 text-ink-300">
          {renderInline(caseId, quote.join("\n"), `quote-${i}`)}
        </blockquote>,
      );
      continue;
    }

    const unordered = trimmed.match(/^[-*+]\s+(.+)$/);
    const ordered = trimmed.match(/^\d+[.)]\s+(.+)$/);
    if (unordered || ordered) {
      const isOrdered = Boolean(ordered);
      const items: ReactNode[] = [];
      while (i < lines.length) {
        const candidate = lines[i].trim();
        const match = isOrdered
          ? candidate.match(/^\d+[.)]\s+(.+)$/)
          : candidate.match(/^[-*+]\s+(.+)$/);
        if (!match) break;
        items.push(<li key={`item-${i}`}>{renderInline(caseId, match[1], `item-${i}`)}</li>);
        i += 1;
      }
      blocks.push(
        isOrdered ? (
          <ol key={`list-${i}`} className="list-decimal space-y-1 pl-5 marker:text-ink-400">{items}</ol>
        ) : (
          <ul key={`list-${i}`} className="list-disc space-y-1 pl-5 marker:text-ink-400">{items}</ul>
        ),
      );
      continue;
    }

    const paragraph: string[] = [];
    while (i < lines.length && lines[i].trim() && !isMarkdownBlockStart(lines[i].trim())) {
      paragraph.push(lines[i].trim());
      i += 1;
    }
    // A non-marker line always enters this branch, but keep progress guaranteed
    // if a future block-start rule is added without a matching renderer above.
    if (paragraph.length === 0) {
      paragraph.push(trimmed);
      i += 1;
    }
    blocks.push(
      <p key={`paragraph-${i}`} className="leading-relaxed">
        {renderInline(caseId, paragraph.join(" "), `paragraph-${i}`)}
      </p>,
    );
  }

  return <div className="space-y-3 break-words">{blocks}</div>;
}

function isMarkdownBlockStart(line: string): boolean {
  return /^(?:```|#{1,6}\s|>\s?|[-*+]\s+|\d+[.)]\s+|---+$|___+$|\*\*\*+$)/.test(line);
}

function renderInline(caseId: string, text: string, keyPrefix: string): ReactNode[] {
  const tokenPattern = /(\[{1,2}(?:event|finding):\d+\]{1,2}|\*\*[^*\n]+\*\*|__[^_\n]+__|`[^`\n]+`|\[[^\]\n]+\]\((?:https?:\/\/|mailto:)[^)\s]+\)|~~[^~\n]+~~|\*[^*\n]+\*|_[^_\n]+_)/g;
  const nodes: ReactNode[] = [];
  let cursor = 0;
  let index = 0;

  for (const match of text.matchAll(tokenPattern)) {
    const start = match.index ?? 0;
    if (start > cursor) nodes.push(text.slice(cursor, start));
    const token = match[0];
    const key = `${keyPrefix}-${index++}`;
    const evidence = token.match(/^\[{1,2}(event|finding):(\d+)\]{1,2}$/);

    if (evidence) {
      nodes.push(
        <EvidenceReference
          key={key}
          caseId={caseId}
          kind={evidence[1] as RefKind}
          id={Number(evidence[2])}
        />,
      );
    } else if ((token.startsWith("**") && token.endsWith("**")) || (token.startsWith("__") && token.endsWith("__"))) {
      nodes.push(<strong key={key} className="font-semibold text-ink-50">{renderInline(caseId, token.slice(2, -2), key)}</strong>);
    } else if (token.startsWith("`") && token.endsWith("`")) {
      nodes.push(<code key={key} className="rounded bg-black/25 px-1.5 py-0.5 font-mono text-[0.9em] text-accent-cyan">{token.slice(1, -1)}</code>);
    } else if (token.startsWith("~~") && token.endsWith("~~")) {
      nodes.push(<del key={key}>{renderInline(caseId, token.slice(2, -2), key)}</del>);
    } else if ((token.startsWith("*") && token.endsWith("*")) || (token.startsWith("_") && token.endsWith("_"))) {
      nodes.push(<em key={key}>{renderInline(caseId, token.slice(1, -1), key)}</em>);
    } else {
      const link = token.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
      nodes.push(link ? (
        <a key={key} href={link[2]} target="_blank" rel="noreferrer" className="text-accent-cyan underline decoration-accent-cyan/40 underline-offset-2 hover:decoration-accent-cyan">
          {link[1]}
        </a>
      ) : <Fragment key={key}>{token}</Fragment>);
    }
    cursor = start + token.length;
  }
  if (cursor < text.length) nodes.push(text.slice(cursor));
  return nodes;
}

function Field({ label, value }: { label: string; value: string }) {
  return <div><div className="label">{label}</div><div className="break-words text-ink-100">{value}</div></div>;
}
