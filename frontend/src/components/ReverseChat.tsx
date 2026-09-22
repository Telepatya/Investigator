import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MessageSquare, Search, Send, Sparkles, Trash2 } from "lucide-react";
import { api } from "../lib/api";
import { ReverseMarkdown } from "./ReverseMarkdown";

const SUGGESTIONS = [
  "What packer or obfuscation was detected?",
  "List the most suspicious strings and what they imply.",
  "Summarize the IOCs with their supporting evidence.",
  "Does the sample show persistence or C2 capability?",
];

export function ReverseChat({ projectId, hasReport }: { projectId: string; hasReport: boolean }) {
  const qc = useQueryClient();
  const [input, setInput] = useState("");
  const [pendingQuestion, setPendingQuestion] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const messages = useQuery({
    queryKey: ["reverse-messages", projectId],
    queryFn: () => api.getReverseMessages(projectId),
    refetchInterval: 4000,
  });
  const send = useMutation({
    mutationFn: (text: string) => api.sendReverseMessage(projectId, text),
    onSettled: () => {
      setPendingQuestion(null);
      qc.invalidateQueries({ queryKey: ["reverse-messages", projectId] });
      qc.invalidateQueries({ queryKey: ["reverse-project", projectId] });
      qc.invalidateQueries({ queryKey: ["reverse-audit", projectId] });
    },
  });
  const clear = useMutation({
    mutationFn: () => api.clearReverseMessages(projectId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reverse-messages", projectId] }),
  });

  const visible = (messages.data ?? []).filter(
    (message) => message.role === "user" || message.role === "assistant",
  );
  const streaming = send.isPending;
  const lastUser = [...visible].reverse().find((message) => message.role === "user");
  const showPendingBubble = pendingQuestion !== null && lastUser?.content !== pendingQuestion;

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [visible.length, pendingQuestion, streaming]);

  function submit(text: string) {
    const trimmed = text.trim();
    if (!trimmed || streaming) return;
    setPendingQuestion(trimmed);
    send.mutate(trimmed);
    setInput("");
  }

  async function clearChat() {
    if (streaming || !visible.length) return;
    if (!window.confirm("Clear this follow-up chat? This cannot be undone.")) return;
    clear.mutate();
  }

  return (
    <div className="card flex flex-col" style={{ height: "calc(100vh - 340px)", minHeight: 520 }}>
      <div className="flex items-center gap-3 border-b border-white/5 bg-base-950/25 px-4 py-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-accent-cyan/10 text-accent-cyan ring-1 ring-inset ring-accent-cyan/20">
          <MessageSquare size={15} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-semibold text-ink-100">Follow-up analysis chat</span>
          <span className="block text-[11px] text-ink-500">
            {visible.length} message{visible.length === 1 ? "" : "s"} · grounded in the report and sandbox evidence
          </span>
        </span>
        <button
          type="button"
          className="grid h-9 w-9 shrink-0 place-items-center rounded-lg text-ink-500 transition hover:bg-sev-critical/10 hover:text-sev-critical disabled:opacity-40"
          onClick={clearChat}
          disabled={streaming || clear.isPending || !visible.length}
          title="Clear chat"
          aria-label="Clear chat"
        >
          <Trash2 size={15} />
        </button>
      </div>

      <div ref={scrollRef} className="flex-1 space-y-4 overflow-y-auto p-5">
        {messages.isLoading && <div className="text-center text-sm text-ink-400">Loading chat...</div>}
        {!messages.isLoading && visible.length === 0 && !showPendingBubble && (
          <div className="flex h-full flex-col items-center justify-center gap-4 text-center">
            <div className="grid h-14 w-14 place-items-center rounded-2xl border border-accent-cyan/30 bg-accent-cyan/10">
              <MessageSquare size={26} className="text-accent-cyan" />
            </div>
            <div>
              <div className="text-lg font-semibold text-ink-100">Ask about this analysis</div>
              <div className="mt-1 max-w-md text-sm text-ink-400">
                {hasReport
                  ? "The assistant answers with evidence from the report and can run additional sandbox tools when needed."
                  : "Complete a static analysis first, then ask follow-up questions grounded in the generated report."}
              </div>
            </div>
            {hasReport && (
              <div className="mt-2 grid w-full max-w-xl gap-2 sm:grid-cols-2">
                {SUGGESTIONS.map((suggestion) => (
                  <button
                    key={suggestion}
                    className="rounded-lg bg-white/5 px-3 py-2 text-left text-sm text-ink-300 transition hover:bg-white/10"
                    onClick={() => submit(suggestion)}
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        {visible.map((message) => {
          const toolUses = Number(message.metadata?.tool_uses ?? 0);
          if (message.role === "user") {
            return (
              <div key={message.id} className="flex justify-end gap-3">
                <div className="max-w-[75%] min-w-0 rounded-xl bg-accent-cyan/90 px-4 py-2.5 text-sm font-medium leading-relaxed text-base-900">
                  <span className="whitespace-pre-wrap">{message.content}</span>
                </div>
              </div>
            );
          }
          return (
            <div key={message.id} className="space-y-1.5">
              {toolUses > 0 && (
                <div className="flex items-center gap-1.5 pl-11 text-xs italic text-ink-400">
                  <Search size={12} /> Ran {toolUses} sandbox tool step{toolUses === 1 ? "" : "s"}
                </div>
              )}
              <div className="flex justify-start gap-3">
                <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-accent-cyan/30 bg-accent-cyan/10">
                  <Sparkles size={15} className="text-accent-cyan" />
                </div>
                <div className="max-w-[75%] min-w-0 rounded-xl border border-white/5 bg-base-900/60 px-4 py-2.5 text-sm leading-relaxed text-ink-100">
                  <ReverseMarkdown content={message.content} />
                </div>
              </div>
            </div>
          );
        })}

        {showPendingBubble && (
          <div className="flex justify-end gap-3">
            <div className="max-w-[75%] min-w-0 rounded-xl bg-accent-cyan/90 px-4 py-2.5 text-sm font-medium leading-relaxed text-base-900">
              <span className="whitespace-pre-wrap">{pendingQuestion}</span>
            </div>
          </div>
        )}
        {streaming && (
          <div className="flex justify-start gap-3">
            <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-accent-cyan/30 bg-accent-cyan/10">
              <Sparkles size={15} className="text-accent-cyan" />
            </div>
            <div className="max-w-[75%] rounded-xl border border-white/5 bg-base-900/60 px-4 py-2.5 text-sm text-ink-100">
              Investigating<span className="animate-pulse">…</span>
            </div>
          </div>
        )}
      </div>

      <div className="border-t border-white/5 p-3">
        <div className="flex items-center gap-2">
          <input
            className="input"
            placeholder={hasReport ? "Ask about imports, strings, behaviors, or report evidence..." : "Complete an analysis to enable follow-up chat"}
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onKeyDown={(event) => event.key === "Enter" && submit(input)}
            disabled={streaming || !hasReport}
          />
          <button
            className="btn-primary"
            onClick={() => submit(input)}
            disabled={streaming || !hasReport || !input.trim()}
          >
            <Send size={16} />
          </button>
        </div>
        {send.error && <div className="mt-2 text-sm text-sev-critical">{String(send.error)}</div>}
        {clear.error && <div className="mt-2 text-sm text-sev-critical">{String(clear.error)}</div>}
      </div>
    </div>
  );
}
