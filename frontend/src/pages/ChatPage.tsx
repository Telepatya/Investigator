import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { wsUrl, api } from "../lib/api";
import { Send, Sparkles, MessageSquare } from "lucide-react";
import { PageShell, PageTitle } from "../components/common";
import { EvidenceLinkedText } from "../components/EvidenceReference";
import { useQueryClient } from "@tanstack/react-query";

interface Msg {
  role: "user" | "assistant" | "tool";
  content: string;
}

const SUGGESTIONS = [
  "What is the most likely initial access vector?",
  "Summarize all persistence mechanisms found.",
  "Which processes show signs of injection or hollowing?",
  "Is there evidence of credential theft or C2 beaconing?",
];

export default function ChatPage() {
  const { caseId } = useParams();
  const queryClient = useQueryClient();
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.getReport(caseId!); // warm cache
    const ws = new WebSocket(wsUrl(`/cases/${caseId}/chat-ws`));
    ws.onmessage = (ev) => {
      const data = JSON.parse(ev.data);
      if (data.type === "start") {
        setStreaming(true);
      } else if (data.type === "tool") {
        setMessages((m) => [...m, { role: "tool", content: data.content }]);
      } else if (data.type === "chunk") {
        setMessages((m) => {
          const copy = [...m];
          const last = copy[copy.length - 1];
          if (last && last.role === "assistant") {
            copy[copy.length - 1] = { role: "assistant", content: last.content + data.content };
          } else {
            copy.push({ role: "assistant", content: data.content });
          }
          return copy;
        });
      } else if (data.type === "finding_suppressed") {
        setMessages((m) => [...m, {
          role: "tool",
          content: `Suppressed finding #${data.finding_id}: ${data.rationale}`,
        }]);
        for (const key of ["findings", "finding-detail", "case", "entities", "entity-dossier", "report", "timeline"]) {
          queryClient.invalidateQueries({ queryKey: [key, caseId] });
        }
      } else if (data.type === "done") {
        setStreaming(false);
      } else if (data.type === "error") {
        setMessages((m) => [...m, { role: "assistant", content: `Error: ${data.content}` }]);
        setStreaming(false);
      }
    };
    wsRef.current = ws;
    return () => ws.close();
  }, [caseId, queryClient]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  function send(text: string) {
    if (!text.trim() || streaming || wsRef.current?.readyState !== WebSocket.OPEN) return;
    const history = messages
      .filter((m) => m.role !== "tool")
      .map((m) => ({ role: m.role, content: m.content }));
    setMessages((m) => [...m, { role: "user", content: text }]);
    wsRef.current.send(JSON.stringify({ message: text, history }));
    setInput("");
  }

  return (
    <PageShell>
      <PageTitle
        icon={<MessageSquare size={22} />}
        title="AI"
        subtitle="Ask case-aware questions grounded in events, findings, processes, and memory results."
      />
    <div className="card flex flex-col" style={{ height: "calc(100vh - 300px)", minHeight: 560 }}>
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-5 space-y-4">
        {messages.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-center gap-4">
            <div className="grid place-items-center w-14 h-14 rounded-2xl bg-accent-cyan/10 border border-accent-cyan/30">
              <MessageSquare size={26} className="text-accent-cyan" />
            </div>
            <div>
              <div className="text-lg font-semibold text-ink-100">Ask about this case</div>
              <div className="text-sm text-ink-400 mt-1 max-w-md">
                The assistant answers using the case's findings, events, processes, and memory
                analysis as context.
              </div>
            </div>
            <div className="grid sm:grid-cols-2 gap-2 mt-2 w-full max-w-xl">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  className="text-left text-sm text-ink-300 bg-white/5 hover:bg-white/10 rounded-lg px-3 py-2 transition"
                  onClick={() => send(s)}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((m, i) =>
          m.role === "tool" ? (
            <div key={i} className="pl-11 text-xs italic text-ink-400">
              🔍 {m.content}
            </div>
          ) : (
            <div
              key={i}
              className={`flex gap-3 ${m.role === "user" ? "justify-end" : "justify-start"}`}
            >
              {m.role === "assistant" && (
                <div className="grid place-items-center w-8 h-8 rounded-lg bg-accent-cyan/10 border border-accent-cyan/30 shrink-0">
                  <Sparkles size={15} className="text-accent-cyan" />
                </div>
              )}
              <div
                className={`max-w-[75%] rounded-xl px-4 py-2.5 text-sm whitespace-pre-wrap leading-relaxed ${
                  m.role === "user"
                    ? "bg-accent-cyan/90 text-base-900 font-medium"
                    : "bg-base-900/60 text-ink-100 border border-white/5"
                }`}
              >
                {m.role === "assistant" && caseId ? (
                  <EvidenceLinkedText caseId={caseId} text={m.content} />
                ) : m.content}
                {!m.content && streaming && i === messages.length - 1 ? "▋" : ""}
              </div>
            </div>
          )
        )}
        {streaming && messages[messages.length - 1]?.role !== "assistant" && (
          <div className="flex gap-3 justify-start">
            <div className="grid place-items-center w-8 h-8 rounded-lg bg-accent-cyan/10 border border-accent-cyan/30 shrink-0">
              <Sparkles size={15} className="text-accent-cyan" />
            </div>
            <div className="max-w-[75%] rounded-xl px-4 py-2.5 text-sm bg-base-900/60 text-ink-100 border border-white/5">
              ▋
            </div>
          </div>
        )}
      </div>

      <div className="border-t border-white/5 p-3">
        <div className="flex items-center gap-2">
          <input
            className="input"
            placeholder="Ask a question about this investigation…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && send(input)}
            disabled={streaming}
          />
          <button className="btn-primary" onClick={() => send(input)} disabled={streaming || !input.trim()}>
            <Send size={16} />
          </button>
        </div>
      </div>
    </div>
    </PageShell>
  );
}
