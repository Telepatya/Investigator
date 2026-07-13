import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { ChevronDown, MessageSquare, Plus, Search, Send, Sparkles, Trash2 } from "lucide-react";
import { PageShell, PageTitle } from "../components/common";
import { EvidenceMarkdown } from "../components/EvidenceReference";
import { api, wsUrl } from "../lib/api";

interface Msg {
  role: "user" | "assistant" | "tool";
  content: string;
}

interface ChatSummary {
  id: string;
  title: string;
  message_count: number;
  preview: string;
  created_at: string;
  updated_at: string;
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
  const [chats, setChats] = useState<ChatSummary[]>([]);
  const [activeChatId, setActiveChatId] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [loadingChat, setLoadingChat] = useState(true);
  const [chatMenuOpen, setChatMenuOpen] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const activeChatRef = useRef<string | null>(null);
  const chatMenuRef = useRef<HTMLDivElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const activeChat = chats.find((chat) => chat.id === activeChatId);

  useEffect(() => {
    activeChatRef.current = activeChatId;
    setChatMenuOpen(false);
  }, [activeChatId]);

  useEffect(() => {
    if (!chatMenuOpen) return;
    const closeMenu = (event: PointerEvent) => {
      if (!chatMenuRef.current?.contains(event.target as Node)) setChatMenuOpen(false);
    };
    document.addEventListener("pointerdown", closeMenu);
    return () => document.removeEventListener("pointerdown", closeMenu);
  }, [chatMenuOpen]);

  async function loadChatList(preferredId?: string | null): Promise<ChatSummary[]> {
    if (!caseId) return [];
    const result = await api.listChats(caseId);
    setChats(result.chats);
    const next = preferredId && result.chats.some((chat) => chat.id === preferredId)
      ? preferredId
      : result.chats[0]?.id ?? null;
    setActiveChatId(next);
    return result.chats;
  }

  useEffect(() => {
    let cancelled = false;
    setMessages([]);
    setChats([]);
    setActiveChatId(null);
    setLoadingChat(true);
    (async () => {
      if (!caseId) return;
      const result = await api.listChats(caseId);
      let next = result.chats;
      if (next.length === 0) {
        const created = await api.createChat(caseId);
        next = [{
          id: created.id,
          title: created.title,
          message_count: 0,
          preview: "",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        }];
      }
      if (!cancelled) {
        setChats(next);
        setActiveChatId(next[0].id);
      }
    })().catch(() => {
      if (!cancelled) setLoadingChat(false);
    });
    return () => { cancelled = true; };
  }, [caseId]);

  useEffect(() => {
    let cancelled = false;
    if (!caseId || !activeChatId) return;
    setLoadingChat(true);
    api.getChat(caseId, activeChatId)
      .then((chat) => {
        if (!cancelled) {
          setMessages(chat.messages.map((message) => ({
            role: message.role,
            content: message.content,
          })));
          setLoadingChat(false);
        }
      })
      .catch(() => { if (!cancelled) setLoadingChat(false); });
    return () => { cancelled = true; };
  }, [caseId, activeChatId]);

  useEffect(() => {
    if (!caseId) return;
    void api.getReport(caseId); // warm cache
    const ws = new WebSocket(wsUrl(`/cases/${caseId}/chat-ws`));
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "start") {
        setStreaming(true);
      } else if (data.type === "tool") {
        setMessages((current) => [...current, { role: "tool", content: data.content }]);
      } else if (data.type === "chunk") {
        setMessages((current) => {
          const copy = [...current];
          const last = copy[copy.length - 1];
          if (last?.role === "assistant") {
            copy[copy.length - 1] = { role: "assistant", content: last.content + data.content };
          } else {
            copy.push({ role: "assistant", content: data.content });
          }
          return copy;
        });
      } else if (data.type === "finding_suppressed") {
        setMessages((current) => [...current, {
          role: "tool",
          content: `Suppressed finding #${data.finding_id}: ${data.rationale}`,
        }]);
        for (const key of ["findings", "finding-detail", "case", "entities", "entity-dossier", "report", "timeline"]) {
          queryClient.invalidateQueries({ queryKey: [key, caseId] });
        }
      } else if (data.type === "done") {
        setStreaming(false);
        api.listChats(caseId).then((result) => setChats(result.chats)).catch(() => undefined);
      } else if (data.type === "error") {
        setMessages((current) => [...current, { role: "assistant", content: `Error: ${data.content}` }]);
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
    const chatId = activeChatRef.current;
    if (!text.trim() || !chatId || streaming || wsRef.current?.readyState !== WebSocket.OPEN) return;
    setMessages((current) => [...current, { role: "user", content: text }]);
    wsRef.current.send(JSON.stringify({ message: text, chat_id: chatId }));
    setInput("");
  }

  async function startNewChat() {
    if (!caseId || streaming) return;
    const created = await api.createChat(caseId);
    await loadChatList(created.id);
  }

  async function removeCurrentChat() {
    if (!caseId || !activeChatId || streaming) return;
    const current = chats.find((chat) => chat.id === activeChatId);
    if (!window.confirm(`Delete “${current?.title ?? "this chat"}”? This cannot be undone.`)) return;
    await api.deleteChat(caseId, activeChatId);
    const remaining = await api.listChats(caseId);
    if (remaining.chats.length > 0) {
      setChats(remaining.chats);
      setActiveChatId(remaining.chats[0].id);
      return;
    }
    const created = await api.createChat(caseId);
    await loadChatList(created.id);
  }

  return (
    <PageShell>
      <PageTitle
        icon={<MessageSquare size={22} />}
        title="AI"
        subtitle="Ask case-aware questions grounded in events, findings, processes, and memory results."
      />
      <div className="card flex flex-col" style={{ height: "calc(100vh - 300px)", minHeight: 560 }}>
        <div className="relative z-20 flex items-center gap-3 border-b border-white/5 bg-base-950/25 px-4 py-3">
          <div ref={chatMenuRef} className="relative min-w-0 flex-1">
            <button
              type="button"
              className="group flex w-full min-w-0 items-center gap-3 rounded-xl border border-white/10 bg-white/[0.035] px-3 py-2 text-left transition hover:border-accent-cyan/30 hover:bg-white/[0.06] disabled:cursor-not-allowed disabled:opacity-60"
              onClick={() => setChatMenuOpen((open) => !open)}
              disabled={streaming || chats.length === 0}
              aria-haspopup="listbox"
              aria-expanded={chatMenuOpen}
            >
              <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-accent-cyan/10 text-accent-cyan ring-1 ring-inset ring-accent-cyan/20">
                <MessageSquare size={15} />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-semibold text-ink-100">
                  {activeChat?.title ?? "Select a chat"}
                </span>
                <span className="block text-[11px] text-ink-500">
                  {activeChat ? `${activeChat.message_count} message${activeChat.message_count === 1 ? "" : "s"}` : "Saved conversations"}
                </span>
              </span>
              <ChevronDown
                size={16}
                className={`shrink-0 text-ink-500 transition group-hover:text-ink-300 ${chatMenuOpen ? "rotate-180" : ""}`}
              />
            </button>

            {chatMenuOpen && (
              <div
                className="absolute left-0 top-[calc(100%+0.5rem)] z-50 w-full max-w-2xl overflow-hidden rounded-xl border border-white/10 bg-base-900/95 p-1.5 shadow-2xl shadow-black/40 backdrop-blur-xl"
                role="listbox"
                aria-label="Saved chats"
              >
                <div className="flex items-center justify-between px-2.5 py-2">
                  <span className="text-[11px] font-semibold uppercase tracking-[0.16em] text-ink-500">Saved chats</span>
                  <span className="rounded-full bg-white/5 px-2 py-0.5 text-[10px] text-ink-500">{chats.length}</span>
                </div>
                <div className="max-h-72 space-y-1 overflow-y-auto">
                  {chats.map((chat) => (
                    <button
                      type="button"
                      key={chat.id}
                      role="option"
                      aria-selected={chat.id === activeChatId}
                      className={`w-full rounded-lg px-3 py-2.5 text-left transition ${
                        chat.id === activeChatId
                          ? "bg-accent-cyan/10 text-ink-100 ring-1 ring-inset ring-accent-cyan/20"
                          : "text-ink-300 hover:bg-white/5 hover:text-ink-100"
                      }`}
                      onClick={() => setActiveChatId(chat.id)}
                    >
                      <span className="flex items-center justify-between gap-3">
                        <span className="truncate text-sm font-medium">{chat.title}</span>
                        <span className="shrink-0 text-[10px] text-ink-500">{chat.message_count}</span>
                      </span>
                      {chat.preview && <span className="mt-0.5 block truncate text-xs text-ink-500">{chat.preview}</span>}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="flex shrink-0 items-center gap-1 rounded-xl border border-white/10 bg-white/[0.025] p-1">
            <button
              type="button"
              className="flex h-9 items-center gap-1.5 rounded-lg px-2.5 text-xs font-semibold text-ink-300 transition hover:bg-accent-cyan/10 hover:text-accent-cyan disabled:opacity-40"
              onClick={startNewChat}
              disabled={streaming}
              title="Start a new chat"
            >
              <Plus size={15} /> <span className="hidden sm:inline">New chat</span>
            </button>
            <span className="h-5 w-px bg-white/10" />
            <button
              type="button"
              className="grid h-9 w-9 place-items-center rounded-lg text-ink-500 transition hover:bg-sev-critical/10 hover:text-sev-critical disabled:opacity-40"
              onClick={removeCurrentChat}
              disabled={streaming || !activeChatId}
              title="Delete current chat"
              aria-label="Delete current chat"
            >
              <Trash2 size={15} />
            </button>
          </div>
        </div>

        <div ref={scrollRef} className="flex-1 overflow-y-auto p-5 space-y-4">
          {loadingChat && <div className="text-center text-sm text-ink-400">Loading chat...</div>}
          {!loadingChat && messages.length === 0 && (
            <div className="h-full flex flex-col items-center justify-center text-center gap-4">
              <div className="grid place-items-center w-14 h-14 rounded-2xl bg-accent-cyan/10 border border-accent-cyan/30">
                <MessageSquare size={26} className="text-accent-cyan" />
              </div>
              <div>
                <div className="text-lg font-semibold text-ink-100">Ask about this case</div>
                <div className="text-sm text-ink-400 mt-1 max-w-md">
                  The assistant verifies answers against the case&apos;s findings, events, processes,
                  memory analysis, and evidence-backed report.
                </div>
              </div>
              <div className="grid sm:grid-cols-2 gap-2 mt-2 w-full max-w-xl">
                {SUGGESTIONS.map((suggestion) => (
                  <button
                    key={suggestion}
                    className="text-left text-sm text-ink-300 bg-white/5 hover:bg-white/10 rounded-lg px-3 py-2 transition"
                    onClick={() => send(suggestion)}
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map((message, index) => message.role === "tool" ? (
            <div key={index} className="flex items-center gap-1.5 pl-11 text-xs italic text-ink-400">
              <Search size={12} /> {message.content}
            </div>
          ) : (
            <div
              key={index}
              className={`flex gap-3 ${message.role === "user" ? "justify-end" : "justify-start"}`}
            >
              {message.role === "assistant" && (
                <div className="grid place-items-center w-8 h-8 rounded-lg bg-accent-cyan/10 border border-accent-cyan/30 shrink-0">
                  <Sparkles size={15} className="text-accent-cyan" />
                </div>
              )}
              <div className={`max-w-[75%] min-w-0 rounded-xl px-4 py-2.5 text-sm leading-relaxed ${
                message.role === "user"
                  ? "bg-accent-cyan/90 text-base-900 font-medium"
                  : "bg-base-900/60 text-ink-100 border border-white/5"
              }`}>
                {message.role === "assistant" && caseId ? (
                  <EvidenceMarkdown caseId={caseId} text={message.content} />
                ) : <span className="whitespace-pre-wrap">{message.content}</span>}
                {!message.content && streaming && index === messages.length - 1 ? "▹" : ""}
              </div>
            </div>
          ))}
          {streaming && messages[messages.length - 1]?.role !== "assistant" && (
            <div className="flex gap-3 justify-start">
              <div className="grid place-items-center w-8 h-8 rounded-lg bg-accent-cyan/10 border border-accent-cyan/30 shrink-0">
                <Sparkles size={15} className="text-accent-cyan" />
              </div>
              <div className="max-w-[75%] rounded-xl px-4 py-2.5 text-sm bg-base-900/60 text-ink-100 border border-white/5">▹</div>
            </div>
          )}
        </div>

        <div className="border-t border-white/5 p-3">
          <div className="flex items-center gap-2">
            <input
              className="input"
              placeholder="Ask a question about this investigation..."
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={(event) => event.key === "Enter" && send(input)}
              disabled={streaming || loadingChat || !activeChatId}
            />
            <button
              className="btn-primary"
              onClick={() => send(input)}
              disabled={streaming || loadingChat || !activeChatId || !input.trim()}
            >
              <Send size={16} />
            </button>
          </div>
        </div>
      </div>
    </PageShell>
  );
}
