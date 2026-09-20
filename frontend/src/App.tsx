import { Suspense, useEffect, useRef, useState, type ReactNode } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Binary, Clock, Folder, Moon, ScrollText, Search, Settings, ShieldCheck, Sun, X } from "lucide-react";
import { clsx } from "clsx";
import { CodeBlock, DetailDrawer, IconButton, SeverityBadge, Spinner } from "./components/common";
import { FlagAsFinding } from "./components/FlagAsFinding";
import { useTheme } from "./lib/theme";
import { api } from "./lib/api";
import { fmtTime } from "./lib/ui";
import type { EventRow } from "./lib/types";
import { useAuth } from "./components/AuthGate";

const BRAND_CREDIT = "Made by Roei.f";
const APP_VERSION = "0.1.0";
const RELEASE_LABEL = "Public Beta";

const NAV = [
  { to: "/", label: "Cases", icon: <Folder size={19} /> },
  { to: "/reverse", label: "Reverse", icon: <Binary size={19} /> },
  { to: "/rules", label: "Rules", icon: <ScrollText size={19} /> },
  { to: "/settings", label: "Settings", icon: <Settings size={19} /> },
];

export default function App() {
  const loc = useLocation();
  const { theme, toggleTheme } = useTheme();
  const { auth, logout } = useAuth();
  const inCase = loc.pathname.startsWith("/cases/");
  const caseId = inCase ? loc.pathname.split("/")[2] : "";
  const [searchOpen, setSearchOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<EventRow | null>(null);
  const q = search.trim();
  const searchRef = useRef<HTMLInputElement>(null);

  const { data: searchResults, isFetching: searching } = useQuery({
    queryKey: ["global-event-search", caseId, q],
    queryFn: ({ signal }) => api.getEvents(caseId, { q, limit: 8 }, signal),
    enabled: searchOpen && Boolean(caseId) && q.length >= 2,
  });

  useEffect(() => {
    setSearchOpen(false);
    setSearch("");
    setSelectedEvent(null);
  }, [caseId]);

  useEffect(() => {
    if (searchOpen) searchRef.current?.focus();
  }, [searchOpen]);

  return (
    <div className="min-h-screen lg:flex">
      <aside className="fixed inset-x-3 top-3 z-40 lg:inset-x-auto lg:bottom-3 lg:left-3 lg:w-[238px]">
        <div className="surface flex h-[72px] items-center justify-between px-4 lg:h-full lg:flex-col lg:items-stretch lg:p-4">
          <Link to="/" className="flex items-center gap-3">
            <div className="grid h-11 w-11 place-items-center rounded-2xl bg-accent-blue/10 text-accent-blue ring-1 ring-accent-blue/20">
              <ShieldCheck size={26} />
            </div>
            <div className="min-w-0 leading-tight">
              <div className="text-lg font-extrabold tracking-tight text-ink-50">Investigator</div>
              <div className="text-xs text-ink-300">DFIR Workstation</div>
              <div className="text-[9px] font-bold uppercase tracking-[0.12em] text-accent-blue">
                {RELEASE_LABEL} · v{APP_VERSION}
              </div>
            </div>
          </Link>

          <nav className="hidden flex-1 py-10 lg:block">
            <div className="space-y-2">
              {NAV.map((item) => (
                <SidebarItem key={item.label} item={item} pathname={loc.pathname} />
              ))}
            </div>
          </nav>

          <div className="hidden border-t border-[rgb(var(--border)/0.58)] pt-4 lg:block">
            <div className="flex items-center gap-3">
              <div className="grid h-10 w-10 place-items-center rounded-full bg-emerald-500/15 text-emerald-600 ring-1 ring-emerald-500/20">
                <ShieldCheck size={18} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-semibold text-ink-100">{auth?.user?.display_name || "Local session"}</div>
                <div className="truncate text-xs text-ink-300">{auth?.enabled ? (auth.user?.email || "Organization SSO") : "Offline analysis"}</div>
              </div>
              {auth?.enabled && <button className="text-xs text-ink-300 hover:text-accent-blue" onClick={() => void logout}>Log out</button>}
            </div>
          </div>

          <div className="flex items-center gap-2 lg:hidden">
            <IconButton label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"} onClick={toggleTheme}>
              {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            </IconButton>
          </div>
        </div>
      </aside>

      <div className="flex min-h-screen flex-1 flex-col pt-24 lg:ml-[260px] lg:pt-5">
        <header className="sticky top-3 z-30 mx-3 mb-4 flex items-center justify-between gap-3 lg:mx-6">
          <div className="flex min-w-0 items-center gap-2">
            {inCase && (
              <div className="relative">
              <div
                className={clsx(
                  "glass flex h-12 items-center gap-2 rounded-2xl transition-all duration-200",
                  searchOpen ? "w-[min(520px,calc(100vw-120px))] px-4" : "w-12 justify-center px-0",
                )}
              >
                <button
                  className="grid h-10 w-10 shrink-0 place-items-center rounded-xl text-ink-300 transition hover:text-accent-blue"
                  onClick={() => setSearchOpen(true)}
                  title="Search current case events"
                >
                  <Search size={18} />
                </button>
                {searchOpen && (
                  <>
                    <input
                      ref={searchRef}
                      className="min-w-0 flex-1 bg-transparent text-sm text-ink-100 outline-none placeholder:text-ink-400"
                      placeholder="Search current case events..."
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Escape") setSearchOpen(false);
                      }}
                    />
                    <button
                      className="grid h-8 w-8 place-items-center rounded-xl text-ink-400 transition hover:bg-white/40 hover:text-ink-100"
                      onClick={() => {
                        setSearch("");
                        setSearchOpen(false);
                      }}
                      title="Close search"
                    >
                      <X size={15} />
                    </button>
                  </>
                )}
              </div>
              {searchOpen && (
                <div className="glass absolute left-0 top-14 z-50 w-[min(520px,calc(100vw-120px))] overflow-hidden rounded-3xl">
                  <div className="border-b border-[rgb(var(--border)/0.58)] px-4 py-3 text-xs font-semibold text-ink-300">
                    {q.length < 2 ? "Type at least 2 characters to search current case events" : searching ? "Searching events..." : `${searchResults?.total ?? 0} matching events`}
                  </div>
                  {q.length >= 2 && (
                    <div className="max-h-[360px] overflow-y-auto p-2">
                      {(searchResults?.events ?? []).length === 0 && !searching ? (
                        <div className="px-3 py-8 text-center text-sm text-ink-300">No matching events found.</div>
                      ) : (
                        (searchResults?.events ?? []).map((event) => (
                          <div
                            key={event.id}
                            className="rounded-2xl px-3 py-2.5 transition hover:bg-[rgb(var(--panel-strong)/0.72)]"
                            onDoubleClick={() => setSelectedEvent(event)}
                            title="Double-click to open event details"
                          >
                            <div className="flex items-center gap-2 text-[11px] text-ink-300">
                              <Clock size={12} className="text-accent-blue" />
                              <span>{fmtTime(event.timestamp)}</span>
                              <span className="rounded-full bg-accent-blue/10 px-2 py-0.5 font-semibold text-accent-blue">
                                {event.category}
                              </span>
                            </div>
                            <div className="mt-1 line-clamp-2 text-sm font-semibold text-ink-100">
                              {event.summary}
                            </div>
                            <div className="mt-1 truncate font-mono text-[11px] text-ink-400">
                              {event.source}
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  )}
                </div>
              )}
              </div>
            )}
          </div>

          <div className="hidden items-center justify-end gap-2 md:flex">
            <IconButton label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"} onClick={toggleTheme}>
              {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            </IconButton>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1680px] flex-1 px-3 pb-6 lg:px-6">
          <Suspense fallback={<Spinner label="Loading…" />}>
            <Outlet />
          </Suspense>
        </main>
      </div>

      {selectedEvent && (
        <DetailDrawer
          eyebrow="Event detail"
          title={selectedEvent.category}
          onClose={() => setSelectedEvent(null)}
          ariaLabel="Event detail"
        >
          <div className="space-y-3 text-sm">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={selectedEvent.severity} />
              <span className="text-ink-400">{fmtTime(selectedEvent.timestamp)}</span>
            </div>
            <SearchEventField
              label="Severity origin"
              value={
                selectedEvent.severity_reason ??
                (selectedEvent.severity === "info"
                  ? "Default severity - no detection or flagged entity touched this event."
                  : "Base severity assigned by the evidence parser for this source.")
              }
            />
            <SearchEventField label="Source" value={selectedEvent.source} mono />
            {selectedEvent.host && <SearchEventField label="Host" value={selectedEvent.host} />}
            {selectedEvent.entity && <SearchEventField label="Entity" value={selectedEvent.entity} mono />}
            <SearchEventField label="Summary" value={selectedEvent.summary} />
            <div>
              <div className="label">Raw</div>
              <CodeBlock>{JSON.stringify(selectedEvent.raw, null, 2)}</CodeBlock>
            </div>
            {caseId && (
              <div className="border-t border-[rgb(var(--border)/0.5)] pt-3">
                <FlagAsFinding
                  caseId={caseId}
                  refType="event"
                  refId={String(selectedEvent.id)}
                  refLabel={selectedEvent.summary}
                  entityHint={selectedEvent.entity ?? undefined}
                  defaultTitle={`Analyst-flagged event: ${selectedEvent.summary.slice(0, 140)}`}
                  defaultSeverity={selectedEvent.severity === "info" ? "medium" : selectedEvent.severity}
                />
              </div>
            )}
          </div>
        </DetailDrawer>
      )}

      <div
        aria-hidden="true"
        className="pointer-events-none fixed bottom-3 right-4 z-30 select-none text-[10px] uppercase tracking-[0.24em] text-ink-500/40"
      >
        {BRAND_CREDIT}
      </div>
    </div>
  );
}

function SearchEventField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="label">{label}</div>
      <div className={clsx("break-words text-ink-100", mono && "font-mono text-xs")}>{value}</div>
    </div>
  );
}

function SidebarItem({
  item,
  pathname,
}: {
  item: { to: string; label: string; icon: ReactNode };
  pathname: string;
}) {
  const active =
    (item.label === "Settings" && pathname.startsWith("/settings")) ||
    (item.label === "Reverse" && pathname.startsWith("/reverse")) ||
    (item.label === "Rules" && pathname.startsWith("/rules")) ||
    (item.label === "Cases" && (pathname === "/" || pathname.startsWith("/cases/")));

  return (
    <Link
      to={item.to}
      className={clsx(
        "flex items-center gap-3 rounded-2xl px-4 py-3 text-sm font-semibold transition-all",
        active
          ? "bg-accent-blue/10 text-accent-blue shadow-sm"
          : "text-ink-200 hover:bg-[rgb(var(--panel-strong)/0.62)] hover:text-accent-blue",
      )}
    >
      {item.icon}
      <span className="flex-1">{item.label}</span>
    </Link>
  );
}
