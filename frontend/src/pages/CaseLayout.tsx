import { NavLink, Outlet, useParams } from "react-router-dom";
import { Suspense, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Boxes,
  Calendar,
  Clock,
  Database,
  FileText,
  FolderOpen,
  HardDrive,
  HelpCircle,
  LayoutDashboard,
  List,
  Loader2,
  MessageSquare,
  ShieldCheck,
  Binary,
} from "lucide-react";
import { clsx } from "clsx";
import { api } from "../lib/api";
import { UploadPanel } from "../components/UploadPanel";
import { AnalyzeButton } from "../components/AnalyzeButton";
import { Spinner } from "../components/common";
import { fmtTime } from "../lib/ui";

const TABS = [
  { to: "overview", label: "Dashboard", icon: <LayoutDashboard size={16} /> },
  { to: "timeline", label: "Timeline", icon: <Clock size={16} /> },
  { to: "findings", label: "Findings", icon: <AlertTriangle size={16} /> },
  { to: "evidence", label: "Evidence", icon: <FolderOpen size={16} /> },
  { to: "entities", label: "Entities", icon: <Boxes size={16} /> },
  { to: "memory", label: "Memory", icon: <HardDrive size={16} /> },
  { to: "events", label: "Events", icon: <List size={16} /> },
  { to: "report", label: "Report", icon: <FileText size={16} /> },
  { to: "chat", label: "AI", icon: <MessageSquare size={16} /> },
  { to: "reverse", label: "Reverse", icon: <Binary size={16} /> },
];

export default function CaseLayout() {
  const { caseId } = useParams();
  const { data: c } = useQuery({
    queryKey: ["case", caseId],
    queryFn: ({ signal }) => api.getCase(caseId!, signal),
    refetchInterval: 4000,
    enabled: !!caseId,
  });

  // Reflect only findings that still need review: suppressed (disabled-rule or
  // marked-benign) findings should not keep the banner in an alerting state.
  const activeFindings = c?.active_finding_count ?? 0;
  const suppressedCount = (c?.finding_count ?? 0) - activeFindings;
  const caseBusy = c?.status === "ingesting" || c?.status === "analyzing";

  // "Clean" is only meaningful once evidence has actually been ingested. A brand
  // new case with nothing uploaded must read as "not assessed", never as clean —
  // absence of findings there reflects absence of data, not a safe environment.
  const hasEvidence =
    (c?.event_count ?? 0) > 0 ||
    (c?.process_count ?? 0) > 0 ||
    !!c?.has_memory_dump;
  const notAssessed = !!c && !hasEvidence;
  const clean = hasEvidence && activeFindings === 0;

  const banner = notAssessed
    ? {
        wrap: "border-white/15 bg-white/[0.03]",
        badge: "bg-white/10 text-ink-300",
        dot: "bg-ink-400",
        icon: <HelpCircle size={34} />,
        title: "Not assessed",
        subtitle: "No evidence analyzed yet",
        footer: "Upload evidence and run analysis to assess this case",
      }
    : clean
      ? {
          wrap: "border-emerald-400/25 bg-emerald-400/10",
          badge: "bg-emerald-400/10 text-emerald-500",
          dot: "bg-emerald-500",
          icon: <ShieldCheck size={34} />,
          title: "Environment appears clean",
          subtitle:
            suppressedCount > 0
              ? `No active findings · ${suppressedCount} suppressed`
              : "No ongoing threat detected",
          footer: `Last scan: ${c ? fmtTime(c.updated_at) : "not available"}`,
        }
      : {
          wrap: "border-sev-high/25 bg-sev-high/10",
          badge: "bg-sev-high/10 text-sev-high",
          dot: "bg-sev-high",
          icon: <AlertTriangle size={34} />,
          title: "Findings need review",
          subtitle: `${activeFindings} active finding${activeFindings === 1 ? "" : "s"}${
            suppressedCount > 0 ? ` · ${suppressedCount} suppressed` : ""
          }`,
          footer: `Last scan: ${c ? fmtTime(c.updated_at) : "not available"}`,
        };

  return (
    <div className="page-enter space-y-5">
      <section className="surface overflow-hidden p-5 md:p-7">
        <div className="grid gap-6 xl:grid-cols-[1fr_540px]">
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <h1 className="truncate text-4xl font-extrabold tracking-tight text-ink-50 md:text-5xl">
                {c?.name ?? "..."}
              </h1>
            </div>
            <p className="mt-3 max-w-3xl text-sm text-ink-300">
              {c?.description || "No description"}
            </p>

            <div className="mt-6 grid gap-4 text-sm text-ink-200 sm:grid-cols-2 xl:grid-cols-4">
              <CaseField label="Case ID" value={caseId ?? "-"} />
              <CaseField label="Status" value={c?.status ?? "-"} icon={<Activity size={15} />} />
              <CaseField label="Created" value={c ? fmtDate(c.created_at) : "-"} icon={<Calendar size={15} />} />
              <CaseField label="Last Updated" value={c ? fmtTime(c.updated_at) : "-"} icon={<Clock size={15} />} />
            </div>
          </div>

          <div className={clsx("rounded-3xl border p-5", banner.wrap)}>
            <div className="flex items-center gap-4">
              <div className={clsx("grid h-16 w-16 place-items-center rounded-3xl", banner.badge)}>
                {banner.icon}
              </div>
              <div>
                <div className="text-lg font-bold text-ink-50">{banner.title}</div>
                <div className="mt-1 text-sm text-ink-300">{banner.subtitle}</div>
                <div className="mt-3 flex items-center gap-2 text-xs text-ink-300">
                  <span className={clsx("h-1.5 w-1.5 rounded-full", banner.dot)} />
                  {banner.footer}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="glass flex max-w-full items-center gap-1 overflow-x-auto rounded-full p-1.5">
          {TABS.map((t) => (
            <NavLink
              key={t.to}
              to={t.to}
              className={({ isActive }) =>
                clsx(
                  "btn whitespace-nowrap rounded-full px-4 py-2 text-sm",
                  isActive
                    ? "bg-[rgb(var(--panel-strong))] text-accent-blue shadow-sm"
                    : "text-ink-300 hover:bg-white/40 hover:text-ink-100",
                )
              }
            >
              {t.icon}
              {t.label}
            </NavLink>
          ))}
        </div>

        <div className="flex items-center gap-2">
          {caseId && <UploadPanel caseId={caseId} status={c?.status} />}
          {caseId && <AnalyzeButton caseId={caseId} status={c?.status} />}
        </div>
      </div>

      {caseBusy && (
        <div className="glass flex items-center gap-3 rounded-2xl border border-accent-blue/25 px-4 py-3 text-sm text-ink-200" role="status">
          <Loader2 size={17} className="animate-spin text-accent-blue" />
          <div className="min-w-0">
            <div className="font-semibold text-ink-100">
              {c?.status === "ingesting" ? "Evidence processing is running" : "Case analysis is running"}
            </div>
            <div className="truncate text-xs text-ink-400">
              The case stays readable while editing actions wait for this operation to finish.
            </div>
          </div>
        </div>
      )}

      <Suspense fallback={<Spinner label="Loading…" />}>
        <div aria-busy={caseBusy}>
          <Outlet />
        </div>
      </Suspense>
    </div>
  );
}

function CaseField({ label, value, icon }: { label: string; value: string; icon?: ReactNode }) {
  return (
    <div>
      <div className="text-xs font-semibold text-ink-300">{label}</div>
      <div className="mt-1 flex min-w-0 items-center gap-2 font-semibold text-ink-100">
        {icon ?? <Database size={15} className="text-ink-400" />}
        <span className="truncate">{value}</span>
      </div>
    </div>
  );
}

function fmtDate(ts: string) {
  return new Date(ts).toLocaleDateString(undefined, {
    month: "short",
    day: "2-digit",
    year: "numeric",
  });
}
