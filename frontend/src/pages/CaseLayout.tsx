import { NavLink, Outlet, useParams } from "react-router-dom";
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  Boxes,
  Calendar,
  Clock,
  Database,
  FileText,
  FolderOpen,
  HardDrive,
  LayoutDashboard,
  List,
  MessageSquare,
  ShieldCheck,
  Star,
  User,
} from "lucide-react";
import { clsx } from "clsx";
import { api } from "../lib/api";
import { UploadPanel } from "../components/UploadPanel";
import { AnalyzeButton } from "../components/AnalyzeButton";
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
];

export default function CaseLayout() {
  const { caseId } = useParams();
  const { data: c } = useQuery({
    queryKey: ["case", caseId],
    queryFn: () => api.getCase(caseId!),
    refetchInterval: 4000,
    enabled: !!caseId,
  });

  const clean = (c?.finding_count ?? 0) === 0;

  return (
    <div className="page-enter space-y-5">
      <section className="surface overflow-hidden p-5 md:p-7">
        <div className="grid gap-6 xl:grid-cols-[1fr_540px]">
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <h1 className="truncate text-4xl font-extrabold tracking-tight text-ink-50 md:text-5xl">
                {c?.name ?? "..."}
              </h1>
              <button className="text-ink-500 transition hover:text-accent-blue" title="Favorite case">
                <Star size={24} />
              </button>
            </div>
            <p className="mt-3 max-w-3xl text-sm text-ink-300">
              {c?.description || "No description"}
            </p>

            <div className="mt-6 grid gap-4 text-sm text-ink-200 sm:grid-cols-2 xl:grid-cols-4">
              <CaseField label="Case ID" value={caseId ?? "-"} />
              <CaseField label="Owner" value="Alex Rivera" icon={<User size={15} />} />
              <CaseField label="Created" value={c ? fmtDate(c.created_at) : "-"} icon={<Calendar size={15} />} />
              <CaseField label="Last Updated" value={c ? fmtTime(c.updated_at) : "-"} icon={<Clock size={15} />} />
            </div>
          </div>

          <div className={clsx("rounded-3xl border p-5", clean ? "border-emerald-400/25 bg-emerald-400/10" : "border-sev-high/25 bg-sev-high/10")}>
            <div className="flex items-center gap-4">
              <div className={clsx("grid h-16 w-16 place-items-center rounded-3xl", clean ? "bg-emerald-400/10 text-emerald-500" : "bg-sev-high/10 text-sev-high")}>
                {clean ? <ShieldCheck size={34} /> : <AlertTriangle size={34} />}
              </div>
              <div>
                <div className="text-lg font-bold text-ink-50">
                  {clean ? "Environment appears clean" : "Findings need review"}
                </div>
                <div className="mt-1 text-sm text-ink-300">
                  {clean ? "No ongoing threat detected" : `${c?.finding_count ?? 0} finding${c?.finding_count === 1 ? "" : "s"} detected`}
                </div>
                <div className="mt-3 flex items-center gap-2 text-xs text-ink-300">
                  <span className={clsx("h-1.5 w-1.5 rounded-full", clean ? "bg-emerald-500" : "bg-sev-high")} />
                  Last scan: {c ? fmtTime(c.updated_at) : "not available"}
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
          {caseId && <UploadPanel caseId={caseId} />}
          {caseId && <AnalyzeButton caseId={caseId} status={c?.status} />}
        </div>
      </div>

      <Outlet />
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
