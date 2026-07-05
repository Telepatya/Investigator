import { NavLink, Outlet, useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  LayoutDashboard,
  FolderOpen,
  Clock,
  Boxes,
  HardDrive,
  AlertTriangle,
  List,
  FileText,
  MessageSquare,
  ChevronLeft,
} from "lucide-react";
import { api } from "../lib/api";
import { UploadPanel } from "../components/UploadPanel";
import { AnalyzeButton } from "../components/AnalyzeButton";

const TABS = [
  { to: "overview", label: "Overview", icon: <LayoutDashboard size={16} /> },
  { to: "evidence", label: "Evidence", icon: <FolderOpen size={16} /> },
  { to: "timeline", label: "Timeline", icon: <Clock size={16} /> },
  { to: "entities", label: "Entity Map", icon: <Boxes size={16} /> },
  { to: "memory", label: "Memory", icon: <HardDrive size={16} /> },
  { to: "findings", label: "Findings", icon: <AlertTriangle size={16} /> },
  { to: "events", label: "Events", icon: <List size={16} /> },
  { to: "report", label: "Report", icon: <FileText size={16} /> },
  { to: "chat", label: "AI Chat", icon: <MessageSquare size={16} /> },
];

export default function CaseLayout() {
  const { caseId } = useParams();
  const { data: c } = useQuery({
    queryKey: ["case", caseId],
    queryFn: () => api.getCase(caseId!),
    refetchInterval: 4000,
    enabled: !!caseId,
  });

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="flex items-start gap-3">
          <Link to="/" className="btn-ghost mt-0.5">
            <ChevronLeft size={16} />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-ink-50">{c?.name ?? "…"}</h1>
            <p className="text-sm text-ink-400 mt-0.5 max-w-2xl">
              {c?.description || "No description"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {caseId && <UploadPanel caseId={caseId} />}
          {caseId && <AnalyzeButton caseId={caseId} status={c?.status} />}
        </div>
      </div>

      <div className="glass rounded-xl p-1 flex items-center gap-1 overflow-x-auto">
        {TABS.map((t) => (
          <NavLink
            key={t.to}
            to={t.to}
            className={({ isActive }) =>
              `btn ${
                isActive
                  ? "bg-accent-cyan/15 text-accent-cyan"
                  : "text-ink-300 hover:bg-white/5 hover:text-ink-100"
              } whitespace-nowrap`
            }
          >
            {t.icon}
            {t.label}
          </NavLink>
        ))}
      </div>

      <Outlet />
    </div>
  );
}
