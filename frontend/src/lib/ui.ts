import type { Severity } from "./types";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#64748b",
};

export function severityChip(sev: Severity): string {
  const map: Record<Severity, string> = {
    critical: "bg-sev-critical/15 text-sev-critical border border-sev-critical/30",
    high: "bg-sev-high/15 text-sev-high border border-sev-high/30",
    medium: "bg-sev-medium/15 text-sev-medium border border-sev-medium/30",
    low: "bg-sev-low/15 text-sev-low border border-sev-low/30",
    info: "bg-sev-info/15 text-ink-200 border border-sev-info/30",
  };
  return map[sev] || map.info;
}

export function fmtTime(ts: string | null | undefined): string {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

export function fmtRelative(ts: string | null | undefined): string {
  if (!ts) return "—";
  const then = new Date(ts).getTime();
  const now = Date.now();
  const diff = Math.floor((now - then) / 1000);
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
