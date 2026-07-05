import type { ReactNode } from "react";
import type { Severity } from "../lib/types";
import { severityChip } from "../lib/ui";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`chip ${severityChip(severity)}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {severity}
    </span>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-ink-300 text-sm">
      <span className="w-4 h-4 rounded-full border-2 border-accent-cyan/30 border-t-accent-cyan animate-spin" />
      {label}
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  hint,
  action,
}: {
  icon?: ReactNode;
  title: string;
  hint?: string;
  action?: ReactNode;
}) {
  return (
    <div className="card p-12 flex flex-col items-center justify-center text-center gap-3">
      {icon && <div className="text-ink-400">{icon}</div>}
      <div className="text-lg font-semibold text-ink-100">{title}</div>
      {hint && <div className="text-sm text-ink-400 max-w-md">{hint}</div>}
      {action}
    </div>
  );
}

export function StatCard({
  label,
  value,
  accent,
  icon,
}: {
  label: string;
  value: ReactNode;
  accent?: string;
  icon?: ReactNode;
}) {
  return (
    <div className="card p-4 flex items-center gap-4">
      {icon && (
        <div
          className="grid place-items-center w-11 h-11 rounded-lg"
          style={{ background: `${accent ?? "#22d3ee"}18`, color: accent ?? "#22d3ee" }}
        >
          {icon}
        </div>
      )}
      <div>
        <div className="text-2xl font-bold text-ink-50 leading-none">{value}</div>
        <div className="text-xs uppercase tracking-wider text-ink-400 mt-1">{label}</div>
      </div>
    </div>
  );
}

export function Section({
  title,
  right,
  children,
}: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-ink-200">
          {title}
        </h2>
        {right}
      </div>
      {children}
    </div>
  );
}

export function CodeBlock({ children }: { children: ReactNode }) {
  return (
    <pre className="bg-base-900/70 border border-white/5 rounded-lg p-3 text-xs font-mono text-ink-200 overflow-x-auto whitespace-pre-wrap break-words">
      {children}
    </pre>
  );
}
