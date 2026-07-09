import { useEffect, type ButtonHTMLAttributes, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { clsx } from "clsx";
import { X } from "lucide-react";
import type { Severity } from "../lib/types";
import { severityChip } from "../lib/ui";

export function PageShell({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx("page-enter space-y-5", className)}>{children}</div>;
}

export function PageTitle({
  icon,
  title,
  subtitle,
  right,
}: {
  icon?: ReactNode;
  title: string;
  subtitle?: ReactNode;
  right?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 flex-wrap">
      <div className="flex items-start gap-3 min-w-0">
        {icon && (
          <div className="grid h-11 w-11 place-items-center rounded-2xl bg-accent-blue/10 text-accent-blue ring-1 ring-accent-blue/20">
            {icon}
          </div>
        )}
        <div className="min-w-0">
          <h1 className="text-2xl font-extrabold tracking-tight text-ink-50">{title}</h1>
          {subtitle && <div className="mt-1 text-sm text-ink-300">{subtitle}</div>}
        </div>
      </div>
      {right}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`chip capitalize ${severityChip(severity)}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {severity}
    </span>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="card flex items-center gap-3 px-4 py-3 text-sm text-ink-300">
      <span className="h-4 w-4 rounded-full border-2 border-accent-blue/25 border-t-accent-blue animate-spin" />
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
    <div className="card flex min-h-[280px] flex-col items-center justify-center gap-3 p-12 text-center">
      {icon && (
        <div className="grid h-16 w-16 place-items-center rounded-3xl bg-accent-blue/10 text-accent-blue ring-1 ring-accent-blue/20">
          {icon}
        </div>
      )}
      <div className="text-lg font-semibold text-ink-100">{title}</div>
      {hint && <div className="max-w-md text-sm text-ink-300">{hint}</div>}
      {action}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  accent,
  icon,
  trend,
}: {
  label: string;
  value: ReactNode;
  accent?: string;
  icon?: ReactNode;
  trend?: ReactNode;
}) {
  const color = accent ?? "rgb(var(--accent-blue))";
  return (
    <div className="card interactive-lift flex min-h-[92px] items-center gap-4 p-4">
      {icon && (
        <div
          className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl"
          style={{ background: `color-mix(in srgb, ${color} 14%, transparent)`, color }}
        >
          {icon}
        </div>
      )}
      <div className="min-w-0">
        <div className="text-xs font-medium text-ink-300">{label}</div>
        <div className="mt-1 text-2xl font-extrabold leading-none text-ink-50">{value}</div>
        {trend && <div className="mt-2 text-[11px] text-ink-300">{trend}</div>}
      </div>
    </div>
  );
}

export function Section({
  title,
  right,
  children,
  className,
}: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={clsx("card p-5", className)}>
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="text-sm font-bold text-ink-100">{title}</h2>
        {right}
      </div>
      {children}
    </div>
  );
}

export function SegmentedControl<T extends string>({
  value,
  options,
  onChange,
  className,
}: {
  value: T;
  options: { value: T; label: ReactNode; icon?: ReactNode }[];
  onChange: (value: T) => void;
  className?: string;
}) {
  return (
    <div className={clsx("glass inline-flex items-center gap-1 rounded-2xl p-1", className)}>
      {options.map((option) => (
        <button
          key={option.value}
          className={clsx(
            "btn px-3 py-1.5 text-xs",
            value === option.value
              ? "bg-[rgb(var(--panel-strong))] text-accent-blue shadow-sm"
              : "text-ink-300 hover:bg-white/40 hover:text-ink-100",
          )}
          onClick={() => onChange(option.value)}
        >
          {option.icon}
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function IconButton({
  children,
  label,
  active,
  danger,
  className,
  ...props
}: {
  children: ReactNode;
  label: string;
  active?: boolean;
  danger?: boolean;
  className?: string;
} & ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      aria-label={label}
      title={label}
      className={clsx(
        "grid h-10 w-10 place-items-center rounded-2xl border transition-all duration-200 active:scale-95",
        active
          ? "border-accent-blue/40 bg-accent-blue/10 text-accent-blue shadow-glow"
          : danger
            ? "border-sev-critical/20 bg-sev-critical/10 text-sev-critical hover:bg-sev-critical/15"
            : "border-[rgb(var(--border)/0.65)] bg-[rgb(var(--panel-strong)/0.58)] text-ink-300 hover:-translate-y-0.5 hover:text-accent-blue",
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}

export function DetailDrawer({
  eyebrow,
  title,
  children,
  onClose,
  ariaLabel,
}: {
  eyebrow: ReactNode;
  title?: ReactNode;
  children: ReactNode;
  onClose: () => void;
  ariaLabel?: string;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const drawer = (
    <>
      <div
        className="fixed inset-0 z-[999] bg-[rgb(var(--shadow)/0.34)] backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        className="detail-drawer-surface fixed inset-y-0 right-0 z-[1000] w-full max-w-md overflow-y-auto p-5"
        role="dialog"
        aria-modal="true"
        aria-label={ariaLabel ?? "Detail drawer"}
      >
      <div className="mb-4 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-xs font-semibold uppercase tracking-wider text-ink-400">{eyebrow}</div>
          {title && <div className="mt-1 truncate text-lg font-semibold text-ink-50">{title}</div>}
        </div>
        <button
          className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-[rgb(var(--panel-strong)/0.78)] text-ink-400 transition hover:bg-[rgb(var(--panel-strong)/0.96)] hover:text-ink-100 active:scale-95"
          onClick={onClose}
          title="Close"
        >
          <X size={18} />
        </button>
      </div>
        {children}
      </div>
    </>
  );

  return createPortal(drawer, document.body);
}

export function CodeBlock({ children }: { children: ReactNode }) {
  return (
    <pre className="overflow-x-auto whitespace-pre-wrap break-words rounded-2xl border border-[rgb(var(--border)/0.65)] bg-[rgb(var(--panel-muted)/0.72)] p-3 font-mono text-xs text-ink-200">
      {children}
    </pre>
  );
}
