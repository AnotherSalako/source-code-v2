import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";

function cx(...classes: Array<string | false | undefined>): string {
  return classes.filter(Boolean).join(" ");
}

export function Card({ className, children, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cx(
        "rounded-[var(--radius-card)] border border-line bg-[color:var(--color-surface-glass)] p-6 shadow-[var(--shadow-lift)] backdrop-blur-2xl backdrop-saturate-150",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function DarkCard({ className, children, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cx(
        "rounded-[var(--radius-card)] bg-ink p-6 text-paper shadow-[var(--shadow-lift-lg)]",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "solid" | "ghost" | "outline";
}

export function Button({ variant = "solid", className, children, ...props }: ButtonProps) {
  const base = "inline-flex items-center justify-center gap-2 rounded-[var(--radius-pill)] px-5 py-2.5 text-sm font-semibold transition-transform active:scale-[0.98] disabled:opacity-40 disabled:pointer-events-none";
  const variants = {
    solid: "bg-ink text-paper hover:bg-ink-soft",
    outline: "border border-line-soft bg-surface text-ink hover:bg-paper",
    ghost: "text-ink-soft hover:text-ink hover:bg-line-soft",
  } as const;
  return (
    <button className={cx(base, variants[variant], className)} {...props}>
      {children}
    </button>
  );
}

export function IconButton({ className, children, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={cx(
        "flex h-10 w-10 items-center justify-center rounded-full border border-line-soft bg-[color:var(--color-surface-glass)] text-ink-soft shadow-[var(--shadow-lift)] backdrop-blur-xl backdrop-saturate-150 transition-colors hover:text-ink",
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}

export function Pill({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-[var(--radius-pill)] px-3 py-1 text-xs font-medium",
        className
      )}
    >
      {children}
    </span>
  );
}

export function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-3xl border border-dashed border-line py-16 text-center">
      <p className="font-semibold text-ink">{title}</p>
      {hint && <p className="max-w-sm text-sm text-ink-faint">{hint}</p>}
      {action}
    </div>
  );
}

export function SectionLabel({ children }: { children: ReactNode }) {
  return <p className="mb-3 text-xs font-semibold uppercase tracking-[0.12em] text-ink-faint">{children}</p>;
}

export function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1.5 text-sm">
      <span className="font-medium text-ink-soft">{label}</span>
      {children}
    </label>
  );
}

export const inputClass =
  "rounded-2xl border border-line-soft bg-paper px-4 py-2.5 text-sm text-ink outline-none transition-colors focus:border-ink/30 focus:bg-surface";
