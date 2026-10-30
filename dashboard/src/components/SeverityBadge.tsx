const severityRing: Record<string, string> = {
  critical: "bg-rose-100 text-rose-800 ring-rose-300/60 dark:bg-rose-950/80 dark:text-rose-200 dark:ring-rose-700/60",
  high: "bg-orange-100 text-orange-800 ring-orange-300/60 dark:bg-orange-950/70 dark:text-orange-200 dark:ring-orange-700/50",
  medium: "bg-amber-100 text-amber-800 ring-amber-300/60 dark:bg-amber-950/60 dark:text-amber-100 dark:ring-amber-700/40",
  low: "bg-slate-200 text-slate-800 ring-slate-400/50 dark:bg-slate-800 dark:text-slate-200 dark:ring-slate-600/50",
  info: "bg-slate-200 text-slate-700 ring-slate-400/50 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-600/50"
};

// Shape cue so severity is not conveyed by color alone.
const severityGlyph: Record<string, string> = { critical: "◆", high: "▲", medium: "■", low: "●", info: "○" };

export function severityBadgeClass(severity: string): string {
  const key = severity.toLowerCase();
  return severityRing[key] ?? severityRing.info;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const label = severity ? severity : "—";
  return (
    <span
      className={`inline-flex rounded px-2 py-0.5 text-xs font-medium capitalize ring-1 ${severityBadgeClass(label)}`}
    >
      <span aria-hidden="true" className="mr-1">{severityGlyph[label.toLowerCase()] ?? "○"}</span>
      {label}
    </span>
  );
}

/** Bar segment color (Tailwind bg class) aligned with badges. */
export function severityBarClass(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-rose-500";
    case "high":
      return "bg-orange-500";
    case "medium":
      return "bg-amber-400";
    case "low":
      return "bg-slate-500";
    default:
      return "bg-slate-600";
  }
}
