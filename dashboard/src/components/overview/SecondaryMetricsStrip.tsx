import type { ScanSummaryResponse } from "../../api/types";
import { formatCount } from "../../lib/format";

// Each accent needs an explicit dark: variant: hs-card applies `dark:border-slate-700`
// to all borders, and under `.dark` that two-class rule outranks a single-class
// `border-l-*` accent - so without a `dark:border-l-*` the colored left edge is
// overridden to slate and disappears in dark mode.
const border: Record<string, string> = {
  orange: "border-l-orange-500/80 dark:border-l-orange-500/80",
  cyan: "border-l-cyan-500/70 dark:border-l-cyan-500/70",
  slate: "border-l-slate-300 dark:border-l-slate-600",
  amber: "border-l-amber-500/75 dark:border-l-amber-500/75"
};

function MiniKpi({
  label,
  value,
  tone,
  onClick
}: {
  label: string;
  value: string;
  tone: keyof typeof border;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`hs-kpi-card px-3 py-3 text-sm ${border[tone]}`}
    >
      <p className="text-[10px] font-medium uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-lg font-semibold tabular-nums text-slate-900 dark:text-slate-100">{value}</p>
    </button>
  );
}

export function SecondaryMetricsStrip({
  summary,
  onOpenHigh,
  onOpenMedium,
  onOpenAll,
  onOpenOrphaned
}: {
  summary: ScanSummaryResponse;
  onOpenHigh: () => void;
  onOpenMedium: () => void;
  onOpenAll: () => void;
  onOpenOrphaned: () => void;
}) {
  return (
    <div>
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
        Counts
      </h2>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MiniKpi label="High findings" value={formatCount(summary.high_count)} tone="orange" onClick={onOpenHigh} />
        <MiniKpi label="Medium findings" value={formatCount(summary.medium_count)} tone="amber" onClick={onOpenMedium} />
        <MiniKpi label="Total findings" value={formatCount(summary.finding_count)} tone="slate" onClick={onOpenAll} />
        <MiniKpi label="Takeover risk" value={formatCount(summary.orphaned_edge_count)} tone="cyan" onClick={onOpenOrphaned} />
      </div>
    </div>
  );
}
