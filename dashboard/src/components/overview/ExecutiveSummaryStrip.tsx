import type { ScanSummaryResponse } from "../../api/types";
import { formatCount, formatUsd } from "../../lib/format";

const emphasisBorder: Record<string, string> = {
  rose: "border-l-rose-500/80",
  violet: "border-l-violet-500/70",
  emerald: "border-l-emerald-500/70",
  neutral: "border-l-slate-300 dark:border-l-slate-600"
};

function formatDelta(delta: number, kind: "count" | "usd"): string {
  if (!Number.isFinite(delta)) {
    return "—";
  }
  if (delta === 0) {
    return "No change";
  }
  const sign = delta > 0 ? "+" : "";
  if (kind === "usd") {
    return `${sign}${formatUsd(delta)}`;
  }
  return `${sign}${formatCount(delta)}`;
}

function TinySparkline({ data }: { data: number[] }) {
  if (data.length < 2) {
    return <div className="h-4 w-16 rounded bg-slate-200/70 dark:bg-slate-800/70" />;
  }
  const min = Math.min(...data);
  const max = Math.max(...data);
  const span = Math.max(1, max - min);
  const width = 64;
  const height = 16;
  const points = data
    .map((v, i) => {
      const x = (i / (data.length - 1)) * width;
      const y = height - ((v - min) / span) * height;
      return `${x},${y}`;
    })
    .join(" ");
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="h-4 w-16 overflow-visible">
      <polyline
        points={points}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        className="text-slate-400 dark:text-slate-500"
      />
    </svg>
  );
}

function ExecCard({
  label,
  value,
  delta,
  sparkline,
  deltaKind = "count",
  emphasis = "neutral",
  onClick
}: {
  label: string;
  value: string;
  delta?: number;
  sparkline?: number[];
  deltaKind?: "count" | "usd";
  emphasis?: keyof typeof emphasisBorder;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`hs-kpi-card flex h-28 flex-col justify-between ${emphasisBorder[emphasis]}`}
    >
      <p className="text-[11px] font-medium uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-2 text-2xl font-semibold tabular-nums tracking-tight text-slate-900 dark:text-slate-100">{value}</p>
      <div className="mt-2 flex items-center justify-between gap-2">
        <span className="text-[11px] text-slate-500">{delta === undefined ? "—" : formatDelta(delta, deltaKind)}</span>
        {sparkline ? <TinySparkline data={sparkline} /> : <div className="h-4 w-16" />}
      </div>
    </button>
  );
}

export function ExecutiveSummaryStrip({
  summary,
  onOpenCritical,
  onOpenHigh,
  onOpenRiskCost,
  onOpenExternal,
  onOpenReclaimable,
  criticalDelta,
  riskDelta,
  criticalSparkline,
  riskSparkline
}: {
  summary: ScanSummaryResponse;
  onOpenCritical: () => void;
  onOpenHigh: () => void;
  onOpenRiskCost: () => void;
  onOpenExternal: () => void;
  onOpenReclaimable: () => void;
  criticalDelta?: number;
  riskDelta?: number;
  criticalSparkline?: number[];
  riskSparkline?: number[];
}) {
  return (
    <div>
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
        Executive summary
      </h2>
      <div className="grid gap-4 [grid-template-columns:repeat(auto-fit,minmax(15rem,1fr))]">
        <ExecCard
          label="Critical findings"
          value={formatCount(summary.critical_count)}
          delta={criticalDelta}
          sparkline={criticalSparkline}
          emphasis="rose"
          onClick={onOpenCritical}
        />
        <ExecCard label="High findings" value={formatCount(summary.high_count)} delta={undefined} emphasis="neutral" onClick={onOpenHigh} />
        {/* Dollar cost exists only for orphaned-edge findings, and at list price it is usually $0. A $0.00 tile on a scan of
            identity findings reads as "no risk", so it is shown only when there is a figure. */}
        {summary.total_monthly_risk_cost_usd > 0 ? (
          <ExecCard
            label="Modeled risk cost / mo (estimate)"
            value={formatUsd(summary.total_monthly_risk_cost_usd)}
            delta={riskDelta}
            sparkline={riskSparkline}
            deltaKind="usd"
            emphasis="neutral"
            onClick={onOpenRiskCost}
          />
        ) : null}
        <ExecCard
          label="External access"
          value={formatCount(summary.external_access_count)}
          delta={undefined}
          emphasis="violet"
          onClick={onOpenExternal}
        />
        {summary.reclaimable_count > 0 ? (
          <ExecCard
            label="Reclaimable assets"
            value={formatCount(summary.reclaimable_count)}
            delta={undefined}
            emphasis="emerald"
            onClick={onOpenReclaimable}
          />
        ) : null}
      </div>
    </div>
  );
}
