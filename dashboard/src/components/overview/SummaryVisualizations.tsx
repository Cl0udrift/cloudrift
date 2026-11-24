import type { ScanSummaryResponse } from "../../api/types";
import { BarChart, DonutChart } from "@tremor/react";
import { formatCount, formatUsd } from "../../lib/format";
import { EXEC_CHART_COLORS } from "./chartColors";

export type SummaryDrilldownHandlers = {
  onSeverityClick?: (severity: "critical" | "high" | "medium" | "low") => void;
  onModuleClick?: (module: string) => void;
  onClaimabilityClick?: (claimability: "reclaimable" | "dangling" | "broken" | "edge_obscured") => void;
};

function pct(part: number, total: number): number {
  if (total <= 0) {
    return 0;
  }
  return Math.round((100 * part) / total);
}

/**
 * Horizontal stacked bar: shares of findings by severity (API counts only).
 *
 * low_count semantics: the API increments `low_count` for every finding whose severity is
 * not critical, high, or medium (see summarizeScan default branch). That single bucket can
 * therefore mix explicit "low" severities with any other non-medium value the model allows
 * (e.g. info-style labels). UI label "Low / info" reflects that aggregation — not a
 * separate info counter from the backend.
 */
export function SeverityDistribution({
  summary,
  onSeverityClick
}: {
  summary: ScanSummaryResponse;
  onSeverityClick?: SummaryDrilldownHandlers["onSeverityClick"];
}) {
  const rows: { key: "critical" | "high" | "medium" | "low"; label: string; count: number; bar: string; dot: string }[] = [
    { key: "critical", label: "Critical", count: summary.critical_count, bar: "bg-rose-500", dot: "bg-rose-500" },
    { key: "high", label: "High", count: summary.high_count, bar: "bg-amber-500", dot: "bg-amber-500" },
    { key: "medium", label: "Medium", count: summary.medium_count, bar: "bg-cyan-500", dot: "bg-cyan-500" },
    { key: "low", label: "Low / info", count: summary.low_count, bar: "bg-slate-400", dot: "bg-slate-400" }
  ];
  const total = rows.reduce((n, r) => n + r.count, 0);

  return (
    <div className="hs-card p-5">
      <h3 className="cr-section-title">Findings by severity</h3>
      {total === 0 ? (
        <p className="mt-3 text-sm text-slate-500">No findings in this scan.</p>
      ) : (
        <>
          <div className="mt-4 flex h-3 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800" role="img" aria-label={rows.map((r) => `${r.count} ${r.label}`).join(", ")}>
            {rows.filter((r) => r.count > 0).map((r) => (
              <span key={r.key} className={r.bar} style={{ width: `${(r.count / total) * 100}%` }} />
            ))}
          </div>
          <ul className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {rows.map((r) => (
              <li key={r.key}>
                <button
                  type="button"
                  disabled={r.count === 0}
                  onClick={() => onSeverityClick?.(r.key)}
                  className={`hs-focus-ring w-full rounded-md px-2 py-1.5 text-left ${r.count > 0 ? "hover:bg-slate-100 dark:hover:bg-slate-800/70" : "opacity-50"}`}
                >
                  <span className="flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-400">
                    <span className={`h-2 w-2 rounded-full ${r.dot}`} />
                    {r.label}
                  </span>
                  <span className="mt-0.5 block text-xl font-semibold tabular-nums text-slate-900 dark:text-slate-100">{formatCount(r.count)}</span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

const MODULE_LABEL: Record<string, string> = {
  iam_entitlement: "Identity and access",
  external_access: "Trust and exposure",
  orphaned_edge: "Takeover risk",
  unused_resource: "Unused resources"
};

/** Findings by module, every module the scan produced. Hidden when there are none. */
export function ModuleDistribution({
  summary,
  onModuleClick
}: {
  summary: ScanSummaryResponse;
  onModuleClick?: (module: string) => void;
}) {
  const rows = Object.entries(summary.module_counts ?? {})
    .filter(([, n]) => n > 0)
    .map(([module, count]) => ({ module, label: MODULE_LABEL[module] ?? module.replace(/_/g, " "), count }))
    .sort((x, y) => y.count - x.count);
  const total = rows.reduce((n, r) => n + r.count, 0);
  if (total === 0) {
    return null;
  }
  return (
    <div className="hs-card p-5">
      <h3 className="cr-section-title">Findings by area</h3>
      <p className="cr-helper mt-1">Where the findings are: identity and access, trust and exposure, takeover risk.</p>
      <div className="cr-chart-focusable mt-4 rounded-md" tabIndex={0} aria-label="Findings by area donut chart">
        <div className="mt-2 flex items-center justify-center">
          <DonutChart
            className="h-44"
            data={rows.map((r) => ({ label: r.label, value: r.count }))}
            category="value"
            index="label"
            colors={["cyan", "violet", "amber", "slate"]}
            valueFormatter={(value) => formatCount(value)}
            showAnimation
            onValueChange={(value) => {
              const row = rows.find((r) => r.label === value?.label);
              if (row && onModuleClick) onModuleClick(row.module);
            }}
          />
        </div>
        <ul className="mt-4 space-y-2 text-sm text-slate-700 dark:text-slate-300">
          {rows.map((r) => (
            <li key={r.module} className="flex cursor-pointer justify-between gap-4 rounded px-1 py-1 hover:bg-slate-100 dark:hover:bg-slate-800/70" onClick={() => onModuleClick?.(r.module)}>
              <span>{r.label}</span>
              <span className="tabular-nums text-slate-600 dark:text-slate-400">{formatCount(r.count)} ({pct(r.count, total)}%)</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

/** Claimability buckets from summary (API fields only). */
export function ClaimabilityDistribution({
  summary,
  onClaimabilityClick
}: {
  summary: ScanSummaryResponse;
  onClaimabilityClick?: SummaryDrilldownHandlers["onClaimabilityClick"];
}) {
  const rows: { key: string; label: string; count: number }[] = [
    { key: "reclaimable", label: "Reclaimable", count: summary.reclaimable_count },
    { key: "dangling", label: "Dangling", count: summary.dangling_count },
    { key: "broken", label: "Broken", count: summary.broken_count },
    { key: "edge_obscured", label: "Edge obscured", count: summary.edge_obscured_count }
  ].sort((a, b) => b.count - a.count);
  const total = rows.reduce((s, r) => s + r.count, 0);
  if (total === 0) {
    return null;
  }

  return (
    <div className="hs-card p-5">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400">Takeover findings by state</h3>
      <p className="mt-1 text-[11px] text-slate-500">Reclaimable, dangling, broken and edge-obscured findings.</p>
      {(
        <div
          className="cr-chart-focusable mt-4 rounded-md"
          tabIndex={0}
          aria-label="Claimability breakdown chart"
        >
          <BarChart
            className="h-[220px]"
            data={rows.map((row) => ({ label: row.label, key: row.key, count: row.count }))}
            index="label"
            categories={["count"]}
            layout="vertical"
            colors={["emerald"]}
            yAxisWidth={100}
            valueFormatter={(value) => formatCount(value)}
            onValueChange={(value) => {
              const key = rows.find((row) => row.label === value?.label)?.key;
              if (key && onClaimabilityClick) {
                onClaimabilityClick(key as "reclaimable" | "dangling" | "broken" | "edge_obscured");
              }
            }}
          />
        </div>
      )}
    </div>
  );
}

/** Scan-level monthly USD split: direct vs risk (summary totals only — not per service). */
export function DirectVsRiskCostSplit({ summary }: { summary: ScanSummaryResponse }) {
  const direct = summary.total_monthly_direct_cost_usd;
  const risk = summary.total_monthly_risk_cost_usd;
  const totalUsd = direct + risk;

  return (
    <div className="hs-card p-5">
      <h3 className="cr-section-title">Cost split</h3>
      <p className="cr-helper mt-1">Direct cost vs risk-adjusted cost (monthly).</p>
      {totalUsd <= 0 ? (
        <p className="mt-3 text-sm text-slate-500">No monthly cost totals in summary.</p>
      ) : (
        <>
          <div
            className="cr-chart-focusable mt-3 flex items-center justify-center rounded-md"
            tabIndex={0}
            aria-label="Cost split donut chart for direct and risk-adjusted monthly cost"
          >
            <DonutChart
              className="h-52"
              data={[
                { label: "Direct cost", value: Math.round(direct * 100) / 100 },
                { label: "Risk-adjusted cost", value: Math.round(risk * 100) / 100 }
              ]}
              category="value"
              index="label"
              colors={[EXEC_CHART_COLORS.costSplit.direct, EXEC_CHART_COLORS.costSplit.riskAdjusted]}
              valueFormatter={(value) => formatUsd(value)}
              showAnimation
            />
          </div>
          <ul className="mt-4 space-y-2 text-sm text-slate-700 dark:text-slate-300">
            <li className="flex justify-between gap-4">
              <span className="flex items-center gap-2">
                <span className="h-2 w-2 shrink-0 rounded-sm bg-emerald-600" />
                Direct / mo
              </span>
              <span className="tabular-nums text-slate-600 dark:text-slate-400">
                {formatUsd(direct)} ({pct(direct, totalUsd)}%)
              </span>
            </li>
            <li className="flex justify-between gap-4">
              <span className="flex items-center gap-2">
                <span className="h-2 w-2 shrink-0 rounded-sm bg-rose-600/90" />
                Risk-adjusted / mo
              </span>
              <span className="tabular-nums text-slate-600 dark:text-slate-400">
                {formatUsd(risk)} ({pct(risk, totalUsd)}%)
              </span>
            </li>
          </ul>
        </>
      )}
    </div>
  );
}
