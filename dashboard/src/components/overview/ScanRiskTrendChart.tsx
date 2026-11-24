import { Link } from "react-router-dom";
import { BarChart } from "@tremor/react";
import type { ScanListItem } from "../../api/types";
import { useScanRiskTrendData } from "../../hooks/useDashboardQueries";
import { formatCount } from "../../lib/format";
import { scansOfSameAccounts } from "../../lib/scanOrder";
import { EXEC_CHART_COLORS } from "./chartColors";

export function ScanRiskTrendChart({
  scans,
  selectedScanId,
  enabled
}: {
  scans: ScanListItem[];
  selectedScanId: string | null;
  enabled: boolean;
}) {
  const sameScans = scansOfSameAccounts(scans, selectedScanId);
  const { points, isLoading, pairCount } = useScanRiskTrendData(sameScans, enabled && sameScans.length >= 2);

  if (!enabled || pairCount === 0) {
    return (
      <div className="rounded-lg border border-slate-200 bg-white/80 p-5 dark:border-slate-800 dark:bg-slate-900/80">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400">Risk trend</h3>
        <p className="mt-2 text-sm text-slate-500">Run at least two scans of the same accounts to see what changed between them.</p>
      </div>
    );
  }

  // Points come newest first; a time axis reads oldest to newest.
  const chartData = [...points].reverse().map((p) => ({
    label: p.label,
    New: p.isError ? 0 : p.newCount,
    Fixed: p.isError ? 0 : p.fixedCount,
    "Gone (deleted or not scanned)": p.isError ? 0 : p.goneCount
  }));

  const quiet = points.every((p) => p.newCount + p.fixedCount + p.goneCount === 0);
  return (
    <div className="hs-card p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <h3 className="cr-section-title">Risk trend</h3>
          <p className="cr-helper mt-1">New findings, likely fixes, and findings that left because the resource was deleted or the account was not scanned.</p>
        </div>
        {selectedScanId ? (
          <Link
            to={`/diff?scan_id=${encodeURIComponent(selectedScanId)}`}
            className="text-xs font-medium text-cyan-700 underline-offset-2 hover:underline dark:text-cyan-300/90"
          >
            Open changes
          </Link>
        ) : null}
      </div>

      {isLoading ? (
        <p className="mt-4 text-sm text-slate-500">Loading changes…</p>
      ) : quiet ? (
        <p className="mt-4 text-sm text-slate-700 dark:text-slate-300">Nothing changed across the last {points.length} {points.length === 1 ? "scan" : "scans"}: no new findings, none fixed, none gone.</p>
      ) : (
        <div
          className="cr-chart-focusable mt-4 rounded-md"
          tabIndex={0}
          aria-label="Risk trend area chart showing new, fixed and gone findings over time"
        >
          <BarChart
            className="h-52"
            stack
            allowDecimals={false}
            data={chartData}
            index="label"
            categories={["New", "Fixed", "Gone (deleted or not scanned)"]}
            colors={[EXEC_CHART_COLORS.trend.newFindings, EXEC_CHART_COLORS.trend.resolvedFindings, "slate"]}
            showAnimation
            yAxisWidth={48}
            valueFormatter={(value) => formatCount(value)}
          />
        </div>
      )}

      <div className="mt-3 flex flex-wrap gap-4 text-[11px] text-slate-600 dark:text-slate-400">
                <span>Latest: {formatCount(points[0]?.newCount ?? 0)} new, {formatCount(points[0]?.fixedCount ?? 0)} fixed, {formatCount(points[0]?.goneCount ?? 0)} gone</span>
      </div>
    </div>
  );
}
