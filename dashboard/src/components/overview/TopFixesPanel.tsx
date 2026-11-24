import type { TopFixItem } from "../../api/types";
import { SeverityBadge } from "../SeverityBadge";
import { StatePanel } from "../StatePanel";
import { formatQueryError } from "../../api/httpError";
import { formatUsd } from "../../lib/format";
import { useTopFixesQuery } from "../../hooks/useDashboardQueries";

type TopFixesPanelProps = {
  scanId: string;
  /** Max rows to request from the API (default 12 for dashboard density). */
  limit?: number;
  onDrilldown: (item: TopFixItem) => void;
};

/** Who answers for it. No owner is said out loud: a finding nobody owns does not get fixed. */
function ownerLine(item: TopFixItem): string {
  return item.owner?.trim() || item.team?.trim() || "No owner";
}

export function TopFixesPanel({ scanId, limit = 12, onDrilldown }: TopFixesPanelProps) {
  const q = useTopFixesQuery(scanId, { limit });

  const rows = q.data?.items?.slice(0, 5) ?? [];
  // A column that says the same thing on every row, or nothing, is noise.
  const hasCost = rows.some((r) => r.monthly_risk_cost_usd > 0);
  const hasScoreSpread = new Set(rows.map((r) => r.priority_score.toFixed(1))).size > 1;
  return (
    <div className="hs-card p-5">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h3 className="cr-section-title">Fix first</h3>
          <p className="cr-helper mt-1">The top findings, most serious first.</p>
        </div>
      </div>

      {q.isLoading ? (
        <div className="mt-4">
          <StatePanel>Loading top fixes…</StatePanel>
        </div>
      ) : q.isError ? (
        <div className="mt-4">
          <StatePanel intent="error" title="Could not load top fixes">
            <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(q.error)}</pre>
          </StatePanel>
        </div>
      ) : !q.data?.items?.length ? (
        <p className="cr-helper mt-4">No findings for this scan.</p>
      ) : (
        <div className="hs-table-wrap mt-4 rounded-md border border-slate-200 dark:border-slate-800">
          <table className="cr-table w-full min-w-[30rem] border-collapse text-left">
            <thead className="sticky top-0 z-10 border-b border-slate-200 bg-slate-50/95 dark:border-slate-800 dark:bg-slate-900/95">
              <tr className="cr-kpi-label">
                <th className="px-2 py-2">Severity</th>
                <th className="px-2 py-2">Issue</th>
                <th className="px-2 py-2">Owner</th>
                {hasCost ? <th className="px-2 py-2">Risk/mo</th> : null}
                {hasScoreSpread ? <th className="px-2 py-2 text-right">Score</th> : null}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {q.data.items.slice(0, 5).map((item) => (
                <tr
                  key={item.id}
                  role="button"
                  tabIndex={0}
                  onClick={() => onDrilldown(item)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onDrilldown(item);
                    }
                  }}
                  className="hs-interactive-row"
                >
                  <td className="px-2 py-2">
                    <SeverityBadge severity={item.severity} />
                  </td>
                  <td className="px-2 py-2">
                    <p className="line-clamp-1 text-sm font-medium text-slate-900 dark:text-slate-100">{item.title}</p>
                  </td>
                  <td className={`px-2 py-2 text-xs ${ownerLine(item) === "No owner" ? "font-medium text-amber-700 dark:text-amber-300" : "text-slate-700 dark:text-slate-300"}`}>{ownerLine(item)}</td>
                  {hasCost ? (
                    <td className="px-2 py-2 text-xs tabular-nums text-slate-700 dark:text-slate-300">{formatUsd(item.monthly_risk_cost_usd)}</td>
                  ) : null}
                  {hasScoreSpread ? (
                    <td className="px-2 py-2 text-right">
                      <span className="cr-chip-compact font-mono text-[10px] text-slate-500" title="Composite priority score">
                        {item.priority_score.toFixed(1)}
                      </span>
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
