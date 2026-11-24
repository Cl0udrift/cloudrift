import { useRemediationGroupsQuery } from "../../hooks/useDashboardQueries";
import { formatCount, formatUsd } from "../../lib/format";

type GroupKey = "reclaimable" | "stale_external_trust" | "dangling_edge" | "admin_like_external" | "broken_edge";

export type RemediationGroup = {
  key: GroupKey;
  label: string;
  why: string;
  findingCount: number;
  totalMonthlyRiskUsd: number;
  topExample?: string;
};

export function sortRemediationGroups(groups: RemediationGroup[]): RemediationGroup[] {
  return [...groups].sort((a, b) => {
    if (b.totalMonthlyRiskUsd !== a.totalMonthlyRiskUsd) {
      return b.totalMonthlyRiskUsd - a.totalMonthlyRiskUsd;
    }
    if (b.findingCount !== a.findingCount) {
      return b.findingCount - a.findingCount;
    }
    return a.label.localeCompare(b.label);
  });
}

export function RemediationGroupingPanel({
  scanId,
  onDrilldown
}: {
  scanId: string;
  onDrilldown: (group: GroupKey) => void;
}) {
  const groupsQuery = useRemediationGroupsQuery(scanId);
  const groups = sortRemediationGroups(
    (groupsQuery.data?.items ?? []).map((item) => ({
      key: item.key,
      label: item.label,
      why: item.why,
      findingCount: item.finding_count,
      totalMonthlyRiskUsd: item.total_monthly_risk_cost_usd,
      topExample: item.top_example
    }))
  ).slice(0, 8);
  const maxRisk = Math.max(...groups.map((group) => group.totalMonthlyRiskUsd), 1);

  if (!groupsQuery.isLoading && !groupsQuery.isError && groups.length === 0) {
    return null;
  }
  return (
    <div className="hs-card p-5">
      <h3 className="cr-section-title">Remediation grouping</h3>
      <p className="cr-helper mt-1">Ranked fix patterns by total risk impact.</p>

      {groupsQuery.isLoading ? (
        <p className="mt-4 text-sm text-slate-500">Loading remediation groups…</p>
      ) : groupsQuery.isError ? (
        <p className="mt-4 text-sm text-rose-600 dark:text-rose-400">Unable to load remediation grouping right now.</p>
      ) : groups.length === 0 ? (
        <p className="mt-4 text-sm text-slate-500">No high-value remediation groups detected for this scan.</p>
      ) : (
        <ul className="mt-4 space-y-2">
          {groups.map((group) => (
            <li key={group.key}>
              <button
                type="button"
                onClick={() => onDrilldown(group.key)}
                className="hs-interactive-card w-full rounded-md border border-slate-200 px-3 py-2.5 text-left dark:border-slate-800"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm font-medium text-slate-800 dark:text-slate-100">{group.label}</p>
                  <div className="flex items-center gap-2">
                    <span className="hs-chip-compact border-slate-300 bg-slate-100 text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                      {formatCount(group.findingCount)}
                    </span>
                    <span className="text-sm font-medium tabular-nums text-slate-900 dark:text-slate-100">
                      {formatUsd(group.totalMonthlyRiskUsd)}
                    </span>
                  </div>
                </div>
                <div className="mt-2 h-1.5 w-full overflow-hidden rounded bg-slate-200 dark:bg-slate-800">
                  <div
                    className="h-full rounded bg-cyan-600/85"
                    style={{ width: `${Math.max(8, Math.round((group.totalMonthlyRiskUsd / maxRisk) * 100))}%` }}
                  />
                </div>
                {group.topExample ? <p className="cr-helper mt-1 truncate">Example: {group.topExample}</p> : null}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

