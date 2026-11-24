import { BarChart } from "@tremor/react";
import type { AccountBreakdownItem } from "../../api/types";
import { formatCount } from "../../lib/format";

const DEFAULT_LIMIT = 6;

export type OwnershipRiskItem = {
  accountId: string;
  accountName: string;
  team?: string;
  riskUsd: number;
  criticalCount: number;
  highCount: number;
  topFinding?: string;
};

function normalizeOwnershipItems(items: AccountBreakdownItem[]): OwnershipRiskItem[] {
  return items
    .filter((item) => Boolean(item?.account_id))
    .map((item) => ({
      accountId: item.account_id,
      accountName: item.account_name?.trim() || item.account_id,
      team: item.team?.trim() || undefined,
      riskUsd: Number.isFinite(item.total_monthly_risk_cost_usd) ? item.total_monthly_risk_cost_usd : 0,
      criticalCount: Number.isFinite(item.critical_count) ? item.critical_count : 0,
      highCount: Number.isFinite(item.high_count) ? item.high_count : 0,
      topFinding: item.top_finding?.trim() || undefined
    }));
}

export function sortOwnershipRiskItems(items: OwnershipRiskItem[]): OwnershipRiskItem[] {
  return [...items].sort((a, b) => {
    if (b.criticalCount !== a.criticalCount) {
      return b.criticalCount - a.criticalCount;
    }
    if (b.highCount !== a.highCount) {
      return b.highCount - a.highCount;
    }
    const byName = a.accountName.localeCompare(b.accountName);
    if (byName !== 0) {
      return byName;
    }
    return a.accountId.localeCompare(b.accountId);
  });
}

export function OwnershipRiskPanel({
  items,
  limit = DEFAULT_LIMIT,
  onAccountClick,
  action
}: {
  items: AccountBreakdownItem[];
  limit?: number;
  onAccountClick?: (accountId: string) => void;
  /** A link or button shown at the right of the heading. */
  action?: React.ReactNode;
}) {
  const normalized = normalizeOwnershipItems(Array.isArray(items) ? items : []);
  const ranked = sortOwnershipRiskItems(normalized).slice(0, Math.max(1, Math.min(limit, 8)));

  return (
    <div className="hs-card p-5">
      <div className="flex items-center justify-between gap-2">
        <h3 className="cr-section-title">Critical and high findings by account</h3>
        {action}
      </div>

      {ranked.length === 0 ? (
        <p className="mt-4 text-sm text-slate-500">No risk detected across accounts</p>
      ) : (
        <div
          className="cr-chart-focusable mt-4 rounded-md"
          tabIndex={0}
          aria-label="Critical and high findings per account"
        >
          <BarChart
            className="h-[300px]"
            data={ranked.map((item) => ({
              account: item.team ? `${item.team} - ${item.accountName}` : item.accountName,
              key: item.accountId,
              Critical: item.criticalCount,
              High: item.highCount
            }))}
            index="account"
            categories={["Critical", "High"]}
            layout="vertical"
            stack
            colors={["rose", "amber"]}
            yAxisWidth={170}
            allowDecimals={false}
            valueFormatter={(value) => formatCount(value)}
            onValueChange={(value) => {
              const key = ranked.find((item) => (item.team ? `${item.team} - ${item.accountName}` : item.accountName) === value?.account)?.accountId;
              if (key) {
                onAccountClick?.(key);
              }
            }}
          />
          <ul className="mt-3 space-y-1">
            {ranked.map((item) => (
              <li key={item.accountId}>
                <button
                  type="button"
                  onClick={() => onAccountClick?.(item.accountId)}
                  className="hs-interactive-row flex w-full items-center justify-between rounded px-2 py-1 text-left text-xs"
                >
                  <span className="truncate text-slate-700 dark:text-slate-200">
                    {item.team ? `${item.team} - ${item.accountName}` : item.accountName}
                  </span>
                  <span className="flex items-center gap-1.5 tabular-nums">
                    <span className="text-rose-600 dark:text-rose-400">C {item.criticalCount}</span>
                    <span className="text-amber-600 dark:text-amber-400">H {item.highCount}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

