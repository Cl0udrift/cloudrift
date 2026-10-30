import { Link } from "react-router-dom";
import { formatQueryError } from "../api/httpError";
import type { AccountBreakdownItem } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { TopAccountsHorizontalBar } from "../components/overview/TopAccountsHorizontalBar";
import { ScanRequired } from "../components/ScanRequired";
import { StatePanel } from "../components/StatePanel";
import { useAccountsQuery } from "../hooks/useDashboardQueries";
import { useScanContext } from "../hooks/useScanContext";
import { formatCount, formatUsd } from "../lib/format";

/**
 * Ordering follows GET /api/scans/:id/accounts (backend sorts by account_id ascending).
 */
export function AccountsPage() {
  const { selectedScanId } = useScanContext();
  const query = useAccountsQuery();
  const accountItems = query.data?.items ?? [];

  return (
    <section className="space-y-6">
      <PageHeader
        title="Accounts"
        description="Per-account rollups for the selected scan."
        details="Rows are ordered deterministically by the API (GET /api/scans/:id/accounts)."
      />
      {!selectedScanId ? (
        <ScanRequired />
      ) : query.isLoading ? (
        <StatePanel>Loading accounts…</StatePanel>
      ) : query.isError ? (
        <StatePanel intent="error" title="Failed to load accounts">
          <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(query.error)}</pre>
        </StatePanel>
      ) : query.isSuccess && accountItems.length === 0 ? (
        <StatePanel intent="empty" title="No account rows">
          The API returned successfully with no per-account breakdown for this scan.
        </StatePanel>
      ) : query.data ? (
        <div className="space-y-6">
          <details>
            <summary className="hs-focus-ring w-fit cursor-pointer rounded text-xs font-medium text-cyan-800 dark:text-cyan-300">Ranking chart (same data as the cards below)</summary>
            <div className="mt-2">
              <TopAccountsHorizontalBar items={accountItems} title="Top accounts by findings" description="Same accounts response as the cards below." />
            </div>
          </details>
          <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
            {accountItems.map((account) => (
              <AccountCard key={account.account_id} account={account} scanId={selectedScanId} />
            ))}
          </div>
        </div>
      ) : (
        <StatePanel intent="empty" title="No data">Unexpected empty response after success.</StatePanel>
      )}
    </section>
  );
}

function AccountCard({ account, scanId }: { account: AccountBreakdownItem; scanId: string | null }) {
  const title = account.account_name?.trim() || account.account_id;

  return (
    <article className="hs-card flex flex-col p-5">
      <header className="border-b border-slate-200 pb-3 dark:border-b-slate-800/90">
        <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
        <p className="mt-1 font-mono text-xs text-slate-500">{account.account_id}</p>
        {account.ou_path ? (
          <p className="mt-2 text-xs text-slate-600 dark:text-slate-400">
            <span className="text-slate-500">OU: </span>
            <span className="break-all">{account.ou_path}</span>
          </p>
        ) : null}
        {account.team ? (
          <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
            <span className="text-slate-500">Team: </span>
            {account.team}
          </p>
        ) : null}
      </header>

      <dl className="mt-4 grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
        <MetricDt label="Findings" value={formatCount(account.finding_count)} />
        <MetricDt label="Critical" value={formatCount(account.critical_count)} emphasize />
        <MetricDt label="High" value={formatCount(account.high_count)} />
        <MetricDt label="Direct / mo" value={formatUsd(account.total_monthly_direct_cost_usd)} mono />
        <MetricDt label="Risk / mo" value={formatUsd(account.total_monthly_risk_cost_usd)} mono />
      </dl>

      <div className="mt-4 border-t border-slate-200 pt-3 dark:border-t-slate-800/90">
        <p className="hs-label !mb-0">Top finding</p>
        <p className="mt-1 text-sm text-slate-800 dark:text-slate-200">{account.top_finding?.trim() || "—"}</p>
        {scanId ? (
          <Link
            className="mt-3 inline-block text-sm text-cyan-800 hover:underline dark:text-cyan-300"
            to={`/identities?scan_id=${encodeURIComponent(scanId)}&account_id=${encodeURIComponent(account.account_id)}`}
          >
            IAM roles
          </Link>
        ) : null}
      </div>
    </article>
  );
}

function MetricDt({
  label,
  value,
  emphasize,
  mono
}: {
  label: string;
  value: string;
  emphasize?: boolean;
  mono?: boolean;
}) {
  return (
    <div>
      <dt className="cr-kpi-label">{label}</dt>
      <dd
        className={`mt-0.5 tabular-nums ${emphasize ? "font-semibold text-rose-200/90" : "text-slate-800 dark:text-slate-200"} ${mono ? "font-mono text-xs" : ""}`}
      >
        {value}
      </dd>
    </div>
  );
}
