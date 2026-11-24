import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import { queryKeys } from "../api/queryKeys";
import type { CostReport, CostResource, CostSplitRow } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { ScanRequired } from "../components/ScanRequired";
import { SpendInReachCard } from "../components/overview/SpendInReachCard";
import { StatePanel } from "../components/StatePanel";
import { useScanContext } from "../hooks/useScanContext";
import { formatMoney } from "../lib/money";

const CHECK_TEXT: Record<string, string> = {
  succeeded: "read",
  partial: "partly read",
  failed: "could not be read",
  unsupported: "not available here",
  not_run: "not collected in this scan"
};

/** A ranked list where each row's bar is its share of the largest one. */
function SplitList({ title, rows }: { title: string; rows: CostSplitRow[] }) {
  const max = Math.max(1, ...rows.map((r) => r.monthly));
  return (
    <section className="hs-card p-4" aria-label={title}>
      <h3 className="cr-kpi-label mb-2">{title}</h3>
      {rows.length === 0 ? (
        <p className="cr-helper">Nothing to split.</p>
      ) : (
        <ul className="space-y-2">
          {rows.map((r) => (
            <li key={r.key}>
              <div className="flex items-baseline justify-between gap-3 text-sm">
                <span className={`min-w-0 truncate ${r.label === "No owner" ? "font-medium text-amber-700 dark:text-amber-300" : "text-slate-800 dark:text-slate-100"}`} title={r.label}>
                  {r.label} <span className="text-slate-500">({r.count})</span>
                </span>
                <span className="shrink-0 tabular-nums text-slate-700 dark:text-slate-300">{r.monthly > 0 ? `${formatMoney(r.monthly)} a month` : "not priced"}</span>
              </div>
              <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800" aria-hidden="true">
                <div className="h-full rounded-full bg-emerald-500/80" style={{ width: `${(r.monthly / max) * 100}%` }} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function SourceChip({ r }: { r: CostResource }) {
  if (!r.priced) return <span className="cr-chip-state cr-tone-unk">Not priced</span>;
  return r.source === "actual" ? <span className="cr-chip-state cr-tone-ok">Billing</span> : <span className="cr-chip-state cr-tone-info">Estimate</span>;
}

function Total({ report }: { report: CostReport }) {
  const s = report.savings;
  return (
    <section className="hs-card border-l-4 border-l-emerald-500/70 p-5" aria-label="Total">
      <h2 className="cr-section-title">What unused resources cost</h2>
      {s.count === 0 ? (
        <p className="mt-2 text-lg font-medium text-slate-900 dark:text-slate-100">No unused resources that cost money were found.</p>
      ) : s.priced === 0 ? (
        <p className="mt-2 text-lg font-medium text-slate-900 dark:text-slate-100">{s.count} unused {s.count === 1 ? "resource" : "resources"} found, none could be priced.</p>
      ) : (
        <p className="mt-2 text-3xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">
          {formatMoney(s.monthly)} a month <span className="text-base font-normal text-slate-600 dark:text-slate-400">({formatMoney(s.yearly)} a year)</span>
        </p>
      )}
      {s.count > 0 ? (
        <p className="cr-helper mt-2">
          {s.actual && s.actual > 0 ? `${s.actual} of ${s.priced} figures come from your billing over the last 14 days; the rest are estimated at AWS list price. ` : "Every figure is estimated at AWS list price (storage and fixed hourly charges). "}
          {s.actuals_status === "not_enabled" ? "To use your billing instead, switch on resource-level data in Cost Explorer settings in the payer account. " : ""}
          {s.unpriced > 0 ? `${s.unpriced} could not be priced and ${s.unpriced === 1 ? "is" : "are"} left out of the total. ` : ""}
          Removing or securing these stops this spend.
        </p>
      ) : null}
      <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-600 dark:text-slate-400" aria-label="What was checked">
        {report.checked.map((c) => (
          <li key={c.label} className={c.status === "succeeded" ? "" : "font-medium text-amber-700 dark:text-amber-300"}>
            {c.label}: {CHECK_TEXT[c.status] ?? c.status}
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Cost in one place: the total, who and what it splits across, what an administrator can reach, and every resource. */
export function CostPage() {
  const { selectedScanId } = useScanContext();
  const q = useQuery({ queryKey: ["cost", selectedScanId], queryFn: () => apiClient.getCost(selectedScanId as string), enabled: Boolean(selectedScanId), staleTime: 60_000 });
  const report = q.data;

  return (
    <section className="space-y-6">
      <PageHeader title="Cost" description="What unused resources cost every month, who and what it splits across, and what is within reach of the identities that need attention." />
      {!selectedScanId ? (
        <ScanRequired />
      ) : q.isLoading ? (
        <StatePanel>Loading cost…</StatePanel>
      ) : q.isError || !report ? (
        <StatePanel intent="error" title="Cost is unavailable"><pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(q.error)}</pre></StatePanel>
      ) : (
        <>
          <Total report={report} />

          {report.resources.length > 0 ? (
            <div className="grid gap-4 md:grid-cols-2">
              <SplitList title="By kind of resource" rows={report.by_kind} />
              <SplitList title="By account" rows={report.by_account} />
              <SplitList title="By owner" rows={report.by_owner} />
              <SplitList title="By AWS service" rows={report.by_service} />
            </div>
          ) : null}

          <SpendInReachCard reach={report.exposed} />

          {report.resources.length > 0 ? (
            <section aria-label="Unused resources" className="space-y-2">
              <h2 className="cr-section-title">Every unused resource</h2>
              <div className="hs-card overflow-x-auto">
                <table className="w-full min-w-[40rem] text-left text-sm">
                  <thead>
                    <tr className="cr-kpi-label border-b border-slate-200 dark:border-slate-800">
                      <th className="px-3 py-2">Resource</th>
                      <th className="px-3 py-2">Owner</th>
                      <th className="px-3 py-2 text-right">Per month</th>
                      <th className="px-3 py-2">Cost from</th>
                      <th className="px-3 py-2 text-right">Unused for</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {report.resources.map((r) => (
                      <tr key={r.id} className="hs-interactive-row">
                        <td className="px-3 py-2">
                          <Link className="font-medium text-slate-900 hover:underline dark:text-slate-100" to={`/findings?scan_id=${encodeURIComponent(selectedScanId)}&finding_id=${encodeURIComponent(r.id)}`}>
                            {r.name}
                          </Link>
                          <p className="cr-helper">{r.kind_label} · {r.detail}{r.region ? ` · ${r.region}` : ""} · {r.account_id}</p>
                        </td>
                        <td className={`px-3 py-2 text-xs ${r.owner ? "text-slate-700 dark:text-slate-300" : "font-medium text-amber-700 dark:text-amber-300"}`}>{r.owner || "No owner"}</td>
                        <td className="px-3 py-2 text-right tabular-nums">{r.priced ? formatMoney(r.monthly) : "—"}</td>
                        <td className="px-3 py-2"><SourceChip r={r} /></td>
                        <td className="px-3 py-2 text-right text-xs tabular-nums text-slate-600 dark:text-slate-400">{r.unused_days < 0 ? "—" : r.unused_days === 0 ? "just found" : `${r.unused_days}+ days`}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="cr-helper">Unused for counts from the first stored scan that found it, so it is a minimum. Each name opens the finding and its fix.</p>
            </section>
          ) : null}
        </>
      )}
    </section>
  );
}
