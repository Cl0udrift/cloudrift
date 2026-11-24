import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiClient } from "../../api/client";
import { queryKeys } from "../../api/queryKeys";
import { SeverityBadge } from "../SeverityBadge";

function Tile({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: "bad" | "warn" }) {
  const rail = tone === "bad" ? "border-l-rose-500" : tone === "warn" ? "border-l-amber-500" : "border-l-slate-300 dark:border-l-slate-600";
  return (
    <div className={`hs-card border-l-4 p-4 ${rail}`}>
      <p className="cr-kpi-label">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-100">{value}</p>
      {sub ? <p className="cr-helper mt-1">{sub}</p> : null}
    </div>
  );
}

/**
 * What a manager runs a team on: how many findings are open, how many are past their deadline, who holds them, and
 * how long fixes have taken. Age counts from the first scan that saw the finding, so it is a minimum.
 */
export function ManagerMetricsPanel({ scanId }: { scanId: string }) {
  const q = useQuery({ queryKey: queryKeys.managerMetrics(scanId), queryFn: () => apiClient.getManagerMetrics(scanId), staleTime: 60_000 });
  const m = q.data;
  if (!m) return null;
  const fix = m.median_days_to_fix;
  return (
    <section aria-label="Team measures" className="space-y-3">
      <h2 className="cr-section-title">How the team is doing</h2>
      <div className="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(8.5rem,1fr))]">
        <Tile label="Open" value={String(m.open_count)} sub="critical, high and medium" />
        <Tile label="Past deadline" value={String(m.overdue_count)} tone={m.overdue_count > 0 ? "bad" : undefined} sub={`Deadlines: ${m.fix_days.critical || "off"} / ${m.fix_days.high || "off"} / ${m.fix_days.medium || "off"} days`} />
        <Tile label="Time to fix" value={fix === undefined ? "—" : `${fix} days`} sub={fix === undefined ? "No fixes recorded yet" : `Median of ${m.fixed_samples} recent ${m.fixed_samples === 1 ? "fix" : "fixes"}`} />
        <Tile label="No owner" value={String(m.no_owner_count)} tone={m.no_owner_count > 0 ? "warn" : undefined} sub={m.no_owner_count > 0 ? "Set owners in Business settings" : "Every finding has an owner"} />
      </div>

      {m.by_owner.length > 0 ? (
        <div className="hs-card p-4">
          <h3 className="cr-kpi-label mb-2">By owner</h3>
          <table className="w-full text-left text-sm">
            <thead><tr className="cr-kpi-label"><th className="py-1 pr-2">Owner</th><th className="py-1 pr-2 text-right">Open</th><th className="py-1 pr-2 text-right">Past deadline</th><th className="py-1 text-right">Critical / high</th></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {m.by_owner.map((o) => (
                <tr key={o.owner}>
                  <td className={`py-1.5 pr-2 ${o.owner === "No owner" ? "font-medium text-amber-700 dark:text-amber-300" : "text-slate-800 dark:text-slate-100"}`}>{o.owner}</td>
                  <td className="py-1.5 pr-2 text-right tabular-nums">{o.open}</td>
                  <td className={`py-1.5 pr-2 text-right tabular-nums ${o.overdue > 0 ? "font-semibold text-rose-700 dark:text-rose-300" : ""}`}>{o.overdue}</td>
                  <td className="py-1.5 text-right tabular-nums">{o.critical} / {o.high}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {m.open.length > 0 ? (
        <div className="hs-card p-4">
          <h3 className="cr-kpi-label mb-2">Open the longest</h3>
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {m.open.slice(0, 5).map((f) => (
              <li key={f.id}>
                <Link to={`/findings?scan_id=${encodeURIComponent(scanId)}&finding_id=${encodeURIComponent(f.id)}`} className="hs-interactive-row flex flex-wrap items-center justify-between gap-2 px-1 py-2 text-sm">
                  <span className="min-w-0 truncate text-slate-800 dark:text-slate-100">{f.title}</span>
                  <span className="flex shrink-0 items-center gap-2">
                    <span className="cr-helper">{f.owner || "No owner"}</span>
                    <span className={`tabular-nums text-xs ${f.overdue ? "font-semibold text-rose-700 dark:text-rose-300" : "text-slate-500"}`}>{f.age_days}d{f.overdue ? `, ${f.days_over}d over` : ""}</span>
                    <SeverityBadge severity={f.severity} />
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
