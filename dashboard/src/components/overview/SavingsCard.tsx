import { Link } from "react-router-dom";
import type { Savings } from "../../api/types";
import { formatMoney } from "../../lib/money";

/**
 * What the unused resources cost to hold, from the AWS list price for their size and Region. It is money that is
 * spent today and stops when they are removed, so it needs no assumption from the reader. It is an estimate and is
 * labelled one: discounts and usage change the bill.
 */
export function SavingsCard({ savings, scanId }: { savings?: Savings; scanId: string }) {
  if (!savings || savings.count === 0) return null;
  return (
    <section className="hs-card border-l-4 border-l-emerald-500/70 p-5" aria-label="Savings from unused resources">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="cr-section-title">Unused resources you are paying for</h2>
        <Link to={`/cost?scan_id=${encodeURIComponent(scanId)}`} className="cr-chip-state cr-tone-unk hs-focus-ring">Open the cost page →</Link>
      </div>
      {savings.priced > 0 ? (
        <>
          <p className="mt-2 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">
            about {formatMoney(savings.monthly)} a month
            <span className="ml-2 text-base font-normal text-slate-600 dark:text-slate-400">({formatMoney(savings.yearly)} a year)</span>
          </p>
          <p className="mt-1 text-sm text-slate-700 dark:text-slate-300">Removing or securing them stops this spend.</p>
        </>
      ) : (
        <p className="mt-2 text-base text-slate-800 dark:text-slate-200">{savings.count} unused {savings.count === 1 ? "resource" : "resources"} found, but none could be priced.</p>
      )}
      <ul className="mt-3 divide-y divide-slate-200 text-sm dark:divide-slate-800">
        {savings.by_kind.map((k) => (
          <li key={k.kind} className="flex items-baseline justify-between gap-3 py-1.5">
            <span className="text-slate-800 dark:text-slate-100">{k.label} <span className="text-slate-500">({k.count})</span></span>
            <span className="tabular-nums text-slate-700 dark:text-slate-300">{k.monthly > 0 ? `${formatMoney(k.monthly)} a month` : "not priced"}</span>
          </li>
        ))}
      </ul>
      <p className="cr-helper mt-2">
        {savings.actual && savings.actual > 0
          ? `${savings.actual} of ${savings.priced} ${savings.priced === 1 ? "figure is" : "figures are"} from your billing over the last 14 days; the rest are estimated at AWS list price. `
          : "Estimated at AWS list price. Storage and fixed hourly charges only; discounts, traffic and snapshots change the bill. "}
        {savings.actuals_status === "not_enabled" ? "To use your actual billing, switch on resource-level data in Cost Explorer settings (payer account). " : ""}
        {savings.actuals_status === "failed" && savings.actuals_detail ? `${savings.actuals_detail} ` : ""}
        Price source: {savings.source || "AWS list prices"}.
        {savings.unpriced > 0 ? ` ${savings.unpriced} could not be priced and ${savings.unpriced === 1 ? "is" : "are"} left out of the total.` : ""}
      </p>
    </section>
  );
}
