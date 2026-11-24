import { Link } from "react-router-dom";
import type { SpendInReach } from "../../api/types";
import { formatMoney } from "../../lib/money";

function names(list: string[]): string {
  if (list.length <= 2) return list.join(" and ");
  return `${list.slice(0, 2).join(", ")} and ${list.length - 2} more`;
}

/**
 * What an administrator can reach is everything the account runs, so the account's real spend last month is the
 * scale of what is exposed. It is billing, not a guess. It says nothing about how likely a breach is.
 */
export function SpendInReachCard({ reach }: { reach?: SpendInReach }) {
  if (!reach || !reach.applicable) return null;
  if (!reach.available) {
    return (
      <section className="hs-card border-dashed p-5" aria-label="Spend within reach">
        <h2 className="cr-section-title">What is within reach</h2>
        <p className="mt-2 text-sm text-slate-700 dark:text-slate-300">{names(reach.subjects)} can reach everything {reach.subjects.length === 1 ? "its" : "their"} account runs. {reach.reason}</p>
        <Link to="/settings#cfg-cost.use_cur" className="cr-chip-state cr-tone-info hs-focus-ring mt-3 inline-flex">Open the setting →</Link>
      </section>
    );
  }
  const top = reach.accounts.flatMap((a) => a.top_services.map((s) => ({ ...s, account: a.account_id }))).sort((x, y) => y.usd - x.usd).slice(0, 4);
  return (
    <section className="hs-card border-l-4 border-l-amber-500/80 p-5" aria-label="Spend within reach">
      <h2 className="cr-section-title">What is within reach</h2>
      {reach.monthly >= 1 ? (
        <>
          <p className="mt-2 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">
            {formatMoney(reach.monthly)} a month <span className="text-base font-normal text-slate-600 dark:text-slate-400">of running infrastructure</span>
          </p>
          <p className="mt-1 text-sm text-slate-700 dark:text-slate-300">
            {names(reach.subjects)} can reach everything {reach.accounts.length === 1 ? "this account runs" : "these accounts run"}. That is what the {reach.accounts.length === 1 ? "account" : "accounts"} actually spent last month.
          </p>
          <ul className="mt-3 divide-y divide-slate-200 text-sm dark:divide-slate-800">
            {top.map((s) => (
              <li key={`${s.account}-${s.service}`} className="flex items-baseline justify-between gap-3 py-1.5">
                <span className="text-slate-800 dark:text-slate-100">{s.service}</span>
                <span className="tabular-nums text-slate-700 dark:text-slate-300">{formatMoney(s.usd)}</span>
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p className="mt-2 text-sm text-slate-700 dark:text-slate-300">
          {names(reach.subjects)} can reach everything {reach.subjects.length === 1 ? "its" : "their"} {reach.accounts.length === 1 ? "account" : "accounts"} runs, but the spend was less than $1 last month, so this measure says little. A new or idle account shows no spend.
        </p>
      )}
      <p className="cr-helper mt-2">Actual billing from {reach.source || "Cost Explorer"}. It measures what is exposed, not how likely a breach is.</p>
    </section>
  );
}
