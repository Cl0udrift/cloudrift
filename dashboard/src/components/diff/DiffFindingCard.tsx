import type { DiffAge, FindingListItem } from "../../api/types";
import { displayTarget, formatUsd, shortenArn } from "../../lib/format";
import { SeverityBadge } from "../SeverityBadge";

const variantStyles = {
  new: "border-l-4 border-l-amber-500/90",
  resolved: "border-l-4 border-l-emerald-600/85",
  // Gone for a reason that is not a fix: the resource was deleted, or the scan did not look.
  gone: "border-l-4 border-l-slate-400/90",
  open: "border-l-4 border-l-slate-300/90"
} as const;

/** "Open since 12 Nov, 5 scans" or "Came back; first here 12 Nov". */
export function ageText(age?: DiffAge): string | null {
  if (!age) return null;
  const since = new Date(age.first_seen).toLocaleDateString(undefined, { day: "numeric", month: "short" });
  const scans = `${age.scans_present} ${age.scans_present === 1 ? "scan" : "scans"}`;
  return age.returned ? `Came back; this run began ${since} (${scans})` : `Open since ${since} (${scans})`;
}

/** Compact finding summary for diff lists (matches audit styling, lighter than full Findings table). */
export function DiffFindingCard({ item, variant, note, age }: { item: FindingListItem; variant: keyof typeof variantStyles; note?: string; age?: DiffAge }) {
  const target = displayTarget(item.hostname, item.affected_arn);
  const accent = variantStyles[variant];
  return (
    <article
      className={`rounded-lg border border-slate-200 bg-white/80 px-4 py-3 dark:border-slate-800 dark:bg-slate-900/80 ${accent}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-slate-900 dark:text-slate-100">{item.title}</p>
          <p className="mt-1 font-mono text-[11px] text-slate-500 break-all" title={item.affected_arn}>
            {target}
            {item.hostname?.trim() && item.affected_arn ? (
              <span className="block text-slate-500 dark:text-slate-600">{shortenArn(item.affected_arn, 32, 20)}</span>
            ) : null}
          </p>
        </div>
        <SeverityBadge severity={item.severity} />
      </div>
      {note ? <p className="mt-2 text-xs text-slate-700 dark:text-slate-300">{note}</p> : null}
      {ageText(age) ? <p className="mt-1 text-xs text-slate-500">{ageText(age)}</p> : null}
      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
        <div>
          <dt className="text-slate-500">Account</dt>
          <dd className="font-mono text-slate-700 dark:text-slate-300">{item.account_id || "—"}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Module</dt>
          <dd className="capitalize text-slate-700 dark:text-slate-300">{item.module || "—"}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Claimability</dt>
          <dd className="capitalize text-slate-700 dark:text-slate-300">{item.claimability || "—"}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Risk / mo</dt>
          <dd className="tabular-nums text-slate-800 dark:text-slate-200">{formatUsd(item.monthly_risk_cost_usd)}</dd>
        </div>
      </dl>
    </article>
  );
}
