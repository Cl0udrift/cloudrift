import { Link } from "react-router-dom";
import type { ScanSummaryResponse } from "../../api/types";

const STALE_DAYS = 7;

function ago(iso: string): { text: string; days: number } {
  const days = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000));
  return { days, text: days === 0 ? "today" : days === 1 ? "yesterday" : `${days} days ago` };
}

/** How far this scan can be trusted: when it ran, what it reached, and what it could not read. */
export function ScanHealthStrip({ summary }: { summary: ScanSummaryResponse }) {
  const h = summary.health;
  if (!h) return null;
  const age = ago(h.scan_time);
  // A complete, recent scan is already said in the attention card. This strip is for when it is not.
  if (h.complete && age.days < STALE_DAYS) return null;
  const problems = [
    ...(h.failed_account_ids ?? []).map((a) => `account ${a} could not be reached`),
    ...(h.failed_collectors ?? []).map((c) => `${c} failed`),
    ...(h.partial_collectors ?? []).map((c) => `${c} was partial`)
  ];
  return (
    <div role="status" className={`rounded border p-3 text-sm ${h.complete ? "border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-900/40" : "border-amber-300 bg-amber-50 text-amber-950 dark:border-amber-800/60 dark:bg-amber-950/30 dark:text-amber-100"}`}>
      <p>
        <span className={`cr-chip-state mr-2 ${h.complete ? "cr-tone-ok" : "cr-tone-warn"}`}>{h.complete ? "Scan complete" : "Scan incomplete"}</span>
        Scanned {age.text}
        {" · "}
        {h.account_count} {h.account_count === 1 ? "account" : "accounts"}
        {h.region_count > 0 ? ` · ${h.region_count} regions` : ""}
        {" · "}
        <Link className="underline" to="/coverage">Coverage</Link>
      </p>
      {problems.length > 0 ? <p className="mt-1 text-xs">Not fully read: {problems.join("; ")}. Findings that depend on these may be missing, so a clean result here is not a safety claim.</p> : null}
      {age.days >= STALE_DAYS ? <p className="mt-1 text-xs">This scan is {age.days} days old. <Link className="underline" to="/scan-control">Run a new one</Link>, or schedule scans so this does not happen.</p> : null}
    </div>
  );
}
