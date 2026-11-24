import { Link } from "react-router-dom";
import type { ScanSummaryResponse } from "../../api/types";
import { SeverityBadge } from "../SeverityBadge";

function scanAge(iso: string): string {
  const days = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000));
  return days === 0 ? "today" : days === 1 ? "yesterday" : `${days} days ago`;
}

const RAIL: Record<string, string> = {
  critical: "border-l-rose-500",
  high: "border-l-amber-500",
  none: "border-l-emerald-500/70"
};

/**
 * What needs attention, one row per identity or resource. The card's left edge carries the worst severity, so the
 * state reads before any text is read. The scan's own state sits in the header, quiet when all is well.
 */
export function AttentionPanel({ summary, scanId, hasPreviousScan, compact = false }: { summary: ScanSummaryResponse; scanId: string; hasPreviousScan: boolean; compact?: boolean }) {
  const groups = summary.attention ?? [];
  const q = `scan_id=${encodeURIComponent(scanId)}`;
  const shown = groups.slice(0, compact ? 3 : 5);
  const worst = groups.some((g) => g.severity === "critical") ? "critical" : groups.length > 0 ? "high" : "none";
  const h = summary.health;
  return (
    <section aria-label="Needs attention" className={`hs-card border-l-4 p-5 ${RAIL[worst]}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="cr-section-title">Needs attention</h2>
        <div className="flex flex-wrap items-center gap-2">
          {h?.complete ? <span className="cr-helper">Scan complete · {scanAge(h.scan_time)} · {h.account_count} {h.account_count === 1 ? "account" : "accounts"}</span> : null}
          {hasPreviousScan ? <Link to={`/diff?${q}`} className="cr-chip-state cr-tone-unk hs-focus-ring">What changed →</Link> : null}
        </div>
      </div>
      {groups.length === 0 ? (
        <p className="mt-3 text-lg font-medium text-slate-900 dark:text-slate-100">
          Nothing critical or high was found.
          {h && !h.complete ? <span className="mt-1 block text-sm font-normal text-slate-600 dark:text-slate-300">The scan was incomplete, so that is not a safety claim.</span> : null}
        </p>
      ) : (
        <>
          {groups.length > 1 ? (
            <p className="mt-3 text-xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">{groups.length} identities or resources need attention</p>
          ) : null}
          <ul className={`${groups.length > 1 ? "mt-3" : "mt-2"} divide-y divide-slate-200 dark:divide-slate-800`}>
            {shown.map((g) => (
              <li key={g.subject_arn || g.subject}>
                <Link to={`/findings?${q}&search=${encodeURIComponent(g.subject)}`} className="hs-interactive-row flex flex-col items-start gap-1.5 px-1 py-2.5 text-sm sm:flex-row sm:items-center sm:justify-between sm:gap-3">
                  <span className="min-w-0 text-slate-700 dark:text-slate-300">
                    <strong className="font-semibold text-slate-900 dark:text-slate-100">{g.subject}</strong>
                    {g.sentence.startsWith(g.subject) ? g.sentence.slice(g.subject.length) : ` — ${g.sentence}`}
                  </span>
                  <span className="flex shrink-0 flex-wrap items-center gap-2">
                    {!compact ? <span className={`text-xs ${g.owner ? "text-slate-500" : "font-medium text-amber-700 dark:text-amber-300"}`}>{g.owner || "No owner"}</span> : null}
                    {g.issue_count > 1 ? <span className="cr-helper tabular-nums">{g.issue_count} findings</span> : null}
                    <SeverityBadge severity={g.severity} />
                  </span>
                </Link>
              </li>
            ))}
          </ul>
          {groups.length > shown.length ? <p className="cr-helper mt-2">and {groups.length - shown.length} more. <Link className="underline" to={`/findings?${q}&severity=high`}>See all high findings</Link></p> : null}
        </>
      )}
    </section>
  );
}
