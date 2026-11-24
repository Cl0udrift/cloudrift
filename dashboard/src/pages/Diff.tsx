import { formatQueryError } from "../api/httpError";
import type { DiffChangedFinding, DiffNewFinding, DiffOpenFinding, DiffResolvedFinding, DiffTrendPoint, ResourceBrief, ResourceChanges } from "../api/types";
import { DiffFindingCard, ageText } from "../components/diff/DiffFindingCard";
import { PageHeader } from "../components/PageHeader";
import { ScanRequired } from "../components/ScanRequired";
import { StatePanel } from "../components/StatePanel";
import { useDiffQuery } from "../hooks/useDashboardQueries";
import { useScanContext } from "../hooks/useScanContext";
import { baselineChoices, getPreviousScanIdForDiff } from "../lib/scanOrder";
import { formatCount } from "../lib/format";
import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";

export function DiffPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { selectedScanId, scans } = useScanContext();
  const defaultOldScanId = getPreviousScanIdForDiff(scans, selectedScanId);
  const oldScanIdFromUrl = searchParams.get("old_scan_id");
  const oldScanId = oldScanIdFromUrl ?? defaultOldScanId;
  const showNew = searchParams.get("show_new") !== "0";
  const showResolved = searchParams.get("show_resolved") !== "0";
  const query = useDiffQuery(oldScanId, selectedScanId);

  const baselineOptions = useMemo(
    () => baselineChoices(scans, selectedScanId),
    [scans, selectedScanId]
  );

  const data = query.data;
  const newFindings = data?.new_findings ?? [];
  const resolvedFindings = data?.resolved_findings ?? [];
  const changedFindings = data?.changed_findings ?? [];
  const newCount = newFindings.length;
  const resolvedCount = resolvedFindings.length;
  const changedCount = changedFindings.length;
  const unchanged = data?.unchanged_count ?? 0;
  const noDrift = data && newCount === 0 && resolvedCount === 0 && changedCount === 0;

  return (
    <section className="space-y-6">
      <PageHeader
        title="Diff"
        description="What changed since the previous scan: findings, and the resources behind them."
        details="The selected scan is compared with the scan before it, or with any earlier scan you choose as the baseline."
      />
      {!selectedScanId ? (
        <ScanRequired />
      ) : !oldScanId ? (
        <StatePanel intent="empty" title="No earlier scan of these accounts">
          A comparison needs an older scan of the same accounts. Scans of other accounts are not used, because every finding would look new or gone. Run this account again, or pick a later scan at the top.
        </StatePanel>
      ) : query.isLoading ? (
        <StatePanel>Loading diff…</StatePanel>
      ) : query.isError ? (
        <StatePanel intent="error" title="Failed to load diff">
          <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(query.error)}</pre>
        </StatePanel>
      ) : !data ? (
        <StatePanel intent="empty" title="Empty response">The diff request succeeded but returned no payload.</StatePanel>
      ) : (
        <>
          <div className="hs-card-soft flex flex-wrap items-baseline justify-between gap-3 px-4 py-3" role="status" aria-live="polite">
            <p className="text-sm text-slate-700 dark:text-slate-200">
              <span className="font-semibold text-amber-800 dark:text-amber-300">+{formatCount(newCount)}</span>
              <span className="text-slate-500"> new</span>
              <span className="mx-2 text-slate-400 dark:text-slate-600">·</span>
              <span className="font-semibold text-emerald-800 dark:text-emerald-300">−{formatCount(resolvedCount)}</span>
              <span className="text-slate-500"> no longer present</span>
              <span className="mx-2 text-slate-400 dark:text-slate-600">·</span>
              <span className="font-semibold text-sky-800 dark:text-sky-300">~{formatCount(changedCount)}</span>
              <span className="text-slate-500"> changed</span>
              <span className="mx-2 text-slate-400 dark:text-slate-600">·</span>
              <span className="font-semibold tabular-nums text-slate-800 dark:text-slate-100">{formatCount(unchanged)}</span>
              <span className="text-slate-500"> unchanged</span>
            </p>
            <p className="cr-helper">"Changed" means the same finding with a different severity, or a change in who can reach it.</p>
          </div>

          {!data.comparability.comparable ? (
            <div role="alert" className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-950 dark:border-amber-800/60 dark:bg-amber-950/30 dark:text-amber-100">
              <p className="font-semibold">These two scans did not look at the same things</p>
              <p>{data.comparability.note}</p>
              <ul className="mt-1 list-disc pl-5 text-xs">
                {data.comparability.differences.map((d) => <li key={d}>{d}</li>)}
              </ul>
            </div>
          ) : null}

          <div className="hs-card-soft p-4 text-sm text-slate-700 dark:text-slate-300">
            <p>
              <span className="text-slate-500">Old (baseline): </span>
              <code className="text-cyan-800 dark:text-cyan-200/90">{data.old_scan_id}</code>
              <span className="mx-2 text-slate-400 dark:text-slate-600">→</span>
              <span className="text-slate-500">New: </span>
              <code className="text-cyan-800 dark:text-cyan-200/90">{data.new_scan_id}</code>
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <label className="hs-label !mb-0">Baseline</label>
              <select
                value={oldScanIdFromUrl ?? ""}
                onChange={(e) => {
                  const v = e.target.value;
                  const next = new URLSearchParams(searchParams);
                  if (v) {
                    next.set("old_scan_id", v);
                  } else {
                    next.delete("old_scan_id");
                  }
                  setSearchParams(next, { replace: true });
                }}
                className="hs-select !w-auto !py-1 !text-xs"
              >
                <option value="">Auto previous</option>
                {baselineOptions.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.id}{o.sameAccounts ? "" : " (other accounts)"}
                  </option>
                ))}
              </select>
              <label className="ml-3 inline-flex items-center gap-1 text-xs text-slate-600 dark:text-slate-300">
                <input
                  type="checkbox"
                  className="hs-checkbox"
                  checked={showNew}
                  onChange={(e) => {
                    const next = new URLSearchParams(searchParams);
                    if (e.target.checked) {
                      next.delete("show_new");
                    } else {
                      next.set("show_new", "0");
                    }
                    setSearchParams(next, { replace: true });
                  }}
                />
                Show new
              </label>
              <label className="inline-flex items-center gap-1 text-xs text-slate-600 dark:text-slate-300">
                <input
                  type="checkbox"
                  className="hs-checkbox"
                  checked={showResolved}
                  onChange={(e) => {
                    const next = new URLSearchParams(searchParams);
                    if (e.target.checked) {
                      next.delete("show_resolved");
                    } else {
                      next.set("show_resolved", "0");
                    }
                    setSearchParams(next, { replace: true });
                  }}
                />
                Show resolved
              </label>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-4">
            <DiffMetric label="New findings" value={newCount} />
            <DiffMetric label="No longer present" value={resolvedCount} />
            <DiffMetric label="Changed severity" value={changedCount} />
            <DiffMetric label="Unchanged" value={unchanged} />
          </div>

          {(data.trend ?? []).length > 1 ? <TrendStrip points={data.trend ?? []} /> : null}

          {data.resources && (data.resources.added_count > 0 || data.resources.removed_count > 0 || (data.resources.newly_internet_facing ?? []).length > 0) ? (
            <ResourcesSection changes={data.resources} />
          ) : null}

          {noDrift && unchanged > 0 ? (
            <StatePanel intent="empty" title="Nothing changed">
              No findings are new, gone or changed.{" "}
              <span className="tabular-nums text-slate-600 dark:text-slate-400">{formatCount(unchanged)}</span> findings are the same as before.
            </StatePanel>
          ) : null}

          {showNew && newCount > 0 ? (
            <DiffSection variant="new" title="New findings" subtitle="Present in the new scan only. A finding that came back says so." items={newFindings} />
          ) : null}

          {changedCount > 0 ? <ChangedSection items={changedFindings} /> : null}

          {showResolved && resolvedCount > 0 ? (
            <ResolvedSection items={resolvedFindings} />
          ) : null}

          {(data.open_longest ?? []).length > 0 ? <OpenLongestSection items={data.open_longest} limited={Boolean(data.history_limited)} /> : null}

          {!noDrift && newCount === 0 && resolvedCount === 0 && changedCount === 0 ? (
            <StatePanel intent="empty" title="No findings changed">
              Nothing to list. The unchanged count is above.
            </StatePanel>
          ) : null}
        </>
      )}
    </section>
  );
}

function DiffMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="hs-card p-4">
      <p className="hs-section-title">{label}</p>
      <p className="mt-2 text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-100">{formatCount(value)}</p>
    </div>
  );
}

function ChangedSection({ items }: { items: DiffChangedFinding[] }) {
  return (
    <div>
      <h2 className="hs-section-title !text-sm">Changed</h2>
      <p className="mt-1 cr-helper">The same finding in both scans, but its severity or who can reach it changed.</p>
      <div className="mt-3 space-y-2">
        {items.map((item) => (
          <div
            key={`${item.id}-${item.affected_arn}`}
            className="hs-card-soft flex flex-wrap items-center justify-between gap-2 px-4 py-3"
          >
            <div className="min-w-0">
              <p className="truncate text-sm font-medium text-slate-800 dark:text-slate-100">{item.title}</p>
              <p className="truncate cr-helper">{item.affected_arn}</p>
              {ageText(item.age) ? <p className="mt-0.5 text-xs text-slate-500">{ageText(item.age)}</p> : null}
              {(item.changes ?? []).length > 0 ? (
                <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs text-slate-700 dark:text-slate-300">
                  {(item.changes ?? []).map((c) => <li key={c}>{c}</li>)}
                </ul>
              ) : null}
            </div>
            <p className="flex items-center gap-2 text-xs font-semibold uppercase tabular-nums">
              {item.old_severity === item.new_severity ? (
                <span className="text-sky-800 dark:text-sky-300">{item.new_severity} (unchanged)</span>
              ) : (
                <>
                  <span className="text-slate-500 dark:text-slate-400">{item.old_severity}</span>
                  <span className="text-slate-400 dark:text-slate-600">→</span>
                  <span className="text-sky-800 dark:text-sky-300">{item.new_severity}</span>
                </>
              )}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

function DiffSection({
  title,
  subtitle,
  items,
  variant
}: {
  title: string;
  subtitle: string;
  items: DiffNewFinding[];
  variant: "new";
}) {
  return (
    <div>
      <h2 className="hs-section-title !text-sm">{title}</h2>
      <p className="mt-1 cr-helper">{subtitle}</p>
      <div className="mt-3 space-y-2">
        {items.map((item) => (
          <DiffFindingCard key={`${item.id}-${item.affected_arn}`} item={item} variant={variant} age={item.age} />
        ))}
      </div>
    </div>
  );
}

const reasonLabel: Record<string, string> = {
  no_longer_reported: "Fixed, or no longer applies",
  resource_gone: "Resource deleted",
  account_not_scanned: "Account not scanned",
  not_a_resource: "Cause unknown"
};

/** Resolved findings grouped by why they went: only the first group is a likely fix. */
function ResolvedSection({ items }: { items: DiffResolvedFinding[] }) {
  const order = ["no_longer_reported", "resource_gone", "account_not_scanned", "not_a_resource"];
  return (
    <div>
      <h2 className="hs-section-title !text-sm">No longer in the new scan</h2>
      <p className="mt-1 cr-helper">Present in the baseline only. Only "fixed" means the problem was dealt with; a deleted resource or an unscanned account is not a fix.</p>
      <div className="mt-3 space-y-4">
        {order.map((reason) => {
          const group = items.filter((i) => i.reason === reason);
          if (group.length === 0) return null;
          return (
            <div key={reason}>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">{reasonLabel[reason]} ({group.length})</p>
              <div className="space-y-2">
                {group.map((item) => (
                  <DiffFindingCard key={`${item.id}-${item.affected_arn}`} item={item} variant={reason === "no_longer_reported" ? "resolved" : "gone"} note={item.reason_text} age={item.age} />
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function OpenLongestSection({ items, limited }: { items: DiffOpenFinding[]; limited: boolean }) {
  return (
    <div>
      <h2 className="hs-section-title !text-sm">Open the longest</h2>
      <p className="mt-1 cr-helper">Findings present in both scans, oldest run first.{limited ? " Ages are measured over the most recent scans only." : ""}</p>
      <div className="mt-3 space-y-2">
        {items.map((item) => (
          <DiffFindingCard key={`${item.id}-${item.affected_arn}`} item={item} variant="open" age={item.age} />
        ))}
      </div>
    </div>
  );
}

/** Critical and high findings in the last scans, oldest first. A scan that covered other accounts is faded. */
function TrendStrip({ points }: { points: DiffTrendPoint[] }) {
  const max = Math.max(1, ...points.map((p) => p.critical + p.high));
  const w = 36;
  const h = 64;
  return (
    <div>
      <h2 className="hs-section-title !text-sm">Critical and high findings over the last {points.length} scans</h2>
      <svg role="img" aria-label={`Critical and high findings per scan: ${points.map((p) => `${p.critical + p.high}`).join(", ")}`} viewBox={`0 0 ${points.length * w} ${h + 18}`} className="mt-2 w-full max-w-xl">
        {points.map((p, i) => {
          const hi = (p.high / max) * h;
          const cr = (p.critical / max) * h;
          const last = i === points.length - 1;
          return (
            <g key={p.scan_id} opacity={p.comparable ? 1 : 0.4}>
              <title>{`${p.scan_id}: ${p.critical} critical, ${p.high} high${p.comparable ? "" : " (covered different accounts)"}`}</title>
              <rect x={i * w + 6} y={h - hi - cr} width={w - 12} height={cr} className="fill-red-600" />
              <rect x={i * w + 6} y={h - hi} width={w - 12} height={hi} className="fill-orange-500" />
              <rect x={i * w + 6} y={h} width={w - 12} height={last ? 3 : 1} className="fill-slate-400" />
              <text x={i * w + w / 2} y={h + 13} textAnchor="middle" className="fill-slate-500 text-[8px]">{new Date(p.timestamp).toLocaleDateString(undefined, { day: "numeric", month: "short" })}</text>
            </g>
          );
        })}
      </svg>
      <p className="cr-helper">Red is critical, orange is high. The last bar is the scan you are viewing. A faded bar covered different accounts, so compare it with care.</p>
    </div>
  );
}

function ResourceList({ title, items, total, tone }: { title: string; items: ResourceBrief[]; total: number; tone: string }) {
  if (total === 0 && items.length === 0) return null;
  return (
    <div>
      <p className={`mb-1 text-xs font-semibold uppercase tracking-wide ${tone}`}>{title} ({total})</p>
      <ul className="space-y-1 text-sm">
        {items.map((r) => (
          <li key={r.arn || `${r.type}-${r.name}`} className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-medium text-slate-800 dark:text-slate-100">{r.name || r.arn}</span>
            <span className="text-xs text-slate-500">{r.type}{r.account_id ? ` · ${r.account_id}` : ""}{r.region ? ` · ${r.region}` : ""}</span>
            {r.why ? <span className="text-xs text-slate-600 dark:text-slate-300">{r.why}</span> : null}
          </li>
        ))}
        {total > items.length ? <li className="cr-helper">and {total - items.length} more</li> : null}
      </ul>
    </div>
  );
}

/** Resources that appeared or went away, whether or not a finding followed. */
function ResourcesSection({ changes }: { changes: ResourceChanges }) {
  return (
    <div>
      <h2 className="hs-section-title !text-sm">Resources</h2>
      <p className="mt-1 cr-helper">What was added to or removed from the inventory since the baseline, with or without a finding.</p>
      <div className="hs-card-soft mt-3 space-y-4 p-4">
        <ResourceList title="Now reachable from the internet" items={changes.newly_internet_facing ?? []} total={(changes.newly_internet_facing ?? []).length} tone="text-red-700 dark:text-red-300" />
        <ResourceList title="Added" items={changes.added ?? []} total={changes.added_count} tone="text-amber-800 dark:text-amber-300" />
        <ResourceList title="Removed" items={changes.removed ?? []} total={changes.removed_count} tone="text-slate-500" />
      </div>
    </div>
  );
}
