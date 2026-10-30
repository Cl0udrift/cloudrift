import { formatQueryError } from "../api/httpError";
import type { DiffChangedFinding, FindingListItem } from "../api/types";
import { DiffFindingCard } from "../components/diff/DiffFindingCard";
import { PageHeader } from "../components/PageHeader";
import { ScanRequired } from "../components/ScanRequired";
import { StatePanel } from "../components/StatePanel";
import { useDiffQuery } from "../hooks/useDashboardQueries";
import { useScanContext } from "../hooks/useScanContext";
import { getPreviousScanIdForDiff } from "../lib/scanOrder";
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
    () => scans.filter((s) => s.scan_id !== selectedScanId).map((s) => s.scan_id),
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
        description="Compare the selected scan with the previous one."
        details="Compares the selected scan (new) to the chronologically previous scan in the newest-first list from GET /api/scans. Baseline = next row after the selected scan."
      />
      {!selectedScanId ? (
        <ScanRequired />
      ) : !oldScanId ? (
        <StatePanel intent="empty" title="No baseline scan">
          Need at least two scans, or select a scan that is not the oldest in the list. The baseline is always the{" "}
          <strong className="text-slate-700 dark:text-slate-300">next</strong> scan after the current one in newest-first order from{" "}
          <code className="text-cyan-800 dark:text-cyan-200/80">/api/scans</code>.
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
              <span className="text-slate-500"> resolved</span>
              <span className="mx-2 text-slate-400 dark:text-slate-600">·</span>
              <span className="font-semibold text-sky-800 dark:text-sky-300">~{formatCount(changedCount)}</span>
              <span className="text-slate-500"> changed</span>
              <span className="mx-2 text-slate-400 dark:text-slate-600">·</span>
              <span className="font-semibold tabular-nums text-slate-800 dark:text-slate-100">{formatCount(unchanged)}</span>
              <span className="text-slate-500"> unchanged</span>
            </p>
            <p className="cr-helper">Matched by stable finding ID. "Changed" = same finding, different severity across scans.</p>
          </div>

          <div className="hs-card-soft p-4 text-sm text-slate-700 dark:text-slate-300">
            <p>
              <span className="text-slate-500">Old (baseline): </span>
              <code className="text-cyan-800 dark:text-cyan-200/90">{data.old_scan_id}</code>
              <span className="mx-2 text-slate-400 dark:text-slate-600">→</span>
              <span className="text-slate-500">New: </span>
              <code className="text-cyan-800 dark:text-cyan-200/90">{data.new_scan_id}</code>
            </p>
            <p className="mt-2 cr-helper">
              Identity for matching: stable finding ID (per API). GET /api/diff?old=…&amp;new=…
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
                {baselineOptions.map((id) => (
                  <option key={id} value={id}>
                    {id}
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
            <DiffMetric label="Resolved findings" value={resolvedCount} />
            <DiffMetric label="Changed severity" value={changedCount} />
            <DiffMetric label="Unchanged" value={unchanged} />
          </div>

          {noDrift && unchanged > 0 ? (
            <StatePanel intent="empty" title="No drift in tracked identities">
              No new, resolved, or severity-changed findings by stable ID.{" "}
              <span className="tabular-nums text-slate-600 dark:text-slate-400">{formatCount(unchanged)}</span> finding identities unchanged.
            </StatePanel>
          ) : null}

          {showNew && newCount > 0 ? (
            <DiffSection variant="new" title="New findings" subtitle="Present in the new scan only." items={newFindings} />
          ) : null}

          {changedCount > 0 ? <ChangedSection items={changedFindings} /> : null}

          {showResolved && resolvedCount > 0 ? (
            <DiffSection
              variant="resolved"
              title="Resolved findings"
              subtitle="Present in the baseline scan only."
              items={resolvedFindings}
            />
          ) : null}

          {!noDrift && newCount === 0 && resolvedCount === 0 && changedCount === 0 ? (
            <StatePanel intent="empty" title="No new, resolved, or changed rows">
              Diff lists are empty; see unchanged count above.
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
      <h2 className="hs-section-title !text-sm">Changed severity</h2>
      <p className="mt-1 cr-helper">Same finding in both scans (matched by stable ID), severity differs.</p>
      <div className="mt-3 space-y-2">
        {items.map((item) => (
          <div
            key={`${item.id}-${item.affected_arn}`}
            className="hs-card-soft flex flex-wrap items-center justify-between gap-2 px-4 py-3"
          >
            <div className="min-w-0">
              <p className="truncate text-sm font-medium text-slate-800 dark:text-slate-100">{item.title}</p>
              <p className="truncate cr-helper">{item.affected_arn}</p>
            </div>
            <p className="flex items-center gap-2 text-xs font-semibold uppercase tabular-nums">
              <span className="text-slate-500 dark:text-slate-400">{item.old_severity}</span>
              <span className="text-slate-400 dark:text-slate-600">→</span>
              <span className="text-sky-800 dark:text-sky-300">{item.new_severity}</span>
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
  items: FindingListItem[];
  variant: "new" | "resolved";
}) {
  return (
    <div>
      <h2 className="hs-section-title !text-sm">{title}</h2>
      <p className="mt-1 cr-helper">{subtitle}</p>
      <div className="mt-3 space-y-2">
        {items.map((item) => (
          <DiffFindingCard key={`${item.id}-${item.affected_arn}`} item={item} variant={variant} />
        ))}
      </div>
    </div>
  );
}
