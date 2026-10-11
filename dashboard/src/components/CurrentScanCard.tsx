import { formatCount } from "../lib/format";
import { useScanContext } from "../hooks/useScanContext";
import { IconScan } from "../lib/icons";

function formatScanTimestamp(iso: string | undefined): string {
  if (!iso) {
    return "—";
  }
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return "—";
  }
  return d.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  });
}

export function CurrentScanCard() {
  const { selectedScanId, currentScan, scansQuery, isResolvingScan } = useScanContext();

  return (
    <div className="hs-card-soft p-3">
      <div className="flex items-center gap-2 text-slate-600 dark:text-slate-400">
        <IconScan className="shrink-0 opacity-80" />
        <span className="cr-section-title !text-[11px] !normal-case !tracking-normal">Current scan</span>
      </div>

      {isResolvingScan ? (
        <p className="cr-helper mt-2">Resolving scan from URL or latest run…</p>
      ) : !selectedScanId ? (
        <div className="mt-2 space-y-1">
          <p className="cr-body text-slate-700 dark:text-slate-300">No scan selected</p>
          <p className="cr-helper">Run a scan from Scan Control or open a scan-linked URL.</p>
        </div>
      ) : (
        <dl className="mt-2 space-y-1.5">
          <div>
            <dt className="cr-kpi-label">Scan ID</dt>
            <dd className="cr-mono mt-0.5 break-all text-slate-800 dark:text-slate-200" title={selectedScanId}>
              {selectedScanId}
            </dd>
            {(currentScan?.synthetic || selectedScanId.startsWith("demo")) && (
              <p className="mt-1 inline-flex rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold tracking-wide text-amber-950 dark:bg-amber-900/40 dark:text-amber-100">
                SYNTHETIC / DEMO
              </p>
            )}
          </div>
          <div className="grid grid-cols-2 gap-x-2 gap-y-1">
            <div>
              <dt className="cr-kpi-label">Captured</dt>
              <dd className="cr-body mt-0.5 text-slate-700 dark:text-slate-300">
                {formatScanTimestamp(currentScan?.timestamp)}
              </dd>
            </div>
            <div>
              <dt className="cr-kpi-label">Findings</dt>
              <dd className="cr-kpi-value mt-0.5 tabular-nums">
                {currentScan != null ? formatCount(currentScan.finding_count) : scansQuery.isLoading ? "…" : "—"}
              </dd>
            </div>
            <div>
              <dt className="cr-kpi-label">Critical</dt>
              <dd className="cr-body mt-0.5 tabular-nums text-slate-700 dark:text-slate-300">
                {currentScan != null ? formatCount(currentScan.critical_count) : "—"}
              </dd>
            </div>
            <div>
              <dt className="cr-kpi-label">High</dt>
              <dd className="cr-body mt-0.5 tabular-nums text-slate-700 dark:text-slate-300">
                {currentScan != null ? formatCount(currentScan.high_count) : "—"}
              </dd>
            </div>
          </div>
        </dl>
      )}
    </div>
  );
}
