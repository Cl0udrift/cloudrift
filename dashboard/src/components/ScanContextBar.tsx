import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiClient } from "../api/client";
import { useScanContext } from "../hooks/useScanContext";
import type { InventorySummary } from "../api/types";
import { formatCount } from "../lib/format";
import { CollectionChip, StateChip } from "./ui/StatusChip";

function formatTimestamp(iso?: string): string {
  const d = iso ? new Date(iso) : null;
  return d && !Number.isNaN(d.getTime()) ? d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";
}

/** Persistent scan scope shown in the topbar on every page. Uses only fields the scan list API returns. */
export function ScanContextBar() {
  const { selectedScanId, currentScan, scansQuery, isResolvingScan } = useScanContext();
  // Shares its cache key with the Overview snapshot, so no extra request when both are mounted.
  const inventory = useQuery({
    queryKey: ["overview", "inventory", selectedScanId],
    queryFn: () => apiClient.inventorySummary(selectedScanId as string, {}),
    enabled: Boolean(selectedScanId),
    staleTime: 60_000,
    retry: false
  });
  if (isResolvingScan) return <p className="cr-helper" role="status">Resolving scan…</p>;
  if (!selectedScanId) {
    return (
      <p className="cr-helper">
        No scan selected. <Link to="/scan-control" className="underline">Open Scan Control</Link>
      </p>
    );
  }
  const synthetic = currentScan?.synthetic || selectedScanId.startsWith("demo");
  const accounts = currentScan?.account_ids ?? [];
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-700 dark:text-slate-300" aria-label="Selected scan">
      <span className="cr-kpi-label !text-[10px]">Scan</span>
      <code className="cr-mono max-w-[14rem] truncate" title={selectedScanId}>{selectedScanId}</code>
      {!currentScan && !selectedScanId.startsWith("demo") ? (
        <StateChip tone="unk" glyph="?" label="Origin unknown" title="Scan is not in the scan list yet" />
      ) : synthetic ? (
        <StateChip tone="warn" glyph="⚑" label="Synthetic" title="Synthetic demo data, not a live AWS scan" />
      ) : (
        <StateChip tone="info" glyph="●" label="Live" title="Collected from AWS" />
      )}
      <span className="hidden sm:inline">{formatTimestamp(currentScan?.timestamp)}</span>
      {accounts.length > 0 ? (
        <span className="hidden md:inline">{accounts.length === 1 ? `Account ${accounts[0]}` : `${accounts.length} accounts`}</span>
      ) : null}
      <span className="hidden lg:inline tabular-nums">
        {currentScan ? `${formatCount(currentScan.finding_count)} ${currentScan.finding_count === 1 ? "finding" : "findings"}` : scansQuery.isLoading ? "…" : "—"}
      </span>
      <CoverageLine scanId={selectedScanId} data={inventory.data} loading={inventory.isLoading} />
    </div>
  );
}

/** One-line coverage: Regions scanned plus supported-inventory state. Facts only; links to the full view. */
function CoverageLine({ scanId, data, loading }: { scanId: string; data?: InventorySummary; loading: boolean }) {
  if (loading) return <span className="cr-helper">Coverage…</span>;
  const accounts = data?.region_coverage?.accounts ?? [];
  const selected = accounts.reduce((n, a) => n + a.selected, 0);
  const ok = accounts.reduce((n, a) => n + a.succeeded, 0);
  const partial = accounts.reduce((n, a) => n + a.partial, 0);
  const failed = accounts.reduce((n, a) => n + a.failed, 0);
  const supported = data?.collection?.supported_inventory;
  return (
    <Link to={`/inventory?scan_id=${encodeURIComponent(scanId)}`} className="hs-focus-ring flex flex-wrap items-center gap-2 rounded-md px-1 underline-offset-2 hover:underline" title="Open collection coverage">
      {selected > 0 ? (
        <span className="tabular-nums">
          {ok} of {selected} Regions succeeded{partial > 0 ? ` · ${partial} partial` : ""}{failed > 0 ? ` · ${failed} failed` : ""}
        </span>
      ) : (
        <span>Regions not recorded</span>
      )}
      <CollectionChip status={supported ?? "not_recorded"} />
    </Link>
  );
}
