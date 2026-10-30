import { useEffect, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { queryKeys } from "../api/queryKeys";
import type { ScanListItem } from "../api/types";

export function useScanContext() {
  const [params] = useSearchParams();
  const queryScanId = params.get("scan_id");

  const scansQuery = useQuery({
    queryKey: queryKeys.scans(),
    queryFn: () => apiClient.getScans(),
    staleTime: 60_000,
    gcTime: 300_000
  });

  const scans = scansQuery.data?.items ?? [];

  const selectedScanId = useMemo(() => {
    if (queryScanId) {
      return queryScanId;
    }
    // Reopen on the last scan viewed when it still exists; otherwise the newest scan.
    try {
      const last = window.localStorage.getItem("cloudrift.lastScan");
      if (last && scans.some((item) => item.scan_id === last)) return last;
    } catch {
      /* storage unavailable */
    }
    return scans[0]?.scan_id ?? null;
  }, [queryScanId, scans]);

  useEffect(() => {
    if (!queryScanId) return;
    try {
      window.localStorage.setItem("cloudrift.lastScan", queryScanId);
    } catch {
      /* ignore */
    }
  }, [queryScanId]);

  const currentScan = useMemo((): ScanListItem | null => {
    if (!selectedScanId) {
      return null;
    }
    return scans.find((s) => s.scan_id === selectedScanId) ?? null;
  }, [scans, selectedScanId]);

  return {
    selectedScanId,
    currentScan,
    scans,
    scansQuery,
    isResolvingScan: scansQuery.isLoading && !selectedScanId
  };
}
