import { useCallback, useEffect, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { queryKeys } from "../api/queryKeys";
import type { ScanListItem } from "../api/types";

export function useScanContext() {
  const [params, setParams] = useSearchParams();
  const queryScanId = params.get("scan_id");

  const scansQuery = useQuery({
    queryKey: queryKeys.scans(),
    queryFn: () => apiClient.getScans(),
    staleTime: 15_000,
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

  /** Pin a scan: remembered across pages and reloads, and carried in the URL so the view can be shared. */
  const selectScan = useCallback(
    (scanId: string) => {
      try {
        window.localStorage.setItem("cloudrift.lastScan", scanId);
      } catch {
        /* ignore */
      }
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.set("scan_id", scanId);
          return next;
        },
        { replace: false }
      );
    },
    [setParams]
  );

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
    selectScan,
    isResolvingScan: scansQuery.isLoading && !selectedScanId
  };
}
