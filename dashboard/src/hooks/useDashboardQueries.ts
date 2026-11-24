import { useMemo } from "react";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { queryKeys } from "../api/queryKeys";
import type { ExternalEntitiesQueryParams, FindingsQueryParams, ScanListItem } from "../api/types";
import { useScanContext } from "./useScanContext";

export type TrustActivityBuckets = {
  lt90: number;
  d90_365: number;
  gt365: number;
  never: number;
};

export const TRUST_ACTIVITY_SAMPLE_CAP = 25;

/** Shared with trust activity sampling so `fetchQuery` and `useFindingDetailQuery` hit one cache entry per finding. */
export const FINDING_DETAIL_STALE_TIME_MS = 60_000;

export function getFindingDetailQueryOptions(scanId: string, findingId: string) {
  return {
    queryKey: queryKeys.findingDetail(scanId, findingId),
    queryFn: () => apiClient.getFindingDetail(scanId, findingId),
    staleTime: FINDING_DETAIL_STALE_TIME_MS
  } as const;
}

function bucketForDays(days: number | undefined | null): keyof TrustActivityBuckets {
  if (days === undefined || days === null) {
    return "never";
  }
  if (days < 0) {
    return "never";
  }
  if (days < 90) {
    return "lt90";
  }
  if (days <= 365) {
    return "d90_365";
  }
  return "gt365";
}

/**
 * Buckets IAM last-used days from finding detail (`trust.days_since_used`) for up to
 * {@link TRUST_ACTIVITY_SAMPLE_CAP} findings. Does not load the full findings list — callers pass
 * current page IDs only. Failed detail fetches are counted in `failed` and omitted from buckets.
 *
 * Uses `queryClient.fetchQuery` with {@link getFindingDetailQueryOptions} so responses populate the same cache as
 * {@link useFindingDetailQuery}; expanding a row that was already sampled reuses fresh data without a second HTTP call.
 */
export function useTrustActivityBucketsQuery(scanId: string | null, findingIds: string[]) {
  const queryClient = useQueryClient();
  const capped = useMemo(() => findingIds.slice(0, TRUST_ACTIVITY_SAMPLE_CAP), [findingIds]);
  const idsKey = useMemo(() => capped.join("|"), [capped]);

  return useQuery({
    queryKey: queryKeys.trustActivityBuckets(scanId, idsKey),
    queryFn: async () => {
      const buckets: TrustActivityBuckets = { lt90: 0, d90_365: 0, gt365: 0, never: 0 };
      let failed = 0;
      const chunkSize = 5;
      for (let i = 0; i < capped.length; i += chunkSize) {
        const chunk = capped.slice(i, i + chunkSize);
        const settled = await Promise.allSettled(
          chunk.map((id) => queryClient.fetchQuery(getFindingDetailQueryOptions(scanId!, id)))
        );
        for (const r of settled) {
          if (r.status === "rejected") {
            failed += 1;
            continue;
          }
          const d = r.value.item.trust?.days_since_used;
          buckets[bucketForDays(d)] += 1;
        }
      }
      return { buckets, sampled: capped.length, failed };
    },
    enabled: Boolean(scanId && capped.length > 0),
    staleTime: 60_000
  });
}

export function useSummaryQuery() {
  const { selectedScanId } = useScanContext();
  return useQuery({
    queryKey: queryKeys.summary(selectedScanId),
    queryFn: () => apiClient.getSummary(selectedScanId as string),
    enabled: Boolean(selectedScanId)
  });
}

/** Paginated external-entity aggregation (same source as summary.external_entity_count when unfiltered). */
export function useExternalEntitiesQuery(
  scanId: string | null,
  params: ExternalEntitiesQueryParams,
  options?: { enabled?: boolean }
) {
  const enabled = options?.enabled ?? Boolean(scanId);
  return useQuery({
    queryKey: queryKeys.externalEntities(scanId, params),
    queryFn: () => apiClient.getExternalEntities(scanId as string, params),
    enabled: Boolean(scanId) && enabled,
    staleTime: 60_000
  });
}

/** Paginated / filtered findings; params must be memoized in the caller for stable cache keys. */
export function useFindingsListQuery(
  scanId: string | null,
  params: FindingsQueryParams,
  options?: { enabled?: boolean }
) {
  const enabled = options?.enabled ?? Boolean(scanId);
  return useQuery({
    queryKey: queryKeys.findings(scanId, params),
    queryFn: () => apiClient.getFindings(scanId as string, params),
    enabled: Boolean(scanId) && enabled
  });
}

/** Server-derived remediation pattern groups from existing findings/trust evidence. */
export function useRemediationGroupsQuery(scanId: string | null, options?: { enabled?: boolean }) {
  const enabled = options?.enabled ?? Boolean(scanId);
  return useQuery({
    queryKey: queryKeys.remediationGroups(scanId),
    queryFn: () => apiClient.getRemediationGroups(scanId as string),
    enabled: Boolean(scanId) && enabled,
    staleTime: 60_000
  });
}

/** Server-ranked top fixes (GET /api/scans/:id/top-fixes). */
export function useTopFixesQuery(scanId: string | null, options?: { limit?: number; enabled?: boolean }) {
  const limit = options?.limit ?? 25;
  const enabled = options?.enabled ?? Boolean(scanId);
  return useQuery({
    queryKey: queryKeys.topFixes(scanId, limit),
    queryFn: () => apiClient.getTopFixes(scanId as string, { limit }),
    enabled: Boolean(scanId) && enabled,
    staleTime: 60_000
  });
}

export function useFindingDetailQuery(scanId: string | null, findingId: string | null, enabled: boolean) {
  const canRun = Boolean(scanId && findingId && enabled);
  const detailOpts =
    scanId && findingId ? getFindingDetailQueryOptions(scanId, findingId) : null;
  return useQuery({
    queryKey: queryKeys.findingDetail(scanId, findingId),
    queryFn: detailOpts?.queryFn ?? (() => Promise.reject(new Error("Finding detail query disabled"))),
    enabled: canRun,
    staleTime: FINDING_DETAIL_STALE_TIME_MS
  });
}

/**
 * Per-scan accounts breakdown for filter dropdowns (e.g. Findings).
 * Cache key includes selectedScanId only — no cross-scan leakage.
 * Relaxed refetch defaults avoid noisy traffic when toggling pages beside Findings.
 */
export function useAccountsQuery() {
  const { selectedScanId } = useScanContext();
  return useQuery({
    queryKey: queryKeys.accounts(selectedScanId),
    queryFn: () => apiClient.getAccounts(selectedScanId as string),
    enabled: Boolean(selectedScanId),
    staleTime: 60_000,
    gcTime: 300_000,
    refetchOnWindowFocus: false
  });
}

export function useDiffQuery(oldScanId: string | null, newScanId: string | null) {
  return useQuery({
    queryKey: queryKeys.diff(oldScanId, newScanId),
    queryFn: () => apiClient.getDiff(oldScanId as string, newScanId as string),
    enabled: Boolean(oldScanId && newScanId)
  });
}

export function useRuntimeStatusQuery() {
  return useQuery({
    queryKey: queryKeys.runtimeStatus(),
    queryFn: () => apiClient.getRuntimeStatus(),
    staleTime: 30_000
  });
}

export function useValidateProfileMutation() {
  return useMutation({
    mutationFn: (profile: string) => apiClient.validateProfile(profile)
  });
}

export function useSSOLoginMutation() {
  return useMutation({
    mutationFn: (profile: string) => apiClient.triggerSSOLogin(profile)
  });
}

export function useStartScanMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: apiClient.startScan,
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: queryKeys.scanRunStatus() });
      await qc.invalidateQueries({ queryKey: queryKeys.scanRunHistory() });
      await qc.invalidateQueries({ queryKey: queryKeys.scans() });
    }
  });
}

export function usePreflightMutation() {
  return useMutation({ mutationFn: (profile: string) => apiClient.preflight(profile) });
}

export function useCancelScanMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiClient.cancelScan(),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: queryKeys.scanRunStatus() });
    }
  });
}

export function useExportNeo4jMutation() {
  return useMutation({
    mutationFn: (scanId: string) => apiClient.exportScanToNeo4j(scanId)
  });
}

export function useScanRunStatusQuery(pollMs = 3000) {
  return useQuery({
    queryKey: queryKeys.scanRunStatus(),
    queryFn: () => apiClient.getScanRunStatus(),
    refetchInterval: pollMs
  });
}

export function useScanRunHistoryQuery(pollMs = 5000) {
  return useQuery({
    queryKey: queryKeys.scanRunHistory(),
    queryFn: () => apiClient.getScanRunHistory(),
    refetchInterval: pollMs
  });
}

/** Consecutive pairs from GET /api/scans (newest first) for GET /api/diff — capped to limit parallel requests. */
export const SCAN_RISK_TREND_MAX_DIFFS = 4;

export type ScanRiskTrendPoint = {
  label: string;
  newCount: number;
  /** No longer reported while the resource is still there: the likely fixes. */
  fixedCount: number;
  /** Gone because the resource was deleted, or the account was not scanned. Not fixes. */
  goneCount: number;
  net: number;
  isPending: boolean;
  isError: boolean;
};

/**
 * Builds diff-based trend points (new vs resolved vs net) for the newest scan transitions.
 * Each point is one `old` → `new` diff in chronological order toward the latest scan in the list slice.
 */
export function useScanRiskTrendData(scansNewestFirst: ScanListItem[], enabled: boolean) {
  const pairs = useMemo(() => {
    if (!enabled || scansNewestFirst.length < 2) {
      return [] as { oldId: string; newId: string; label: string }[];
    }
    const limit = Math.min(SCAN_RISK_TREND_MAX_DIFFS, scansNewestFirst.length - 1);
    const out: { oldId: string; newId: string; label: string }[] = [];
    for (let i = 0; i < limit; i++) {
      const newer = scansNewestFirst[i];
      const older = scansNewestFirst[i + 1];
      if (!newer?.scan_id || !older?.scan_id) {
        break;
      }
      const label = newer.timestamp ? new Date(newer.timestamp).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : newer.scan_id.slice(0, 8);
      out.push({ oldId: older.scan_id, newId: newer.scan_id, label });
    }
    return out;
  }, [scansNewestFirst, enabled]);

  const diffResults = useQueries({
    queries: pairs.map((p) => ({
      queryKey: queryKeys.diff(p.oldId, p.newId),
      queryFn: () => apiClient.getDiff(p.oldId, p.newId),
      enabled: enabled && pairs.length > 0,
      staleTime: 120_000,
      gcTime: 300_000
    }))
  });

  const points: ScanRiskTrendPoint[] = useMemo(
    () =>
      pairs.map((p, i) => {
        const r = diffResults[i];
        const pending = Boolean(r?.isPending || r?.isLoading);
        const err = Boolean(r?.isError);
        const newCount = r?.data?.new_findings?.length ?? 0;
        const resolved = r?.data?.resolved_findings ?? [];
        const fixedCount = resolved.filter((f) => f.reason === "no_longer_reported").length;
        const goneCount = resolved.length - fixedCount;
        return {
          label: p.label,
          newCount,
          fixedCount,
          goneCount,
          net: newCount - fixedCount,
          isPending: pending,
          isError: err
        };
      }),
    [pairs, diffResults]
  );

  const isLoading = diffResults.some((r) => r.isPending || r.isLoading);

  return { points, isLoading, pairCount: pairs.length };
}

