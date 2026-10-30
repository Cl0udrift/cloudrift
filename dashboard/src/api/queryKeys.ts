import type { ExternalEntitiesQueryParams, FindingsQueryParams } from "./types";

export const queryKeys = {
  config: () => ["config"] as const,
  coverage: (scanId: string | null) => ["coverage", scanId] as const,
  scans: () => ["scans"] as const,
  summary: (scanId: string | null) => ["summary", scanId] as const,
  externalEntities: (scanId: string | null, params: ExternalEntitiesQueryParams) =>
    ["external-entities", scanId, params] as const,
  findings: (scanId: string | null, params: FindingsQueryParams) => ["findings", scanId, params] as const,
  remediationGroups: (scanId: string | null) => ["remediation-groups", scanId] as const,
  topFixes: (scanId: string | null, limit: number) => ["top-fixes", scanId, limit] as const,
  findingDetail: (scanId: string | null, findingId: string | null) =>
    ["finding", scanId, findingId] as const,
  accounts: (scanId: string | null) => ["accounts", scanId] as const,
  /** Fingerprint of finding IDs (order-preserving) for batched trust activity buckets. */
  trustActivityBuckets: (scanId: string | null, idsKey: string) =>
    ["trust-activity-buckets", scanId, idsKey] as const,
  diff: (oldScanId: string | null, newScanId: string | null) => ["diff", oldScanId, newScanId] as const,
  runtimeStatus: () => ["runtime-status"] as const,
  scanRunStatus: () => ["scan-run-status"] as const,
  scanRunHistory: () => ["scan-run-history"] as const,
  alertCatalog: () => ["alerts", "catalog"] as const,
  alertRouting: () => ["alerts", "routing"] as const,
  alertRules: () => ["alerts", "rules"] as const,
  alertEvents: (limit: number) => ["alerts", "events", limit] as const,
  blastSummary: (scanId: string | null, findingId: string | null, mode: string) =>
    ["blast-radius", "summary", scanId, findingId, mode] as const,
  blastExplorer: (scanId: string | null, findingId: string | null, mode: string) =>
    ["blast-radius", "explorer", scanId, findingId, mode] as const,
  entityBlastSummary: (scanId: string | null, entityId: string | null, mode: string) =>
    ["blast-radius", "entity-summary", scanId, entityId, mode] as const,
  entityBlastExplorer: (scanId: string | null, entityId: string | null, mode: string) =>
    ["blast-radius", "entity-explorer", scanId, entityId, mode] as const,
  principalBlastSummary: (scanId: string | null, principalId: string | null, mode: string) =>
    ["blast-radius", "principal-summary", scanId, principalId, mode] as const,
  principalBlastExplorer: (scanId: string | null, principalId: string | null, mode: string) =>
    ["blast-radius", "principal-explorer", scanId, principalId, mode] as const
};
