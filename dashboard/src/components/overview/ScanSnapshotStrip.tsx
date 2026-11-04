import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../../api/client";
import { MetricCard } from "../ui/MetricCard";
import { Link } from "react-router-dom";
import type { ScanSummaryResponse } from "../../api/types";

/**
 * Scope of the selected scan from existing endpoints: what was discovered, how complete collection
 * was, and how many IAM roles were stored. A scan with zero findings is not a safety claim.
 */
export function ScanSnapshotStrip({ scanId, summary, hasPreviousScan }: { scanId: string; summary?: ScanSummaryResponse; hasPreviousScan?: boolean }) {
  const inventory = useQuery({
    queryKey: ["overview", "inventory", scanId],
    queryFn: () => apiClient.inventorySummary(scanId, {}),
    staleTime: 60_000
  });
  const identities = useQuery({
    queryKey: ["overview", "identities", scanId],
    queryFn: () => apiClient.listIdentities(scanId, { page: 1, page_size: 1 }),
    staleTime: 60_000
  });
  const principals = useQuery({
    queryKey: ["overview", "principals", scanId],
    queryFn: () => apiClient.getPrincipals(scanId),
    staleTime: 60_000,
    retry: false
  });
  const users = (principals.data?.items ?? []).filter((p) => p.kind === "user");
  const noMfa = users.filter((p) => p.credentials_collected && p.console_enabled && !p.mfa_active).length;
  const admins = users.filter((p) => p.broad_candidates.includes("administrative_wildcard")).length;
  const q = `?scan_id=${encodeURIComponent(scanId)}`;
  const supported = inventory.data?.collection?.supported_inventory;
  const q0 = `scan_id=${encodeURIComponent(scanId)}`;
  // Only items backed by stored counts or recorded collection status. No score is computed.
  const attention: { label: string; to: string; tone: string }[] = [];
  if (summary && summary.critical_count > 0) attention.push({ label: `${summary.critical_count} critical finding${summary.critical_count === 1 ? "" : "s"}`, to: `/findings?${q0}&severity=critical`, tone: "cr-tone-bad" });
  if (summary && summary.high_count > 0) attention.push({ label: `${summary.high_count} high finding${summary.high_count === 1 ? "" : "s"}`, to: `/findings?${q0}&severity=high`, tone: "cr-tone-warn" });
  if (summary && (summary.external_entity_count ?? 0) > 0) attention.push({ label: `${summary.external_entity_count} external entities`, to: `/external-entities?${q0}`, tone: "cr-tone-info" });
  if (supported && supported !== "completed") attention.push({ label: supported === "not_recorded" ? "Collection not recorded" : "Collection incomplete", to: `/inventory?${q0}`, tone: "cr-tone-warn" });
  return (
    <section aria-label="Scan snapshot" className="space-y-3">
      <div className="hs-card flex flex-wrap items-center gap-2 p-3" aria-label="Needs attention">
        <span className="cr-kpi-label mr-1">Needs attention</span>
        {attention.length === 0 ? (
          <span className="cr-helper">Nothing flagged in the stored findings. This is not a safety claim when collection is partial or analysis was not run.</span>
        ) : (
          attention.map((item) => (
            <Link key={item.label} to={item.to} className={`cr-chip-state ${item.tone} hs-focus-ring`}>
              {item.label} →
            </Link>
          ))
        )}
        {hasPreviousScan ? (
          <Link to={`/diff?${q0}`} className="cr-chip-state cr-tone-unk hs-focus-ring ml-auto">Compare with previous scan →</Link>
        ) : null}
      </div>
      <h3 className="cr-section-title">Scan snapshot</h3>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <MetricCard
          label="Discovered AWS resources"
          value={inventory.data ? inventory.data.total_assets : null}
          context={inventory.isError ? "Inventory not available for this scan" : "Infrastructure only"}
          to={`/inventory${q}`}
          actionLabel="Browse inventory"
        />
        <MetricCard
          label="IAM roles stored"
          value={identities.data ? identities.data.total_items : null}
          context={identities.isError ? "Identity data not available for this scan" : "Declared permissions are not evaluated access"}
          to={`/identities${q}`}
          actionLabel="Explore identities"
        />
        <MetricCard
          label="IAM users"
          value={principals.data ? users.length : null}
          context={
            principals.isError
              ? "User data not available for this scan"
              : users.length === 0
                ? "No users collected (policy inventory may be off)"
                : `${noMfa} console without MFA · ${admins} with administrative access`
          }
          to={`/principals${q}`}
          actionLabel="Open Users & Groups"
        />
      </div>
    </section>
  );
}
