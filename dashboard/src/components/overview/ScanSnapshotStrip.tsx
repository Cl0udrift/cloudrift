import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../../api/client";
import { MetricCard } from "../ui/MetricCard";

/**
 * Scope of the selected scan from existing endpoints: what was discovered, how complete collection
 * was, and how many IAM roles were stored. A scan with zero findings is not a safety claim.
 */
export function ScanSnapshotStrip({ scanId }: { scanId: string }) {
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
  return (
    <section aria-label="Scan snapshot" className="space-y-3">
      <h3 className="cr-section-title">Scan snapshot</h3>
      <div className="hs-card grid divide-y divide-slate-200 dark:divide-slate-800 sm:grid-cols-3 sm:divide-x sm:divide-y-0">
        <MetricCard
          bare
          label="Discovered AWS resources"
          value={inventory.data ? inventory.data.total_assets : null}
          context={inventory.isError ? "Inventory not available for this scan" : "Resources the scan found. IAM is counted separately."}
          to={`/inventory${q}`}
          actionLabel="Browse inventory"
        />
        <MetricCard
          bare
          label="IAM roles stored"
          value={identities.data ? identities.data.total_items : null}
          context={identities.isError ? "Identity data not available for this scan" : "Permissions as written in policies. Not proof of what a role can do."}
          to={`/identities${q}`}
          actionLabel="Explore identities"
        />
        <MetricCard
          bare
          label="IAM users"
          value={principals.data ? users.length : null}
          context={
            principals.isError
              ? "User data not available for this scan"
              : users.length === 0
                ? "No users were collected. IAM policy inventory may be switched off."
                : `${noMfa} console without MFA · ${admins} with administrative access`
          }
          to={`/principals${q}`}
          actionLabel="Open Users & Groups"
        />
      </div>
    </section>
  );
}
