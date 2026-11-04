import type { ScanSummaryResponse } from "../../api/types";
import { formatCount } from "../../lib/format";

export function HighRiskCombinationStrip({
  summary,
  onOpenReclaimable,
  onOpenPrivilegedExternal,
  onOpenStaleTrustExternal,
  onOpenAdminLikeExternal,
  onOpenStalePrivilegedExternal,
  onOpenIdentity
}: {
  summary: ScanSummaryResponse;
  onOpenReclaimable: () => void;
  onOpenPrivilegedExternal: () => void;
  onOpenStaleTrustExternal: () => void;
  onOpenAdminLikeExternal: () => void;
  onOpenStalePrivilegedExternal: () => void;
  onOpenIdentity?: (category: string) => void;
}) {
  const priv = summary.external_privileged_count ?? 0;
  const stale = summary.external_trust_stale_count ?? 0;
  const admin = summary.external_admin_like_count ?? 0;
  const stalePriv = summary.external_stale_privileged_count ?? 0;
  const items = [
    { label: "Reclaimable", count: summary.reclaimable_count, onClick: onOpenReclaimable },
    { label: "External + Privileged", count: priv, onClick: onOpenPrivilegedExternal },
    { label: "Stale Trust", count: stale, onClick: onOpenStaleTrustExternal },
    { label: "Admin-like", count: admin, onClick: onOpenAdminLikeExternal },
    { label: "Stale + Privileged", count: stalePriv, onClick: onOpenStalePrivilegedExternal }
  ];

  // Combinations only identity data can show: a weak credential one step from admin, admin compute, admin users.
  const idc = summary.identity_issue_counts;
  const identityItems = idc && onOpenIdentity
    ? [
        { label: "Weak credential → admin role", category: "weak_credential_reaches_administrative_role" },
        { label: "Admin users", category: "user_administrative_access" },
        { label: "Admin workloads", category: "workload_runs_as_administrative_role" },
        { label: "Console without MFA", category: "user_console_without_mfa" },
        { label: "Key hygiene", category: "user_access_key_hygiene" }
      ].map((i) => ({ label: i.label, count: idc[i.category] ?? 0, onClick: () => onOpenIdentity(i.category) }))
    : [];

  return (
    <div className="hs-card-soft border-slate-300 p-4 dark:border-slate-700">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="cr-section-title !text-xs">High-signal combinations</h3>
      </div>
      <div className="flex flex-wrap gap-2">
        {items.map((item) => (
          <button
            key={item.label}
            type="button"
            onClick={item.onClick}
            className="hs-action-pill gap-2"
          >
            <span>{item.label}</span>
            <span className="tabular-nums text-slate-500 dark:text-slate-400">{formatCount(item.count)}</span>
          </button>
        ))}
      </div>
      {identityItems.length > 0 ? (
        <>
          <h3 className="cr-section-title mt-3 !text-xs">Identity combinations</h3>
          <div className="mt-2 flex flex-wrap gap-2">
            {identityItems.map((item) => (
              <button key={item.label} type="button" onClick={item.onClick} className="hs-action-pill gap-2">
                <span>{item.label}</span>
                <span className={`tabular-nums ${item.count > 0 ? "font-semibold text-red-700 dark:text-red-300" : "text-slate-500 dark:text-slate-400"}`}>{formatCount(item.count)}</span>
              </button>
            ))}
          </div>
        </>
      ) : null}
    </div>
  );
}
