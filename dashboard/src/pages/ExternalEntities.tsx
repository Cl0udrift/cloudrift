import { useCallback, useMemo } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { formatQueryError } from "../api/httpError";
import type { ExternalEntitiesQueryParams, ExternalEntityRow } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { SeverityBadge } from "../components/SeverityBadge";
import { ScanRequired } from "../components/ScanRequired";
import { StatePanel } from "../components/StatePanel";
import { useExternalEntitiesQuery } from "../hooks/useDashboardQueries";
import { useScanContext } from "../hooks/useScanContext";
import { formatCount, formatUsd, shortenArn } from "../lib/format";

const DEFAULT_PAGE_SIZE = 25;

function parsePage(raw: string | null): number {
  const n = parseInt(raw ?? "1", 10);
  return Number.isFinite(n) && n > 0 ? n : 1;
}

export function ExternalEntitiesPage() {
  const { selectedScanId } = useScanContext();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const page = parsePage(searchParams.get("page"));
  const principalType = searchParams.get("principal_type") ?? "";
  const externalPrincipal = searchParams.get("external_principal") ?? "";
  const externalAccountId = searchParams.get("external_account_id") ?? "";
  const hasStaleRole = searchParams.get("has_stale_role") === "true";
  const hasPrivilegedRole = searchParams.get("has_privileged_role") === "true";
  const hasAdminLikeRole = searchParams.get("has_admin_like_role") === "true";

  const listParams: ExternalEntitiesQueryParams = useMemo(
    () => ({
      page,
      page_size: DEFAULT_PAGE_SIZE,
      ...(principalType.trim() ? { principal_type: principalType.trim() } : {}),
      ...(externalPrincipal.trim() ? { external_principal: externalPrincipal.trim() } : {}),
      ...(externalAccountId.trim() ? { external_account_id: externalAccountId.trim() } : {}),
      ...(hasStaleRole ? { has_stale_role: true } : {}),
      ...(hasPrivilegedRole ? { has_privileged_role: true } : {}),
      ...(hasAdminLikeRole ? { has_admin_like_role: true } : {})
    }),
    [
      page,
      principalType,
      externalPrincipal,
      externalAccountId,
      hasStaleRole,
      hasPrivilegedRole,
      hasAdminLikeRole
    ]
  );

  const query = useExternalEntitiesQuery(selectedScanId, listParams);
  const entityItems = query.data?.items ?? [];
  const safeFilters = query.data?.filters ?? {};

  const patchParams = useCallback(
    (
      next: Partial<{
        page: number;
        principal_type: string;
        external_principal: string;
        external_account_id: string;
        has_stale_role: boolean;
        has_privileged_role: boolean;
        has_admin_like_role: boolean;
      }>
    ) => {
      const sp = new URLSearchParams(searchParams);
      const merged = {
        page: next.page ?? page,
        principal_type: next.principal_type ?? principalType,
        external_principal: next.external_principal ?? externalPrincipal,
        external_account_id: next.external_account_id ?? externalAccountId,
        has_stale_role: next.has_stale_role ?? hasStaleRole,
        has_privileged_role: next.has_privileged_role ?? hasPrivilegedRole,
        has_admin_like_role: next.has_admin_like_role ?? hasAdminLikeRole
      };
      if (merged.page <= 1) {
        sp.delete("page");
      } else {
        sp.set("page", String(merged.page));
      }
      for (const [k, v] of [
        ["principal_type", merged.principal_type],
        ["external_principal", merged.external_principal],
        ["external_account_id", merged.external_account_id]
      ] as const) {
        const t = v.trim();
        if (!t) {
          sp.delete(k);
        } else {
          sp.set(k, t);
        }
      }
      for (const [k, on] of [
        ["has_stale_role", merged.has_stale_role],
        ["has_privileged_role", merged.has_privileged_role],
        ["has_admin_like_role", merged.has_admin_like_role]
      ] as const) {
        if (on) {
          sp.set(k, "true");
        } else {
          sp.delete(k);
        }
      }
      setSearchParams(sp, { replace: true });
    },
    [
      searchParams,
      setSearchParams,
      page,
      principalType,
      externalPrincipal,
      externalAccountId,
      hasStaleRole,
      hasPrivilegedRole,
      hasAdminLikeRole
    ]
  );

  const goToFindingsForRow = useCallback(
    (row: ExternalEntityRow) => {
      const q = new URLSearchParams();
      if (selectedScanId) {
        q.set("scan_id", selectedScanId);
      }
      q.set("module", "external_access");
      q.set("page", "1");
      q.set("principal_type", row.principal_type);
      q.set("external_principal", row.external_principal);
      q.set("external_account_id", row.external_account_id);
      navigate({ pathname: "/findings", search: `?${q.toString()}` });
    },
    [navigate, selectedScanId]
  );

  const pagination = query.data?.pagination;
  const totalPages = Math.max(1, pagination?.total_pages ?? 1);

  return (
    <section className="space-y-6">
      <PageHeader
        title="External entities"
        description="External principals grouped from trust findings, highest severity first."
        details="Entity-centric aggregation of external_access findings, grouped by (external_principal, principal_type, external_account_id) from trust evidence. Missing evidence in any dimension is bucketed as 'unknown' and may merge multiple unidentified entries. Rows are ordered by highest severity first, then total monthly risk — not a pure cost ranking. Flags like stale / privileged / admin-like mean AT LEAST ONE distinct trusted role for that entity meets the signal; other roles for the same entity may not. Unfiltered total matches summary.external_entity_count."
      />
      {!selectedScanId ? (
        <ScanRequired />
      ) : query.isLoading ? (
        <StatePanel>Loading external entities…</StatePanel>
      ) : query.isError ? (
        <StatePanel intent="error" title="Failed to load external entities">
          <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(query.error)}</pre>
        </StatePanel>
      ) : query.data ? (
        <div className="space-y-4">
          <div className="hs-filter-bar md:flex-row md:flex-wrap md:items-end">
            <label className="block min-w-[10rem] flex-1">
              <span className="hs-label">Principal type</span>
              <input
                className="hs-input w-full"
                value={principalType}
                onChange={(e) => patchParams({ page: 1, principal_type: e.target.value })}
                placeholder="e.g. oidc or unknown"
              />
            </label>
            <label className="block min-w-[12rem] flex-1">
              <span className="hs-label">External principal (exact)</span>
              <input
                className="hs-input w-full"
                value={externalPrincipal}
                onChange={(e) => patchParams({ page: 1, external_principal: e.target.value })}
                placeholder="ARN or unknown"
              />
            </label>
            <label className="block min-w-[10rem] flex-1">
              <span className="hs-label">External account id</span>
              <input
                className="hs-input w-full"
                value={externalAccountId}
                onChange={(e) => patchParams({ page: 1, external_account_id: e.target.value })}
                placeholder="12-digit id or unknown"
              />
            </label>
            <div className="min-w-[12rem]">
              <span className="hs-label">Signals</span>
              <div className="flex w-full flex-wrap gap-3 md:w-auto">
              <label className="hs-toggle-inline cursor-pointer">
                <input
                  type="checkbox"
                  className="hs-checkbox"
                  checked={hasStaleRole}
                  onChange={(e) => patchParams({ page: 1, has_stale_role: e.target.checked })}
                />
                Stale roles
              </label>
              <label className="hs-toggle-inline cursor-pointer">
                <input
                  type="checkbox"
                  className="hs-checkbox"
                  checked={hasPrivilegedRole}
                  onChange={(e) => patchParams({ page: 1, has_privileged_role: e.target.checked })}
                />
                Privileged tier
              </label>
              <label className="hs-toggle-inline cursor-pointer">
                <input
                  type="checkbox"
                  className="hs-checkbox"
                  checked={hasAdminLikeRole}
                  onChange={(e) => patchParams({ page: 1, has_admin_like_role: e.target.checked })}
                />
                Admin-like
              </label>
              </div>
            </div>
            <button
              type="button"
              className="hs-btn-default text-xs"
              onClick={() =>
                patchParams({
                  page: 1,
                  principal_type: "",
                  external_principal: "",
                  external_account_id: "",
                  has_stale_role: false,
                  has_privileged_role: false,
                  has_admin_like_role: false
                })
              }
            >
              Clear filters
            </button>
          </div>

          <p className="cr-helper">
            Showing {formatCount(entityItems.length)} of {formatCount(pagination?.total_items ?? 0)} entities
            {safeFilters.principal_type || safeFilters.external_principal || safeFilters.external_account_id
              ? " (filtered)"
              : ""}
            .
          </p>
          <p className="cr-helper text-xs">
            Blast radius uses entity context; principal blast uses the underlying principal identity when derivable.
          </p>

          {pagination && pagination.total_items === 0 ? (
            <StatePanel intent="empty" title="No external entities">
              No rows match the current filters for this scan.
            </StatePanel>
          ) : (
            <div className="hs-table-wrap">
            <table className="w-full min-w-[720px] border-collapse text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-700">
                  <th
                    className="hs-table-head font-medium"
                    title="From evidence.external_principal. Missing evidence renders as 'unknown' and may merge distinct unidentified principals."
                  >
                    External principal
                  </th>
                  <th
                    className="hs-table-head font-medium"
                    title="From evidence.principal_type (lower-cased). Missing evidence renders as 'unknown'."
                  >
                    Type
                  </th>
                  <th
                    className="hs-table-head font-medium"
                    title="From evidence.external_account_id. Missing evidence renders as 'unknown'."
                  >
                    Ext. account
                  </th>
                  <th className="hs-table-head font-medium">Severity</th>
                  <th className="hs-table-head font-medium">Risk / mo</th>
                  <th
                    className="hs-table-head text-center font-medium"
                    title="Distinct trusted roles in this entity bucket."
                  >
                    Roles
                  </th>
                  <th
                    className="hs-table-head text-center font-medium"
                    title="Distinct internal accounts hosting those roles."
                  >
                    Accounts
                  </th>
                  <th
                    className="hs-table-head text-center font-medium"
                    title="Count of DISTINCT trusted roles for this entity with verdict stale_review_now. Does NOT imply every role for this entity is stale."
                  >
                    Stale
                  </th>
                  <th
                    className="hs-table-head text-center font-medium"
                    title="Count of DISTINCT trusted roles classified as privileged tier (permission_visibility.classification). AT LEAST one role hits the signal; others may not."
                  >
                    Priv.
                  </th>
                  <th
                    className="hs-table-head text-center font-medium"
                    title="Count of DISTINCT trusted roles with permission_visibility.capabilities.admin_like. AT LEAST one role hits the signal; others may not."
                  >
                    Admin∼
                  </th>
                  <th className="hs-table-head text-center font-medium">Findings</th>
                  <th className="hs-table-head font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {entityItems.map((row) => (
                  <tr
                    key={row.entity_id || `${row.external_principal}|${row.principal_type}|${row.external_account_id}`}
                    className="hs-interactive-row border-b border-slate-100 dark:border-slate-800/80"
                  >
                    <td className="px-3 py-2 font-mono text-xs text-slate-800 dark:text-slate-200">
                      {shortenArn(row.external_principal, 36, 16)}
                    </td>
                    <td className="px-3 py-2 text-xs">{row.principal_type}</td>
                    <td className="px-3 py-2 font-mono text-xs text-slate-600 dark:text-slate-400">{row.external_account_id}</td>
                    <td className="px-3 py-2">
                      <SeverityBadge severity={row.highest_severity} />
                    </td>
                    <td className="px-3 py-2 tabular-nums text-xs">{formatUsd(row.total_monthly_risk_cost_usd)}</td>
                    <td className="px-3 py-2 text-center tabular-nums text-xs">{formatCount(row.unique_trusted_role_count)}</td>
                    <td className="px-3 py-2 text-center tabular-nums text-xs">
                      {formatCount(row.unique_internal_account_count)}
                    </td>
                    <td className="px-3 py-2 text-center tabular-nums text-xs">{formatCount(row.stale_role_count)}</td>
                    <td className="px-3 py-2 text-center tabular-nums text-xs">{formatCount(row.privileged_role_count)}</td>
                    <td className="px-3 py-2 text-center tabular-nums text-xs">{formatCount(row.admin_like_role_count)}</td>
                    <td className="px-3 py-2 text-center tabular-nums text-xs">
                      {formatCount(row.external_access_finding_count)}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">
                      <div className="flex flex-col items-start gap-1">
                        <button
                          type="button"
                          onClick={() => goToFindingsForRow(row)}
                          className="hs-focus-ring text-xs font-medium text-cyan-700 hover:underline dark:text-cyan-400"
                        >
                          Findings
                        </button>
                        {selectedScanId && row.entity_id ? (
                          <Link
                            to={`/blast-explorer?scan=${encodeURIComponent(selectedScanId)}&entity=${encodeURIComponent(
                              row.entity_id
                            )}&mode=blast_radius`}
                            title="View blast radius for this external entity"
                            className="hs-focus-ring text-xs font-medium text-amber-800 hover:underline dark:text-amber-300/90"
                          >
                            Blast radius
                          </Link>
                        ) : null}
                        {selectedScanId && row.principal_id ? (
                          <Link
                            to={`/blast-explorer?scan=${encodeURIComponent(selectedScanId)}&principal=${encodeURIComponent(
                              row.principal_id
                            )}&mode=blast_radius`}
                            className="hs-focus-ring text-xs font-medium text-violet-700 hover:underline dark:text-violet-300"
                            title="Open blast radius from principal identity"
                          >
                            Principal blast
                          </Link>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          )}

          {pagination && pagination.total_items > 0 ? (
            <div className="hs-pagination !text-xs">
              <span className="hs-pagination-meta !text-xs">
                Page {pagination.page} / {totalPages}
              </span>
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={pagination.page <= 1}
                  className="hs-btn-default px-2 py-1 text-xs"
                  onClick={() => patchParams({ page: pagination.page - 1 })}
                >
                  Previous
                </button>
                <button
                  type="button"
                  disabled={pagination.page >= totalPages}
                  className="hs-btn-default px-2 py-1 text-xs"
                  onClick={() => patchParams({ page: pagination.page + 1 })}
                >
                  Next
                </button>
              </div>
            </div>
          ) : null}
        </div>
      ) : (
        <StatePanel intent="empty" title="No data">
          Select a scan to load external entities.
        </StatePanel>
      )}
    </section>
  );
}
