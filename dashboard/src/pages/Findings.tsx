import { EntityDrawer } from "../components/ui/EntityDrawer";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable
} from "@tanstack/react-table";
import { useQueryClient } from "@tanstack/react-query";
import { Fragment, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { formatQueryError } from "../api/httpError";
import type { FindingListItem, FindingsQueryParams } from "../api/types";
import {
  FindingDetailPanelContent,
  FindingDetailPanelError,
  FindingDetailPanelLoading
} from "../components/findings/FindingDetailPanel";
import { InterimHeuristicIndicator } from "../components/InterimHeuristicIndicator";
import { PageHeader } from "../components/PageHeader";
import { SafeExternalLink } from "../components/SafeExternalLink";
import { SeverityBadge } from "../components/SeverityBadge";
import { ScanRequired } from "../components/ScanRequired";
import { StatePanel } from "../components/StatePanel";
import {
  getFindingDetailQueryOptions,
  useAccountsQuery,
  useFindingDetailQuery,
  useFindingsListQuery
} from "../hooks/useDashboardQueries";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import { DEFAULT_PAGE_SIZE, useFindingsUrlState } from "../hooks/useFindingsUrlState";
import { useScanContext } from "../hooks/useScanContext";
import { findingInlineHint } from "../lib/findingHints";
import { displayTarget, formatUsd, shortenArn } from "../lib/format";

const PAGE_SIZE_OPTIONS = [25, 50, 100] as const;
const SEARCH_DEBOUNCE_MS = 350;
const TRIAGE_FETCH_PAGE_SIZE = 200;

const SEVERITY_OPTIONS = ["", "critical", "high", "medium", "low"] as const;
// Preset filters over existing API filters. Not stored per user; each is a plain URL state.
const SAVED_VIEWS: { label: string; hint: string; filter: { module?: string; claimability?: string; adminLike?: boolean; trustStale?: boolean } }[] = [
  { label: "All findings", hint: "No module or flag filter", filter: {} },
  { label: "Declared IAM exposure", hint: "Declared permissions, not evaluated access", filter: { module: "iam_entitlement" } },
  { label: "External access", hint: "Trust and resource policies naming external principals", filter: { module: "external_access" } },
  { label: "Admin-like trust", hint: "Trusted roles with admin-like declared permissions", filter: { adminLike: true } },
  { label: "Stale trust", hint: "Trust with no recent observed activity", filter: { trustStale: true } },
  { label: "Reclaimable assets", hint: "Orphaned edge assets that can be reclaimed", filter: { module: "orphaned_edge", claimability: "reclaimable" } }
];

const MODULE_OPTIONS = ["", "orphaned_edge", "external_access", "iam_entitlement"] as const;
const CLAIM_OPTIONS = ["", "reclaimable", "dangling", "broken", "edge_obscured"] as const;

const columnHelper = createColumnHelper<FindingListItem>();

export type FindingsPageProps = {
  /** Critical + high only, merged client-side, sorted by monthly risk (see banner for API limits). */
  triage?: boolean;
};

function bucketFindingsByAccount(items: FindingListItem[]): { accountId: string; items: FindingListItem[] }[] {
  const m = new Map<string, FindingListItem[]>();
  for (const it of items) {
    const acc = it.account_id?.trim() || "—";
    if (!m.has(acc)) {
      m.set(acc, []);
    }
    m.get(acc)!.push(it);
  }
  const groups = [...m.entries()].map(([accountId, list]) => ({ accountId, items: list }));
  groups.sort((a, b) => {
    const maxA = Math.max(0, ...a.items.map((i) => i.monthly_risk_cost_usd));
    const maxB = Math.max(0, ...b.items.map((i) => i.monthly_risk_cost_usd));
    if (maxB !== maxA) {
      return maxB - maxA;
    }
    return a.accountId.localeCompare(b.accountId);
  });
  return groups;
}

export function FindingsPage({ triage = false }: FindingsPageProps) {
  const { selectedScanId } = useScanContext();
  const queryClient = useQueryClient();
  const { state, patch } = useFindingsUrlState();
  const accountsQuery = useAccountsQuery();

  const [searchInput, setSearchInput] = useState(state.search);
  useEffect(() => {
    setSearchInput(state.search);
  }, [state.search]);

  const debouncedSearch = useDebouncedValue(searchInput.trim(), SEARCH_DEBOUNCE_MS);

  useEffect(() => {
    if (debouncedSearch === state.search) {
      return;
    }
    patch({ search: debouncedSearch, page: 1 });
  }, [debouncedSearch, state.search, patch]);

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const findingScrollFocusRef = useRef<string | null>(null);
  const prefetchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const listParams: FindingsQueryParams = useMemo(() => {
    const p: FindingsQueryParams = { page: state.page, page_size: state.pageSize };
    if (state.severity) {
      p.severity = state.severity;
    }
    if (state.module) {
      p.module = state.module;
    }
    if (state.accountId) {
      p.account_id = state.accountId;
    }
    if (state.claimability) {
      p.claimability = state.claimability;
    }
    if (debouncedSearch) {
      p.search = debouncedSearch;
    }
    if (state.trustStale) {
      p.trust_stale = true;
    }
    if (state.adminLike) {
      p.admin_like = true;
    }
    if (state.trustClassification.trim()) {
      p.trust_classification = state.trustClassification.trim();
    }
    if (state.principalType.trim()) {
      p.principal_type = state.principalType.trim();
    }
    if (state.externalPrincipal.trim()) {
      p.external_principal = state.externalPrincipal.trim();
    }
    if (state.externalAccountId.trim()) {
      p.external_account_id = state.externalAccountId.trim();
    }
    return p;
  }, [
    state.page,
    state.pageSize,
    state.severity,
    state.module,
    state.accountId,
    state.claimability,
    debouncedSearch,
    state.trustStale,
    state.adminLike,
    state.trustClassification,
    state.principalType,
    state.externalPrincipal,
    state.externalAccountId
  ]);

  const triageBackendParams: FindingsQueryParams = useMemo(() => {
    const p: FindingsQueryParams = { page: 1, page_size: TRIAGE_FETCH_PAGE_SIZE };
    if (state.module) {
      p.module = state.module;
    }
    if (state.accountId) {
      p.account_id = state.accountId;
    }
    if (state.claimability) {
      p.claimability = state.claimability;
    }
    if (debouncedSearch) {
      p.search = debouncedSearch;
    }
    if (state.trustStale) {
      p.trust_stale = true;
    }
    if (state.adminLike) {
      p.admin_like = true;
    }
    if (state.trustClassification.trim()) {
      p.trust_classification = state.trustClassification.trim();
    }
    if (state.principalType.trim()) {
      p.principal_type = state.principalType.trim();
    }
    if (state.externalPrincipal.trim()) {
      p.external_principal = state.externalPrincipal.trim();
    }
    if (state.externalAccountId.trim()) {
      p.external_account_id = state.externalAccountId.trim();
    }
    return p;
  }, [
    state.module,
    state.accountId,
    state.claimability,
    debouncedSearch,
    state.trustStale,
    state.adminLike,
    state.trustClassification,
    state.principalType,
    state.externalPrincipal,
    state.externalAccountId
  ]);

  const defaultQuery = useFindingsListQuery(selectedScanId, listParams, {
    enabled: Boolean(selectedScanId) && !triage
  });

  const triageCrit = useFindingsListQuery(
    selectedScanId,
    { ...triageBackendParams, severity: "critical" },
    { enabled: Boolean(selectedScanId) && triage }
  );
  const triageHigh = useFindingsListQuery(
    selectedScanId,
    { ...triageBackendParams, severity: "high" },
    { enabled: Boolean(selectedScanId) && triage }
  );

  const mergedTriageItems = useMemo(() => {
    if (!triage) {
      return [] as FindingListItem[];
    }
    const map = new Map<string, FindingListItem>();
    for (const it of triageCrit.data?.items ?? []) {
      map.set(it.id, it);
    }
    for (const it of triageHigh.data?.items ?? []) {
      map.set(it.id, it);
    }
    const arr = [...map.values()];
    arr.sort((a, b) => {
      if (b.monthly_risk_cost_usd !== a.monthly_risk_cost_usd) {
        return b.monthly_risk_cost_usd - a.monthly_risk_cost_usd;
      }
      return a.id.localeCompare(b.id);
    });
    return arr;
  }, [triage, triageCrit.data?.items, triageHigh.data?.items]);

  const triageTotalPages = useMemo(
    () => Math.max(1, Math.ceil(mergedTriageItems.length / state.pageSize)),
    [mergedTriageItems.length, state.pageSize]
  );

  useEffect(() => {
    if (!triage || mergedTriageItems.length === 0) {
      return;
    }
    if (state.page > triageTotalPages) {
      patch({ page: triageTotalPages });
    }
  }, [triage, mergedTriageItems.length, state.page, triageTotalPages, patch]);

  const pageItems: FindingListItem[] = useMemo(() => {
    if (triage) {
      const start = (state.page - 1) * state.pageSize;
      return mergedTriageItems.slice(start, start + state.pageSize);
    }
    return defaultQuery.data?.items ?? [];
  }, [triage, mergedTriageItems, state.page, state.pageSize, defaultQuery.data?.items]);

  const pagination = useMemo(() => {
    if (triage) {
      return {
        page: state.page,
        page_size: state.pageSize,
        total_items: mergedTriageItems.length,
        total_pages: triageTotalPages
      };
    }
    return (
      defaultQuery.data?.pagination ?? {
        page: 1,
        page_size: DEFAULT_PAGE_SIZE,
        total_items: 0,
        total_pages: 1
      }
    );
  }, [triage, state.page, state.pageSize, mergedTriageItems.length, triageTotalPages, defaultQuery.data?.pagination]);

  const isLoading = triage
    ? triageCrit.isPending || triageHigh.isPending
    : defaultQuery.isPending;
  const isError = triage ? triageCrit.isError || triageHigh.isError : defaultQuery.isError;
  const error = triage ? triageCrit.error ?? triageHigh.error : defaultQuery.error;
  const isFetching = triage ? triageCrit.isFetching || triageHigh.isFetching : defaultQuery.isFetching;
  const isSuccess = triage ? triageCrit.isSuccess && triageHigh.isSuccess : defaultQuery.isSuccess;

  useEffect(() => {
    setExpandedId(null);
  }, [selectedScanId, listParams, triageBackendParams, triage]);

  // j / k move through the list and open the detail drawer; Esc closes it (handled by the drawer).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable)) return;
      if (e.metaKey || e.ctrlKey || e.altKey || (e.key !== "j" && e.key !== "k")) return;
      if (pageItems.length === 0) return;
      const idx = pageItems.findIndex((item) => item.id === expandedId);
      const next = e.key === "j" ? Math.min(idx + 1, pageItems.length - 1) : Math.max(idx - 1, 0);
      const target = pageItems[idx === -1 ? 0 : next];
      setExpandedId(target.id);
      document.querySelector(`[data-finding-id="${target.id}"]`)?.scrollIntoView({ block: "nearest" });
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [pageItems, expandedId]);

  const detailQuery = useFindingDetailQuery(selectedScanId, expandedId, expandedId !== null);

  const hasActiveFilters = Boolean(
    triage ||
      state.severity ||
      state.module ||
      state.accountId ||
      state.claimability ||
      debouncedSearch ||
      state.trustStale ||
      state.adminLike ||
      state.trustClassification.trim() ||
      state.principalType.trim() ||
      state.externalPrincipal.trim() ||
      state.externalAccountId.trim()
  );

  const clearPrefetchTimer = useCallback(() => {
    if (prefetchTimer.current) {
      clearTimeout(prefetchTimer.current);
      prefetchTimer.current = null;
    }
  }, []);

  const onRowPointerEnter = useCallback(
    (findingId: string) => {
      if (!selectedScanId || findingId === expandedId) {
        return;
      }
      clearPrefetchTimer();
      prefetchTimer.current = setTimeout(() => {
        queryClient.prefetchQuery(getFindingDetailQueryOptions(selectedScanId, findingId));
      }, 140);
    },
    [selectedScanId, expandedId, queryClient, clearPrefetchTimer]
  );

  const onRowPointerLeave = useCallback(() => {
    clearPrefetchTimer();
  }, [clearPrefetchTimer]);

  useEffect(() => () => clearPrefetchTimer(), [clearPrefetchTimer]);

  const columns = useMemo(
    () => [
      columnHelper.display({
        id: "expand",
        header: "",
        cell: ({ row }) => {
          const open = expandedId === row.original.id;
          return (
            <button
              type="button"
              aria-expanded={open}
              aria-label={open ? "Collapse finding detail" : "Expand finding detail"}
              className="hs-focus-ring rounded p-1 text-slate-600 transition-colors duration-150 hover:bg-slate-200 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-200"
              onClick={(e) => {
                e.stopPropagation();
                setExpandedId((id) => (id === row.original.id ? null : row.original.id));
              }}
            >
              <span className="inline-block text-xs transition-transform" style={{ transform: open ? "rotate(90deg)" : "none" }}>
                ▸
              </span>
            </button>
          );
        },
        size: 36
      }),
      columnHelper.accessor("severity", {
        header: "Severity",
        cell: (info) => <SeverityBadge severity={info.getValue()} />
      }),
      columnHelper.display({
        id: "target",
        header: "Finding",
        cell: ({ row }) => {
          const hint = findingInlineHint(row.original);
          const hostname = row.original.hostname?.trim() ?? "";
          return (
            <div>
              <div className="font-medium text-slate-800 dark:text-slate-200">{row.original.title?.trim() || "—"}</div>
              <div className="mt-0.5 text-xs text-slate-600 dark:text-slate-400">
                {hostname ? (
                  <SafeExternalLink
                    href={hostname}
                    className="text-cyan-700 underline decoration-cyan-400/60 underline-offset-2 hover:text-cyan-800 dark:text-cyan-300 dark:hover:text-cyan-200"
                    fallback={displayTarget(row.original.hostname, row.original.affected_arn)}
                  >
                    {hostname}
                  </SafeExternalLink>
                ) : (
                  displayTarget(row.original.hostname, row.original.affected_arn)
                )}
              </div>
              {row.original.hostname?.trim() ? (
                <div className="mt-0.5 font-mono text-[11px] text-slate-500 break-all">{shortenArn(row.original.affected_arn, 36, 24)}</div>
              ) : null}
              {hint ? (
                <div className="mt-1 inline-flex items-center gap-1.5">
                  <p className="inline-flex rounded-full border border-amber-300/60 bg-amber-100/80 px-2 py-0.5 text-[11px] font-medium text-amber-900/90 dark:border-amber-700/70 dark:bg-amber-900/30 dark:text-amber-200/85">
                    {hint}
                  </p>
                  <InterimHeuristicIndicator
                    label="inferred"
                    tooltip="Derived from list fields (module, claimability, title keywords). Interim heuristic, not authoritative."
                  />
                </div>
              ) : null}
            </div>
          );
        }
      }),
      columnHelper.display({
        id: "account",
        header: "Account",
        cell: ({ row }) => {
          const name = row.original.account_name?.trim();
          const id = row.original.account_id;
          if (name && id) {
            return (
              <div>
                <div className="text-slate-800 dark:text-slate-200">{name}</div>
                <div className="font-mono text-[11px] text-slate-500">{id}</div>
              </div>
            );
          }
          return <span className="font-mono text-xs text-slate-700 dark:text-slate-300">{id || "—"}</span>;
        }
      }),
      columnHelper.display({
        id: "assessment",
        header: "Assessment",
        cell: ({ row }) => (
          <div>
            <div className="text-slate-800 dark:text-slate-200">{row.original.module || "—"}</div>
            <div className="text-[11px] capitalize text-slate-500">Claimability: {row.original.claimability || "unknown"}</div>
          </div>
        )
      }),
      columnHelper.accessor("monthly_risk_cost_usd", {
        header: () => <span className="whitespace-nowrap">Risk cost / mo</span>,
        cell: (info) => (
          <span className="tabular-nums text-slate-800 dark:text-slate-200">{formatUsd(info.getValue())}</span>
        )
      })
    ],
    [expandedId]
  );

  const table = useReactTable({
    data: pageItems,
    columns,
    getCoreRowModel: getCoreRowModel()
  });

  const totalPages = Math.max(1, pagination.total_pages);
  const totalItems = pagination.total_items;

  const grouped = useMemo(() => {
    if (!triage || !state.groupByAccount) {
      return null;
    }
    return bucketFindingsByAccount(pageItems);
  }, [triage, state.groupByAccount, pageItems]);

  const targetedFindingInPage = useMemo(
    () => Boolean(state.findingId && pageItems.some((item) => item.id === state.findingId)),
    [state.findingId, pageItems]
  );

  useEffect(() => {
    const target = state.findingId.trim();
    if (!target) {
      return;
    }
    const hit = pageItems.find((item) => item.id === target);
    if (!hit) {
      return;
    }
    if (expandedId !== target) {
      setExpandedId(target);
    }
    if (findingScrollFocusRef.current === target) {
      return;
    }
    findingScrollFocusRef.current = target;
    requestAnimationFrame(() => {
      const el = document.querySelector<HTMLElement>(`[data-finding-id="${target}"]`);
      if (!el) {
        return;
      }
      el.scrollIntoView({ block: "nearest", behavior: "smooth" });
      el.focus({ preventScroll: true });
    });
  }, [state.findingId, pageItems, expandedId]);

  return (
    <section className="space-y-6">
      <PageHeader
        title={triage ? "Triage" : "Findings"}
        description={
          triage
            ? "Critical and high severity findings, sorted by estimated monthly risk."
            : "Findings for the selected scan. Filters are saved in the URL."
        }
        details={
          triage
            ? "Merged and sorted by estimated monthly risk on this device. Pagination applies after merge. See the banner for fetch limits."
            : "Server-paginated from GET /api/scans/:id/findings. Detail loads when a row is opened. Filters sync to the URL for sharing."
        }
      />
      {triage ? (
        <div
          className="rounded-lg border border-amber-800/40 bg-amber-950/20 px-4 py-3 text-sm text-amber-100/95 dark:border-amber-500/35 dark:bg-amber-950/40"
          role="status"
        >
          <p className="font-medium text-amber-50 dark:text-amber-100">Triage mode: showing highest-risk findings</p>
          <p className="mt-1 text-xs leading-relaxed text-amber-100/85 dark:text-amber-200/80">
            Severity is limited to <strong>critical</strong> and <strong>high</strong>. Rows are sorted by{" "}
            <strong>monthly_risk_cost_usd</strong> descending after merge. Up to {TRIAGE_FETCH_PAGE_SIZE} critical and{" "}
            {TRIAGE_FETCH_PAGE_SIZE} high rows are loaded from the API per request; if your scan exceeds those caps,
            increase filters or use the full Findings view.
          </p>
        </div>
      ) : null}

      {!selectedScanId ? (
        <ScanRequired />
      ) : isLoading ? (
        <StatePanel>Loading findings…</StatePanel>
      ) : isError ? (
        <StatePanel intent="error" title="Failed to load findings">
          <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(error)}</pre>
        </StatePanel>
      ) : isSuccess && totalItems === 0 ? (
        <div className="space-y-3">
          <StatePanel intent="empty" title={hasActiveFilters ? "No matching findings" : "No findings in this scan"}>
            {hasActiveFilters ? (
              <div className="space-y-3">
                <p>Zero results for the active filter combination. The filters below are all applied as AND conditions — try removing one to broaden the search.</p>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  {state.severity && (
                    <span className="rounded-full border border-slate-300 bg-slate-100 px-2 py-0.5 dark:border-slate-700 dark:bg-slate-900">
                      <span className="text-slate-500">severity=</span>
                      <span className="font-mono text-[11px] text-cyan-800 dark:text-cyan-200/90">{state.severity}</span>
                    </span>
                  )}
                  {state.claimability && (
                    <span className="rounded-full border border-slate-300 bg-slate-100 px-2 py-0.5 dark:border-slate-700 dark:bg-slate-900">
                      <span className="text-slate-500">claimability=</span>
                      <span className="font-mono text-[11px] text-cyan-800 dark:text-cyan-200/90">{state.claimability}</span>
                    </span>
                  )}
                  {state.module && (
                    <span className="rounded-full border border-slate-300 bg-slate-100 px-2 py-0.5 dark:border-slate-700 dark:bg-slate-900">
                      <span className="text-slate-500">module=</span>
                      <span className="font-mono text-[11px] text-cyan-800 dark:text-cyan-200/90">{state.module}</span>
                    </span>
                  )}
                  {state.accountId && (
                    <span className="rounded-full border border-slate-300 bg-slate-100 px-2 py-0.5 dark:border-slate-700 dark:bg-slate-900">
                      <span className="text-slate-500">account=</span>
                      <span className="font-mono text-[11px] text-cyan-800 dark:text-cyan-200/90">{state.accountId}</span>
                    </span>
                  )}
                  {state.trustClassification.trim() && (
                    <span className="rounded-full border border-slate-300 bg-slate-100 px-2 py-0.5 dark:border-slate-700 dark:bg-slate-900">
                      <span className="text-slate-500">trust_classification=</span>
                      <span className="font-mono text-[11px] text-cyan-800 dark:text-cyan-200/90">{state.trustClassification}</span>
                    </span>
                  )}
                  {state.principalType.trim() && (
                    <span className="rounded-full border border-slate-300 bg-slate-100 px-2 py-0.5 dark:border-slate-700 dark:bg-slate-900">
                      <span className="text-slate-500">principal_type=</span>
                      <span className="font-mono text-[11px] text-cyan-800 dark:text-cyan-200/90">{state.principalType}</span>
                    </span>
                  )}
                </div>
                <button
                  type="button"
                  className="rounded border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                  onClick={() =>
                    patch({
                      severity: "",
                      module: "",
                      accountId: "",
                      claimability: "",
                      search: "",
                      trustStale: false,
                      adminLike: false,
                      trustClassification: "",
                      principalType: "",
                      externalPrincipal: "",
                      externalAccountId: "",
                      findingId: "",
                      page: 1
                    })
                  }
                >
                  Clear all filters
                </button>
              </div>
            ) : (
              "The API returned successfully with zero findings for this scan."
            )}
          </StatePanel>
        </div>
      ) : pageItems.length > 0 || (!isLoading && isSuccess) ? (
        <>
          {expandedId ? (
            <EntityDrawer title="Finding detail" onClose={() => setExpandedId(null)}>
              {detailQuery.isLoading ? (
                <FindingDetailPanelLoading />
              ) : detailQuery.isError ? (
                <FindingDetailPanelError error={detailQuery.error} />
              ) : detailQuery.data?.item ? (
                <FindingDetailPanelContent item={detailQuery.data.item} scanId={selectedScanId ?? undefined} findingId={expandedId} />
              ) : (
                <StatePanel intent="empty">No detail payload.</StatePanel>
              )}
            </EntityDrawer>
          ) : null}
          {!triage ? (
            <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Saved views">
              <span className="cr-kpi-label mr-1">Views</span>
              {SAVED_VIEWS.map((view) => {
                const active = (["module", "claimability", "adminLike", "trustStale"] as const).every(
                  (k) => (view.filter[k] ?? (k === "adminLike" || k === "trustStale" ? false : "")) === state[k]
                );
                return (
                  <button
                    key={view.label}
                    type="button"
                    aria-pressed={active}
                    title={view.hint}
                    onClick={() => patch({ severity: "", module: "", claimability: "", adminLike: false, trustStale: false, ...view.filter, page: 1 })}
                    className={`hs-focus-ring rounded-md border px-2.5 py-1 text-xs font-medium ${
                      active
                        ? "border-cyan-500 bg-cyan-500/10 text-cyan-900 dark:text-cyan-200"
                        : "border-slate-300 text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                    }`}
                  >
                    {view.label}
                  </button>
                );
              })}
            </div>
          ) : null}
          {!triage ? (
            <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Quick severity filter">
              {[["", "All"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]].map(([value, label]) => (
                <button
                  key={label}
                  type="button"
                  aria-pressed={state.severity === value}
                  onClick={() => patch({ severity: value, page: 1 })}
                  className={`hs-focus-ring rounded-full border px-3 py-1 text-xs font-medium ${
                    state.severity === value
                      ? "border-cyan-500 bg-cyan-500/10 text-cyan-900 dark:text-cyan-200"
                      : "border-slate-300 text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          ) : null}
          <details open={Boolean(state.module || state.accountId || state.claimability || state.search || state.trustStale || state.adminLike || state.trustClassification || state.principalType || state.findingId)}>
            <summary className="hs-focus-ring mb-2 w-fit cursor-pointer rounded text-xs font-medium text-cyan-800 dark:text-cyan-300">More filters</summary>
          <div className="hs-filter-bar">
            {!triage ? (
              <FilterField label="Severity">
                <select
                  value={state.severity}
                  onChange={(e) => patch({ severity: e.target.value, page: 1 })}
                  className="hs-select w-full min-w-[8rem]"
                >
                  {SEVERITY_OPTIONS.map((v) => (
                    <option key={v || "all"} value={v}>
                      {v ? v : "All"}
                    </option>
                  ))}
                </select>
              </FilterField>
            ) : (
              <FilterField label="Severity">
                <div className="hs-card-soft rounded-lg px-2 py-2 text-xs text-slate-700 dark:text-slate-300">
                  Critical + high (fixed)
                </div>
              </FilterField>
            )}
            <FilterField label="Module">
              <select
                value={state.module}
                onChange={(e) => patch({ module: e.target.value, page: 1 })}
                className="hs-select w-full min-w-[10rem]"
              >
                {MODULE_OPTIONS.map((v) => (
                  <option key={v || "all"} value={v}>
                    {v ? v.replace(/_/g, " ") : "All"}
                  </option>
                ))}
              </select>
            </FilterField>
            <FilterField label="Account">
              <select
                value={state.accountId}
                onChange={(e) => patch({ accountId: e.target.value, page: 1 })}
                className="hs-select w-full min-w-[12rem]"
                disabled={accountsQuery.isLoading}
              >
                <option value="">All accounts</option>
                {(accountsQuery.data?.items ?? []).map((a) => (
                  <option key={a.account_id} value={a.account_id}>
                    {a.account_name ? `${a.account_name} (${a.account_id})` : a.account_id}
                  </option>
                ))}
              </select>
            </FilterField>
            <FilterField label="Claimability">
              <select
                value={state.claimability}
                onChange={(e) => patch({ claimability: e.target.value, page: 1 })}
                className="hs-select w-full min-w-[10rem]"
              >
                {CLAIM_OPTIONS.map((v) => (
                  <option key={v || "all"} value={v}>
                    {v ? v.replace(/_/g, " ") : "All"}
                  </option>
                ))}
              </select>
            </FilterField>
            {!triage && state.module === "external_access" ? (
              <>
                <FilterField
                  label="Trust stale"
                  hint="Structured filter: evidence.verdict === stale_review_now. Unrelated to permission tier or admin_like."
                >
                  <label className="hs-toggle-card cursor-pointer">
                    <input
                      type="checkbox"
                      className="hs-checkbox"
                      checked={state.trustStale}
                      onChange={(e) => patch({ trustStale: e.target.checked, page: 1 })}
                    />
                    Verdict stale_review_now
                  </label>
                </FilterField>
                <FilterField
                  label="Admin-like (capability)"
                  hint="Stronger signal: permission_visibility.capabilities.admin_like. Distinct from privileged tier — a role can be one, both, or neither. Does not imply trust_classification=privileged."
                >
                  <label className="hs-toggle-card cursor-pointer">
                    <input
                      type="checkbox"
                      className="hs-checkbox"
                      checked={state.adminLike}
                      onChange={(e) => patch({ adminLike: e.target.checked, page: 1 })}
                    />
                    admin_like flag
                  </label>
                </FilterField>
                <FilterField
                  label="Permission tier"
                  hint="Backend coarse label: permission_visibility.classification (e.g. privileged, admin). Not the same as admin_like capability — compare both filters if you expected overlap."
                >
                  <select
                    value={state.trustClassification}
                    onChange={(e) => patch({ trustClassification: e.target.value, page: 1 })}
                  className="hs-select w-full min-w-[9rem]"
                  >
                    <option value="">Any</option>
                    <option value="admin">admin</option>
                    <option value="privileged">privileged</option>
                    <option value="scoped">scoped</option>
                    <option value="limited">limited</option>
                    <option value="unknown">unknown</option>
                  </select>
                </FilterField>
                <FilterField label="Principal type">
                  <input
                    type="text"
                    value={state.principalType}
                    onChange={(e) => patch({ principalType: e.target.value, page: 1 })}
                    placeholder="e.g. oidc, aws_account, saml"
                    className="hs-input w-full min-w-[10rem]"
                  />
                </FilterField>
                <FilterField
                  label="External principal"
                  hint="Exact evidence.external_principal (use unknown for missing). AND with other filters."
                >
                  <input
                    type="text"
                    value={state.externalPrincipal}
                    onChange={(e) => patch({ externalPrincipal: e.target.value, page: 1 })}
                    placeholder="ARN or unknown"
                    className="hs-input w-full min-w-[12rem]"
                  />
                </FilterField>
                <FilterField
                  label="External account id"
                  hint="Exact evidence.external_account_id (use unknown for missing)."
                >
                  <input
                    type="text"
                    value={state.externalAccountId}
                    onChange={(e) => patch({ externalAccountId: e.target.value, page: 1 })}
                    placeholder="12-digit id or unknown"
                    className="hs-input w-full min-w-[10rem]"
                  />
                </FilterField>
              </>
            ) : null}
            <FilterField label="Search" className="min-w-[16rem] flex-1">
              <input
                type="search"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder="Title, ARN, account, hostname…"
                className="hs-input"
              />
              {searchInput.trim() !== debouncedSearch ? <p className="mt-1 cr-helper">Debouncing search…</p> : null}
            </FilterField>
            <FilterField label="Finding id">
              <input
                type="text"
                value={state.findingId}
                onChange={(e) => patch({ findingId: e.target.value, page: 1 })}
                placeholder="Exact id (auto-expand on match)"
                className="hs-input w-full min-w-[14rem]"
              />
            </FilterField>
            <FilterField label="Page size">
              <select
                value={state.pageSize}
                onChange={(e) => patch({ pageSize: Number(e.target.value) as (typeof PAGE_SIZE_OPTIONS)[number], page: 1 })}
                className="hs-select"
              >
                {PAGE_SIZE_OPTIONS.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </FilterField>
            {triage ? (
              <FilterField label="Layout">
                <label className="hs-toggle-inline cursor-pointer">
                  <input
                    type="checkbox"
                    className="hs-checkbox"
                    checked={state.groupByAccount}
                    onChange={(e) => patch({ groupByAccount: e.target.checked, page: 1 })}
                  />
                  Group by account
                </label>
              </FilterField>
            ) : null}
          </div>
          </details>

          <AppliedFiltersBar
            triage={triage}
            severity={state.severity}
            moduleFilter={state.module}
            accountId={state.accountId}
            claimability={state.claimability}
            search={debouncedSearch}
            trustStale={state.trustStale}
            adminLike={state.adminLike}
            trustClassification={state.trustClassification}
            principalType={state.principalType}
            findingId={state.findingId}
            groupByAccount={state.groupByAccount}
          />
          {state.findingId.trim() && !targetedFindingInPage ? (
            <p className="cr-helper">
              `finding_id` target not found in this page result. Adjust filters/page or clear `finding_id`.
            </p>
          ) : null}

          <div className="hs-table-wrap">
            <table className="w-full min-w-[56rem] border-collapse text-left text-sm">
              <thead className="sticky top-0 z-10 border-b border-slate-200 bg-slate-100/95 backdrop-blur-sm dark:border-b-slate-800 dark:bg-slate-950/95">
                {table.getHeaderGroups().map((hg) => (
                  <tr key={hg.id}>
                    {hg.headers.map((header) => (
                      <th key={header.id} className="hs-table-head whitespace-nowrap">
                        {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800/90">
                {grouped
                  ? grouped.flatMap((g) => [
                      <tr key={`h-${g.accountId}`} className="bg-slate-200/90 dark:bg-slate-800/80">
                        <td colSpan={columns.length} className="px-3 py-2 text-xs font-semibold text-slate-700 dark:text-slate-200">
                          Account <span className="font-mono text-cyan-900 dark:text-cyan-200/90">{g.accountId}</span>
                          <span className="ml-2 font-normal text-slate-500">({g.items.length} on this page)</span>
                        </td>
                      </tr>,
                      ...g.items.map((rowItem) => renderFindingRowFragment(rowItem))
                    ])
                  : table.getRowModel().rows.map((row) => renderFindingRowFragment(row.original))}
              </tbody>
            </table>
          </div>

          <div className="hs-pagination">
            <p className="hs-pagination-meta">
              Page <span className="tabular-nums text-slate-700 dark:text-slate-300">{pagination.page}</span> of{" "}
              <span className="tabular-nums text-slate-700 dark:text-slate-300">{totalPages}</span>
              <span className="mx-2 text-slate-500 dark:text-slate-600">·</span>
              <span className="tabular-nums text-slate-700 dark:text-slate-300">{totalItems}</span> total
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={state.page <= 1 || isFetching}
                onClick={() => patch({ page: Math.max(1, state.page - 1) })}
                className="hs-btn-default px-3 py-1.5 text-sm"
              >
                Previous
              </button>
              <button
                type="button"
                disabled={state.page >= totalPages || isFetching}
                onClick={() => patch({ page: state.page + 1 })}
                className="hs-btn-default px-3 py-1.5 text-sm"
              >
                Next
              </button>
            </div>
          </div>
        </>
      ) : (
        <StatePanel intent="empty" title="No data">Unexpected empty response after success.</StatePanel>
      )}
    </section>
  );

  function renderFindingRowFragment(rowItem: FindingListItem) {
    const row = table.getRowModel().rows.find((r) => r.original.id === rowItem.id);
    if (!row) {
      return null;
    }
    return (
      <Fragment key={row.id}>
        <tr
          data-finding-id={rowItem.id}
          tabIndex={-1}
          className={`group hs-interactive-row ${expandedId === rowItem.id ? "bg-cyan-50 dark:bg-cyan-950/30" : "bg-slate-50/80 dark:bg-slate-900/40"}`}
          onPointerEnter={() => onRowPointerEnter(rowItem.id)}
          onPointerLeave={onRowPointerLeave}
        >
          {row.getVisibleCells().map((cell) => (
            <td
              key={cell.id}
              className="px-3 py-3 align-top text-slate-700 transition-colors group-hover:text-slate-900 dark:text-slate-300 dark:group-hover:text-slate-100"
            >
              {flexRender(cell.column.columnDef.cell, cell.getContext())}
            </td>
          ))}
        </tr>
      </Fragment>
    );
  }
}

function FilterField({
  label,
  children,
  className = "",
  hint
}: {
  label: string;
  children: ReactNode;
  className?: string;
  /** Shown as native tooltip on the field group (privileged vs admin_like clarity). */
  hint?: string;
}) {
  return (
    <div className={className} title={hint}>
      <label className="hs-label">{label}</label>
      {children}
    </div>
  );
}

function AppliedFiltersBar({
  triage,
  severity,
  moduleFilter,
  accountId,
  claimability,
  search,
  trustStale,
  adminLike,
  trustClassification,
  principalType,
  findingId,
  groupByAccount
}: {
  triage: boolean;
  severity: string;
  moduleFilter: string;
  accountId: string;
  claimability: string;
  search: string;
  trustStale: boolean;
  adminLike: boolean;
  trustClassification: string;
  principalType: string;
  findingId: string;
  groupByAccount: boolean;
}) {
  const chips: { label: string; value: string }[] = [];
  if (triage) {
    chips.push({ label: "mode", value: "triage (critical+high)" });
  }
  if (severity) {
    chips.push({ label: "severity", value: severity });
  }
  if (moduleFilter) {
    chips.push({ label: "module", value: moduleFilter });
  }
  if (accountId) {
    chips.push({ label: "account", value: accountId });
  }
  if (claimability) {
    chips.push({ label: "claimability", value: claimability });
  }
  if (trustStale) {
    chips.push({ label: "trust_stale", value: "true" });
  }
  if (adminLike) {
    chips.push({ label: "admin_like", value: "true" });
  }
  if (trustClassification.trim()) {
    chips.push({ label: "trust_classification", value: trustClassification.trim() });
  }
  if (principalType.trim()) {
    chips.push({ label: "principal_type", value: principalType.trim() });
  }
  if (search) {
    chips.push({ label: "search", value: search });
  }
  if (findingId.trim()) {
    chips.push({ label: "finding_id", value: findingId.trim() });
  }
  if (triage && groupByAccount) {
    chips.push({ label: "group_by", value: "account" });
  }

  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <span className="text-slate-500">Applied filters</span>
      {chips.length === 0 ? (
        <span className="text-slate-500 dark:text-slate-600">— none (unfiltered within this page set)</span>
      ) : (
        chips.map((c) => (
          <span
            key={`${c.label}-${c.value}`}
            className="rounded-full border border-slate-300 bg-slate-100 px-2 py-0.5 dark:border-slate-700 dark:bg-slate-900 text-slate-700 dark:text-slate-300"
          >
            <span className="text-slate-500">{c.label}=</span>
            <span className="font-mono text-[11px] text-cyan-800 dark:text-cyan-200/90">{c.value}</span>
          </span>
        ))
      )}
    </div>
  );
}
