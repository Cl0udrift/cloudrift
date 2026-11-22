import { MetricCard } from "../components/ui/MetricCard";
import { CollectionChip } from "../components/ui/StatusChip";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { apiClient } from "../api/client";
import type { InventoryDetail, InventoryRegionCoverage } from "../api/types";
import { formatQueryError } from "../api/httpError";
import { PageHeader } from "../components/PageHeader";
import { cov, plural } from "../lib/inventoryView";
import { encodePrincipalId } from "../lib/principalId";
import { EntityDrawer } from "../components/ui/EntityDrawer";
import { SeverityBadge } from "../components/SeverityBadge";
import { ScanRequired } from "../components/ScanRequired";
import { StatePanel } from "../components/StatePanel";
import { useScanContext } from "../hooks/useScanContext";

const semanticLabel: Record<string, string> = {
  configuration: "Configuration",
  ownership: "Ownership",
  trust: "Trust",
  evidence: "Evidence",
  validated_attacker_transition: "Validated attacker transition"
};

const sortColumns: { key: string; label: string; asc: string; desc?: string }[] = [
  { key: "name", label: "Name", asc: "name" },
  { key: "account", label: "Account", asc: "account" },
  { key: "region", label: "Region", asc: "region" },
  { key: "findings", label: "Findings", asc: "severity", desc: "-severity" }
];

/** Last path segment of an ARN, which is the resource name for IAM identities and policies. */
const shortName = (arn: string) => arn.split("/").pop() || arn;

export function InventoryPage() {
  const { selectedScanId, currentScan } = useScanContext();
  const [params, setParams] = useSearchParams();
  const accountID = params.get("account_id") ?? "";
  const region = params.get("region") ?? "";
  const service = params.get("service") ?? "";
  const category = params.get("category") ?? "";
  const resourceType = params.get("resource_type") ?? "";
  const q = params.get("q") ?? "";
  const hasFindings = params.get("has_findings") === "true";
  // AWS managed policies and service-linked roles are hidden by default: they are not the customer's to fix.
  const showAws = params.get("show_aws") === "true";
  const internetOnly = params.get("internet_facing") === "true";
  const newResources = params.get("new_resources") === "true";
  const owner = params.get("owner") ?? "";
  const severities = (params.get("severity") ?? "").split(",").filter(Boolean);
  const newOnly = params.get("new_only") === "true";
  const sort = params.get("sort") ?? "-severity";
  const resource = params.get("resource") ?? "";
  const page = Number(params.get("page") || "1");
  const [evidenceOpen, setEvidenceOpen] = useState(false);

  const summaryParams = useMemo(() => ({ account_id: accountID, region }), [accountID, region]);
  const listParams = useMemo(
    () => ({ account_id: accountID, region, service, resource_type: resourceType, category, q, has_findings: hasFindings ? "true" : "", hide_aws: showAws ? "" : "true", internet_facing: internetOnly ? "true" : "", new_resources: newResources ? "true" : "", owner, severity: severities.join(","), new_only: newOnly ? "true" : "", sort, page, page_size: 25 }),
    [accountID, region, service, resourceType, category, q, hasFindings, showAws, internetOnly, newResources, owner, severities.join(","), newOnly, sort, page]
  );
  const summary = useQuery({
    queryKey: ["inventory-summary", selectedScanId, summaryParams],
    queryFn: () => apiClient.inventorySummary(selectedScanId!, summaryParams),
    enabled: Boolean(selectedScanId)
  });
  const list = useQuery({
    queryKey: ["inventory-resources", selectedScanId, listParams],
    queryFn: () => apiClient.inventoryResources(selectedScanId!, listParams),
    enabled: Boolean(selectedScanId)
  });
  // Resources with findings under the account and region filter only, for the summary strip.
  const risky = useQuery({
    queryKey: ["inventory-risky", selectedScanId, summaryParams],
    queryFn: () => apiClient.inventoryResources(selectedScanId!, { ...summaryParams, has_findings: "true", page: 1, page_size: 1 }),
    enabled: Boolean(selectedScanId)
  });
  const internet = useQuery({
    queryKey: ["inventory-internet", selectedScanId, summaryParams],
    queryFn: () => apiClient.inventoryResources(selectedScanId!, { ...summaryParams, internet_facing: "true", hide_aws: "true", page: 1, page_size: 1 }),
    enabled: Boolean(selectedScanId)
  });
  const previousScan = list.data?.previous_scan_id ?? "";
  const fresh = useQuery({
    queryKey: ["inventory-new", selectedScanId, summaryParams, previousScan],
    queryFn: () => apiClient.inventoryResources(selectedScanId!, { ...summaryParams, new_only: "true", page: 1, page_size: 1 }),
    enabled: Boolean(selectedScanId && previousScan)
  });
  const detail = useQuery({
    queryKey: ["inventory-resource", selectedScanId, resource],
    queryFn: () => apiClient.inventoryResource(selectedScanId!, resource),
    enabled: Boolean(selectedScanId && resource)
  });

  const patch = (updates: Record<string, string>, keepResource = false) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(updates)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    if (!("page" in updates)) next.delete("page");
    if (!keepResource) next.delete("resource");
    setEvidenceOpen(false);
    setParams(next, { replace: "q" in updates });
  };

  const items = list.data?.items ?? [];
  // State and Identity are hidden when no row on the page has a value. Account, Region and Category follow the whole scan.
  // Account and Region come from the scan summary, not the current page, so the layout does not jump between pages.
  const showAccount = (summary.data?.accounts.length ?? 0) > 1;
  const showRegion = (summary.data?.regions.length ?? 0) > 1;
  const showState = items.some((i) => i.state);
  const showIdentity = items.some((i) => i.identity_associated);
  // Always shown: hiding them when the current page has no value made them vanish depending on the page.
  const showExposure = true;
  const showOwner = true;
  const showCategory = (summary.data?.categories.filter((c) => c.count > 0).length ?? 0) > 1;

  const serviceCards = summary.data?.services ?? [];
  const attention = serviceCards.filter((c) => c.count > 0 || cov(c) !== "collected");
  const quiet = serviceCards.filter((c) => c.count === 0 && cov(c) === "collected");
  const regionProblem = (summary.data?.region_coverage?.accounts ?? []).some((a) => a.partial > 0 || a.failed > 0 || a.unknown > 0);
  const col = summary.data?.collection;
  const collectionProblem = Boolean(col && [col.account_scope, col.region_discovery, col.regional_collectors, col.service_collection, col.supported_inventory].some((v) => v !== "completed" && v !== "not_recorded"));
  const notRecordedNames = serviceCards.filter((c) => cov(c) === "not_recorded").map((c) => c.name);
  const notRecorded = notRecordedNames.length;
  const collectedCount = serviceCards.filter((c) => cov(c) === "collected").length;
  // A service the account or Region does not offer, or that Cloudrift has no collector for, is not a gap in what was collected.
  const unavailableNames = serviceCards.filter((c) => cov(c) === "unsupported").map((c) => c.name);
  // Opt-in collectors that are off are a choice, not a gap: they are listed with the setting that turns them on.
  const offNames = serviceCards.filter((c) => c.config_key && cov(c) === "not_collected").map((c) => c.name);
  const collectableCount = serviceCards.length - unavailableNames.length - offNames.length;
  const notInventoried = summary.data?.not_inventoried ?? [];
  const totalFindings = serviceCards.reduce((n, c) => n + c.finding_count, 0);
  const shownBars = (summary.data?.distribution ?? []).filter((item) => item.count > 0);
  const maxBar = Math.max(...shownBars.map((item) => item.count), 1);

  const filters: { key: string; label: string; clear: Record<string, string> }[] = [];
  if (service) filters.push({ key: "service", label: `Service: ${serviceCards.find((c) => c.service === service)?.name ?? service}`, clear: { service: "" } });
  if (category) filters.push({ key: "category", label: `Category: ${summary.data?.categories.find((c) => c.category === category)?.name ?? category}`, clear: { category: "" } });
  if (resourceType) filters.push({ key: "type", label: `Type: ${resourceType}`, clear: { resource_type: "" } });
  if (accountID) filters.push({ key: "account", label: `Account: ${accountID}`, clear: { account_id: "" } });
  if (region) filters.push({ key: "region", label: `Region: ${region}`, clear: { region: "" } });
  for (const sev of severities) filters.push({ key: `sev-${sev}`, label: `Severity: ${sev}`, clear: { severity: severities.filter((s) => s !== sev).join(",") } });
  if (newOnly) filters.push({ key: "new", label: "New since previous scan", clear: { new_only: "" } });
  if (internetOnly) filters.push({ key: "internet", label: "Internet-facing", clear: { internet_facing: "" } });
  if (newResources) filters.push({ key: "newres", label: "New resources", clear: { new_resources: "" } });
  if (owner) filters.push({ key: "owner", label: `Owner: ${owner}`, clear: { owner: "" } });
  if (hasFindings) filters.push({ key: "findings", label: "Has findings", clear: { has_findings: "" } });
  if (q) filters.push({ key: "q", label: `Search: ${q}`, clear: { q: "" } });
  const clearAll = { service: "", category: "", resource_type: "", account_id: "", region: "", has_findings: "", internet_facing: "", new_resources: "", owner: "", severity: "", new_only: "", q: "" };

  const sortHeader = (c: (typeof sortColumns)[number]) => {
    const desc = c.desc ?? "-" + c.asc;
    const active = sort === c.asc ? "ascending" : sort === desc ? "descending" : "none";
    return (
      <th key={c.key} scope="col" aria-sort={active} className={`sticky top-0 z-10 bg-slate-50 px-3 py-2.5 dark:bg-slate-900 ${c.key === "findings" || c.key === "name" ? "" : "hidden sm:table-cell"}`}>
        <button
          type="button"
          className="hs-focus-ring inline-flex items-center gap-1 rounded uppercase"
          onClick={() => patch({ sort: sort === (c.desc ?? c.asc) ? (c.desc ? c.asc : desc) : (c.desc ?? c.asc) }, true)}
        >
          {c.label}
          <span aria-hidden="true">{active === "ascending" ? "▲" : active === "descending" ? "▼" : ""}</span>
        </button>
      </th>
    );
  };

  return (
    <section className="space-y-4">
      <PageHeader title="AWS Inventory" description={`Resources discovered in the selected scan · ${summary.data?.timestamp || currentScan?.timestamp || "timestamp not recorded"}`} />
      {!selectedScanId ? (
        <ScanRequired />
      ) : (
        <>
          {summary.isLoading ? <StatePanel>Loading inventory summary…</StatePanel> : null}
          {summary.isError ? <StatePanel intent="error" title="Failed to load inventory"><pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(summary.error)}</pre></StatePanel> : null}
          {summary.data ? (
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <div className="hs-card flex h-full flex-col gap-1 p-4">
                <p className="cr-kpi-label">Resources</p>
                <p className="cr-kpi-value">{summary.data.total_assets}</p>
                <p className="cr-helper">{`${plural(summary.data.service_count, "service")} · ${plural(summary.data.region_count, "region")} · ${plural(summary.data.account_count, "account")}`}</p>
                {summary.data.change ? (
                  <p className="cr-helper" title={summary.data.change.removed_names?.length ? `Removed: ${summary.data.change.removed_names.join(", ")}` : undefined}>
                    <button type="button" className="hs-focus-ring rounded font-medium text-cyan-800 underline dark:text-cyan-300" onClick={() => patch({ new_resources: newResources ? "" : "true" })}>+{summary.data.change.added} added</button> · −{summary.data.change.removed} removed since the previous scan
                  </p>
                ) : null}
              </div>
              <button type="button" aria-pressed={internetOnly} className={`hs-card hs-interactive-card flex h-full flex-col gap-1 p-4 text-left ${internetOnly ? "border-cyan-500 ring-1 ring-cyan-500" : ""}`} onClick={() => patch({ internet_facing: internetOnly ? "" : "true" })}>
                <p className="cr-kpi-label">Internet-facing</p>
                <p className="cr-kpi-value">{internet.data?.total_items ?? "…"}</p>
                <p className="cr-helper">Reachable from the internet. Click to filter.</p>
              </button>
              <button type="button" aria-pressed={hasFindings} className={`hs-card hs-interactive-card flex h-full flex-col gap-1 p-4 text-left ${hasFindings ? "border-cyan-500 ring-1 ring-cyan-500" : ""}`} onClick={() => patch({ has_findings: hasFindings ? "" : "true" })}>
                <p className="cr-kpi-label">With findings</p>
                <p className="cr-kpi-value">{risky.data?.total_items ?? "…"}</p>
                <p className="cr-helper">{plural(totalFindings, "finding")} on these. Click to filter.</p>
              </button>
              <div className="hs-card flex h-full flex-col gap-1 p-4">
                <div className="flex items-center justify-between gap-2">
                  <p className="cr-kpi-label">Collection</p>
                  {col ? <CollectionChip status={collectionProblem || regionProblem || notRecorded > 0 ? "partial" : "completed"} /> : null}
                </div>
                <p className="cr-kpi-value">{collectedCount}<span className="text-base font-normal text-slate-500"> / {serviceCards.length} services</span></p>
                <div className="h-1.5 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800" role="progressbar" aria-label="Services collected" aria-valuemin={0} aria-valuemax={serviceCards.length} aria-valuenow={collectedCount}>
                  <div className="h-full rounded-full bg-cyan-600 dark:bg-cyan-400" style={{ width: `${serviceCards.length ? Math.round((collectedCount / serviceCards.length) * 100) : 0}%` }} />
                </div>
                <p className="cr-helper">{offNames.length} off · {unavailableNames.length} unavailable · <a href="#inventory-coverage" className="underline">Details</a></p>
              </div>
            </div>
          ) : null}

          {summary.data ? (
            <nav aria-label="Services" className="-mx-1 flex gap-2 overflow-x-auto px-1 pb-1">
              <ServiceChip active={!service} label="All" count={summary.data.total_assets} onClick={() => patch({ service: "" }, true)} />
              {serviceCards.filter((c) => c.count > 0 || c.service === service).map((c) => (
                <ServiceChip key={c.service} active={service === c.service} label={c.name} count={c.count} onClick={() => patch({ service: service === c.service ? "" : c.service }, true)} />
              ))}
              {serviceCards.filter((c) => c.config_key && cov(c) === "not_collected" && c.count === 0).map((c) => (
                <Link key={c.service} to={`/settings#cfg-${c.config_key}`} title={`${c.name} is off. Turn it on in Settings, then scan again.`} className="hs-focus-ring inline-flex shrink-0 items-center gap-2 whitespace-nowrap rounded-full border border-dashed border-slate-300 px-3 py-1 text-sm text-slate-500 hover:border-cyan-500 dark:border-slate-700">
                  {c.name} <span className="text-xs">Off</span>
                </Link>
              ))}
            </nav>
          ) : null}

          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <input className="hs-input !w-auto min-w-[16rem] flex-1" placeholder="Search name or ARN" value={q} aria-label="Search name or ARN" onChange={(e) => patch({ q: e.target.value }, true)} />
              <div className="order-last flex basis-full flex-wrap items-center gap-2">
              <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Quick filters">
                <TogglePill on={hasFindings} onClick={() => patch({ has_findings: hasFindings ? "" : "true" }, true)}>Has findings</TogglePill>
                <TogglePill on={internetOnly} onClick={() => patch({ internet_facing: internetOnly ? "" : "true" }, true)}>Internet-facing</TogglePill>
                {previousScan ? (
                  <TogglePill on={newOnly} title={`Findings that scan ${previousScan} did not have`} onClick={() => patch({ new_only: newOnly ? "" : "true" }, true)}>
                    New findings{fresh.data ? ` (${fresh.data.total_items})` : ""}
                  </TogglePill>
                ) : null}
                <TogglePill on={!showAws} title="AWS managed policies and service-linked roles" onClick={() => patch({ show_aws: showAws ? "" : "true" }, true)}>Hide AWS-managed</TogglePill>
              </div>
              <div className="flex items-center gap-1" role="group" aria-label="Severity">
                {["critical", "high", "medium", "low", "info"].map((sev) => {
                  const on = severities.includes(sev);
                  return <TogglePill key={sev} on={on} onClick={() => patch({ severity: (on ? severities.filter((s) => s !== sev) : [...severities, sev]).join(",") }, true)}><span className="capitalize">{sev === "medium" ? "Med" : sev}</span></TogglePill>;
                })}
              </div>
              </div>
              <details className="relative">
                <summary className="hs-action-pill cursor-pointer list-none">More filters{[category, resourceType, accountID, region, owner].filter(Boolean).length ? ` (${[category, resourceType, accountID, region, owner].filter(Boolean).length})` : ""}</summary>
                <div className="absolute right-0 z-20 mt-2 w-72 space-y-3 rounded-lg border border-slate-200 bg-white p-3 shadow-lg dark:border-slate-700 dark:bg-slate-900">
                  <label className="block text-xs text-slate-500">Category
                    <select className="hs-input mt-1" aria-label="Category" value={category} onChange={(e) => patch({ category: e.target.value }, true)}>
                      <option value="">All categories</option>
                      {(summary.data?.categories ?? []).filter((c) => c.count > 0 || c.category === category).map((item) => (<option key={item.category} value={item.category}>{item.name} ({item.count})</option>))}
                    </select>
                  </label>
                  <label className="block text-xs text-slate-500">Resource type
                    <input className="hs-input mt-1" placeholder="e.g. iam_role" value={resourceType} aria-label="Resource type" onChange={(e) => patch({ resource_type: e.target.value }, true)} />
                  </label>
                  {showAccount || accountID ? (
                    <label className="block text-xs text-slate-500">Account
                      <select className="hs-input mt-1" aria-label="Account" value={accountID} onChange={(e) => patch({ account_id: e.target.value })}>
                        <option value="">All accounts</option>
                        {(summary.data?.accounts ?? []).map((a) => <option key={a} value={a}>{a}</option>)}
                      </select>
                    </label>
                  ) : null}
                  {showRegion || region ? (
                    <label className="block text-xs text-slate-500">Region
                      <select className="hs-input mt-1" aria-label="Region" value={region} onChange={(e) => patch({ region: e.target.value })}>
                        <option value="">All regions</option>
                        {(summary.data?.regions ?? []).map((r) => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </label>
                  ) : null}
                  <label className="block text-xs text-slate-500">Owner
                    <input className="hs-input mt-1" placeholder="A name, or none" value={owner} aria-label="Owner" onChange={(e) => patch({ owner: e.target.value }, true)} />
                  </label>
                </div>
              </details>
              <a className="hs-action-pill" download href={selectedScanId ? apiClient.inventoryExportUrl(selectedScanId, { account_id: accountID, region, service, resource_type: resourceType, category, q, has_findings: hasFindings ? "true" : "", hide_aws: showAws ? "" : "true", internet_facing: internetOnly ? "true" : "", new_resources: newResources ? "true" : "", owner, severity: severities.join(",") }) : "#"}>Export CSV</a>
            </div>
            {filters.length > 0 ? (
              <ul className="flex flex-wrap items-center gap-2" aria-label="Active filters">
                {filters.map((f) => (
                  <li key={f.key}>
                    <button type="button" className="hs-focus-ring inline-flex items-center gap-1 rounded-full border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-0.5 text-xs text-cyan-900 dark:text-cyan-100" onClick={() => patch(f.clear)} aria-label={`Remove filter ${f.label}`}>{f.label} <span aria-hidden="true">✕</span></button>
                  </li>
                ))}
                <li><button type="button" className="text-xs text-cyan-800 underline dark:text-cyan-300" onClick={() => patch(clearAll)}>Clear all</button></li>
              </ul>
            ) : null}
          </div>

          <section className="space-y-3">
            {list.isLoading ? <StatePanel>Loading resources…</StatePanel> : null}
            {list.isError ? <StatePanel intent="error" title="Failed to load resources"><pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(list.error)}</pre></StatePanel> : null}
            {list.data && items.length === 0 ? (
              <StatePanel intent="empty" title="No inventory assets match">
                {list.data.coverage_note}{" "}
                {filters.length > 0 ? <button type="button" className="underline" onClick={() => patch(clearAll)}>Clear filters</button> : null}
              </StatePanel>
            ) : null}
            {items.length > 0 ? (
              <div className="hs-card max-h-[70vh] overflow-auto !p-0">
                <table className="w-full text-left text-sm">
                  <thead className="text-[11px] font-semibold tracking-wide text-slate-500">
                    <tr>
                      {sortColumns.filter((c) => (c.key === "account" ? showAccount : c.key === "region" ? showRegion : true)).map(sortHeader)}
                      {showExposure ? <th scope="col" className="sticky top-0 z-10 hidden bg-slate-50 px-3 py-2.5 uppercase dark:bg-slate-900 sm:table-cell">Exposure</th> : null}
                      <th scope="col" className="sticky top-0 z-10 hidden bg-slate-50 px-3 py-2.5 uppercase dark:bg-slate-900 lg:table-cell">Tags</th>
                      {showOwner ? <th scope="col" className="sticky top-0 z-10 hidden bg-slate-50 px-3 py-2.5 uppercase dark:bg-slate-900 sm:table-cell">Owner</th> : null}
                      {showState ? <th scope="col" className="sticky top-0 z-10 hidden bg-slate-50 px-3 py-2.5 uppercase dark:bg-slate-900 sm:table-cell">State</th> : null}
                      {showIdentity ? <th scope="col" className="sticky top-0 z-10 hidden bg-slate-50 px-3 py-2.5 uppercase dark:bg-slate-900 sm:table-cell">Identity</th> : null}
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => (
                      <tr key={item.id} onClick={() => patch({ resource: item.id }, true)} className={`hs-interactive-row border-t border-slate-200 dark:border-slate-800 ${resource === item.id ? "bg-cyan-500/10" : ""}`}>
                        <td className="max-w-[14rem] px-3 py-2.5 sm:max-w-[26rem]">
                          <button type="button" title={item.arn} aria-current={resource === item.id} className="hs-focus-ring block max-w-full truncate text-left font-medium text-slate-900 hover:underline dark:text-slate-100" onClick={(e) => { e.stopPropagation(); patch({ resource: item.id }, true); }}>
                            {item.name}
                          </button>
                          <span className="block truncate text-xs text-slate-500">
                            {item.resource_type_name}{showCategory ? ` · ${item.category_name}` : ""}{item.record_kind === "configuration" ? " · configuration" : ""}
                            {item.is_new ? <span className="ml-1.5 rounded bg-cyan-500/15 px-1 text-cyan-800 dark:text-cyan-300">New</span> : null}
                          </span>
                        </td>
                        {showAccount ? <td className="hidden px-3 py-2.5 font-mono text-xs sm:table-cell">{item.account_id || "—"}</td> : null}
                        {showRegion ? <td className="hidden px-3 py-2.5 sm:table-cell">{item.region || "global"}</td> : null}
                        <td className="px-3 py-2.5">
                          {item.finding_count > 0 ? (
                            <span className="inline-flex flex-wrap items-center gap-1">
                              <SeverityBadge severity={item.max_severity ?? "info"} />
                              <span className="text-xs tabular-nums text-slate-600 dark:text-slate-400">{item.finding_count}</span>
                              {item.new_finding_count ? <span className="rounded bg-cyan-500/15 px-1.5 text-xs text-cyan-800 dark:text-cyan-300" title="Not in the previous scan">New</span> : null}
                            </span>
                          ) : item.related_finding_count ? (
                            <span className="text-xs text-slate-600 dark:text-slate-400" title={`Findings on ${(item.related_to ?? []).join(", ")} name this resource as how they hold access. It has no finding of its own.`}>
                              Named in <span className="capitalize">{item.related_max_severity}</span> ×{item.related_finding_count}
                            </span>
                          ) : <span className="text-xs text-slate-500" title="No finding in this scan names this resource. This does not mean it was assessed as safe.">none</span>}
                        </td>
                        {showExposure ? <td className="hidden px-3 py-2.5 sm:table-cell">{item.internet_facing ? <span className="cr-chip-state cr-tone-bad" title={item.exposure_detail}>Internet-facing</span> : item.exposure_detail ? <span className="cr-chip-state cr-tone-warn" title={item.exposure_detail}>{item.exposure_kind === "restricted" ? "Public, restricted" : "Open rule"}</span> : <span className="text-slate-400">—</span>}</td> : null}
                        <td className="hidden max-w-[16rem] px-3 py-2.5 lg:table-cell">
                          {Object.keys(item.tags ?? {}).length === 0 ? <span className="text-slate-400">—</span> : (
                            <span className="flex flex-wrap gap-1">
                              {Object.entries(item.tags ?? {}).slice(0, 2).map(([k, v]) => <span key={k} className="max-w-[9rem] truncate rounded border border-slate-200 bg-slate-50 px-1.5 text-xs dark:border-slate-700 dark:bg-slate-900" title={`${k}=${v}`}>{k}={v}</span>)}
                              {Object.keys(item.tags ?? {}).length > 2 ? <span className="text-xs text-slate-500" title={Object.entries(item.tags ?? {}).map(([k, v]) => `${k}=${v}`).join("\n")}>+{Object.keys(item.tags ?? {}).length - 2}</span> : null}
                            </span>
                          )}
                        </td>
                        {showOwner ? <td className="hidden px-3 py-2.5 sm:table-cell">{item.owner || <span className="text-slate-400">—</span>}</td> : null}
                        {showState ? <td className="hidden px-3 py-2.5 sm:table-cell">{item.state || "—"}</td> : null}
                        {showIdentity ? <td className="hidden px-3 py-2.5 sm:table-cell">{item.identity_associated ? "Configured" : "—"}</td> : null}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
            {list.data && list.data.total_items > 0 ? (
              <div className="flex items-center justify-between text-xs text-slate-500">
                <p>Showing {(page - 1) * list.data.page_size + 1}–{(page - 1) * list.data.page_size + items.length} of {list.data.total_items}</p>
                {list.data.total_pages > 1 ? (
                  <div className="flex gap-2">
                    <button type="button" className="hs-input px-2 py-1" disabled={page <= 1} onClick={() => patch({ page: String(page - 1) }, true)}>Previous</button>
                    <button type="button" className="hs-input px-2 py-1" disabled={page >= list.data.total_pages} onClick={() => patch({ page: String(page + 1) }, true)}>Next</button>
                  </div>
                ) : null}
              </div>
            ) : null}
          </section>

          {summary.data ? (
            <details id="inventory-coverage" className="hs-card p-4" open={collectionProblem || regionProblem}>
              <summary className="hs-focus-ring cursor-pointer rounded text-sm font-semibold text-slate-900 dark:text-slate-100">
                Collection coverage
                <span className="ml-2 text-xs font-normal text-slate-500">
                  {collectedCount} of {serviceCards.length} supported services collected
                  {notRecorded > 0 ? ` · ${notRecorded} not recorded` : ""}{regionProblem ? " · region issues" : ""}
                </span>
              </summary>
              <div className="mt-4 space-y-4">
                {notRecorded > 0 ? <p className="text-sm"><span className="font-medium">Not recorded:</span> {notRecordedNames.join(", ")}. A missing asset is not evidence the service is empty.</p> : null}
                {offNames.length > 0 ? <p className="text-sm"><span className="font-medium">Off (opt-in):</span> {offNames.join(", ")}. <Link className="underline" to={`/settings#cfg-${serviceCards.find((c) => c.config_key && cov(c) === "not_collected")?.config_key ?? "scan.resource_policies"}`}>Turn on in Settings</Link>, then scan again.</p> : null}
                {notInventoried.length + unavailableNames.length > 0 ? <p className="text-sm"><span className="font-medium">Not inventoried:</span> {[...notInventoried, ...unavailableNames].join(", ")}. {unavailableNames.length > 0 ? "Some of these are services this account or Region does not offer." : ""}</p> : null}
                <p className="cr-helper">{summary.data.accounts_note} {summary.data.coverage_note} {col?.note}</p>
                {col ? (
                  <dl className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-5">
                    {([
                      ["Account scope", col.account_scope],
                      ["Region discovery", col.region_discovery],
                      ["Regional collectors", col.regional_collectors],
                      ["Service collection", col.service_collection],
                      ["Supported inventory", col.supported_inventory]
                    ] as [string, string][]).map(([label, value]) => (
                      <div key={label}>
                        <dt className="cr-kpi-label">{label}</dt>
                        <dd className="mt-1"><CollectionChip status={value} /></dd>
                      </div>
                    ))}
                  </dl>
                ) : null}
                <RegionCoveragePanel coverage={summary.data.region_coverage} />
                <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                  {attention.map((card) => (
                    <button
                      key={card.service}
                      type="button"
                      aria-pressed={service === card.service}
                      className={`hs-card p-4 text-left ${service === card.service ? "ring-1 ring-cyan-500" : ""}`}
                      onClick={() => patch({ service: service === card.service ? "" : card.service })}
                    >
                      <span className="flex items-center gap-2">
                        <ServiceMark service={card.service} name={card.name} />
                        <span className="font-medium text-slate-900 dark:text-slate-100">{card.name}</span>
                      </span>
                      <p className="mt-3 text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-100">{card.count}</p>
                      <div className="mt-1"><CollectionChip status={card.coverage} /></div>
                      <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">{card.coverage_text}</p>
                      <p className="mt-2 text-xs text-slate-500">{card.resource_types.join(", ")}</p>
                      {card.finding_count > 0 ? <p className="mt-1 text-xs text-slate-500">{card.finding_count} linked findings</p> : null}
                    </button>
                  ))}
                </div>
                {quiet.length > 0 ? (
                  <p className="text-xs text-slate-600 dark:text-slate-400">
                    Collected, nothing found ({quiet.length}): {quiet.map((c) => c.name).join(", ")}.
                  </p>
                ) : null}
                <section>
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Resources by service</h3>
                  <p className="mt-1 text-xs text-slate-500">Same counts as the service cards. Services with nothing found or no collection record are left out rather than drawn as zero.</p>
                  {shownBars.length === 0 ? <p className="mt-3 text-sm text-slate-500">No discovered resources in this filter.</p> : (
                    <ul className="mt-3 space-y-3" aria-label="Resource distribution by AWS service">
                      {shownBars.map((bar) => (
                        <li key={bar.service}>
                          <div className="mb-1 flex justify-between gap-3 text-xs text-slate-700 dark:text-slate-300">
                            <span>{bar.name}</span>
                            <span className="tabular-nums">{bar.count}</span>
                          </div>
                          <div className="h-2 overflow-hidden rounded bg-slate-200 dark:bg-slate-800">
                            <div className="h-full rounded bg-cyan-700 dark:bg-cyan-500" style={{ width: `${Math.round((100 * bar.count) / maxBar)}%` }} />
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </section>
              </div>
            </details>
          ) : null}

          {resource ? (
            <EntityDrawer title={detail.data?.resource.resource_type_name ?? "Resource"} onClose={() => patch({ resource: "" }, true)}>
              <div className="space-y-4">
                {detail.isLoading ? <StatePanel>Loading resource…</StatePanel> : null}
                {detail.isError ? <StatePanel intent="error" title="Failed to load the resource"><pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(detail.error)}</pre></StatePanel> : null}
                {detail.data ? (
                  <ResourceDetailBody d={detail.data} scanId={selectedScanId} scanTime={summary.data?.timestamp} evidenceOpen={evidenceOpen} onToggleEvidence={() => setEvidenceOpen((open) => !open)} onOpen={(id) => patch({ resource: id }, true)} />
                ) : null}
              </div>
            </EntityDrawer>
          ) : null}
        </>
      )}
    </section>
  );
}

function RegionCoveragePanel({ coverage }: { coverage?: InventoryRegionCoverage }) {
  if (!coverage) {
    return null;
  }
  return (
    <div className="hs-card p-4">
      <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Region coverage</h2>
      <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{coverage.note}</p>
      {coverage.accounts.length === 0 ? null : (
        <div className="mt-3 space-y-3">
          {coverage.accounts.map((account) => (
            <div key={account.account_id}>
              <p className="text-sm font-medium text-slate-800 dark:text-slate-200">
                {account.account_id}
                {account.region_mode ? ` · ${account.region_mode}` : ""}
                {account.partition ? ` · ${account.partition}` : ""}
                {` · discovery ${account.discovery}`}
              </p>
              <p className="text-xs text-slate-500">
                enabled {account.enabled} · selected {account.selected} · succeeded {account.succeeded} · partial {account.partial} · failed {account.failed} · excluded {account.excluded} · unknown {account.unknown}
              </p>
              <div className="mt-2 flex flex-wrap gap-1" role="img" aria-label={`Region grid: ${account.regions.length} Regions`}>
                {account.regions.map((row) => {
                  const tone = row.state === "REGION_SCAN_SUCCEEDED" ? "bg-emerald-500" : row.state === "REGION_SCAN_PARTIAL" ? "bg-amber-400" : row.state === "REGION_SCAN_FAILED" || row.state === "REGION_DISCOVERY_FAILED" ? "bg-rose-500" : row.state === "REGION_NOT_ENABLED" ? "border border-slate-500 bg-transparent" : "bg-slate-500";
                  return <span key={row.region + row.state} title={`${row.region} · ${row.state}`} className={`h-3.5 w-3.5 rounded-sm ${tone}`} />;
                })}
                <span className="cr-helper ml-2">Green succeeded · amber partial · red failed · hollow not enabled · grey unknown</span>
              </div>
              {(() => {
                // Disabled opt-in Regions are collapsed. Scanned, partial, failed and unknown Regions stay visible.
                const quiet = account.regions.filter((row) => row.state === "REGION_NOT_ENABLED");
                const rows = account.regions.filter((row) => row.state !== "REGION_NOT_ENABLED");
                const renderRow = (row: (typeof account.regions)[number]) => (
                  <li key={`${account.account_id}:${row.region}:${row.state}`} className="flex flex-wrap items-center gap-2 text-xs text-slate-700 dark:text-slate-300">
                    <span className="w-32 font-medium">{row.region || "discovery"}</span> <CollectionChip status={row.state} />
                    {row.services && row.services.length > 0 ? <span className="text-slate-500">{row.services.map((svc) => `${svc.service} ${svc.status}`).join(", ")}</span> : null}
                  </li>
                );
                return (
                  <>
                    {rows.every((row) => row.state === "REGION_SCAN_SUCCEEDED") && rows.length > 3 ? (
                      <details className="mt-2 text-xs">
                        <summary className="hs-focus-ring cursor-pointer text-slate-600 dark:text-slate-300">{rows.length} Regions scanned and succeeded</summary>
                        <ul className="mt-1 space-y-1">{rows.map(renderRow)}</ul>
                      </details>
                    ) : <ul className="mt-1 space-y-1">{rows.map(renderRow)}</ul>}
                    {quiet.length > 0 ? (
                      <details className="mt-2 text-xs">
                        <summary className="hs-focus-ring cursor-pointer text-slate-600 dark:text-slate-300">{quiet.length} Regions not enabled for this account (not scanned)</summary>
                        <ul className="mt-1 space-y-1">{quiet.map(renderRow)}</ul>
                      </details>
                    ) : null}
                  </>
                );
              })()}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const serviceIcons: Record<string, string> = {
  ec2: "/icons/aws/ec2.svg",
  lambda: "/icons/aws/lambda.svg",
  s3: "/icons/aws/s3.svg",
  iam: "/icons/aws/iam.svg",
  route53: "/icons/aws/route53.svg",
  cloudfront: "/icons/aws/cloudfront.svg",
  acm: "/icons/aws/acm.svg",
  ecs: "/icons/aws/ecs.svg",
  eks: "/icons/aws/eks.svg",
  apigateway: "/icons/aws/apigateway.svg",
  api_gateway: "/icons/aws/apigateway.svg"
};

function ServiceMark({ service, name }: { service: string; name: string }) {
  const src = serviceIcons[service];
  if (!src) {
    return (
      <svg width="24" height="24" viewBox="0 0 24 24" aria-hidden="true" className="h-6 w-6 shrink-0 text-slate-700 dark:text-slate-200">
        <rect x="3" y="3" width="18" height="18" rx="3" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <text x="12" y="15" textAnchor="middle" fontSize="7" fill="currentColor">{name.slice(0, 3).toUpperCase()}</text>
      </svg>
    );
  }
  return <img src={src} alt="" width={24} height={24} className="h-6 w-6 shrink-0" />;
}


function ServiceChip({ active, label, count, onClick }: { active: boolean; label: string; count: number; onClick: () => void }) {
  return (
    <button type="button" aria-pressed={active} onClick={onClick} className={`hs-focus-ring hs-control-transition inline-flex shrink-0 items-center gap-2 whitespace-nowrap rounded-full border px-3 py-1 text-sm ${active ? "border-cyan-500 bg-cyan-500/10 font-medium text-cyan-900 dark:text-cyan-100" : "border-slate-300 text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"}`}>
      {label}
      <span className="text-xs tabular-nums text-slate-500">{count}</span>
    </button>
  );
}

function TogglePill({ on, onClick, title, children }: { on: boolean; onClick: () => void; title?: string; children: React.ReactNode }) {
  return (
    <button type="button" aria-pressed={on} title={title} onClick={onClick} className={`hs-action-pill ${on ? "!border-cyan-500 !bg-cyan-500/10 text-cyan-900 dark:text-cyan-100" : ""}`}>
      {children}
    </button>
  );
}


const relLabel: Record<string, { out: string; in: string }> = {
  USES_SECURITY_GROUP: { out: "Security groups", in: "Attached to" },
  LOAD_BALANCER_ROUTES_TO: { out: "Sends traffic to", in: "Receives traffic from" },
  EC2_INSTANCE_USES_INSTANCE_PROFILE: { out: "Instance profile", in: "Instances using it" },
  INSTANCE_PROFILE_CONTAINS_ROLE: { out: "Role in profile", in: "Instance profile" },
  POLICY_ATTACHED_TO: { out: "Policies", in: "Attached to" },
  OBSERVED_ASSUME_ROLE: { out: "Seen assuming", in: "Seen assuming this role" },
  MEMBER_OF: { out: "Member of", in: "Members" },
  TRUSTS: { out: "Trusts", in: "Trusted by" }
};

function relGroupTitle(relType: string, direction: string): string {
  const known = relLabel[relType];
  if (known) return direction === "incoming" ? known.in : known.out;
  const base = relType.toLowerCase().replace(/_/g, " ");
  return `${base.charAt(0).toUpperCase()}${base.slice(1)} (${direction})`;
}

function DrawerSection({ title, count, children }: { title: string; count?: number; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <h4 className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
        {title}
        {count !== undefined ? <span className="rounded-full bg-slate-200 px-1.5 text-[10px] tabular-nums text-slate-600 dark:bg-slate-800 dark:text-slate-300">{count}</span> : null}
      </h4>
      {children}
    </section>
  );
}

function ResourceDetailBody({ d, scanId, scanTime, evidenceOpen, onToggleEvidence, onOpen }: { d: InventoryDetail; scanId: string; scanTime?: string; evidenceOpen: boolean; onToggleEvidence: () => void; onOpen: (id: string) => void }) {
  const r = d.resource;
  const tags = Object.entries(r.tags ?? {});
  const linkable = d.relationships.filter((x) => !x.other_id.startsWith("arn:cloudrift:"));
  const evidenceRels = d.relationships.filter((x) => x.other_id.startsWith("arn:cloudrift:"));
  const groups = new Map<string, typeof linkable>();
  for (const rel of linkable) {
    const title = relGroupTitle(rel.rel_type, rel.direction);
    groups.set(title, [...(groups.get(title) ?? []), rel]);
  }
  const facts: [string, string][] = [
    ...d.facts.map((f) => [f.label, f.value] as [string, string]),
    ["Account", r.account_id || "none recorded"],
    ["Region", r.region || "global"],
    ...(r.state ? ([["State", r.state]] as [string, string][]) : []),
    ["Collected", r.collected_at || scanTime || "not recorded"]
  ];
  const principal = encodePrincipalId(r.arn, "iam_user", r.account_id ?? "");
  return (
    <div className="space-y-6">
      <header className="space-y-3">
        <div className="flex items-start gap-3">
          <ServiceMark service={r.service} name={r.service_name} />
          <div className="min-w-0">
            <p className="break-words text-base font-semibold leading-snug text-slate-900 dark:text-slate-100">{r.name}</p>
            <p className="text-xs text-slate-500">{r.resource_type_name} · {r.category_name}{r.record_kind === "configuration" ? " · configuration record" : ""}</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {r.internet_facing ? <span className="cr-chip-state cr-tone-bad">Internet-facing</span> : r.exposure_kind === "restricted" ? <span className="cr-chip-state cr-tone-warn">Public, restricted</span> : r.exposure_kind === "open_rule" ? <span className="cr-chip-state cr-tone-warn">Open rule</span> : null}
          {r.finding_count > 0 ? <SeverityBadge severity={r.max_severity ?? "info"} /> : null}
          {r.is_new ? <span className="cr-chip-state cr-tone-info">New since previous scan</span> : null}
          {r.owner ? <span className="cr-chip-state cr-tone-unk">Owner: {r.owner}</span> : null}
        </div>
        <div className="flex items-center gap-2 rounded-md border border-slate-200 bg-slate-50 px-2 py-1.5 dark:border-slate-700 dark:bg-slate-950/40">
          <code className="min-w-0 flex-1 truncate text-xs text-slate-600 dark:text-slate-300" title={r.arn}>{r.arn}</code>
          <button type="button" className="hs-focus-ring shrink-0 rounded text-xs font-medium text-cyan-800 hover:underline dark:text-cyan-300" onClick={() => void navigator.clipboard?.writeText(r.arn)}>Copy</button>
        </div>
        <div className="flex flex-wrap gap-2">
          {r.resource_type === "iam_user" ? (
            <>
              <Link className="hs-action-pill" to={`/principals?scan_id=${encodeURIComponent(scanId)}&principal=${encodeURIComponent(principal)}`}>Users &amp; Groups</Link>
              <Link className="hs-action-pill" to={`/blast-explorer?scan=${encodeURIComponent(scanId)}&principal=${encodeURIComponent(principal)}&mode=attack_path`}>Blast Explorer</Link>
            </>
          ) : null}
          {r.resource_type === "iam_role" ? <Link className="hs-action-pill" to={`/identities?scan_id=${encodeURIComponent(scanId)}&role=${encodeURIComponent(r.arn)}`}>Open in Identities</Link> : null}
        </div>
      </header>

      {r.exposure_detail ? (
        <div className={`rounded-md border px-3 py-2 text-sm ${r.internet_facing ? "cr-tone-bad" : "cr-tone-warn"}`}>
          <p className="font-medium">{r.internet_facing ? "Reachable from the internet" : r.exposure_kind === "restricted" ? "Public, but not open to the world" : "Open rule"}</p>
          <p className="mt-0.5 text-xs opacity-90">{r.exposure_detail}</p>
        </div>
      ) : null}

      <DrawerSection title="Details">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
          {facts.map(([k, v]) => (
            <div key={k} className="min-w-0">
              <dt className="text-xs text-slate-500">{k}</dt>
              <dd className="break-words text-sm text-slate-900 dark:text-slate-100">{v}</dd>
            </div>
          ))}
        </dl>
      </DrawerSection>

      {d.inbound_rules && d.inbound_rules.length > 0 ? (
        <DrawerSection title="Inbound rules" count={d.inbound_rules.length}>
          <div className="overflow-hidden rounded-md border border-slate-200 dark:border-slate-700">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-[11px] uppercase tracking-wide text-slate-500 dark:bg-slate-900"><tr><th className="px-2 py-1.5">Protocol</th><th className="px-2 py-1.5">Port</th><th className="px-2 py-1.5">Source</th></tr></thead>
              <tbody>
                {d.inbound_rules.map((rule, i) => (
                  <tr key={i} className="border-t border-slate-200 align-top dark:border-slate-800">
                    <td className="px-2 py-1.5">{rule.protocol}</td>
                    <td className="px-2 py-1.5 tabular-nums">{rule.ports}</td>
                    <td className="px-2 py-1.5">
                      {rule.sources.length === 0 ? <span className="text-slate-400">none</span> : rule.sources.map((src) => (
                        <span key={src} className="mr-1 inline-block font-mono">{src}{src === "0.0.0.0/0" || src === "::/0" ? <span className="cr-chip-state cr-tone-bad ml-1">Anywhere</span> : null}</span>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </DrawerSection>
      ) : null}

      <DrawerSection title="Tags" count={tags.length}>
        {tags.length === 0 ? <p className="text-sm text-slate-500">No tags collected for this resource.</p> : (
          <ul className="flex flex-wrap gap-1.5">
            {tags.map(([k, v]) => <li key={k} className="rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs dark:border-slate-700 dark:bg-slate-900"><span className="text-slate-500">{k}</span> <span className="font-medium">{v}</span></li>)}
          </ul>
        )}
      </DrawerSection>

      <DrawerSection title="Security findings" count={d.findings.length}>
        {d.findings.length === 0 ? (
          <p className="text-sm text-slate-500">{r.related_finding_count ? `Named in ${r.related_finding_count} finding(s) on ${(r.related_to ?? []).join(", ")} as how they hold access.` : "No finding is attached to this resource itself."}</p>
        ) : (
          <ul className="space-y-2">
            {d.findings.map((f) => (
              <li key={f.id} className="flex items-start gap-2 text-sm">
                <SeverityBadge severity={f.severity} />
                <Link className="text-cyan-800 underline dark:text-cyan-200" to={`/findings?scan_id=${encodeURIComponent(scanId)}&finding_id=${encodeURIComponent(f.id)}`}>{f.title}</Link>
              </li>
            ))}
          </ul>
        )}
      </DrawerSection>

      {r.resource_type === "iam_role" ? (
        <DrawerSection title="Runs on" count={(d.runs_on ?? []).length}>
          {(d.runs_on ?? []).length === 0 ? <p className="text-sm text-slate-500">No collected workload runs as this role. A workload in an uncollected service or Region would not appear.</p> : (
            <ul className="space-y-1.5">
              {(d.runs_on ?? []).map((w) => (
                <li key={`${w.id}-${w.label}`} className="text-sm">
                  <button type="button" className="hs-focus-ring break-all text-left text-cyan-800 underline dark:text-cyan-200" onClick={() => onOpen(w.id)}>{w.name}</button>
                  <span className="text-xs text-slate-500"> · {w.type.replace(/_/g, " ")} · {w.label}</span>
                </li>
              ))}
            </ul>
          )}
        </DrawerSection>
      ) : null}

      {d.identity_links.length > 0 ? (
        <DrawerSection title="Runs as" count={d.identity_links.length}>
          <ul className="space-y-2">
            {d.identity_links.map((link) => (
              <li key={`${link.role_arn}-${link.mechanism}`} className="text-sm">
                <span className="block text-xs text-slate-500">{link.label}</span>
                <Link className="break-all font-mono text-xs text-cyan-800 underline dark:text-cyan-200" to={`/identities?scan_id=${encodeURIComponent(scanId)}&role=${encodeURIComponent(link.role_arn)}`}>{link.role_arn}</Link>
              </li>
            ))}
          </ul>
        </DrawerSection>
      ) : null}

      <DrawerSection title="Connected resources" count={linkable.length}>
        {linkable.length === 0 ? <p className="text-sm text-slate-500">No directly evidenced relationship.</p> : (
          <div className="space-y-3">
            {[...groups.entries()].map(([title, items]) => (
              <div key={title}>
                <p className="mb-1 text-xs font-medium text-slate-600 dark:text-slate-300">{title}</p>
                <ul className="space-y-1">
                  {items.map((rel) => (
                    <li key={`${rel.direction}-${rel.rel_type}-${rel.other_id}`} className="rounded-md border border-slate-200 px-2 py-1.5 dark:border-slate-800">
                      {rel.other_type ? (
                        <button type="button" className="hs-focus-ring break-all text-left text-sm font-medium text-cyan-800 hover:underline dark:text-cyan-200" onClick={() => onOpen(rel.other_id)}>{shortName(rel.other_id)}</button>
                      ) : <span className="break-all text-sm font-medium">{shortName(rel.other_id)}</span>}
                      <span className="text-xs text-slate-500">{rel.other_type ? ` · ${rel.other_type.replace(/_/g, " ")}` : ""} · {semanticLabel[rel.semantic] || rel.semantic}</span>
                      {rel.note ? <p className="mt-0.5 text-xs text-slate-500">{rel.note}</p> : null}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
        {evidenceRels.length > 0 ? (
          <details className="text-xs">
            <summary className="cursor-pointer text-slate-600 dark:text-slate-300">Policy statement evidence ({evidenceRels.length}). Internal records with no readable name.</summary>
            <ul className="mt-1 space-y-1">{evidenceRels.map((rel) => <li key={`${rel.rel_type}-${rel.other_id}`} className="break-all font-mono">{rel.rel_type} · {rel.other_id}</li>)}</ul>
          </details>
        ) : null}
      </DrawerSection>

      <section>
        <button type="button" className="hs-focus-ring rounded text-sm font-medium text-cyan-800 hover:underline dark:text-cyan-300" onClick={onToggleEvidence} aria-expanded={evidenceOpen}>
          {evidenceOpen ? "Hide collected evidence" : "Show collected evidence"}
        </button>
        {evidenceOpen ? (
          <>
            <p className="mt-2 text-xs text-slate-500">{d.evidence_note}</p>
            <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-all rounded-md bg-slate-50 p-2 text-xs dark:bg-slate-950/40">{JSON.stringify(d.evidence, null, 2)}</pre>
          </>
        ) : null}
      </section>
    </div>
  );
}
