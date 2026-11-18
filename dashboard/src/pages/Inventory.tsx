import { MetricCard } from "../components/ui/MetricCard";
import { CollectionChip } from "../components/ui/StatusChip";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { apiClient } from "../api/client";
import type { InventoryRegionCoverage } from "../api/types";
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
  { key: "type", label: "Type", asc: "type" },
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
  const severities = (params.get("severity") ?? "").split(",").filter(Boolean);
  const newOnly = params.get("new_only") === "true";
  const sort = params.get("sort") ?? "-severity";
  const resource = params.get("resource") ?? "";
  const page = Number(params.get("page") || "1");
  const [evidenceOpen, setEvidenceOpen] = useState(false);

  const summaryParams = useMemo(() => ({ account_id: accountID, region }), [accountID, region]);
  const listParams = useMemo(
    () => ({ account_id: accountID, region, service, resource_type: resourceType, category, q, has_findings: hasFindings ? "true" : "", severity: severities.join(","), new_only: newOnly ? "true" : "", sort, page, page_size: 25 }),
    [accountID, region, service, resourceType, category, q, hasFindings, severities.join(","), newOnly, sort, page]
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
  if (hasFindings) filters.push({ key: "findings", label: "Has findings", clear: { has_findings: "" } });
  if (q) filters.push({ key: "q", label: `Search: ${q}`, clear: { q: "" } });
  const clearAll = { service: "", category: "", resource_type: "", account_id: "", region: "", has_findings: "", severity: "", new_only: "", q: "" };

  const sortHeader = (c: (typeof sortColumns)[number]) => {
    const desc = c.desc ?? "-" + c.asc;
    const active = sort === c.asc ? "ascending" : sort === desc ? "descending" : "none";
    return (
      <th key={c.key} scope="col" aria-sort={active} className={`sticky top-0 z-10 bg-white py-2 pr-3 dark:bg-slate-950 ${c.key === "findings" || c.key === "name" ? "" : "hidden sm:table-cell"}`}>
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
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
              <MetricCard label="Resources" value={summary.data.total_assets} context={`${plural(summary.data.service_count, "service")} · ${plural(summary.data.region_count, "region")} · ${plural(summary.data.account_count, "account")}`} />
              <button type="button" aria-pressed={hasFindings} className={`text-left ${hasFindings ? "rounded ring-1 ring-cyan-500" : ""}`} onClick={() => patch({ has_findings: hasFindings ? "" : "true" })}>
                <MetricCard label="With findings" value={risky.data?.total_items ?? "…"} context={`${plural(totalFindings, "finding")} on these · click to filter`} />
              </button>
              <div className="hs-card col-span-2 p-4 lg:col-span-1">
                <p className="cr-kpi-label">Collection of supported services</p>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  {col ? <CollectionChip status={collectionProblem || regionProblem || notRecorded > 0 ? "partial" : "completed"} /> : null}
                  <span className="text-xs text-slate-600 dark:text-slate-400">{collectedCount} of {collectableCount} services collected</span>
                </div>
                {notRecorded > 0 ? <p className="mt-2 hidden text-xs text-slate-600 dark:text-slate-400 sm:block"><span className="font-medium">Not recorded:</span> {notRecordedNames.join(", ")}. A missing asset is not evidence the service is empty.</p> : null}
                {offNames.length > 0 ? <p className="mt-1 hidden text-xs text-slate-600 dark:text-slate-400 sm:block"><span className="font-medium">Off (opt-in):</span> {offNames.join(", ")}. <Link className="underline" to="/settings#cfg-scan.resource_policies">Turn on in Settings</Link>, then scan again.</p> : null}
                {notInventoried.length + unavailableNames.length > 0 ? <p className="mt-1 hidden text-xs text-slate-600 dark:text-slate-400 sm:block"><span className="font-medium">Not inventoried:</span> {[...notInventoried, ...unavailableNames].join(", ")}.</p> : null}
                <a href="#inventory-coverage" className="mt-2 block text-xs text-cyan-800 underline dark:text-cyan-300">Collection coverage ↓</a>
              </div>
            </div>
          ) : null}

          <div className="space-y-2">
            <div className="flex flex-wrap gap-2">
              <input className="hs-input !w-auto min-w-[14rem] flex-1" placeholder="Search name or ARN" value={q} aria-label="Search name or ARN" onChange={(e) => patch({ q: e.target.value }, true)} />
              <select className="hs-input !w-auto" aria-label="Service" value={service} onChange={(e) => patch({ service: e.target.value }, true)}>
                <option value="">All services</option>
                {serviceCards.filter((c) => c.count > 0).map((c) => <option key={c.service} value={c.service}>{c.name} ({c.count})</option>)}
              </select>
              <select className="hs-input !w-auto" aria-label="Category" value={category} onChange={(e) => patch({ category: e.target.value }, true)}>
                <option value="">All categories</option>
                {(summary.data?.categories ?? []).filter((c) => c.count > 0 || c.category === category).map((item) => (
                  <option key={item.category} value={item.category}>{item.name} ({item.count})</option>
                ))}
              </select>
              <input className="hs-input !w-40" placeholder="Type, e.g. iam_role" value={resourceType} aria-label="Resource type" onChange={(e) => patch({ resource_type: e.target.value }, true)} />
              {showAccount || accountID ? (
                <select className="hs-input !w-auto" aria-label="Account" value={accountID} onChange={(e) => patch({ account_id: e.target.value })}>
                  <option value="">All accounts</option>
                  {(summary.data?.accounts ?? []).map((a) => <option key={a} value={a}>{a}</option>)}
                </select>
              ) : null}
              {showRegion || region ? (
                <select className="hs-input !w-auto" aria-label="Region" value={region} onChange={(e) => patch({ region: e.target.value })}>
                  <option value="">All regions</option>
                  {(summary.data?.regions ?? []).map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              ) : null}
            </div>
            <div className="flex items-center gap-2 overflow-x-auto sm:flex-wrap sm:overflow-visible [&>button]:shrink-0" role="group" aria-label="Risk filters">
              <button type="button" aria-pressed={hasFindings} className={`hs-btn-default px-3 py-1 text-sm ${hasFindings ? "ring-1 ring-cyan-500" : ""}`} onClick={() => patch({ has_findings: hasFindings ? "" : "true" }, true)}>Has findings</button>
              {["critical", "high", "medium", "low"].map((sev) => {
                const on = severities.includes(sev);
                return (
                  <button key={sev} type="button" aria-pressed={on} className={`hs-btn-default px-3 py-1 text-sm capitalize ${on ? "ring-1 ring-cyan-500" : ""}`} onClick={() => patch({ severity: (on ? severities.filter((s) => s !== sev) : [...severities, sev]).join(",") }, true)}>{sev}</button>
                );
              })}
              {previousScan ? (
                <button type="button" aria-pressed={newOnly} title={`Findings that scan ${previousScan} did not have`} className={`hs-btn-default px-3 py-1 text-sm ${newOnly ? "ring-1 ring-cyan-500" : ""}`} onClick={() => patch({ new_only: newOnly ? "" : "true" }, true)}>
                  New since previous scan{fresh.data ? ` (${plural(fresh.data.total_items, "resource")})` : ""}
                </button>
              ) : null}
            </div>
            {filters.length > 0 ? (
              <ul className="flex flex-wrap items-center gap-2" aria-label="Active filters">
                {filters.map((f) => (
                  <li key={f.key}>
                    <button type="button" className="hs-input inline-flex items-center gap-1 px-2 py-0.5 text-xs" onClick={() => patch(f.clear)} aria-label={`Remove filter ${f.label}`}>{f.label} <span aria-hidden="true">✕</span></button>
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
              <div className="max-h-[70vh] overflow-auto">
                <table className="w-full text-left text-sm">
                  <thead className="text-xs text-slate-500">
                    <tr>
                      {sortColumns.filter((c) => (c.key === "account" ? showAccount : c.key === "region" ? showRegion : true)).map(sortHeader)}
                      {showState ? <th scope="col" className="sticky top-0 z-10 hidden bg-white py-2 pr-3 uppercase dark:bg-slate-950 sm:table-cell">State</th> : null}
                      {showIdentity ? <th scope="col" className="sticky top-0 z-10 hidden bg-white py-2 uppercase dark:bg-slate-950 sm:table-cell">Identity</th> : null}
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => (
                      <tr key={item.id} className={`border-t border-slate-200 dark:border-slate-800 ${resource === item.id ? "bg-cyan-500/10" : ""}`}>
                        <td className="max-w-[11rem] py-2 pr-3 sm:max-w-[22rem]">
                          <button type="button" title={item.arn} aria-current={resource === item.id} className="hs-focus-ring block max-w-full truncate text-left font-medium text-cyan-800 underline dark:text-cyan-200" onClick={() => patch({ resource: item.id }, true)}>
                            {item.name}
                          </button>
                          <span className="block truncate text-xs text-slate-500 sm:hidden">{item.resource_type_name}</span>
                        </td>
                        <td className="hidden py-2 pr-3 sm:table-cell">
                          {item.resource_type_name}
                          {showCategory ? <span className="block text-xs text-slate-500">{item.category_name}</span> : null}
                          {item.record_kind === "configuration" ? <span className="ml-1 text-xs text-slate-500">(configuration)</span> : null}
                        </td>
                        {showAccount ? <td className="hidden py-2 pr-3 font-mono text-xs sm:table-cell">{item.account_id || "—"}</td> : null}
                        {showRegion ? <td className="hidden py-2 pr-3 sm:table-cell">{item.region || "global"}</td> : null}
                        <td className="py-2 pr-3">
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
                        {showState ? <td className="hidden py-2 pr-3 sm:table-cell">{item.state || "—"}</td> : null}
                        {showIdentity ? <td className="hidden py-2 sm:table-cell">{item.identity_associated ? "Configured" : "—"}</td> : null}
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
                  {collectedCount} of {collectableCount} services collected
                  {notRecorded > 0 ? ` · ${notRecorded} not recorded` : ""}{regionProblem ? " · region issues" : ""}
                </span>
              </summary>
              <div className="mt-4 space-y-4">
                {notRecorded > 0 ? <p className="text-sm"><span className="font-medium">Not recorded:</span> {notRecordedNames.join(", ")}. A missing asset is not evidence the service is empty.</p> : null}
                {offNames.length > 0 ? <p className="text-sm"><span className="font-medium">Off (opt-in):</span> {offNames.join(", ")}. <Link className="underline" to="/settings#cfg-scan.resource_policies">Turn on in Settings</Link>, then scan again.</p> : null}
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
            <EntityDrawer title={detail.data?.resource.name ?? "Resource"} onClose={() => patch({ resource: "" }, true)}>
              <div className="space-y-4">
                {detail.isLoading ? <StatePanel>Loading resource…</StatePanel> : null}
                {detail.isError ? <StatePanel intent="error" title="Failed to load the resource"><pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(detail.error)}</pre></StatePanel> : null}
                {detail.data ? (
                  <>
                    <header>
                      <h3 className="break-all font-mono text-sm text-slate-900 dark:text-slate-100">{detail.data.resource.arn}</h3>
                      <dl className="mt-3 grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 text-sm">
                        {([
                          ["Service", detail.data.resource.service_name],
                          ["Type", detail.data.resource.resource_type_name],
                          ["Category", `${detail.data.resource.category_name} · ${detail.data.resource.record_kind === "configuration" ? "configuration record" : "deployed infrastructure"}`],
                          ["Account", detail.data.resource.account_id || "none recorded"],
                          ["Region", detail.data.resource.region || "global"],
                          ["State", detail.data.resource.state || "not collected"],
                          ["Collection", detail.data.resource.collection_status || "not recorded"],
                          ["Collected at", detail.data.resource.collected_at || "not recorded"]
                        ] as [string, string][]).map(([k, v]) => (
                          <div key={k} className="contents"><dt className="text-slate-500">{k}</dt><dd className="break-words">{v}</dd></div>
                        ))}
                      </dl>
                      {detail.data.resource.related_finding_count ? (
                        <p className="mt-2 text-sm">Named in {detail.data.resource.related_finding_count} finding(s) on {(detail.data.resource.related_to ?? []).join(", ")} as how they hold access.</p>
                      ) : null}
                      <p className="mt-2 flex flex-wrap gap-3 text-xs">
                        <button type="button" className="text-cyan-800 underline dark:text-cyan-300" onClick={() => void navigator.clipboard?.writeText(detail.data.resource.arn)}>Copy ARN</button>
                        {detail.data.resource.resource_type === "iam_user" ? (
                          <>
                            <Link className="text-cyan-800 underline dark:text-cyan-300" to={`/principals?scan_id=${encodeURIComponent(selectedScanId)}&principal=${encodeURIComponent(encodePrincipalId(detail.data.resource.arn, "iam_user", detail.data.resource.account_id ?? ""))}`}>Open in Users &amp; Groups</Link>
                            <Link className="text-cyan-800 underline dark:text-cyan-300" to={`/blast-explorer?scan=${encodeURIComponent(selectedScanId)}&principal=${encodeURIComponent(encodePrincipalId(detail.data.resource.arn, "iam_user", detail.data.resource.account_id ?? ""))}&mode=attack_path`}>Open in Blast Explorer</Link>
                          </>
                        ) : null}
                        {detail.data.resource.resource_type === "iam_role" ? (
                          <Link className="text-cyan-800 underline dark:text-cyan-300" to={`/identities?scan_id=${encodeURIComponent(selectedScanId)}&role=${encodeURIComponent(detail.data.resource.arn)}`}>Open in Identities</Link>
                        ) : null}
                      </p>
                    </header>
                    <section>
                      <h4 className="text-sm font-semibold">Security findings</h4>
                      {detail.data.findings.length === 0 ? <p className="text-sm">No finding is attached to this resource itself.</p> : (
                        <ul className="space-y-2">
                          {detail.data.findings.map((finding) => (
                            <li key={finding.id} className="text-sm">
                              <SeverityBadge severity={finding.severity} />{" "}
                              <Link className="text-cyan-800 underline dark:text-cyan-200" to={`/findings?scan_id=${encodeURIComponent(selectedScanId)}&finding_id=${encodeURIComponent(finding.id)}`}>{finding.title}</Link>
                              <span className="text-xs text-slate-500"> {finding.module}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </section>
                    <section>
                      <h4 className="text-sm font-semibold">Identity relationships</h4>
                      {detail.data.identity_links.length === 0 ? <p className="text-sm">No configured IAM role was stored for this resource.</p> : (
                        <ul className="space-y-2">
                          {detail.data.identity_links.map((link) => (
                            <li key={`${link.role_arn}-${link.mechanism}`} className="text-sm">
                              <span>{link.label}</span>
                              <Link className="block break-all font-mono text-xs text-cyan-800 underline dark:text-cyan-200" to={`/identities?scan_id=${encodeURIComponent(selectedScanId)}&role=${encodeURIComponent(link.role_arn)}`}>{link.role_arn}</Link>
                            </li>
                          ))}
                        </ul>
                      )}
                    </section>
                    <section>
                      <h4 className="text-sm font-semibold">Related resources</h4>
                      {detail.data.relationships.length === 0 ? <p className="text-sm">No directly evidenced relationship.</p> : (
                        <>
                          <ul className="space-y-2">
                            {detail.data.relationships.filter((rel) => !rel.other_id.startsWith("arn:cloudrift:")).map((rel) => (
                              <li key={`${rel.direction}-${rel.rel_type}-${rel.other_id}`} className="text-sm">
                                <span className="font-medium">{shortName(rel.other_id)}</span>
                                <span className="text-xs text-slate-500"> · {semanticLabel[rel.semantic] || rel.semantic} · {rel.rel_type.toLowerCase().replace(/_/g, " ")} · {rel.direction}</span>
                                <span className="block break-all font-mono text-xs text-slate-500">{rel.other_id}</span>
                                {rel.note ? <span className="text-xs text-slate-500">{rel.note}</span> : null}
                              </li>
                            ))}
                          </ul>
                          {detail.data.relationships.some((rel) => rel.other_id.startsWith("arn:cloudrift:")) ? (
                            <details className="mt-2 text-xs">
                              <summary className="cursor-pointer text-slate-600 dark:text-slate-300">Policy statement evidence ({detail.data.relationships.filter((rel) => rel.other_id.startsWith("arn:cloudrift:")).length}). Internal records with no readable name.</summary>
                              <ul className="mt-1 space-y-1">
                                {detail.data.relationships.filter((rel) => rel.other_id.startsWith("arn:cloudrift:")).map((rel) => (
                                  <li key={`${rel.rel_type}-${rel.other_id}`} className="break-all font-mono">{rel.rel_type} · {rel.other_id}</li>
                                ))}
                              </ul>
                            </details>
                          ) : null}
                        </>
                      )}
                    </section>
                    <section>
                      <button type="button" className="text-sm font-semibold" onClick={() => setEvidenceOpen((open) => !open)} aria-expanded={evidenceOpen}>
                        {evidenceOpen ? "Hide collected evidence" : "Show collected evidence"}
                      </button>
                      {evidenceOpen ? (
                        <>
                          <p className="mt-2 text-xs text-slate-500">{detail.data.evidence_note}</p>
                          <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(detail.data.evidence, null, 2)}</pre>
                        </>
                      ) : null}
                    </section>
                  </>
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
