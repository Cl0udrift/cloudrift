import { MetricCard } from "../components/ui/MetricCard";
import { CollectionChip } from "../components/ui/StatusChip";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { apiClient } from "../api/client";
import type { InventoryRegionCoverage } from "../api/types";
import { formatQueryError } from "../api/httpError";
import { PageHeader } from "../components/PageHeader";
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

export function InventoryPage() {
  const { selectedScanId, currentScan } = useScanContext();
  const [params, setParams] = useSearchParams();
  const accountID = params.get("account_id") ?? "";
  const region = params.get("region") ?? "";
  const service = params.get("service") ?? "";
  const category = params.get("category") ?? "";
  const resourceType = params.get("resource_type") ?? "";
  const q = params.get("q") ?? "";
  const sort = params.get("sort") ?? "name";
  const resource = params.get("resource") ?? "";
  const page = Number(params.get("page") || "1");
  const [evidenceOpen, setEvidenceOpen] = useState(false);

  const summaryParams = useMemo(() => ({ account_id: accountID, region }), [accountID, region]);
  const listParams = useMemo(
    () => ({ account_id: accountID, region, service, resource_type: resourceType, category, q, sort, page, page_size: 25 }),
    [accountID, region, service, resourceType, category, q, sort, page]
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
    setParams(next);
  };

  const maxBar = Math.max(...(summary.data?.distribution ?? []).map((item) => item.count), 1);

  return (
    <section className="space-y-6">
      <PageHeader title="AWS Inventory" description="Resources discovered in the selected scan." />
      {!selectedScanId ? (
        <ScanRequired />
      ) : (
        <>
          <div className="flex flex-wrap items-end justify-between gap-3 text-sm text-slate-600 dark:text-slate-300">
            <p className="cr-helper">{summary.data?.timestamp || currentScan?.timestamp || "Timestamp not recorded"}</p>
            <div className="grid gap-2 sm:grid-cols-2">
              <input className="hs-input" placeholder="Account ID" value={accountID} onChange={(e) => patch({ account_id: e.target.value })} aria-label="Account ID" />
              <input className="hs-input" placeholder="Region" value={region} onChange={(e) => patch({ region: e.target.value })} aria-label="Region" />
            </div>
          </div>
          {summary.isLoading ? <StatePanel>Loading inventory summary…</StatePanel> : null}
          {summary.isError ? <StatePanel intent="error" title="Failed to load inventory"><pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(summary.error)}</pre></StatePanel> : null}
          {summary.data ? (
            <>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <MetricCard label="Discovered assets" value={summary.data.total_assets} context="Infrastructure only; evidence records excluded" />
                <MetricCard label="Accounts" value={summary.data.account_count} context="With discovered assets" />
                <MetricCard label="Regions" value={summary.data.region_count} context="With discovered assets" />
                <MetricCard label="Services" value={summary.data.service_count} context="With discovered assets" />
              </div>
              <details>
                <summary className="hs-focus-ring w-fit cursor-pointer rounded text-xs font-medium text-cyan-800 dark:text-cyan-300">How these counts work</summary>
                <p className="cr-helper mt-1">{summary.data.accounts_note}</p>
                <p className="cr-helper mt-1">{summary.data.coverage_note}</p>
                {summary.data.collection ? <p className="cr-helper mt-1">{summary.data.collection.note}</p> : null}
              </details>
              {summary.data.collection ? (
                <div className="hs-card p-4">
                  <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Collection completeness</h2>
                  <dl className="mt-2 grid grid-cols-2 gap-2 text-xs sm:grid-cols-5">
                    {([
                      ["Account scope", summary.data.collection.account_scope],
                      ["Region discovery", summary.data.collection.region_discovery],
                      ["Regional collectors", summary.data.collection.regional_collectors],
                      ["Service collection", summary.data.collection.service_collection],
                      ["Supported inventory", summary.data.collection.supported_inventory]
                    ] as [string, string][]).map(([label, value]) => (
                      <div key={label}>
                        <dt className="cr-kpi-label">{label}</dt>
                        <dd className="mt-1"><CollectionChip status={value} /></dd>
                      </div>
                    ))}
                  </dl>
                </div>
              ) : null}
              <details open={(summary.data.region_coverage?.accounts ?? []).some((a) => a.partial > 0 || a.failed > 0 || a.unknown > 0)}>
                <summary className="hs-focus-ring mb-2 w-fit cursor-pointer rounded text-xs font-medium text-cyan-800 dark:text-cyan-300">Region coverage (opens automatically when a Region is partial, failed or unknown)</summary>
                <RegionCoveragePanel coverage={summary.data.region_coverage} />
              </details>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                {summary.data.services.map((card) => (
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
              <details>
                <summary className="hs-focus-ring mb-2 w-fit cursor-pointer rounded text-xs font-medium text-cyan-800 dark:text-cyan-300">Resources by service (same counts as the service cards)</summary>
              <section className="hs-card p-4">
                <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Resources by service</h3>
                <p className="mt-1 text-xs text-slate-500">Same counts as the service cards. Services whose collection was not recorded are omitted rather than drawn as zero.</p>
                {summary.data.distribution.length === 0 ? <p className="mt-3 text-sm text-slate-500">No discovered resources in this filter.</p> : (
                  <ul className="mt-4 space-y-3" aria-label="Resource distribution by AWS service">
                    {summary.data.distribution.map((bar) => (
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
              </details>
            </>
          ) : null}
          <section className="space-y-3">
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
              <input className="hs-input" placeholder="Search ARN or name" value={q} aria-label="Search ARN or name" onChange={(e) => patch({ q: e.target.value }, true)} />
              <select className="hs-input" aria-label="Category" value={category} onChange={(e) => patch({ category: e.target.value }, true)}>
                <option value="">All categories</option>
                {(summary.data?.categories ?? []).map((item) => (
                  <option key={item.category} value={item.category}>{item.name} ({item.count})</option>
                ))}
              </select>
              <input className="hs-input" placeholder="Resource type" value={resourceType} aria-label="Resource type" onChange={(e) => patch({ resource_type: e.target.value }, true)} />
              <select className="hs-input" aria-label="Sort" value={sort} onChange={(e) => patch({ sort: e.target.value }, true)}>
                <option value="name">Name</option>
                <option value="type">Type</option>
                <option value="account">Account</option>
                <option value="region">Region</option>
                <option value="-findings">Linked findings</option>
              </select>
            </div>
            {list.isLoading ? <StatePanel>Loading resources…</StatePanel> : null}
            {list.isError ? <StatePanel intent="error" title="Failed to load resources"><pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(list.error)}</pre></StatePanel> : null}
            {list.data && list.data.items.length === 0 ? <StatePanel intent="empty" title="No inventory assets match">{list.data.coverage_note}</StatePanel> : null}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-slate-500">
                  <tr>
                    <th className="py-2 pr-3">Name</th>
                    <th className="py-2 pr-3">Type</th>
                    <th className="py-2 pr-3">Category</th>
                    <th className="py-2 pr-3">Account</th>
                    <th className="py-2 pr-3">Region</th>
                    <th className="py-2 pr-3">State</th>
                    <th className="py-2 pr-3">Findings</th>
                    <th className="py-2">Identity</th>
                  </tr>
                </thead>
                <tbody>
                  {(list.data?.items ?? []).map((item) => (
                    <tr key={item.id} className="border-t border-slate-200 dark:border-slate-800">
                      <td className="py-2 pr-3">
                        <button type="button" className="break-all text-left font-medium text-cyan-800 underline dark:text-cyan-200" onClick={() => patch({ resource: item.id }, true)}>
                          {item.name}
                        </button>
                      </td>
                      <td className="py-2 pr-3">{item.resource_type_name}</td>
                      <td className="py-2 pr-3">{item.category_name}{item.record_kind === "configuration" ? " · configuration record" : ""}</td>
                      <td className="py-2 pr-3 font-mono text-xs">{item.account_id || "—"}</td>
                      <td className="py-2 pr-3">{item.region || "global"}</td>
                      <td className="py-2 pr-3">{item.state || "—"}</td>
                      <td className="py-2 pr-3 tabular-nums">{item.finding_count}</td>
                      <td className="py-2">{item.identity_associated ? "Configured" : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {list.data ? (
              <div className="flex items-center justify-between text-xs text-slate-500">
                <p>Showing {list.data.items.length} of {list.data.total_items}.</p>
                <div className="flex gap-2">
                  <button type="button" className="hs-input px-2 py-1" disabled={page <= 1} onClick={() => patch({ page: String(page - 1) }, true)}>Previous</button>
                  <button type="button" className="hs-input px-2 py-1" disabled={page >= list.data.total_pages} onClick={() => patch({ page: String(page + 1) }, true)}>Next</button>
                </div>
              </div>
            ) : null}
          </section>
          {resource ? (
            <article className="hs-card space-y-4 p-5">
              {detail.isLoading ? <StatePanel>Loading resource…</StatePanel> : null}
              {detail.isError ? <StatePanel intent="error" title="Failed to load the resource"><pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(detail.error)}</pre></StatePanel> : null}
              {detail.data ? (
                <>
                  <header>
                    <h3 className="break-all font-mono text-sm text-slate-900 dark:text-slate-100">{detail.data.resource.arn}</h3>
                    <p className="mt-2 text-sm">{detail.data.resource.service_name} · {detail.data.resource.resource_type_name} · {detail.data.resource.category_name} · {detail.data.resource.record_kind === "configuration" ? "configuration record" : "deployed infrastructure"} · {detail.data.resource.account_id || "no account"} · {detail.data.resource.region || "global"}</p>
                    <p className="text-sm">State {detail.data.resource.state || "not collected"} · collection {detail.data.resource.collection_status} · {detail.data.resource.collected_at || "timestamp not recorded"}</p>
                  </header>
                  <section>
                    <h4 className="text-sm font-semibold">Security findings</h4>
                    {detail.data.findings.length === 0 ? <p className="text-sm">No finding in this scan names this resource.</p> : (
                      <ul className="space-y-2">
                        {detail.data.findings.map((finding) => (
                          <li key={finding.id} className="text-sm">
                            <Link className="text-cyan-800 underline dark:text-cyan-200" to={`/findings?scan_id=${encodeURIComponent(selectedScanId)}&finding_id=${encodeURIComponent(finding.id)}`}>{finding.title}</Link>
                            <span className="text-xs text-slate-500"> {finding.severity} · {finding.module} · {finding.id}</span>
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
                    <ul className="space-y-2">
                      {detail.data.relationships.map((rel) => (
                        <li key={`${rel.direction}-${rel.rel_type}-${rel.other_id}`} className="text-sm">
                          <span className="font-medium">{semanticLabel[rel.semantic] || rel.semantic}</span> · {rel.rel_type} · {rel.direction}
                          <span className="block break-all font-mono text-xs">{rel.other_id}</span>
                          {rel.note ? <span className="text-xs text-slate-500">{rel.note}</span> : null}
                        </li>
                      ))}
                    </ul>
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
            </article>
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
                    <ul className="mt-1 space-y-1">{rows.map(renderRow)}</ul>
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
