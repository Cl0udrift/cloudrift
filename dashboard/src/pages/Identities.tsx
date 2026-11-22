import { TagList } from "../components/ui/TagList";
import { UserMatrix } from "../components/identities/UserMatrix";
import { RoleUsage } from "../components/identities/RoleUsage";
import { AccountPermissionMatrix, type MatrixSelection } from "../components/identities/AccountPermissionMatrix";
import { EvidenceChip, StateChip, SectionHeader } from "../components/ui/StatusChip";
import { lastUsedLabel } from "../lib/lastUsed";
import { ageLabel, capitalize, categoryLabel, LEVEL, serviceLabel, severityTone } from "../lib/identityLabels";
import { IDLE_DAYS } from "../lib/lastUsedConstants";
import { CopyIdentifier } from "../components/ui/CopyIdentifier";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import type { RoleEntitlementProfile, WorkloadListResponse } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { EntityDrawer } from "../components/ui/EntityDrawer";
import { SeverityBadge } from "../components/SeverityBadge";
import { ScanRequired } from "../components/ScanRequired";
import { PolicyInventoryNotice } from "../components/identities/PolicyInventoryNotice";
import { StatePanel } from "../components/StatePanel";
import { useScanContext } from "../hooks/useScanContext";

const CLASS_LABEL: Record<string, string> = {
  SERVICE_LINKED_ROLE: "Service-linked",
  SAME_ACCOUNT: "Same account",
  AWS_SERVICE_ROLE: "Assumed by an AWS service",
  EXTERNAL_DELEGATED: "Trusts an outside account",
  INTERNAL_CROSS_ACCOUNT: "Trusts another of your accounts",
  INTERNAL_NOT_SCANNED: "Trusts an account not scanned",
  UNKNOWN_ORG_MEMBERSHIP: "Trusts an account of unknown membership",
  FEDERATED_ROLE: "Federated",
  MIXED_TRUST: "Mixed trust",
  UNRESOLVED: "Unresolved",
  UNCLASSIFIED: "Unclassified"
};
const humanize = (c: string) => CLASS_LABEL[c] ?? c.toLowerCase().replace(/_/g, " ");

function TogglePill({ on, onClick, title, children }: { on: boolean; onClick: () => void; title?: string; children: React.ReactNode }) {
  return (
    <button type="button" aria-pressed={on} title={title} onClick={onClick} className={`hs-action-pill ${on ? "!border-cyan-500 !bg-cyan-500/10 text-cyan-900 dark:text-cyan-100" : ""}`}>
      {children}
    </button>
  );
}

type TileKey = "all" | "findings" | "internet" | "external" | "powerful_idle";

/** The numbers a reviewer wants first. Each is a filter on the list below. */
function RoleTiles({ scanId, idleDays, hideAws, active, onPick }: { scanId: string; idleDays: number; hideAws: boolean; active: TileKey | null; onPick: (key: TileKey) => void }) {
  const base: Record<string, string> = hideAws ? { hide_aws_managed: "true" } : {};
  const useCount = (key: string, extra: Record<string, string>) =>
    useQuery({ queryKey: ["identities-count", scanId, key, hideAws, extra], queryFn: () => apiClient.listIdentities(scanId, { page: 1, page_size: 1, ...base, ...extra }), enabled: Boolean(scanId) });
  const counts: Record<TileKey, ReturnType<typeof useCount>> = {
    all: useCount("all", {}),
    findings: useCount("findings", { findings: "true" }),
    internet: useCount("internet", { internet: "true" }),
    external: useCount("external", { trust: "external" }),
    powerful_idle: useCount("powerful_idle", { powerful_idle: "true", idle_days: String(idleDays) })
  };
  const defs: [TileKey, string, string][] = [
    ["all", hideAws ? "Your roles" : "Roles", hideAws ? "Without the roles AWS creates and owns" : "Every IAM role in this scan"],
    ["findings", "With findings", "At least one finding above Info"],
    ["internet", "Reachable from the internet", "A workload running as it is open to the world"],
    ["external", "Trust an outside account", "Trust names an account that is not yours"],
    ["powerful_idle", `Powerful and idle ${idleDays}d+`, "Broad permission, no recent use"]
  ];
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
      {defs.map(([key, label, hint]) => (
        <button key={key} type="button" aria-pressed={active === key} onClick={() => onPick(key)} className={`hs-card hs-interactive-card flex h-full flex-col gap-1 p-4 text-left ${active === key ? "border-cyan-500 ring-1 ring-cyan-500" : ""}`}>
          <p className="cr-kpi-label">{label}</p>
          <p className="cr-kpi-value">{counts[key].data ? counts[key].data!.total_items : "…"}</p>
          <p className="cr-helper">{hint}</p>
        </button>
      ))}
    </div>
  );
}

export function IdentitiesPage() {
  const { selectedScanId } = useScanContext();
  const [params, setParams] = useSearchParams();
  const accountID = params.get("account_id") ?? "";
  const region = params.get("region") ?? "";
  const purpose = params.get("purpose") ?? "";
  const trust = params.get("trust") ?? "";
  const broad = params.get("broad") ?? "";
  const evidence = params.get("evidence") ?? "";
  const workload = params.get("workload") ?? "";
  const workloadType = params.get("type") ?? "";
  const q = params.get("q") ?? "";
  const category = params.get("category") ?? "";
  const unknownOnly = params.get("unknown") === "true";
  const findingsOnly = params.get("findings") === "true";
  const internetOnly = params.get("internet") === "true";
  const powerfulIdle = params.get("powerful_idle") === "true";
  const showAws = params.get("aws") === "show";
  const idleOnly = params.get("idle") === "true";
  const idleDays = Number(params.get("idle_days")) > 0 ? Number(params.get("idle_days")) : IDLE_DAYS;
  const selected = params.get("role") ?? "";
  const page = Number(params.get("page") || "1");

  const filters = useMemo(
    () => ({ account_id: accountID, region, purpose, trust, broad, evidence, workload, type: workloadType, q, category, unknown: unknownOnly ? "true" : "", idle: idleOnly ? "true" : "", idle_days: idleOnly || powerfulIdle ? String(idleDays) : "", findings: findingsOnly ? "true" : "", internet: internetOnly ? "true" : "", powerful_idle: powerfulIdle ? "true" : "", hide_aws_managed: showAws ? "" : "true", page, page_size: 25 }),
    [accountID, region, purpose, trust, broad, evidence, workload, workloadType, q, category, unknownOnly, idleOnly, idleDays, findingsOnly, internetOnly, powerfulIdle, showAws, page]
  );
  const list = useQuery({
    queryKey: ["identities", selectedScanId, filters],
    queryFn: () => apiClient.listIdentities(selectedScanId!, filters),
    enabled: Boolean(selectedScanId)
  });
  const profile = useQuery({
    queryKey: ["identity-profile", selectedScanId, selected],
    queryFn: () => apiClient.getIdentityProfile(selectedScanId!, selected, true),
    enabled: Boolean(selectedScanId && selected)
  });
  const workloadList = useQuery({
    queryKey: ["workloads", selectedScanId],
    queryFn: () => apiClient.listWorkloads(selectedScanId!),
    enabled: Boolean(selectedScanId)
  });
  const unresolved = (workloadList.data?.items ?? []).filter((item) => item.kind === "UNRESOLVED_ROLE");

  // Matrix cell: replace the account, category and unknown filters together.
  const selectFromMatrix = (sel: MatrixSelection) => {
    const next = new URLSearchParams(params);
    next.set("account_id", sel.account_id);
    if (sel.category) next.set("category", sel.category);
    else next.delete("category");
    if (sel.unknown) next.set("unknown", "true");
    else next.delete("unknown");
    if (sel.idle) next.set("idle", "true");
    else next.delete("idle");
    next.delete("role");
    next.delete("page");
    setParams(next);
  };

  const patch = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "role") next.delete("role");
    if (key !== "page") next.delete("page");
    setParams(next);
  };

  return (
    <section className="space-y-6">
      <PageHeader
        title="Identities"
        description="IAM roles in this scan, riskiest first. Users and groups are on the Users & Groups page."
        details="Roles are ordered by their worst finding, then by a workload reachable from the internet, then by declared broad permissions. A trust relationship is configuration, not proof a caller can assume the role. Hypothetical impact runs only after you select a role."
      />
      <PolicyInventoryNotice scanId={selectedScanId} />
      {!selectedScanId ? (
        <ScanRequired />
      ) : (
        <div className="space-y-6">
        <RoleTiles
          scanId={selectedScanId}
          idleDays={idleDays}
          hideAws={!showAws}
          active={findingsOnly ? "findings" : internetOnly ? "internet" : powerfulIdle ? "powerful_idle" : trust === "external" ? "external" : !idleOnly && broad !== "candidate" && !unknownOnly && !category ? "all" : null}
          onPick={(key) => {
            const n = new URLSearchParams(params);
            for (const k of ["idle", "idle_days", "broad", "unknown", "category", "role", "page", "findings", "internet", "trust", "powerful_idle"]) n.delete(k);
            if (key === "findings") n.set("findings", "true");
            if (key === "internet") n.set("internet", "true");
            if (key === "external") n.set("trust", "external");
            if (key === "powerful_idle") { n.set("powerful_idle", "true"); n.set("idle_days", String(idleDays)); }
            setParams(n);
          }}
        />
        <details className="hs-card p-4">
          <summary className="hs-focus-ring cursor-pointer rounded text-sm font-semibold">Per-account tables: declared permissions of roles and users</summary>
          <div className="mt-4 space-y-6">
            <AccountPermissionMatrix scanId={selectedScanId} onSelect={selectFromMatrix} idleDays={idleDays} onIdleDays={(d) => { const n = new URLSearchParams(params); if (d === IDLE_DAYS) n.delete("idle_days"); else n.set("idle_days", String(d)); n.delete("page"); setParams(n); }} />
            <UserMatrix scanId={selectedScanId} />
          </div>
        </details>
        {category || unknownOnly || idleOnly ? (
          <p className="cr-helper flex flex-wrap items-center gap-2" role="status">
            Showing roles with {idleOnly ? `no recent use reported by IAM (${idleDays} days or more, or none in the tracking window)` : unknownOnly ? "unknown policy evidence" : `declared ${category}`}{accountID ? ` in account ${accountID}` : ""}.
            <button type="button" className="hs-btn-default px-2 py-0.5 text-xs" onClick={() => { const n = new URLSearchParams(params); n.delete("category"); n.delete("unknown"); n.delete("idle"); n.delete("account_id"); n.delete("page"); setParams(n); }}>Clear</button>
          </p>
        ) : null}
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filters">
            <input className="hs-input !w-auto min-w-[16rem] flex-1" placeholder="Search role or account" value={q} onChange={(e) => patch("q", e.target.value)} aria-label="Search role or account" />
            <TogglePill on={trust === "external"} onClick={() => patch("trust", trust === "external" ? "" : "external")}>Trusts outside accounts</TogglePill>
            <TogglePill on={workload === "attached"} onClick={() => patch("workload", workload === "attached" ? "" : "attached")}>Runs a workload</TogglePill>
            <TogglePill on={!showAws} title="Service-linked roles that AWS creates and owns" onClick={() => patch("aws", showAws ? "" : "show")}>Hide AWS-managed</TogglePill>
            {idleOnly ? (
              <span className="flex flex-wrap items-center gap-1" role="group" aria-label="Idle after">
                <span className="text-xs text-slate-500">Idle after</span>
                {[30, 60, 90, 180, 365].map((d) => (
                  <TogglePill key={d} on={idleDays === d} onClick={() => { const n = new URLSearchParams(params); if (d === IDLE_DAYS) n.delete("idle_days"); else n.set("idle_days", String(d)); n.delete("page"); setParams(n); }}>{d}d</TogglePill>
                ))}
              </span>
            ) : null}
            <details className="relative" open={Boolean(accountID || region || purpose || broad || evidence || workloadType) || undefined}>
              <summary className="hs-action-pill cursor-pointer list-none">More filters{[accountID, region, purpose, broad, evidence, workloadType].filter(Boolean).length ? ` (${[accountID, region, purpose, broad, evidence, workloadType].filter(Boolean).length})` : ""}</summary>
              <div className="absolute right-0 z-20 mt-2 grid w-80 gap-2 rounded-lg border border-slate-200 bg-white p-3 shadow-lg dark:border-slate-700 dark:bg-slate-900">
                <input className="hs-input" placeholder="Account ID" value={accountID} onChange={(e) => patch("account_id", e.target.value)} />
                <input className="hs-input" placeholder="Region" value={region} onChange={(e) => patch("region", e.target.value)} />
                <select className="hs-input" value={purpose} onChange={(e) => patch("purpose", e.target.value)} aria-label="Who the role trusts">
                  <option value="">Any trust</option>
                  {["EXTERNAL_DELEGATED", "INTERNAL_CROSS_ACCOUNT", "INTERNAL_NOT_SCANNED", "UNKNOWN_ORG_MEMBERSHIP", "SAME_ACCOUNT", "AWS_SERVICE_ROLE", "SERVICE_LINKED_ROLE", "FEDERATED_ROLE", "MIXED_TRUST", "UNRESOLVED"].map((item) => (
                    <option key={item} value={item}>{humanize(item)}</option>
                  ))}
                </select>
                <select className="hs-input" value={broad} onChange={(e) => patch("broad", e.target.value)} aria-label="Permission breadth">
                  <option value="">Any permissions</option>
                  <option value="candidate">Declares a broad permission</option>
                </select>
                <select className="hs-input" value={evidence} onChange={(e) => patch("evidence", e.target.value)} aria-label="Evidence">
                  <option value="">Any evidence</option>
                  <option value="recorded">Controls recorded</option>
                  <option value="incomplete">Evidence incomplete</option>
                </select>
                <select className="hs-input" value={workloadType} onChange={(e) => patch("type", e.target.value)} aria-label="Workload type">
                  <option value="">Any workload</option>
                  <option value="ec2_instance">EC2 instance</option>
                  <option value="lambda_function">Lambda function</option>
                  <option value="ecs_task">ECS task</option>
                  <option value="ecs_service">ECS service</option>
                  <option value="eks_pod_identity_association">EKS Pod Identity</option>
                  <option value="irsa_trust">IRSA trust</option>
                </select>
              </div>
            </details>
          </div>
          {list.isLoading ? <StatePanel>Loading roles…</StatePanel> : null}
          {list.isError ? (
            <StatePanel intent="error" title="Failed to load roles">
              <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(list.error)}</pre>
            </StatePanel>
          ) : null}
          {list.data && list.data.items.length === 0 ? (
            <StatePanel intent="empty" title="No roles match">
              {list.data.coverage_note}
            </StatePanel>
          ) : null}
          {unresolved.length > 0 ? (
            <section className="hs-card space-y-2 p-3">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Roles named by a workload but not collected</h3>
              <ul className="space-y-2">
                {unresolved.map((item) => (
                  <li key={item.relationship_id || item.workload_arn} className="text-sm">
                    <span className="font-medium">{humanize(item.workload_type)}</span>
                    <span className="block break-all font-mono text-xs">{item.workload_arn}</span>
                    <span className="block break-all font-mono text-xs text-slate-500">{item.role_arn}</span>
                    <span className="text-xs text-slate-500">{item.note}</span>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
          {(list.data?.items ?? []).length > 0 ? (
            <div className="hs-card max-h-[70vh] overflow-auto !p-0">
              <table className="w-full text-left text-sm">
                <thead className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                  <tr>
                    {["Role", "Findings", "Exposure", "Can do", "Owner", "Last used"].map((h, i) => (
                      <th key={h} scope="col" className={`sticky top-0 z-10 bg-slate-50 px-3 py-2.5 dark:bg-slate-900 ${i >= 4 ? "hidden lg:table-cell" : i >= 2 ? "hidden sm:table-cell" : ""}`}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(list.data?.items ?? []).map((role) => (
                    <tr key={role.role_arn} onClick={() => patch("role", role.role_arn)} className={`hs-interactive-row border-t border-slate-200 dark:border-slate-800 ${selected === role.role_arn ? "bg-cyan-500/10" : ""}`}>
                      <td className="max-w-[16rem] px-3 py-2.5">
                        <button type="button" title={role.role_arn} aria-current={selected === role.role_arn} className="hs-focus-ring block max-w-full truncate text-left font-medium text-slate-900 hover:underline dark:text-slate-100" onClick={(e) => { e.stopPropagation(); patch("role", role.role_arn); }}>{role.name}</button>
                        <span className="block truncate text-xs text-slate-500">
                          {(role.classifications.length ? role.classifications : ["UNCLASSIFIED"]).map(humanize).join(" · ")}
                          {role.workload_count > 0 ? ` · ${role.workload_count} workload${role.workload_count === 1 ? "" : "s"}` : ""}
                          {(role.inline_policy_count ?? 0) > 0 ? ` · ${role.inline_policy_count} inline polic${role.inline_policy_count === 1 ? "y" : "ies"}` : ""}
                        </span>
                      </td>
                      <td className="px-3 py-2.5">
                        {role.finding_count > 0 ? (
                          <span className="inline-flex items-center gap-1.5">
                            <SeverityBadge severity={role.max_severity ?? "info"} />
                            <span className="text-xs tabular-nums text-slate-600 dark:text-slate-400">{role.finding_count}</span>
                          </span>
                        ) : (
                          <span className="text-xs text-slate-500" title="No finding above Info names this role. That does not mean it was assessed as safe.">none</span>
                        )}
                      </td>
                      <td className="hidden px-3 py-2.5 sm:table-cell">
                        {role.exposure_state === "reachable" ? <span className="cr-chip-state cr-tone-bad" title={role.exposure_detail}>Internet-facing</span>
                          : role.exposure_state === "restricted" ? <span className="cr-chip-state cr-tone-warn" title={role.exposure_detail}>Specific addresses</span>
                          : role.exposure_state === "not_checked" ? <span className="cr-chip-state cr-tone-unk" title={role.exposure_detail}>Not checked</span>
                          : role.exposure_state === "not_reachable" ? <span className="text-xs text-slate-500" title={role.exposure_detail}>Not reachable</span>
                          : <span className="text-slate-400">—</span>}
                      </td>
                      <td className="hidden max-w-[16rem] px-3 py-2.5 sm:table-cell">
                        {(role.broad_candidates ?? []).length === 0 ? <span className="text-slate-400">—</span> : (
                          <span className="flex flex-wrap gap-1">
                            {Array.from(new Set(role.broad_candidates)).slice(0, 2).map((c) => <span key={c} className="cr-chip-state cr-tone-warn" title="Declared in a policy document. Not evaluated access.">{categoryLabel(c)}</span>)}
                            {new Set(role.broad_candidates).size > 2 ? <span className="text-xs text-slate-500">+{new Set(role.broad_candidates).size - 2}</span> : null}
                          </span>
                        )}
                      </td>
                      <td className="hidden px-3 py-2.5 lg:table-cell">{role.owner || <span className="text-slate-400">—</span>}</td>
                      <td className="hidden whitespace-nowrap px-3 py-2.5 text-xs lg:table-cell">{lastUsedLabel(role.last_used_status, role.days_since_used, role.last_used_region).text}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          {list.data ? (
            <div className="flex items-center justify-between gap-2 text-xs text-slate-500">
              <p>{list.data.coverage_note} Showing {list.data.items.length} of {list.data.total_items}.</p>
              <div className="flex gap-2">
                <button type="button" className="hs-btn-default px-2 py-1" disabled={page <= 1} onClick={() => patch("page", String(page - 1))}>Previous</button>
                <button type="button" className="hs-btn-default px-2 py-1" disabled={page >= list.data.total_pages} onClick={() => patch("page", String(page + 1))}>Next</button>
              </div>
            </div>
          ) : null}
        </div>
        {selected ? (
          <EntityDrawer title={profile.data?.name ?? "Role"} onClose={() => patch("role", "")}>
            <RoleDetail scanId={selectedScanId || ""} profile={profile.data} loading={profile.isLoading} error={profile.error} />
          </EntityDrawer>
        ) : null}
        </div>
      )}
    </section>
  );
}

const REASON: Record<string, string> = { missing_session_policy: "no session policy was recorded for the role" };
const escalationText = (v?: string) =>
  !v || v === "NOT_ASSESSED" ? "Escalation was not assessed." : v === "NONE_FOUND_IN_MODELED_TECHNIQUES" ? "No way to gain more access was found among the techniques Cloudrift models." : `Escalation: ${humanize(v)}.`;

function RoleDetail({ scanId, profile, loading, error }: { scanId: string; profile?: RoleEntitlementProfile; loading: boolean; error: unknown }) {
  if (!profile && !loading && !error) {
    return <StatePanel intent="empty" title="Select a role">What it can do, who can become it and what to change appear here.</StatePanel>;
  }
  if (loading) return <StatePanel>Loading the role…</StatePanel>;
  if (error || !profile) {
    return (
      <StatePanel intent="error" title="Failed to load the role">
        <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(error)}</pre>
      </StatePanel>
    );
  }
  const recs = profile.recommendations ?? [];
  return (
    <article className="space-y-5 [&>section]:border-t [&>section]:border-slate-200 [&>section]:pt-5 dark:[&>section]:border-slate-800">
      <header>
        <p className="flex flex-wrap gap-1.5 text-xs">
          {(profile.classifications ?? []).map((c) => <span key={c} className="rounded-full border border-slate-300 px-2 py-0.5 dark:border-slate-700">{humanize(c)}</span>)}
          {profile.collection_status !== "collected" ? <span className="rounded-full border border-slate-300 px-2 py-0.5 dark:border-slate-700">Collection: {humanize(profile.collection_status)}</span> : null}
        </p>
        <div className="mt-2"><CopyIdentifier value={profile.role_arn} /></div>
        <RoleSummary profile={profile} scanId={scanId} />
      </header>

      <RoleCapabilities profile={profile} />
      <RoleContext profile={profile} />
      <RoleImpact profile={profile} />

      <section aria-label="Who can become this role" className="space-y-3">
        <SectionHeader title="Who can become this role" hint="The trust policy names who may assume the role. Trust is configuration; whether a caller can use it also depends on that caller's own permissions." />
        {(profile.trust_statements ?? []).length > 0 ? (
          <ul className="space-y-2">
            {(profile.trust_statements ?? []).map((t, i) => (
              <li key={`${t.kind}-${i}`} className="hs-card-soft space-y-1 p-3 text-sm">
                <p className="flex flex-wrap items-center gap-2">
                  {t.kind === "wildcard" ? <StateChip tone="bad" glyph="◉" label="Open to any AWS account" /> : t.outside ? <StateChip tone="warn" glyph="◆" label="Outside account" /> : <StateChip tone="info" glyph="○" label={t.kind === "service" ? "AWS service" : t.kind === "federated" ? "Federated sign-in" : "Inside your accounts"} />}
                  {(t.guards ?? []).map((g) => <StateChip key={g} tone="ok" glyph="✓" label={g} />)}
                </p>
                <p>{t.summary}</p>
              </li>
            ))}
          </ul>
        ) : (profile.trusts ?? []).length > 0 ? (
          <ul className="space-y-1 text-sm">
            {(profile.trusts ?? []).map((t) => <li key={`${t.kind}-${t.principal_arn}`}>{humanize(t.scope)}: <span className="break-all font-mono text-xs">{t.principal_arn || t.principal_type}</span></li>)}
          </ul>
        ) : (
          <p className="text-sm">No trust principal was read from stored evidence.</p>
        )}
        <RoleUsage scanId={scanId} roleArn={profile.role_arn} />
      </section>

      <section aria-label="Role activity">
        <SectionHeader title="Is it used?" hint="Reported by IAM for the whole role, not per permission." />
        <p className="mt-1 text-sm">
          {lastUsedLabel(profile.last_used_status, profile.days_since_used, profile.last_used_region).text}
          {profile.last_used ? ` · ${profile.last_used.slice(0, 10)}` : ""}
        </p>
        <p className="cr-helper mt-1">
          {!profile.service_last_accessed_status ? (
            <>Which services it uses was not collected. <Link className="underline" to="/settings#cfg-scan.service_last_accessed">Turn on service last accessed</Link> to see unused permissions.</>
          ) : profile.service_last_accessed_status === "complete" ? (
            `${(profile.service_access ?? []).filter((s) => s.last_authenticated).length} of ${(profile.service_access ?? []).length} listed services were used${profile.service_last_accessed_completed ? ` (collected ${profile.service_last_accessed_completed})` : ""}.`
          ) : (
            `Service last accessed is ${profile.service_last_accessed_status.replace(/_/g, " ")}. Treat service use as unknown.`
          )}
        </p>
      </section>

      <section aria-label="Suggested changes">
        <SectionHeader title="Suggested changes" hint="Read-only suggestions. Cloudrift does not change anything." />
        {recs.length === 0 ? <p className="mt-1 text-sm">No change is suggested from the recorded evidence.</p> : null}
        <ul className="mt-2 space-y-3">
          {recs.map((rec) => (
            <li key={rec.id} className="hs-card-soft space-y-1 p-3 text-sm">
              <p className="font-medium">{rec.title}</p>
              <p>{rec.issue}</p>
              <p className="text-xs text-slate-600 dark:text-slate-300"><span className="font-medium">Could break:</span> {rec.operational_risk}</p>
              <p className="text-xs text-slate-600 dark:text-slate-300"><span className="font-medium">Check afterwards:</span> {rec.verification}</p>
            </li>
          ))}
        </ul>
      </section>

      <details className="hs-card-soft p-3">
        <summary className="hs-focus-ring cursor-pointer text-sm font-semibold text-slate-900 dark:text-slate-100">Evidence behind this page (for review)</summary>
        <div className="mt-3 space-y-4">
          <section>
            <SectionHeader title="Sensitive permissions declared" hint={profile.candidate_note} />
            <p className="mt-1 text-xs text-slate-600 dark:text-slate-300">
              {profile.candidate_count} declared · {profile.conditional_count} conditional · {profile.unknown_count} could not be read · {profile.deny_evidence_count} explicit deny. Policies: {profile.attached_policies?.join(", ") || "none recorded"}.
            </p>
            <ul className="mt-2 space-y-2">
              {(profile.permission_candidates ?? []).map((item) => (
                <li key={item.evidence_fingerprint} className="hs-card-soft space-y-1 p-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{item.category ? categoryLabel(item.category) : "Could not be classified"}</span>
                    <EvidenceChip state={item.outcome} />
                    {item.eligible ? <StateChip tone="warn" glyph="⚑" label="Counts toward a finding" /> : null}
                    {item.service_activity ? (
                      <StateChip
                        tone={item.service_activity === "not_accessed_in_window" ? "info" : "unk"}
                        glyph={item.service_activity === "accessed" ? "●" : item.service_activity === "not_accessed_in_window" ? "○" : "?"}
                        label={item.service_activity === "accessed" ? `Service used ${item.service_last_accessed?.slice(0, 10) ?? ""}` : item.service_activity === "not_accessed_in_window" ? "Service not used in IAM window" : "Service use unknown"}
                        title="IAM access advisor, service level only."
                      />
                    ) : null}
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-300">
                    {item.effect || "—"} {item.actions?.join(", ")} on {item.resources?.join(", ") || "—"} · {item.resource_breadth === "global_wildcard" ? "every resource" : humanize(item.resource_breadth || "unknown scope")}
                  </p>
                  {item.conditions && Object.keys(item.conditions).length > 0 ? <p className="cr-mono break-all text-slate-600 dark:text-slate-300">Condition: {JSON.stringify(item.conditions)}</p> : null}
                  <p className="cr-ident">{item.policy_arn || "inline document"}</p>
                </li>
              ))}
            </ul>
          </section>
          <section>
            <SectionHeader title="Coverage" hint="What the scan could and could not read for this role." />
            <ul className="mt-1 list-disc pl-5 text-sm">
              {(profile.evidence_coverage?.lines ?? []).map((line) => <li key={line}>{line}</li>)}
            </ul>
          </section>
        </div>
      </details>
    </article>
  );
}

/** What the role's policies allow, per service. Written policy text: denies are not applied. */
function RoleCapabilities({ profile }: { profile: RoleEntitlementProfile }) {
  const all = profile.capabilities ?? [];
  // S3 Object Lambda access comes from the same S3 policy line; one row says it.
  const caps = all.filter((c) => !(c.service === "s3-object-lambda" && all.some((o) => o.service === "s3" && o.level === c.level)));
  const row = (c: NonNullable<RoleEntitlementProfile["capabilities"]>[number]) => {
    const [tone, glyph, label] = LEVEL[c.level] ?? LEVEL.read;
    return (
      <tr key={c.service} title={(c.actions ?? []).join(", ")}>
        <td className="py-1.5 pr-3"><span className="block font-medium">{serviceLabel(c.service)}</span><span className="block text-xs text-slate-500">{c.policies.join(", ")}</span></td>
        <td className="py-1.5 pr-3"><StateChip tone={tone} glyph={glyph} label={label} />{c.limited_by_boundary ? <span className="mt-1 block text-xs text-slate-500">narrowed by its boundary</span> : null}</td>
        <td className="py-1.5">{c.scope}{c.conditional ? " · conditional" : ""}</td>
      </tr>
    );
  };
  return (
    <section aria-label="What the role can do" className="space-y-2">
      <SectionHeader title="What it can do" hint="Read from the role's policies, per service. Explicit denies are not applied." />
      {caps.length === 0 ? (
        <p className="text-sm">No allow statement was read for this role. {profile.capability_note || "No policy is attached, or none could be read."}</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-slate-500"><th className="pb-1 pr-3 font-normal">Service</th><th className="pb-1 pr-3 font-normal">Level</th><th className="pb-1 font-normal">On</th></tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">{caps.slice(0, 8).map(row)}</tbody>
        </table>
      )}
      {caps.length > 8 ? (
        <details>
          <summary className="cursor-pointer text-xs font-medium text-cyan-800 dark:text-cyan-300">Show {caps.length - 8} more services</summary>
          <table className="mt-1 w-full text-sm"><tbody className="divide-y divide-slate-200 dark:divide-slate-800">{caps.slice(8).map(row)}</tbody></table>
        </details>
      ) : null}
      {caps.length > 0 && profile.capability_note ? <p className="cr-helper">{profile.capability_note}</p> : null}
      {profile.controls_note ? (
        <p className="flex items-start gap-1.5 text-xs text-slate-600 dark:text-slate-300">
          <span aria-hidden="true">{profile.controls_complete ? "✓" : "?"}</span>
          {profile.controls_note}
        </p>
      ) : null}
    </section>
  );
}

/** Where the role is exposed and who owns it. Not checked is never shown as safe. */
function RoleContext({ profile }: { profile: RoleEntitlementProfile }) {
  const state = profile.exposure_state;
  const chip =
    state === "reachable" ? <StateChip tone="bad" glyph="◉" label="Reachable from the internet" /> :
    state === "restricted" ? <StateChip tone="warn" glyph="◐" label="Open to specific addresses" /> :
    state === "not_reachable" ? <StateChip tone="ok" glyph="✓" label="No way in from the internet" /> :
    state === "not_checked" ? <StateChip tone="unk" glyph="?" label="Exposure not checked" /> :
    <StateChip tone="unk" glyph="–" label="No workload runs as it" />;
  const keys = (profile.owner_tag_keys ?? []).join(", ");
  return (
    <section aria-label="Exposure and ownership" className="space-y-2">
      <SectionHeader title="Exposure and ownership" hint="Whether a workload that runs as this role can be reached from the internet, from its security group rules. It does not mean the workload can be exploited." />
      <p className="flex flex-wrap items-center gap-2 text-sm">{chip}<span>{profile.exposure_detail}</span></p>
      {(profile.entry_points ?? []).length > 0 ? (
        <ul className="space-y-1 text-sm">
          {(profile.entry_points ?? []).map((e) => <li key={e.text} className="flex gap-2"><span aria-hidden="true" className="text-slate-400">→</span><span>{e.text}</span></li>)}
        </ul>
      ) : null}
      {(profile.runs_on ?? []).map((w) => (
        <p key={w.arn} className="hs-card-soft break-all p-2 text-sm">
          <span className="cr-kpi-label mr-2">Runs on</span>
          <span className="font-medium">{w.name || humanize(w.type)}</span>
          <span className="block text-xs text-slate-500">{[w.arn.split("/").pop(), w.state, w.public_ip ? `public IP ${w.public_ip}` : w.type === "ec2_instance" ? "no public IP" : "", w.profile ? `instance profile ${w.profile}` : ""].filter(Boolean).join(" · ")}</span>
        </p>
      ))}
      <p className="text-sm">
        {profile.owner ? <>Owner: <span className="font-medium">{profile.owner}</span>. </> : <span className="text-amber-800 dark:text-amber-300">No owner tag{keys ? ` (looked for ${keys})` : ""}. </span>}
        {profile.created_at ? `Created ${profile.created_at.slice(0, 10)} (${ageLabel(profile.created_at)}).` : ""}
      </p>
      {profile.tags && Object.keys(profile.tags).length > 0 ? <div><span className="cr-kpi-label mr-2">Tags</span><TagList tags={profile.tags} /></div> : null}
    </section>
  );
}

/** What stolen credentials for this role could reach. Computed on open, from the stored policies. */
function RoleImpact({ profile }: { profile: RoleEntitlementProfile }) {
  const i = profile.impact;
  const fromWorkload = (profile.workloads ?? []).length > 0;
  if (!i) return <StatePanel>Working out what this role could reach…</StatePanel>;
  const reasons = (i.missing_evidence ?? []).map((m) => m.split(": ").pop() ?? m);
  // When every undecided result is "no allow in the role's policies", the role simply lacks those permissions.
  const noAllowOnly = reasons.length > 0 && reasons.every((r) => r === "no_applicable_allow");
  const tile = (n: number, label: string, hint: string) => (
    <div className="hs-card-soft p-2" title={hint}>
      <p className="text-xl font-semibold tabular-nums">{n}</p>
      <p className="text-xs">{label}</p>
    </div>
  );
  const verb = (r: { service: string; level: string }) => (r.level === "read" ? (r.service === "s3" ? "Can read" : "Can list") : "Can change");
  const single = (r: { noun: string; count: number }) => (r.count === 1 ? r.noun.replace("databases", "database").replace(/s$/, "") : r.noun);
  return (
    <section aria-label="If the credentials are stolen" className="space-y-2">
      <SectionHeader title="If this role's credentials are stolen" hint={fromWorkload ? "Credentials taken from a workload carry no session policy, so none is assumed." : "No workload runs as this role, so the session's own restrictions are unknown."} />
      {(profile.reach ?? []).length > 0 ? (
        <ul className="space-y-2 text-sm">
          {(profile.reach ?? []).map((r) => (
            <li key={r.service}>
              <StateChip tone={r.level === "read" ? "info" : "bad"} glyph="●" label={`${verb(r)} ${r.count} ${single(r)}`} />
              {(r.items ?? []).length > 0 ? (
                <p className="mt-1 break-all text-xs text-slate-600 dark:text-slate-300">
                  {(r.items ?? []).map((it, n) => (
                    <span key={it.name}>{n > 0 ? ", " : ""}{it.hint ? <strong className="font-semibold text-amber-800 dark:text-amber-300" title={it.hint}>{it.name} ({it.hint})</strong> : it.name}</span>
                  ))}
                  {r.count > (r.items ?? []).length ? `, and ${r.count - (r.items ?? []).length} more` : ""}
                </p>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
      <p className="cr-helper">From the policy text, for every resource the scan collected in this account. The checks below cover sensitive actions only (IAM changes, assuming roles, secrets, keys).</p>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {tile(i.validated_allowed, "Confirmed allowed", "Sensitive actions the policies clearly allow")}
        {tile(i.conditional, "Depends on a condition", "Allowed only if a condition in the policy holds")}
        {noAllowOnly
          ? tile(i.unknown, "Not in its policies", "Nothing in the role's own policies allows these. They are not counted as denied because a resource's own policy could still grant access.")
          : tile(i.unknown, "Could not be decided", "Not allowed and not ruled out")}
        {tile(i.reachable_identities, "Other roles reachable", "Roles the holder could move to")}
      </div>
      <p className="text-sm">{escalationText(i.privilege_escalation)}</p>
      {i.truncated ? <p className="cr-helper">The search stopped at its limit, so these counts are not complete.</p> : null}
    </section>
  );
}

/** Two lines that say what this role is, then the ways out of this page: its findings, its blast radius, its workloads. */
function RoleSummary({ profile, scanId }: { profile: RoleEntitlementProfile; scanId: string }) {
  const workloads = profile.workloads ?? [];
  const declared = Array.from(new Set((profile.permission_candidates ?? []).filter((c) => c.category && (c.outcome === "DECLARED" || c.outcome === "CONDITIONAL")).map((c) => categoryLabel(c.category))));
  const used = lastUsedLabel(profile.last_used_status, profile.days_since_used, profile.last_used_region).text;
  const enc = encodeURIComponent;
  return (
    <div className="mt-3 space-y-3">
      <p className="text-sm text-slate-700 dark:text-slate-300">
        {workloads.length > 0 ? `Used by ${workloads.length} workload${workloads.length === 1 ? "" : "s"} (${workloads.slice(0, 2).map((w) => humanize(w.workload_type)).join(", ")}). ` : "No collected workload runs as this role. "}
        {declared.length > 0 ? `Declares ${declared.join(", ").toLowerCase()}. ` : "Declares no broad permission, which is not a safety claim. "}
        {used}.
      </p>
      <div className="flex flex-wrap gap-2">
        <Link className="hs-action-pill" to={`/blast-explorer?scan=${enc(scanId)}&principal=${enc(profile.role_arn)}`}>What can this role reach? (Blast Explorer)</Link>
        <Link className="hs-action-pill" to={`/access?scan_id=${enc(scanId)}&arn=${enc(profile.role_arn)}&action=sts:AssumeRole`}>Who can assume it? (Access Explorer)</Link>
        {workloads[0] ? <Link className="hs-action-pill" to={`/inventory?scan_id=${enc(scanId)}&resource=${enc(workloads[0].workload_arn)}`}>Open the workload in Inventory</Link> : null}
      </div>
      {(profile.findings ?? []).length > 0 ? (
        <section aria-label="Findings on this role">
          <p className="cr-kpi-label mb-1">Findings on this role</p>
          <ul className="space-y-1">
            {(profile.findings ?? []).map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-2 text-sm">
                <StateChip tone={severityTone(f.severity)} glyph="●" label={capitalize(f.severity)} />
                <Link className="text-cyan-800 underline dark:text-cyan-200" to={`/findings?scan_id=${enc(scanId)}&finding_id=${enc(f.id)}`}>{f.title}</Link>
              </li>
            ))}
          </ul>
        </section>
      ) : (
        <p className="cr-helper">No finding above Info is recorded on this role itself.</p>
      )}
    </div>
  );
}
