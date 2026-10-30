import { AccountPermissionMatrix, type MatrixSelection } from "../components/identities/AccountPermissionMatrix";
import { AttackStatusChip, AuthorizationChip, EvidenceChip, StateChip, SectionHeader } from "../components/ui/StatusChip";
import { lastUsedLabel } from "../lib/lastUsed";
import { IDLE_DAYS } from "../lib/lastUsedConstants";
import { CopyIdentifier } from "../components/ui/CopyIdentifier";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import type { RoleEntitlementProfile, WorkloadListResponse } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { ScanRequired } from "../components/ScanRequired";
import { StatePanel } from "../components/StatePanel";
import { useScanContext } from "../hooks/useScanContext";

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
  const idleOnly = params.get("idle") === "true";
  const idleDays = Number(params.get("idle_days")) > 0 ? Number(params.get("idle_days")) : IDLE_DAYS;
  const selected = params.get("role") ?? "";
  const page = Number(params.get("page") || "1");
  const [impact, setImpact] = useState(false);
  const [impactWorkload, setImpactWorkload] = useState("");

  const filters = useMemo(
    () => ({ account_id: accountID, region, purpose, trust, broad, evidence, workload, type: workloadType, q, category, unknown: unknownOnly ? "true" : "", idle: idleOnly ? "true" : "", idle_days: idleOnly ? String(idleDays) : "", page, page_size: 25 }),
    [accountID, region, purpose, trust, broad, evidence, workload, workloadType, q, category, unknownOnly, idleOnly, idleDays, page]
  );
  const list = useQuery({
    queryKey: ["identities", selectedScanId, filters],
    queryFn: () => apiClient.listIdentities(selectedScanId!, filters),
    enabled: Boolean(selectedScanId)
  });
  const profile = useQuery({
    queryKey: ["identity-profile", selectedScanId, selected, impact, impactWorkload],
    queryFn: () => apiClient.getIdentityProfile(selectedScanId!, selected, impact, impactWorkload),
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
    setImpact(false);
    setParams(next);
  };

  const patch = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "role") next.delete("role");
    if (key !== "page") next.delete("page");
    setImpact(false);
    setParams(next);
  };

  return (
    <section className="space-y-6">
      <PageHeader
        title="IAM roles"
        description="IAM roles stored in this scan."
        details="A trust relationship is configuration, not proof a caller can assume the role. Hypothetical impact runs only after you select a role."
      />
      {!selectedScanId ? (
        <ScanRequired />
      ) : (
        <div className="space-y-6">
        <AccountPermissionMatrix scanId={selectedScanId} onSelect={selectFromMatrix} idleDays={idleDays} onIdleDays={(d) => { const n = new URLSearchParams(params); if (d === IDLE_DAYS) n.delete("idle_days"); else n.set("idle_days", String(d)); n.delete("page"); setParams(n); }} />
        {category || unknownOnly || idleOnly ? (
          <p className="cr-helper flex flex-wrap items-center gap-2" role="status">
            Showing roles with {idleOnly ? `no recent use reported by IAM (${idleDays} days or more, or none in the tracking window)` : unknownOnly ? "unknown policy evidence" : `declared ${category}`}{accountID ? ` in account ${accountID}` : ""}.
            <button type="button" className="hs-btn-default px-2 py-0.5 text-xs" onClick={() => { const n = new URLSearchParams(params); n.delete("category"); n.delete("unknown"); n.delete("idle"); n.delete("account_id"); n.delete("page"); setParams(n); }}>Clear</button>
          </p>
        ) : null}
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
          <div className="space-y-3">
            <div className="grid gap-2 sm:grid-cols-2">
              <input className="hs-input sm:col-span-2" placeholder="Search role or account" value={q} onChange={(e) => patch("q", e.target.value)} aria-label="Search role or account" />
            </div>
            <details open={Boolean(accountID || category || unknownOnly || idleOnly || region || purpose || params.get("trust") || params.get("broad") || params.get("evidence") || params.get("workload") || params.get("type"))}>
              <summary className="hs-focus-ring w-fit cursor-pointer rounded text-xs font-medium text-cyan-800 dark:text-cyan-300">More filters</summary>
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              <input className="hs-input" placeholder="Account ID" value={accountID} onChange={(e) => patch("account_id", e.target.value)} />
              <input className="hs-input" placeholder="Region" value={region} onChange={(e) => patch("region", e.target.value)} />
              <select className="hs-input" value={purpose} onChange={(e) => patch("purpose", e.target.value)}>
                <option value="">All purposes</option>
                {["EXTERNAL_DELEGATED", "INTERNAL_CROSS_ACCOUNT", "INTERNAL_NOT_SCANNED", "UNKNOWN_ORG_MEMBERSHIP", "SAME_ACCOUNT", "AWS_SERVICE_ROLE", "SERVICE_LINKED_ROLE", "FEDERATED_ROLE", "MIXED_TRUST", "UNRESOLVED"].map((item) => (
                  <option key={item} value={item}>{item}</option>
                ))}
              </select>
              <select className="hs-input" value={trust} onChange={(e) => patch("trust", e.target.value)}>
                <option value="">All trust scopes</option>
                <option value="internal">Internal trust</option>
                <option value="external">External trust</option>
              </select>
              <select className="hs-input" value={broad} onChange={(e) => patch("broad", e.target.value)}>
                <option value="">All entitlement breadth</option>
                <option value="candidate">Broad permission candidates</option>
              </select>
              <select className="hs-input" value={evidence} onChange={(e) => patch("evidence", e.target.value)}>
                <option value="">All evidence states</option>
                <option value="recorded">Recorded controls</option>
                <option value="incomplete">Incomplete evidence</option>
              </select>
              <select className="hs-input" value={workload} onChange={(e) => patch("workload", e.target.value)}>
                <option value="">All workload attachments</option>
                <option value="attached">Configured workload</option>
                <option value="unattached">No collected workload</option>
              </select>
              <select className="hs-input" value={params.get("type") ?? ""} onChange={(e) => patch("type", e.target.value)}>
                <option value="">All workload types</option>
                <option value="ec2_instance">EC2 instance</option>
                <option value="lambda_function">Lambda function</option>
                <option value="ecs_task">ECS task</option>
                <option value="ecs_service">ECS service</option>
                <option value="ecs_task_definition">ECS task definition</option>
                <option value="eks_pod_identity_association">EKS Pod Identity</option>
                <option value="irsa_trust">IRSA trust</option>
              </select>
            </div>
            </details>
            {list.isLoading ? <StatePanel>Loading roles…</StatePanel> : null}
            {list.isError ? (
              <StatePanel intent="error" title="Failed to load roles">
                <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(list.error)}</pre>
              </StatePanel>
            ) : null}
            {list.data && list.data.items.length === 0 ? (
              <StatePanel intent="empty" title="No IAM roles match">
                {list.data.coverage_note}
              </StatePanel>
            ) : null}
            {unresolved.length > 0 ? (
              <section className="hs-card space-y-2 p-3">
                <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Unresolved role references</h3>
                <ul className="space-y-2">
                  {unresolved.map((item) => (
                    <li key={item.relationship_id || item.workload_arn} className="text-sm">
                      <span className="font-medium">{item.workload_type}</span>
                      <span className="block break-all font-mono text-xs">{item.workload_arn}</span>
                      <span className="block break-all font-mono text-xs text-slate-500">{item.role_arn}</span>
                      <span className="text-xs text-slate-500">{item.note}</span>
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
            <ul className="space-y-2">
              {(list.data?.items ?? []).map((role) => (
                <li key={role.role_arn}>
                  <button
                    type="button"
                    className={`hs-card w-full p-3 text-left ${selected === role.role_arn ? "ring-1 ring-cyan-500" : ""}`}
                    onClick={() => {
                      setImpact(false);
                      patch("role", role.role_arn);
                    }}
                  >
                    <p className="text-sm font-medium text-slate-900 dark:text-slate-100">{role.name}</p>
                    <p className="cr-ident !text-[11px] text-slate-500">{role.role_arn}</p>
                    <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                      {role.account_id} · {role.classifications.join(", ") || "unclassified"} · workloads {role.workload_count}
                    </p>
                    <p className="cr-helper mt-0.5">{lastUsedLabel(role.last_used_status, role.days_since_used, role.last_used_region).text}</p>
                    {role.broad_candidates && role.broad_candidates.length > 0 ? (
                      <p className="mt-1 flex flex-wrap gap-1">{role.broad_candidates.map((c) => <StateChip key={c} tone="warn" glyph="◆" label={`Declared: ${c}`} title="Declared in a policy document. Not evaluated access." />)}</p>
                    ) : null}
                  </button>
                </li>
              ))}
            </ul>
            {list.data ? (
              <div className="flex items-center justify-between gap-2 text-xs text-slate-500">
                <p>{list.data.coverage_note} Showing {list.data.items.length} of {list.data.total_items}.</p>
                <div className="flex gap-2">
                  <button type="button" className="hs-input px-2 py-1" disabled={page <= 1} onClick={() => patch("page", String(page - 1))}>Previous</button>
                  <button type="button" className="hs-input px-2 py-1" disabled={page >= list.data.total_pages} onClick={() => patch("page", String(page + 1))}>Next</button>
                </div>
              </div>
            ) : null}
          </div>
          <RoleDetail
            scanId={selectedScanId || ""}
            profile={profile.data}
            loading={profile.isLoading}
            error={profile.error}
            impact={impact}
            impactWorkload={impactWorkload}
            onImpactWorkload={setImpactWorkload}
            onImpact={(arn) => {
              setImpactWorkload(arn);
              setImpact(true);
            }}
          />
        </div>
        </div>
      )}
    </section>
  );
}

function RoleDetail({
  scanId,
  profile,
  loading,
  error,
  impact,
  impactWorkload,
  onImpactWorkload,
  onImpact
}: {
  scanId: string;
  profile?: RoleEntitlementProfile;
  loading: boolean;
  error: unknown;
  impact: boolean;
  impactWorkload: string;
  onImpactWorkload: (arn: string) => void;
  onImpact: (workloadArn: string) => void;
}) {
  if (!profile && !loading && !error) {
    return <StatePanel intent="empty" title="Select a role">Entitlement evidence and hypothetical impact appear here.</StatePanel>;
  }
  if (loading) return <StatePanel>Loading entitlement profile…</StatePanel>;
  if (error || !profile) {
    return (
      <StatePanel intent="error" title="Failed to load the role">
        <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(error)}</pre>
      </StatePanel>
    );
  }
  return (
    <article className="hs-card space-y-4 p-5">
      <header>
        <h2 className="sr-only">IAM role {profile.role_arn}</h2>
        <CopyIdentifier value={profile.role_arn} />
        <p className="mt-2 text-sm text-slate-700 dark:text-slate-300">{profile.assumption}</p>
        <p className="mt-1 text-xs text-slate-500">{(profile.classifications ?? []).join(", ")} · collection {profile.collection_status}</p>
      </header>
      <section aria-label="Role activity">
        <SectionHeader title="Role activity" hint="Reported by IAM for the whole role, not per permission. It does not show which individual permissions are used." />
        <p className="mt-1 text-sm">
          {lastUsedLabel(profile.last_used_status, profile.days_since_used, profile.last_used_region).text}
          {profile.last_used ? ` · ${profile.last_used}` : ""}
        </p>
        <p className="cr-helper mt-1">
          {!profile.service_last_accessed_status
            ? "Service-level last access was not collected for this scan (opt-in)."
            : profile.service_last_accessed_status === "complete"
              ? `Service last-accessed collected${profile.service_last_accessed_completed ? ` ${profile.service_last_accessed_completed}` : ""}: ${(profile.service_access ?? []).filter((s) => s.last_authenticated).length} of ${(profile.service_access ?? []).length} listed services used.`
              : `Service last-accessed is ${profile.service_last_accessed_status.replace(/_/g, " ")}. Treat service use as unknown.`}
        </p>
      </section>
      <section aria-label="Configuration chain">
        <SectionHeader title="Configuration chain" hint="How this role is wired. Configuration and declared evidence, not an attacker path." />
        <ol className="mt-2 flex flex-col gap-2 text-xs lg:flex-row lg:items-stretch">
          {[
            ["Workload", (profile.workloads ?? []).length > 0 ? (profile.workloads ?? []).slice(0, 3).map((w) => `${w.workload_type} ${w.workload_name || ""}`.trim()).join(", ") + ((profile.workloads ?? []).length > 3 ? ` +${(profile.workloads ?? []).length - 3}` : "") : "None collected"],
            ["IAM role", profile.role_arn.split("/").pop() || profile.role_arn],
            ["Attached policy", (profile.attached_policies ?? []).length + profile.inline_policy_count > 0 ? [...(profile.attached_policies ?? []).slice(0, 3), ...(profile.inline_policy_count > 0 ? [`${profile.inline_policy_count} inline`] : [])].join(", ") : "None recorded"],
            ["Declared permission", Array.from(new Set((profile.permission_candidates ?? []).filter((c) => c.category && (c.outcome === "DECLARED" || c.outcome === "CONDITIONAL")).map((c) => c.category))).join(", ") || "No sensitive candidate (not a safety claim)"]
          ].map(([label, value], i, all) => (
            <li key={label} className="flex min-w-0 flex-1 flex-col items-stretch gap-1 lg:flex-row lg:items-center lg:gap-2">
              <div className="hs-card-soft min-w-0 flex-1 p-2">
                <p className="cr-kpi-label">{label}</p>
                <p className="mt-1 break-words">{value}</p>
              </div>
              {i < all.length - 1 ? <span aria-hidden="true" className="text-center text-slate-400"><span className="lg:hidden">↓</span><span className="hidden lg:inline">→</span></span> : null}
            </li>
          ))}
        </ol>
      </section>
      <section aria-label="Conclusion levels">
        <SectionHeader title="What is known" hint="Each level is a separate conclusion. Earlier levels do not imply later ones." />
        <ol className="mt-2 grid gap-2 sm:grid-cols-2 2xl:grid-cols-5">
          <li className="hs-card-soft min-w-0 break-words p-2 text-xs">
            <p className="cr-kpi-label">1 Policy attached</p>
            <p className="mt-1 tabular-nums">{(profile.attached_policies ?? []).length} managed · {profile.inline_policy_count} inline</p>
          </li>
          <li className="hs-card-soft min-w-0 break-words p-2 text-xs">
            <p className="cr-kpi-label">2 Permission declared</p>
            <p className="mt-1 tabular-nums">{profile.candidate_count} declared · {profile.conditional_count} conditional</p>
            <p className="cr-helper">Zero is not a safety claim.</p>
          </li>
          <li className="hs-card-soft min-w-0 break-words p-2 text-xs">
            <p className="cr-kpi-label">3 Access evaluated</p>
            <div className="mt-1">
              {impact ? <StateChip tone="info" glyph="✓" label="Evaluated (supported scope)" /> : <AuthorizationChip status="not_assessed" />}
            </div>
            <p className="cr-helper">{impact ? `${profile.impact?.validated_allowed ?? 0} allowed · ${profile.impact?.unknown ?? 0} unknown` : "Not requested"}</p>
          </li>
          <li className="hs-card-soft min-w-0 break-words p-2 text-xs">
            <p className="cr-kpi-label">4 Hypothetical impact</p>
            <div className="mt-1">{impact ? <AttackStatusChip kind="hypothetical" /> : <StateChip tone="unk" glyph="–" label="Not requested" />}</div>
          </li>
          <li className="hs-card-soft min-w-0 break-words p-2 text-xs">
            <p className="cr-kpi-label">5 Validated transitions</p>
            <p className="mt-1 tabular-nums">{impact ? profile.impact?.validated_transitions ?? 0 : "Not assessed"}</p>
          </li>
        </ol>
      </section>
      <section>
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Permission evidence</h3>
        <p className="text-sm text-slate-700 dark:text-slate-300">{profile.candidate_note}</p>
        <ul className="mt-2 space-y-1 text-sm">
          <li>Declared exposure assessment: {profile.entitlement_assessment} · eligible {profile.eligible_exposure_count} · source {profile.assessment_source} · algorithm {profile.assessment_version || "stored"}</li>
          <li>Conditional candidates: {profile.conditional_count} · unknown evidence or unsupported constructs: {profile.unknown_count} · deny evidence: {profile.deny_evidence_count}</li>
        </ul>
        <p className="mt-1 text-sm">Attached names: {profile.attached_policies?.join(", ") || "none recorded"} · policy retrieval: {profile.policy_retrieval}</p>
        <ul className="mt-2 space-y-2">
          {(profile.permission_candidates ?? []).map((item) => (
            <li key={item.evidence_fingerprint} className="hs-card-soft space-y-1 p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{item.category || "no category"}</span>
                <EvidenceChip state={item.outcome} />
                {item.eligible ? <StateChip tone="warn" glyph="⚑" label="Finding eligible" /> : <StateChip tone="unk" glyph="–" label="Not a finding" />}
                <AuthorizationChip status="not_assessed" />
                {item.service_activity ? (
                  <StateChip
                    tone={item.service_activity === "not_accessed_in_window" ? "info" : "unk"}
                    glyph={item.service_activity === "accessed" ? "●" : item.service_activity === "not_accessed_in_window" ? "○" : "?"}
                    label={
                      item.service_activity === "accessed"
                        ? `${item.service_activity_scope === "action" ? "Action used" : "Service used"} ${item.service_last_accessed?.slice(0, 10) ?? ""}`
                        : item.service_activity === "not_accessed_in_window"
                          ? "Service not used in IAM window"
                          : item.service_activity === "not_reported"
                            ? "Service not listed by IAM"
                            : "Service use unknown"
                    }
                    title="IAM access advisor, service level only. It does not show which actions were used."
                  />
                ) : null}
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-300">
                {item.effect || "—"} {item.actions?.join(", ")} on {item.resources?.join(", ") || "—"} · scope {item.resource_breadth || "unknown"} · {item.exposure_class || "unclassified"} · version {item.version_verification || "unverified"}
              </p>
              {item.conditions && Object.keys(item.conditions).length > 0 ? (
                <p className="cr-mono break-all text-slate-600 dark:text-slate-300">Condition ({item.condition_status}): {JSON.stringify(item.conditions)}</p>
              ) : null}
              <p className="cr-ident">{item.policy_arn || "inline document"}{item.policy_version ? ` · ${item.policy_version}` : ""}{item.statement_id ? ` · ${item.statement_id}` : ""}</p>
              <p className="cr-helper">{item.note}</p>
            </li>
          ))}
        </ul>
      </section>
      <section>
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Workload attachments</h3>
        <p className="text-sm text-slate-700 dark:text-slate-300">{profile.attachment_note || "No EC2 or Lambda attachment was collected for this role."}</p>
        <ul className="space-y-2">
          {(profile.workloads ?? []).map((item) => (
            <li key={item.relationship_id || item.workload_arn} className="text-sm">
              <span className="font-medium">{item.kind}</span> · {item.workload_type} · {item.mechanism}
              {item.status ? <span> · {item.status}</span> : null}
              {item.region ? <span> · {item.region}</span> : null}
              {item.runtime_observed ? <span> · runtime {item.runtime_observed}</span> : null}
              <Link className="block break-all font-mono text-xs text-cyan-800 underline dark:text-cyan-200" to={`/inventory?scan_id=${encodeURIComponent(scanId)}&resource=${encodeURIComponent(item.workload_arn)}`}>
                {item.workload_arn}
              </Link>
              {item.cluster ? <span className="block break-all font-mono text-xs">{item.cluster}{item.namespace ? ` / ${item.namespace}` : ""}{item.service_account ? ` / ${item.service_account}` : ""}</span> : null}
              <span className="text-xs text-slate-500">{item.note}</span>
            </li>
          ))}
        </ul>
        {profile.shared_role ? <p className="text-xs text-slate-500">This role is shared. Resource impact is counted once, not once per workload.</p> : null}
      </section>
      <section>
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Configured trust</h3>
        <p className="text-sm text-slate-700 dark:text-slate-300">{profile.trust_evidence_note}</p>
        {(profile.trusts ?? []).length === 0 ? <p className="text-sm">No trust principal was read from stored evidence.</p> : null}
        <ul className="space-y-2">
          {(profile.trusts ?? []).map((trust) => (
            <li key={`${trust.evidence}-${trust.kind}-${trust.principal_type}-${trust.principal_arn}`} className="text-sm">
              <span className="font-medium">{trust.kind}</span> · {trust.scope}
              {trust.condition_status ? <span> · condition {trust.condition_status}</span> : null}
              <span className="block break-all font-mono text-xs">{trust.principal_arn || trust.principal_type}</span>
              <span className="text-xs text-slate-500">{trust.evidence ? `${trust.evidence} · ` : ""}{trust.note}</span>
            </li>
          ))}
        </ul>
      </section>
      <details className="hs-card-soft p-3">
        <summary className="hs-focus-ring cursor-pointer text-sm font-semibold text-slate-900 dark:text-slate-100">Evidence and collection coverage</summary>
        <div className="mt-2">
      <section>
        
        <ul className="list-disc pl-5 text-sm">
          {(profile.evidence_coverage?.lines ?? []).map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </section>
        </div>
      </details>
      <section>
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Hypothetical compromise</h3>
        {!impact ? (
          <div className="space-y-2">
            {(profile.workloads ?? []).length > 0 ? (
              <label className="block text-sm">
                Workload for the credential assumption
                <select
                  className="hs-input mt-1"
                  value={impactWorkload || profile.workloads?.[0]?.workload_arn || ""}
                  onChange={(e) => onImpactWorkload(e.target.value)}
                >
                  {(profile.workloads ?? []).map((item) => (
                    <option key={item.workload_arn} value={item.workload_arn}>
                      {item.workload_type} {item.workload_name || item.workload_arn}
                    </option>
                  ))}
                </select>
              </label>
            ) : null}
            <button
              type="button"
              className="rounded bg-cyan-700 px-3 py-2 text-sm text-white dark:bg-cyan-600"
              onClick={() => onImpact(impactWorkload || profile.workloads?.[0]?.workload_arn || "")}
            >
              {(profile.workloads ?? []).length > 0 ? "Calculate hypothetical workload credential impact" : "Calculate hypothetical impact"}
            </button>
          </div>
        ) : profile.impact ? (
          <div className="space-y-1 text-sm">
            <p className="font-medium">{profile.impact.kind}</p>
            <p>{profile.impact.assumption}</p>
            <p>
              Allowed {profile.impact.validated_allowed}, denied {profile.impact.validated_denied}, conditional {profile.impact.conditional}, unknown {profile.impact.unknown}.
            </p>
            <p>
              Resource paths {profile.impact.resource_impact_paths}. Validated transitions {profile.impact.validated_transitions}. Reachable roles {profile.impact.reachable_identities}.
            </p>
            <p>Privilege escalation: {profile.impact.privilege_escalation || "NOT_ASSESSED"}.</p>
            {profile.impact.missing_evidence && profile.impact.missing_evidence.length > 0 ? (
              <p>Unknown or unevaluated reasons: {profile.impact.missing_evidence.join(", ")}.</p>
            ) : null}
            {profile.impact.truncated ? <p>The search stopped at its bound. These counts are not a complete reachable universe.</p> : null}
          </div>
        ) : (
          <StatePanel>Calculating impact…</StatePanel>
        )}
      </section>
      <details className="hs-card-soft p-3">
        <summary className="hs-focus-ring cursor-pointer text-sm font-semibold text-slate-900 dark:text-slate-100">Review recommendations (read-only)</summary>
        <div className="mt-2">
      <section>
        
        {(profile.recommendations ?? []).length === 0 ? <p className="text-sm">No review item was produced from the recorded evidence.</p> : null}
        <ul className="space-y-3">
          {(profile.recommendations ?? []).map((rec) => (
            <li key={rec.id} className="text-sm">
              <p className="font-medium">{rec.title}</p>
              <p>{rec.issue}</p>
              <p className="text-xs text-slate-500">{rec.operational_risk}</p>
              <p className="text-xs">Read-only. This recommendation is not executed.</p>
            </li>
          ))}
        </ul>
      </section>
        </div>
      </details>
    </article>
  );
}
