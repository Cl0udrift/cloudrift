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
  const selected = params.get("role") ?? "";
  const page = Number(params.get("page") || "1");
  const [impact, setImpact] = useState(false);
  const [impactWorkload, setImpactWorkload] = useState("");

  const filters = useMemo(
    () => ({ account_id: accountID, region, purpose, trust, broad, evidence, workload, type: workloadType, q, page, page_size: 25 }),
    [accountID, region, purpose, trust, broad, evidence, workload, workloadType, q, page]
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
        description="Collected roles in this scan. A trust relationship is configuration, not proof a caller can assume the role. Hypothetical impact runs only after you select a role."
      />
      {!selectedScanId ? (
        <ScanRequired />
      ) : (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
          <div className="space-y-3">
            <div className="grid gap-2 sm:grid-cols-2">
              <input className="hs-input" placeholder="Search role or account" value={q} onChange={(e) => patch("q", e.target.value)} />
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
                    <p className="break-all font-mono text-xs text-slate-900 dark:text-slate-100">{role.role_arn}</p>
                    <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                      {role.account_id} · {role.classifications.join(", ") || "unclassified"} · workloads {role.workload_count}
                    </p>
                    {role.broad_candidates && role.broad_candidates.length > 0 ? (
                      <p className="mt-1 text-xs text-amber-800 dark:text-amber-200">Candidate: {role.broad_candidates.join(", ")}</p>
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
        <h2 className="break-all font-mono text-sm text-slate-900 dark:text-slate-100">{profile.role_arn}</h2>
        <p className="mt-2 text-sm text-slate-700 dark:text-slate-300">{profile.assumption}</p>
        <p className="mt-1 text-xs text-slate-500">{(profile.classifications ?? []).join(", ")} · collection {profile.collection_status}</p>
      </header>
      <section>
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Declared entitlements</h3>
        <p className="text-sm text-slate-700 dark:text-slate-300">{profile.candidate_note}</p>
        <p className="mt-1 text-sm">Attached policies: {profile.attached_policies?.join(", ") || "none recorded"} · inline documents: {profile.inline_policy_count}</p>
        <p className="text-sm">Candidates: {profile.broad_candidates?.join(", ") || "none"}</p>
        <p className="text-sm">Policy retrieval: {profile.policy_retrieval}</p>
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
        {(profile.trusts ?? []).length === 0 ? <p className="text-sm">No trust relationships were stored.</p> : null}
        <ul className="space-y-2">
          {(profile.trusts ?? []).map((trust) => (
            <li key={`${trust.principal_type}-${trust.principal_arn}`} className="text-sm">
              <span className="font-medium">{trust.kind}</span> · {trust.scope}
              <span className="block break-all font-mono text-xs">{trust.principal_arn || trust.principal_type}</span>
              <span className="text-xs text-slate-500">{trust.note}</span>
            </li>
          ))}
        </ul>
      </section>
      <section>
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Evidence</h3>
        <ul className="list-disc pl-5 text-sm">
          {(profile.evidence_coverage?.lines ?? []).map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </section>
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
      <section>
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Review recommendations</h3>
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
    </article>
  );
}
