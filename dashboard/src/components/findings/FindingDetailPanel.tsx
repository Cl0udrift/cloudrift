import { AttackStatusChip, AuthorizationChip, StateChip } from "../ui/StatusChip";
import { CopyIdentifier } from "../ui/CopyIdentifier";
import { SeverityBadge } from "../SeverityBadge";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { IdentityPath, RemediationOptions } from "./IdentityPath";
import { formatQueryError } from "../../api/httpError";
import type { FindingDetailItem } from "../../api/types";
import { BlastRadiusSection } from "../blast/BlastRadiusSection";
import { daysSinceUsedColorClass, formatAdminEvalStateLabel, formatDaysSinceUsedLabel } from "../../lib/trustLabels";
import { StatePanel } from "../StatePanel";
import { PermissionVisibilityPanel } from "../trust/PermissionVisibilityPanel";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="border-t border-slate-200 pt-4 first:border-t-0 first:pt-0 dark:border-t-slate-800">
      <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">{title}</h4>
      <div className="mt-2 text-sm text-slate-800 dark:text-slate-200">{children}</div>
    </div>
  );
}

function TrustBlock({ trust }: { trust: NonNullable<FindingDetailItem["trust"]> }) {
  const rows: [string, string | number | boolean | undefined, string?][] = [
    ["Role ARN", trust.role_arn],
    ["Role name", trust.role_name],
    ["External principal", trust.external_principal],
    ["Principal type", trust.principal_type],
    ["External account", trust.external_account_id],
    ["Last used", formatDaysSinceUsedLabel(trust.days_since_used), daysSinceUsedColorClass(trust.days_since_used)],
    ["Activity status", trust.activity_status],
    ["Verdict", trust.verdict],
    ["Reason", trust.reason],
    ["Admin evaluation", formatAdminEvalStateLabel(trust.admin_eval_state)],
    ["Unknown vendor", trust.unknown_vendor !== undefined ? String(trust.unknown_vendor) : undefined]
  ];
  const visible = rows.filter(([, v]) => v !== undefined && v !== "");
  const hasPermissionVisibility = Boolean(trust.permission_visibility);

  if (visible.length === 0 && !hasPermissionVisibility) {
    return <p className="text-slate-500">No trust metadata populated.</p>;
  }

  return (
    <div className="space-y-4">
      {visible.length > 0 ? (
        <dl className="grid gap-2 sm:grid-cols-2">
          {visible.map(([k, v, colorClass]) => (
            <div key={k}>
              <dt className="text-xs text-slate-500">{k}</dt>
              <dd className={`mt-0.5 font-mono text-xs break-words font-medium ${colorClass ?? "text-slate-800 dark:text-slate-200"}`}>{String(v)}</dd>
            </div>
          ))}
        </dl>
      ) : null}
      <div className="rounded-md border border-slate-200 bg-slate-50/70 p-3 dark:border-slate-800 dark:bg-slate-900/40">
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
          Permission visibility
        </p>
        <PermissionVisibilityPanel permission={trust.permission_visibility} />
      </div>
    </div>
  );
}

/** Pretty-printed JSON: keeps nested structure readable; flattening keys would lose fidelity. */
function EvidenceBlock({ evidence }: { evidence: Record<string, unknown> }) {
  const keys = Object.keys(evidence);
  if (keys.length === 0) {
    return <p className="text-slate-500">No evidence object on this finding.</p>;
  }
  return (
    <pre className="max-h-64 overflow-auto rounded border border-slate-300 bg-slate-100 p-3 font-mono text-xs text-slate-700 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300">
      {JSON.stringify(evidence, null, 2)}
    </pre>
  );
}

function CIEMBlock({ ciem }: { ciem: NonNullable<FindingDetailItem["ciem"]> }) {
  if (!ciem.applicable) {
    return <p className="text-slate-500">This finding is outside the external-access CIEM assessment.</p>;
  }
  return (
    <div className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
      <p>{ciem.assumption}</p>
      <p>
        Entry feasibility: {ciem.entry_feasibility}. Delegation: {ciem.delegation_breadth}. Principal class: {ciem.principal_class}.
      </p>
      <p>
        Hypothetical impact: {ciem.validated_allowed} validated allows, {ciem.validated_denied} denied, {ciem.conditional} conditional, {ciem.unknown} unknown.
        Complete resource paths: {ciem.resource_impact_paths}. Validated transitions: {ciem.validated_transitions}. Additional reachable roles: {ciem.reachable_identities}.
      </p>
      <p>
        Privilege escalation: {ciem.privilege_escalation || "NOT_ASSESSED"}. A validated resource read is not privilege escalation.
        Identity movement: {ciem.validated_identity_movement ? "validated" : "none"}. Resource access: {ciem.validated_resource_access ? "validated" : "none"}.
      </p>
      {(ciem.unique_impacted_resources ?? []).length > 0 ? (
        <p className="break-all">Collected resources: {ciem.unique_impacted_resources?.join(", ")}</p>
      ) : null}
      {(ciem.broad_privilege_candidates ?? []).length > 0 ? (
        <p>Administrative candidates, not validated access: {ciem.broad_privilege_candidates?.join(", ")}</p>
      ) : null}
      {(ciem.unsupported_actions ?? []).length > 0 ? <p>Unsupported actions: {ciem.unsupported_actions?.join(", ")}</p> : null}
      {(ciem.evidence_coverage?.lines ?? []).map((line) => (
        <p key={line}>{line}</p>
      ))}
      {(ciem.bucket_scope_notes ?? []).map((note) => (
        <p key={note} className="break-all">
          {note}
        </p>
      ))}
      {(ciem.missing_evidence ?? []).slice(0, 4).map((note) => (
        <p key={note}>Missing or limited evidence: {note}</p>
      ))}
      {(ciem.sibling_finding_ids ?? []).length > 0 ? (
        <p>Same role impact is shared with findings {ciem.sibling_finding_ids?.join(", ")}. Resources are not counted again.</p>
      ) : null}
      {ciem.truncated ? <p>Analysis truncated. Counts are incomplete.</p> : null}
      {(ciem.recommendations ?? []).map((rec) => (
        <div key={rec.id} className="rounded border border-slate-200 p-2 dark:border-slate-700">
          <p className="font-medium">{rec.title}</p>
          <p>{rec.issue}</p>
          <p>Change: {rec.change_target}. Expected change: {rec.expected_reduction}</p>
          <p>Risk: {rec.operational_risk}</p>
          <p>Verify: {rec.verification}</p>
          <p>{rec.executable || ciem.execution_enabled ? "Executable" : "Read-only. This recommendation is not executed."}</p>
        </div>
      ))}
    </div>
  );
}

function declaredExposure(evidence?: Record<string, unknown>) {
  const kind = String(evidence?.assessment_type || "");
  return kind === "DECLARED_UNCONDITIONAL_EXPOSURE" || kind === "DECLARED_CONDITIONAL_EXPOSURE" || kind === "DECLARED_ENTITLEMENT_EXPOSURE";
}

const IDENTITY_LABELS: Record<string, string> = {
  user_console_without_mfa: "Console access without MFA",
  user_access_key_hygiene: "Access key hygiene",
  user_administrative_access: "Administrative access held by a user",
  weak_credential_reaches_administrative_role: "Weak credential reaches an administrative role",
  workload_runs_as_administrative_role: "Workload runs as an administrative role"
};

function identityEvidenceRows(ev: Record<string, unknown>): [string, string][] {
  const skip = new Set(["issue_category", "assessment_version", "principal_arn", "keys", "track", "path", "severity_factors", "remediation_options"]);
  return Object.entries(ev)
    .filter(([k]) => !skip.has(k))
    .map(([k, v]) => [k.replace(/_/g, " "), Array.isArray(v) ? v.map(String).join(", ") : typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)]);
}

export function FindingDetailPanelContent({
  item,
  scanId,
  findingId
}: {
  item: FindingDetailItem;
  /** When set (list row id), enables blast-radius summary + link to 3D explorer. */
  scanId?: string;
  findingId?: string;
}) {
  const ev = item.evidence ?? {};
  const declared = declaredExposure(item.evidence);
  const identity = ev.assessment_version === "ciem-identity.1";
  const verification = String(ev.version_verification || "");
  const list = (v: unknown) => (Array.isArray(v) ? v.join(", ") : "");
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <div className="flex items-start gap-2">
          <SeverityBadge severity={item.severity} />
          <p className="text-sm font-medium text-slate-900 dark:text-slate-100">{item.title}</p>
        </div>
        {declared ? (
          <div className="flex flex-wrap gap-2" aria-label="Security conclusions">
            <StateChip tone="warn" glyph="◆" label={String(ev.assessment_type) === "DECLARED_CONDITIONAL_EXPOSURE" ? "Declared, conditional" : "Declared exposure"} />
            <AuthorizationChip status="not_assessed" />
            <AttackStatusChip kind="configuration" />
            <StateChip tone={verification === "verified" || verification === "not_applicable" ? "ok" : "unk"} glyph={verification === "verified" ? "✓" : "?"} label={`Policy version ${verification || "unverified"}`} />
          </div>
        ) : null}
      </div>
      {item.account_id ? (
        <Section title="Account context">
          <dl className="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-1 text-xs">
            <dt className="cr-kpi-label">Account</dt>
            <dd className="break-all">{item.account_name ? `${item.account_name} · ` : ""}{item.account_id}</dd>
            {item.ou_path ? (<><dt className="cr-kpi-label">OU path</dt><dd className="break-all">{item.ou_path}</dd></>) : null}
            {item.team ? (<><dt className="cr-kpi-label">Team tag</dt><dd>{item.team}</dd></>) : null}
          </dl>
          <p className="cr-helper">Read from collected account metadata. Cloudrift does not track ownership or assignment.</p>
        </Section>
      ) : null}
      {identity ? (
        <>
          <Section title="Identity finding">
            <p>{IDENTITY_LABELS[String(ev.issue_category)] ?? String(ev.issue_category)}</p>
            <CopyIdentifier value={String(ev.principal_arn || item.affected_arn || "")} />
            <p className="cr-helper">
              {String(ev.principal_arn || "").includes(":user/") ? (
                <Link className="underline" to={`/principals?${scanId ? `scan_id=${encodeURIComponent(scanId)}&` : ""}principal=${encodeURIComponent(String(ev.principal_arn || ""))}`}>Open Users &amp; Groups</Link>
              ) : (
                <Link className="underline" to={`/identities${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""}`}>Open Identities</Link>
              )}
            </p>
          </Section>
          {ev.track ? (
            <Section title={ev.track === "toxic_combination" ? "Toxic combination" : "Posture issue"}>
              <p className="cr-helper">
                {ev.track === "toxic_combination"
                  ? "Several facts that are modest alone add up to a short route to administrative access. Fix any link in the chain."
                  : "A weakness in how this identity is set up. It is not a route to anything by itself."}
              </p>
              <IdentityPath path={ev.path as never} />
            </Section>
          ) : null}
          {Array.isArray(ev.severity_factors) ? (
            <Section title="Why this severity">
              <ul className="list-disc space-y-0.5 pl-5 text-sm">{(ev.severity_factors as string[]).map((x) => <li key={x}>{x}</li>)}</ul>
            </Section>
          ) : null}
          {Array.isArray(ev.remediation_options) ? (
            <Section title="How to fix it">
              <RemediationOptions options={ev.remediation_options as never} />
            </Section>
          ) : null}
          <Section title="What this rests on">
            <dl className="grid grid-cols-[10rem_1fr] gap-x-3 gap-y-1 text-xs">
              {identityEvidenceRows(ev).map(([k, v]) => (
                <div key={k} className="contents"><dt className="cr-kpi-label">{k}</dt><dd className="break-all">{v}</dd></div>
              ))}
            </dl>
          </Section>
        </>
      ) : declared ? (
        <>
          <Section title="Security interpretation">
            <p>A collected Allow statement matches a sensitive pattern. Effective authorization was not evaluated, and this is not a validated attack path.</p>
            <p className="text-slate-600 dark:text-slate-300">{String(ev.why || "")}</p>
          </Section>
          <Section title="Affected resource">
            <CopyIdentifier value={String(ev.role_arn || item.affected_arn || "")} />
          </Section>
          <Section title="Declared permission">
            <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 text-xs">
              <dt className="cr-kpi-label">Actions</dt><dd className="break-all">{list(ev.actions) || "—"}</dd>
              <dt className="cr-kpi-label">Resources</dt><dd className="break-all">{list(ev.resources) || "—"}</dd>
              <dt className="cr-kpi-label">Resource scope</dt><dd>{String(ev.resource_breadth || "not recorded (older assessment)")}</dd>
              <dt className="cr-kpi-label">Sensitivity</dt><dd>{String(ev.action_sensitivity || "not recorded (older assessment)")}</dd>
              <dt className="cr-kpi-label">Condition</dt>
              <dd className="break-all">{String(ev.condition_status || "none")}{ev.conditions && Object.keys(ev.conditions as object).length > 0 ? ` · ${JSON.stringify(ev.conditions)}` : ""}</dd>
            </dl>
          </Section>
          <Section title="Policy provenance">
            <p className="break-all text-xs">{list(ev.policy_arns) || String(ev.policy_arn || "inline document")} · {String(ev.policy_type || "")} · version {String(ev.policy_version || "—")} · statements {list(ev.statement_ids) || "—"}</p>
          </Section>
        </>
      ) : scanId && findingId ? (
        <BlastRadiusSection scanId={scanId} findingId={findingId} severity={item.severity} />
      ) : null}
      {item.impact ? (
        <Section title="Impact">
          <p className="whitespace-pre-wrap text-slate-700 dark:text-slate-300">{item.impact}</p>
        </Section>
      ) : null}
      {item.recommendation ? (
        <Section title="Recommendation">
          <p className="whitespace-pre-wrap text-slate-700 dark:text-slate-300">{item.recommendation}</p>
        </Section>
      ) : null}
      {item.remediation_command ? (
        <Section title="Remediation command">
          <pre className="overflow-x-auto rounded border border-slate-300 bg-slate-100 p-3 font-mono text-xs text-emerald-900 dark:border-slate-800 dark:bg-slate-950 dark:text-emerald-200/90">
            {item.remediation_command}
          </pre>
        </Section>
      ) : null}
      {item.trust ? (
        <Section title="Trust (external access)">
          <TrustBlock trust={item.trust} />
        </Section>
      ) : null}
      {item.ciem ? (
        <Section title="CIEM assessment">
          <CIEMBlock ciem={item.ciem} />
        </Section>
      ) : null}
      <details className="rounded border border-slate-200 p-2 text-xs dark:border-slate-700">
        <summary className="hs-focus-ring cursor-pointer font-semibold uppercase tracking-wide text-slate-500">Technical details</summary>
        <dl className="mt-2 space-y-1">
          <dt className="cr-kpi-label">Finding ID</dt>
          <dd className="cr-ident">{item.id}</dd>
          {ev.evidence_fingerprint ? (
            <>
              <dt className="cr-kpi-label">Evidence fingerprint</dt>
              <dd className="cr-ident">{String(ev.evidence_fingerprint)}</dd>
            </>
          ) : null}
          {ev.assessment_version ? (
            <>
              <dt className="cr-kpi-label">Assessment version</dt>
              <dd className="cr-ident">{String(ev.assessment_version)}</dd>
            </>
          ) : null}
        </dl>
        {item.evidence && Object.keys(item.evidence).length > 0 ? (
          <div className="mt-2">
            <EvidenceBlock evidence={item.evidence} />
          </div>
        ) : null}
      </details>
    </div>
  );
}

export function FindingDetailPanelLoading() {
  return (
    <div className="py-6 text-center text-sm text-slate-500" role="status">
      Loading finding detail…
    </div>
  );
}

export function FindingDetailPanelError({ error }: { error: unknown }) {
  return (
    <StatePanel intent="error" title="Failed to load finding detail">
      <pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(error)}</pre>
    </StatePanel>
  );
}
