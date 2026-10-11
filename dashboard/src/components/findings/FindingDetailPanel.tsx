import type { ReactNode } from "react";
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
  return (
    <div className="space-y-4">
      <div>
        <p className="text-sm font-medium text-slate-900 dark:text-slate-100">{item.title}</p>
        <p className="mt-1 font-mono text-xs text-slate-500 break-all">{item.id}</p>
      </div>
      {scanId && findingId ? (
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
      {item.evidence && Object.keys(item.evidence).length > 0 ? (
        <Section title="Evidence">
          <EvidenceBlock evidence={item.evidence} />
        </Section>
      ) : null}
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
