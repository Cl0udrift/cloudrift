import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiClient } from "../../api/client";
import { formatQueryError } from "../../api/httpError";
import { queryKeys } from "../../api/queryKeys";
import { StateChip, SectionHeader, type Tone } from "../ui/StatusChip";

const statusChip: Record<string, [Tone, string, string]> = {
  VALIDATED_ALLOWED: ["bad", "●", "Can assume"],
  ALLOWED_PENDING_CONTROLS: ["warn", "◐", "Allowed by policies, org controls unchecked"],
  CONDITIONAL: ["warn", "◐", "Conditional"]
};

/** Who (users and roles) can assume this role and which workloads run as it. Policy based, not CloudTrail. */
export function RoleUsage({ scanId, roleArn }: { scanId: string; roleArn: string }) {
  const q = useQuery({ queryKey: queryKeys.roleUsage(scanId, roleArn), queryFn: () => apiClient.getRoleUsage(scanId, roleArn), enabled: Boolean(scanId && roleArn) });
  return (
    <section aria-label="Who and what uses this role">
      <SectionHeader title="Who and what uses this role" hint="Users and roles in this scan that the trust policy and their own policies allow to assume it, and the workloads configured to run as it." />
      {q.isLoading ? (
        <p className="cr-helper" role="status">Checking who can assume this role…</p>
      ) : q.isError || !q.data ? (
        <p className="cr-helper">{formatQueryError(q.error)}</p>
      ) : (
        <div className="mt-2 space-y-3 text-sm">
          <p>
            <span className="font-semibold">{q.data.allowed}</span> can assume it, <span className="font-semibold">{q.data.possible}</span> more are allowed by policies with organization controls not checked, <span className="font-semibold">{(q.data.workloads ?? []).length}</span> workloads run as it. {q.data.evaluated} users and roles were checked; {q.data.unknown} could not be evaluated because their policy documents are missing.
          </p>
          {(q.data.assumers ?? []).length > 0 ? (
            <ul className="space-y-1">
              {(q.data.assumers ?? []).map((a) => {
                const [tone, glyph, label] = statusChip[a.status] ?? statusChip.CONDITIONAL;
                return (
                  <li key={a.arn} className="flex flex-wrap items-center gap-2">
                    <StateChip tone={tone} glyph={glyph} label={label} title={a.reason} />
                    <span className="text-xs uppercase text-slate-500">{a.kind}</span>
                    {a.kind === "user" ? (
                      <Link className="font-mono text-xs underline" to={`/principals?principal=${encodeURIComponent(a.arn)}`}>{a.name}</Link>
                    ) : (
                      <span className="font-mono text-xs">{a.name}</span>
                    )}
                    <span className="text-xs text-slate-500">{a.account_id}</span>
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="cr-helper">No user or role in this scan was found able to assume it.</p>
          )}
          {(q.data.workloads ?? []).length > 0 ? (
            <ul className="space-y-1">
              {(q.data.workloads ?? []).map((w) => (
                <li key={`${w.workload_arn}-${w.mechanism}`} className="flex flex-wrap items-center gap-2">
                  <StateChip tone="info" glyph="▣" label={w.workload_type} />
                  <span className="font-mono text-xs">{w.workload_name || w.workload_arn}</span>
                  <span className="text-xs text-slate-500">{w.mechanism}</span>
                </li>
              ))}
            </ul>
          ) : null}
          {(q.data.notes ?? []).map((n) => (
            <p key={n} className="cr-helper">{n}</p>
          ))}
        </div>
      )}
    </section>
  );
}
