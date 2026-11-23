import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../../api/client";
import { formatQueryError } from "../../api/httpError";
import { queryKeys } from "../../api/queryKeys";
import { AnswerSummary, CallerCard, ObservedCallersList, UnknownCallersList } from "../access/CallerCard";
import { StateChip } from "../ui/StatusChip";

/** Who (users and roles) can assume this role and which workloads run as it. Policy based, not CloudTrail. */
export function RoleUsage({ scanId, roleArn }: { scanId: string; roleArn: string }) {
  const q = useQuery({ queryKey: queryKeys.roleUsage(scanId, roleArn), queryFn: () => apiClient.getRoleUsage(scanId, roleArn), enabled: Boolean(scanId && roleArn) });
  return (
    <section aria-label="Who and what uses this role" aria-live="polite" className="space-y-3">
      <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">Who can assume this role?</h3>
      {q.isLoading ? (
        <p className="cr-helper" role="status">Checking who can assume this role…</p>
      ) : q.isError || !q.data ? (
        <p className="cr-helper">{formatQueryError(q.error)}</p>
      ) : (
        <div className="space-y-4 text-sm">
          <AnswerSummary callers={q.data.assumers ?? []} unknown={q.data.unknown} verb="assume this role" evaluated={q.data.evaluated} />
          {(q.data.assumers ?? []).length > 0 ? (
            <ul className="space-y-3">
              {(q.data.assumers ?? []).map((a) => <CallerCard key={a.arn} caller={a} verb="assume this role" />)}
            </ul>
          ) : null}
          <UnknownCallersList callers={q.data.unknown_callers ?? []} open={(q.data.assumers ?? []).length === 0} />
          <ObservedCallersList callers={q.data.observed ?? []} historyRead={q.data.history_read ?? false} />
          {(q.data.workloads ?? []).length > 0 ? (
            <div>
              <p className="cr-kpi-label mb-1">Workloads that run as this role</p>
              <ul className="flex flex-wrap gap-2">
                {(q.data.workloads ?? []).map((w) => (
                  <li key={`${w.workload_arn}-${w.mechanism}`} className="flex items-center gap-2 rounded-lg border border-slate-300 px-2 py-1 dark:border-slate-700">
                    <StateChip tone="info" glyph="▣" label={w.workload_type.replace(/_/g, " ")} />
                    <span className="break-all text-xs font-medium">{w.workload_name || w.workload_arn}</span>
                    <span className="text-xs text-slate-500">{w.mechanism.replace(/_/g, " ")}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          <details className="text-xs text-slate-500">
            <summary className="cursor-pointer">About this result</summary>
            {(q.data.notes ?? []).map((n) => <p key={n} className="mt-1">{n}</p>)}
          </details>
        </div>
      )}
    </section>
  );
}
