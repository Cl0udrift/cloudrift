import { useMemo, useState } from "react";
import type { PermissionDecision } from "../../api/types";
import { AuthorizationChip } from "../ui/StatusChip";

const FILTERS: [string, string][] = [
  ["ALL", "All"],
  ["VALIDATED_ALLOWED", "Allowed"],
  ["VALIDATED_DENIED", "Denied"],
  ["CONDITIONAL", "Conditional"],
  ["UNKNOWN", "Unknown"]
];

const human = (code: string) => code.replace(/_/g, " ");

/** Every evaluated decision with its plain-language reason, plus what evidence would settle the unknowns. */
export function PermissionDecisions({ decisions }: { decisions: PermissionDecision[] }) {
  const [filter, setFilter] = useState("ALL");
  const shown = useMemo(
    () => decisions.filter((d) => filter === "ALL" || d.status === filter || (filter === "UNKNOWN" && d.status !== "VALIDATED_ALLOWED" && d.status !== "VALIDATED_DENIED" && d.status !== "CONDITIONAL")),
    [decisions, filter]
  );
  // Which missing evidence blocks the most decisions: the shortest list of things to collect.
  const blockers = useMemo(() => {
    const counts = new Map<string, number>();
    for (const d of decisions) {
      if (d.status === "VALIDATED_ALLOWED" || d.status === "VALIDATED_DENIED") continue;
      for (const m of new Set([...(d.missing_evidence ?? []), ...(d.missing_context ?? [])])) counts.set(m, (counts.get(m) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [decisions]);

  if (decisions.length === 0) return null;
  return (
    <details className="rounded border border-amber-300/60 bg-white/60 p-2 dark:border-amber-800/40 dark:bg-slate-950/40">
      <summary className="cursor-pointer font-medium">Decisions and why ({decisions.length})</summary>
      {blockers.length > 0 ? (
        <p className="mt-2">
          Most often blocking a decision: {blockers.map(([m, n]) => `${human(m)} (${n})`).join(", ")}. Unknown is not a denial.
        </p>
      ) : null}
      <div className="mt-2 flex flex-wrap gap-1" role="group" aria-label="Filter decisions by result">
        {FILTERS.map(([value, label]) => (
          <button key={value} type="button" aria-pressed={filter === value} onClick={() => setFilter(value)}
            className={`rounded border px-2 py-0.5 ${filter === value ? "border-amber-700 font-semibold" : "border-amber-300/60"}`}>
            {label}
          </button>
        ))}
      </div>
      <ul className="mt-2 max-h-80 space-y-1.5 overflow-auto">
        {shown.slice(0, 200).map((d) => (
          <li key={`${d.action}|${d.resource_arn}`} className="rounded border border-amber-200/70 p-1.5 dark:border-amber-900/50">
            <div className="flex flex-wrap items-center gap-2">
              <AuthorizationChip status={d.status} />
              <span className="font-mono">{d.action}</span>
            </div>
            <p className="mt-0.5 break-all font-mono text-[10px] opacity-80">{d.resource_arn}</p>
            <p className="mt-0.5">{d.explanation || human(d.reason)}</p>
            {(d.explicit_deny ?? []).length > 0 ? <p>Deny: {d.explicit_deny?.join("; ")}</p> : null}
            {(d.applied_statements ?? []).length > 0 ? <p>Applied: {d.applied_statements?.join("; ")}</p> : null}
            {(d.missing_evidence ?? []).length > 0 ? <p>Missing evidence: {d.missing_evidence?.map(human).join(", ")}</p> : null}
          </li>
        ))}
      </ul>
      {shown.length > 200 ? <p className="mt-1">Showing the first 200 of {shown.length}.</p> : null}
    </details>
  );
}
