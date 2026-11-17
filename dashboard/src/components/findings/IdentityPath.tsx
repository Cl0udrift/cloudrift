import { useState } from "react";
import { Link } from "react-router-dom";

type PathNode = { kind: string; label: string; detail?: string; risk?: string };
type Option = { strategy: string; why: string; steps: string[] };

const KIND_LABEL: Record<string, string> = { user: "User", group: "Group", role: "Role", workload: "Workload", policy: "Policy" };

/** The chain that makes an identity finding matter, read left to right, with risk growing toward the target. */
export function IdentityPath({ path }: { path: PathNode[] }) {
  if (!Array.isArray(path) || path.length === 0) return null;
  return (
    <ol className="flex flex-wrap items-stretch gap-2" aria-label="Path">
      {path.map((n, i) =>
        n.kind === "edge" ? (
          <li key={i} className="flex items-center text-xs text-slate-500" aria-hidden={false}>
            <span aria-hidden>→</span>
            <span className="ml-1 max-w-[9rem]">{n.label}</span>
          </li>
        ) : (
          <li
            key={i}
            className={`min-w-[7rem] rounded border px-3 py-2 text-sm ${
              n.risk === "bad" ? "border-red-400 bg-red-50 dark:border-red-800 dark:bg-red-950/30" : n.risk === "warn" ? "border-amber-400 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/30" : "border-slate-300 dark:border-slate-700"
            }`}
          >
            <span className="cr-kpi-label block !text-[10px]">{KIND_LABEL[n.kind] ?? n.kind}</span>
            <span className="break-all font-medium">{n.label}</span>
            {n.detail ? <span className="block text-xs text-slate-600 dark:text-slate-300">{n.detail}</span> : null}
          </li>
        )
      )}
    </ol>
  );
}

/** Pick a strategy first, then read its steps, rather than one flat list of advice. */
export function RemediationOptions({ options }: { options: Option[] }) {
  const [i, setI] = useState(0);
  if (!Array.isArray(options) || options.length === 0) return null;
  const cur = options[Math.min(i, options.length - 1)];
  return (
    <div>
      <div role="tablist" aria-label="Fix strategy" className="flex flex-wrap gap-1">
        {options.map((o, k) => (
          <button
            key={o.strategy}
            type="button"
            role="tab"
            aria-selected={k === i}
            onClick={() => setI(k)}
            className={`rounded px-2 py-1 text-xs font-medium ${k === i ? "bg-cyan-500/20 text-cyan-900 dark:text-cyan-100" : "text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-800"}`}
          >
            {o.strategy}
          </button>
        ))}
      </div>
      <p className="mt-2 text-sm">{cur.why}</p>
      <ol className="mt-1 list-decimal space-y-0.5 pl-5 text-sm">
        {cur.steps.map((s) => <li key={s}>{s}</li>)}
      </ol>
    </div>
  );
}

type Caller = { arn: string; name: string; kind: string; status: string; weak_credential?: boolean; weakness?: string };
export type ReachableBy = { callers?: Caller[]; total?: number; weak?: number; evaluated?: number; unknown?: number; note?: string };

/** Who can assume the role an escalation finding is about, weak credentials first. */
export function ReachableByList({ reach, scanId }: { reach: ReachableBy; scanId?: string }) {
  const callers = reach.callers ?? [];
  const total = reach.total ?? callers.length;
  if (total === 0) {
    return <p className="cr-helper">No user or role in this scan can assume it. Only a principal that already holds the role (an instance, a function, a federated login) can use this path.</p>;
  }
  const scan = scanId ? `scan_id=${encodeURIComponent(scanId)}&` : "";
  return (
    <div className="space-y-2">
      <p className="text-sm">
        <span className="font-semibold">{total}</span> {total === 1 ? "user or role can" : "users and roles can"} assume it
        {reach.weak ? <>, <span className="font-semibold text-red-700 dark:text-red-300">{reach.weak} with a weak credential</span></> : null}.
      </p>
      <ul className="space-y-1 text-sm">
        {callers.map((c) => (
          <li key={c.arn} className="flex flex-wrap items-center gap-2">
            {c.kind === "user" ? (
              <Link className="underline" to={`/principals?${scan}principal=${encodeURIComponent(c.arn)}`}>{c.name}</Link>
            ) : (
              <span className="font-medium">{c.name}</span>
            )}
            <span className="text-xs text-slate-500">{c.kind}</span>
            {c.weak_credential ? <span className="rounded border border-red-400 px-1.5 text-xs text-red-700 dark:border-red-800 dark:text-red-300">weak credential: {c.weakness}</span> : null}
            {c.status === "ALLOWED_PENDING_CONTROLS" ? <span className="text-xs text-slate-500">by policies only; organization controls not checked</span> : null}
          </li>
        ))}
      </ul>
      {total > callers.length ? <p className="cr-helper">Showing {callers.length} of {total}. The Access Explorer lists all of them.</p> : null}
      {reach.note ? <p className="cr-helper">{reach.note}</p> : null}
    </div>
  );
}
