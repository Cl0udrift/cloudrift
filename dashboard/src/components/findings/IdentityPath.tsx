import { useState } from "react";

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
