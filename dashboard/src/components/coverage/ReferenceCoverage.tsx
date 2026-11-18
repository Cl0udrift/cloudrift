import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../../api/client";
import type { ReferenceGroup, ReferencePath } from "../../api/types";

function Bar({ g }: { g: ReferenceGroup }) {
  const pct = (n: number) => (g.total ? (100 * n) / g.total : 0);
  return (
    <div className="flex h-2 w-full overflow-hidden rounded bg-slate-200 dark:bg-slate-800" role="img" aria-label={`${g.detected} detected, ${g.partial} partly, ${g.not_detected} not detected of ${g.total}`}>
      <div className="bg-emerald-600 dark:bg-emerald-500" style={{ width: `${pct(g.detected)}%` }} />
      <div className="bg-amber-500" style={{ width: `${pct(g.partial)}%` }} />
    </div>
  );
}

/**
 * How much of an outside list of known privilege-escalation paths Cloudrift detects. The denominator is the
 * reference catalog, not Cloudrift's own technique list, so a gap cannot hide by being unmodelled.
 */
export function ReferenceCoverage() {
  const q = useQuery({ queryKey: ["coverage", "reference"], queryFn: () => apiClient.getReferenceCoverage(), staleTime: 5 * 60_000 });
  const [filter, setFilter] = useState<"missed" | "all">("missed");
  const [group, setGroup] = useState("");
  if (!q.data) return q.isError ? <p className="cr-helper">The reference coverage could not be loaded.</p> : null;
  const r = q.data;
  const shown: ReferencePath[] = r.paths.filter((p) => (filter === "all" || p.status !== "detected") && (!group || p.category === group));
  return (
    <section className="hs-card space-y-4 p-5" aria-label="Coverage against the reference catalog">
      <div>
        <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">Against an outside reference</h2>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Known privilege-escalation paths from <a className="underline" href={r.source.url} target="_blank" rel="noreferrer noopener">{r.source.name}</a>. The list is not Cloudrift's own, so a gap cannot hide by being unmodelled.
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-4">
        <div className="cr-tone-ok rounded-lg border p-3"><div className="text-2xl font-semibold tabular-nums">{r.totals.detected}</div><div className="text-xs font-medium">Detected of {r.totals.paths}</div></div>
        <div className="cr-tone-hyp rounded-lg border p-3"><div className="text-2xl font-semibold tabular-nums">{r.totals.partial}</div><div className="text-xs font-medium">Partly detected</div></div>
        <div className="cr-tone-unk rounded-lg border p-3"><div className="text-2xl font-semibold tabular-nums">{r.totals.not_detected}</div><div className="text-xs font-medium">Not detected</div></div>
        <div className="cr-tone-info rounded-lg border p-3" title="In the benchmark's negative controls: a path with one required permission removed, a wrong trust policy, or a boundary that blocks it">
          <div className="text-2xl font-semibold tabular-nums">{r.totals.false_positives}</div><div className="text-xs font-medium">False alarms in {r.totals.true_negatives} negative checks</div>
        </div>
      </div>
      <ul className="space-y-3">
        {r.categories.map((c) => (
          <li key={c.key}>
            <button type="button" className="block w-full text-left" aria-pressed={group === c.key} onClick={() => { setGroup(group === c.key ? "" : c.key); setFilter("all"); }}>
              <div className="mb-1 flex justify-between gap-3 text-sm"><span className={group === c.key ? "font-semibold" : ""}>{c.name}</span><span className="tabular-nums text-slate-600 dark:text-slate-400">{c.detected} of {c.total}</span></div>
              <Bar g={c} />
            </button>
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Which reference paths to list">
        {([["missed", `Not detected (${r.totals.not_detected + r.totals.partial})`], ["all", `All ${r.totals.paths}`]] as const).map(([k, label]) => (
          <button key={k} type="button" aria-pressed={filter === k} onClick={() => setFilter(k)} className={`rounded-full border px-3 py-1 text-xs ${filter === k ? "border-cyan-500 bg-cyan-500/15 font-medium" : "border-slate-300 dark:border-slate-700"}`}>{label}</button>
        ))}
        {group ? <button type="button" className="text-xs underline" onClick={() => setGroup("")}>Clear category</button> : null}
      </div>
      <ul className="divide-y divide-slate-200 text-sm dark:divide-slate-800">
        {shown.map((p) => (
          <li key={p.id} className="py-2">
            <a className="font-mono font-medium underline" href={p.url} target="_blank" rel="noreferrer noopener">{p.id}</a>
            <span className="ml-2 text-xs text-slate-500">{p.status === "detected" ? "Detected" : p.status === "partial" ? "Partly detected" : "Not detected"} · needs {p.required.join(", ")}</span>
            {p.reason ? <p className="text-xs text-slate-600 dark:text-slate-400">{p.reason}</p> : null}
          </li>
        ))}
        {shown.length === 0 ? <li className="py-2 text-xs text-slate-500">Nothing to list.</li> : null}
      </ul>
      <details className="text-xs text-slate-500">
        <summary className="cursor-pointer">How this is measured</summary>
        <p className="mt-1">{r.source.method}</p>
        <p className="mt-1">{r.source.excluded} Reference snapshot {r.source.snapshot_date}, commit <code>{r.source.commit.slice(0, 8)}</code>, {r.source.license}. Precision {r.totals.precision.toFixed(2)}, recall {r.totals.recall.toFixed(2)}. Replacing the snapshot and re-running the benchmark updates this section.</p>
      </details>
    </section>
  );
}
