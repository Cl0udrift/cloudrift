import { useQueries, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { apiClient } from "../../api/client";
import { formatQueryError } from "../../api/httpError";
import type { WhoCanResponse } from "../../api/types";
import { DATA_ACTIONS, describeResource, TYPE_WORD, type Link as Rel } from "../../lib/resourceBlast";
import { StatePanel } from "../StatePanel";
import { KindIcon } from "./KindIcon";
import { CallerFacts, callerLink } from "../access/CallerCard";

function Chain({ from, relation, to }: { from: Rel; relation: string; to: Rel }) {
  const box = (r: Rel) => (
    <div className="flex min-w-0 items-center gap-2 rounded-lg border border-slate-300 bg-slate-100/60 px-3 py-2 dark:border-slate-700 dark:bg-slate-800/60">
      <KindIcon kind={r.type} className="text-slate-500" />
      <div className="min-w-0">
        <div className="text-[10px] font-medium uppercase tracking-wide text-slate-500">{TYPE_WORD[r.type] ?? r.type.replace(/_/g, " ")}</div>
        <div className="break-words text-sm font-medium text-slate-900 dark:text-slate-100">{r.name}</div>
      </div>
    </div>
  );
  return (
    <li className="flex flex-col items-stretch gap-1 sm:flex-row sm:items-center">
      {box(from)}
      <span aria-hidden="true" className="flex items-center justify-center gap-1 text-slate-400 sm:px-2"><span className="hidden h-px w-4 bg-slate-300 sm:block dark:bg-slate-600" /><span className="rounded-full border border-slate-300 px-2 py-0.5 text-[11px] text-slate-600 dark:border-slate-700 dark:text-slate-300">{relation}</span><span className="hidden h-px w-4 bg-slate-300 sm:block dark:bg-slate-600" /></span>
      {box(to)}
    </li>
  );
}

const RELATION: Record<string, string> = { POINTS_TO: "points at", FRONTS: "fronts", USES_CERT: "uses certificate", TRUSTS: "trusts", LOAD_BALANCER_ROUTES_TO: "sends traffic to", USES_SECURITY_GROUP: "uses security group" };

/**
 * The blast radius of a resource (a bucket, certificate, DNS record, CloudFront distribution and so on): what happens if it
 * is hijacked, exposed or lost. It is built from the inventory detail and, for data resources, the who-can answer, so it
 * needs no graph database.
 */
export function ResourceBlast({ scanId, resourceId }: { scanId: string; resourceId: string }) {
  const detail = useQuery({ queryKey: ["blast", "resource", scanId, resourceId], queryFn: () => apiClient.inventoryResource(scanId, resourceId), enabled: Boolean(scanId && resourceId), staleTime: 60_000 });
  const type = detail.data?.resource.resource_type ?? "";
  const actions = DATA_ACTIONS[type] ?? [];
  const arn = detail.data?.resource.arn ?? resourceId;
  const whoQueries = useQueries({
    queries: actions.map(([action]) => ({ queryKey: ["blast", "who", scanId, action, arn], queryFn: () => apiClient.getWhoCan(scanId, action, arn), staleTime: 60_000, retry: false }))
  });
  const [copied, setCopied] = useState(false);
  if (detail.isLoading) return <p className="text-sm text-slate-500" role="status">Working out what happens if it is compromised…</p>;
  if (detail.isError || !detail.data) return <StatePanel intent="error" title="This resource is not in the scan">{formatQueryError(detail.error)}</StatePanel>;

  const d = detail.data;
  const who: Record<string, WhoCanResponse | undefined> = {};
  actions.forEach(([a], i) => (who[a] = whoQueries[i]?.data));
  const answer = describeResource(d, who);
  const callers = new Map<string, WhoCanResponse["callers"][number]>();
  for (const [a] of actions) for (const c of who[a]?.callers ?? []) if (!callers.has(c.arn)) callers.set(c.arn, c);
  const people = [...callers.values()].sort((a, b) => Number(Boolean(a.admin)) - Number(Boolean(b.admin)));
  const kindWord = TYPE_WORD[type] ?? d.resource.resource_type_name;
  const self: Rel = { relation: "", name: d.resource.name, type, id: d.resource.id };
  const enc = encodeURIComponent;
  const summary = [`If the ${kindWord} ${d.resource.name} is compromised or exposed`, ...answer.lines.map((l) => `- ${l}`), "", `Scan ${scanId}. Modeled from stored facts; not observed activity.`].join("\n");

  return (
    <div className="space-y-5">
      <section aria-label="Answer" className={`hs-card space-y-4 border-l-4 p-5 ${answer.takeover ? "border-l-rose-500" : people.length > 0 || d.findings.length > 0 ? "border-l-amber-500" : "border-l-slate-400"}`}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-slate-300 bg-slate-100 text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"><KindIcon kind={type} className="!h-6 !w-6" /></span>
            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-slate-500">If this is compromised or exposed</p>
              <h2 className="break-all text-xl font-semibold leading-tight text-slate-900 dark:text-slate-100">{d.resource.name}</h2>
              <p className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-slate-500"><span className="capitalize">{kindWord}</span>{d.resource.internet_facing ? <span className="cr-chip-state cr-tone-bad">Internet-facing</span> : null}{answer.takeover ? <span className="cr-chip-state cr-tone-bad">Takeover risk</span> : null}</p>
            </div>
          </div>
          <button type="button" className="hs-action-pill" onClick={() => void navigator.clipboard?.writeText(summary).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500); })}>
            {copied ? "Copied" : "Copy summary"}
          </button>
        </div>
        <dl className="grid grid-cols-3 gap-2 sm:gap-3">
          {([[people.length, "identities that can reach it"], [answer.dependsOnIt.length + answer.itDependsOn.length, "things connected to it"], [d.findings.length, "findings on it"]] as [number, string][]).map(([n, label]) => (
            <div key={label} className={`rounded-lg border px-2 py-2 sm:px-3 ${n > 0 ? "border-slate-300 bg-slate-50 dark:border-slate-700 dark:bg-slate-900/60" : "border-slate-200 opacity-60 dark:border-slate-800"}`}>
              <dd className="text-2xl font-semibold tabular-nums leading-none text-slate-900 dark:text-slate-100">{n}</dd>
              <dt className="mt-1 text-xs text-slate-500">{label}</dt>
            </div>
          ))}
        </dl>
        <ul className="space-y-2 text-sm">
          {answer.lines.map((l, i) => (
            <li key={l} className="flex items-start gap-2.5">
              <span aria-hidden="true" className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${answer.takeover && l.startsWith("Takeover") ? "bg-rose-500" : "bg-slate-400"}`} />
              <span className={answer.takeover && l.startsWith("Takeover") ? "font-semibold text-slate-900 dark:text-slate-100" : "text-slate-700 dark:text-slate-300"} data-line={i}>{l}</span>
            </li>
          ))}
        </ul>
        <p className="cr-helper">Built from what the scan collected. It is a model, not evidence that anything happened.</p>
      </section>

      {answer.dependsOnIt.length + answer.itDependsOn.length > 0 ? (
        <section aria-label="Connections" className="space-y-2">
          <h3 className="cr-section-title">What it is connected to</h3>
          <ul className="space-y-2">
            {answer.dependsOnIt.map((l) => <Chain key={`in-${l.relation}-${l.id}`} from={l} relation={RELATION[l.relation] ?? l.relation.toLowerCase().replace(/_/g, " ")} to={self} />)}
            {answer.itDependsOn.map((l) => <Chain key={`out-${l.relation}-${l.id}`} from={self} relation={RELATION[l.relation] ?? l.relation.toLowerCase().replace(/_/g, " ")} to={l} />)}
          </ul>
        </section>
      ) : null}

      {people.length > 0 ? (
        <section aria-label="Who can reach it" className="space-y-2">
          <h3 className="cr-section-title">Who can reach it ({people.length})</h3>
          <ul className="divide-y divide-slate-200 dark:divide-slate-800">
            {people.map((c) => (
              <li key={c.arn} className="space-y-1 py-2">
                <p className="text-sm"><Link className="break-all font-medium underline" to={callerLink(c)}>{c.name}</Link> <span className="text-xs text-slate-500">{c.kind}{c.admin ? " · administrator" : ""}</span></p>
                <CallerFacts caller={c} />
              </li>
            ))}
          </ul>
          <p className="cr-helper">Access limited to a prefix, and access the resource's own policy gives to accounts outside this scan, are not listed.</p>
        </section>
      ) : null}

      <section aria-label="What to do" className="space-y-2">
        <h3 className="cr-section-title">What to do</h3>
        {d.findings.length > 0 ? (
          <ul className="space-y-1 text-sm">
            {d.findings.map((f) => <li key={f.id}><Link className="underline" to={`/findings?scan_id=${enc(scanId)}&finding_id=${enc(f.id)}`}>{f.title}</Link> <span className="text-xs text-slate-500">{f.severity}</span></li>)}
          </ul>
        ) : <p className="text-sm">No finding names this resource.</p>}
        <div className="flex flex-wrap gap-2">
          <Link className="hs-action-pill" to={`/inventory?scan_id=${enc(scanId)}&resource=${enc(d.resource.arn)}`}>Open in Inventory</Link>
          {actions.length > 0 ? <Link className="hs-action-pill" to={`/access?scan_id=${enc(scanId)}&arn=${enc(d.resource.arn)}&action=${enc(actions[0][0])}`}>Who can reach it? (Access Explorer)</Link> : null}
        </div>
      </section>
    </div>
  );
}
