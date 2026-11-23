import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { apiClient } from "../../api/client";
import type { BlastExplorerResponse, RoleCapability } from "../../api/types";
import { furtherSteps, headline, routesOf } from "../../lib/blastAnswer";
import { KindIcon } from "./KindIcon";
import { StateChip } from "../ui/StatusChip";

const nameOf = (arn: string) => arn.slice(arn.lastIndexOf("/") + 1) || arn;

/** What the identity is, from the pages that already know it: its policies, what it can reach and who it is. */
function useIdentity(scanId: string, arn: string) {
  const isUser = arn.includes(":user/");
  const isRole = arn.includes(":role/");
  const user = useQuery({ queryKey: ["blast", "user", scanId, arn], queryFn: () => apiClient.getPrincipalPolicies(scanId, arn), enabled: Boolean(scanId && isUser), staleTime: 60_000 });
  const role = useQuery({ queryKey: ["blast", "role", scanId, arn], queryFn: () => apiClient.getIdentityProfile(scanId, arn, false), enabled: Boolean(scanId && isRole), staleTime: 60_000 });
  const caps: RoleCapability[] = (isUser ? user.data?.capabilities : role.data?.capabilities) ?? [];
  const reach = (isUser ? user.data?.reach : role.data?.reach) ?? [];
  const sources = user.data?.sources ?? [];
  return { isUser, isRole, caps, reach, sources };
}

/**
 * The answer first: what can happen if this identity's credentials are stolen, in plain statements, then the routes as
 * boxes, then what gives it that access and what to change. Everything here comes from the stored scan; nothing needs a
 * graph database.
 */
export function BlastAnswer({ scanId, payload }: { scanId: string; payload: BlastExplorerResponse }) {
  const report = payload.summary.identity_attack;
  const arn = payload.summary.source_principal_arn || report?.initial_principal || payload.summary.permission_blast?.role_arn || "";
  const name = nameOf(arn);
  const { isUser, isRole, caps, reach, sources } = useIdentity(scanId, arn);
  const [showAll, setShowAll] = useState(false);
  const [copied, setCopied] = useState(false);
  const admin = caps.find((c) => c.service === "all services" && c.level === "full" && c.scope === "all resources");
  const isAdmin = Boolean(admin);
  const routes = report ? routesOf(report) : [];
  const head = report ? headline(report, isAdmin) : null;
  const shown = showAll ? routes : routes.slice(0, 6);
  const adminSource = admin ? sources.find((s) => admin.policies.includes(s.policy_name)) : undefined;
  const via = adminSource?.via === "group" ? ` through the group ${adminSource.group_name}` : "";
  const iamCaps = caps.filter((c) => c.service === "iam" && c.level !== "read");
  const enc = encodeURIComponent;
  const fix = isAdmin
    ? `Its administrator access comes from ${admin!.policies.join(", ")}${via}. Replacing it with only the permissions this ${isUser ? "user" : "role"} needs would close ${routes.length === 1 ? "this route" : `these ${routes.length} routes`}.`
    : iamCaps.length > 0 && routes.length > 0
      ? `It can change IAM through ${iamCaps.flatMap((c) => c.policies).filter((v, i, a) => a.indexOf(v) === i).join(", ")}. Narrowing those permissions closes these routes.`
      : "";

  const summary = () =>
    [
      `If ${name} is compromised`,
      ...(head?.lines.map((l) => `- ${l}`) ?? []),
      ...(head?.sample ? ["(The search stopped early, so this is a sample.)"] : []),
      ...(routes.length ? ["", "Routes:", ...routes.map((r) => `- ${name} can ${r.verb} ${r.target}`)] : []),
      ...(reach.length ? ["", "Can reach:", ...reach.map((r) => `- ${r.level === "read" ? "list/read" : "change"} ${r.count} ${r.noun}${(r.items ?? []).length ? ` (${(r.items ?? []).map((i) => i.name).join(", ")})` : ""}`)] : []),
      ...(fix ? ["", `Suggested change: ${fix}`] : []),
      "",
      `Scan ${scanId}. Modeled from stored policies; not observed activity.`
    ].join("\n");

  if (!report && !payload.summary.permission_blast) return null;
  const kindOfArn = isUser ? "user" : isRole ? "role" : "box";
  const count = (...kinds: string[]) => routes.filter((r) => kinds.includes(r.kind) || kinds.some((k) => k.endsWith("*") && r.kind.startsWith(k.slice(0, -1)))).length;
  const stats: [number, string][] = [
    [count("USER_TAKEOVER", "TRUST_REWRITE", "ASSUME_ROLE", "PASS_ROLE*"), "identities it can become"],
    [count("SELF_POLICY_GRANT", "GRANT_ON_REACHABLE_ROLE", "SELF_GROUP_JOIN"), "policies it can change"],
    [reach.filter((r) => r.level !== "read").reduce((n, r) => n + r.count, 0), "resources it can change"]
  ];
  const accent = !report ? "border-l-slate-400" : isAdmin || routes.some((r) => r.kind === "SELF_POLICY_GRANT") ? "border-l-rose-500" : routes.length > 0 ? "border-l-amber-500" : "border-l-slate-400";
  const grouped = new Map<string, typeof routes>();
  for (const r of routes) grouped.set(r.verb, [...(grouped.get(r.verb) ?? []), r]);
  const cap = (v: string) => v.charAt(0).toUpperCase() + v.slice(1);
  return (
    <div className="space-y-6">
      {report ? (
        <section aria-label="Answer" className={`hs-card space-y-4 border-l-4 p-5 ${accent}`}>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-slate-300 bg-slate-100 text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"><KindIcon kind={kindOfArn} className="!h-6 !w-6" /></span>
              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-slate-500">If this is compromised</p>
                <h2 className="text-xl font-semibold leading-tight text-slate-900 dark:text-slate-100">{name}</h2>
                <p className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-slate-500">
                  <span>{isUser ? "IAM user" : isRole ? "IAM role" : "Identity"}</span>
                  {isAdmin ? <span className="cr-chip-state cr-tone-bad">Administrator</span> : null}
                </p>
              </div>
            </div>
            <button
              type="button"
              className="hs-action-pill"
              onClick={() => void navigator.clipboard?.writeText(summary()).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500); })}
            >
              {copied ? "Copied" : "Copy summary"}
            </button>
          </div>
          {stats.some(([n]) => n > 0) ? (
            <dl className="grid grid-cols-3 gap-2 sm:gap-3">
              {stats.map(([n, label]) => (
                <div key={label} className={`rounded-lg border px-2 py-2 sm:px-3 ${n > 0 ? "border-slate-300 bg-slate-50 dark:border-slate-700 dark:bg-slate-900/60" : "border-slate-200 opacity-60 dark:border-slate-800"}`}>
                  <dd className="text-2xl font-semibold tabular-nums leading-none text-slate-900 dark:text-slate-100">{n}</dd>
                  <dt className="mt-1 text-xs text-slate-500">{label}</dt>
                </div>
              ))}
            </dl>
          ) : null}
          <ul className="space-y-2 text-sm">
            {(head?.lines ?? []).map((l, i) => (
              <li key={l} className="flex items-start gap-2.5">
                <span aria-hidden="true" className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${i === 0 && isAdmin ? "bg-rose-500" : "bg-slate-400"}`} />
                <span className={i === 0 && isAdmin ? "font-semibold text-slate-900 dark:text-slate-100" : "text-slate-700 dark:text-slate-300"}>{l}</span>
              </li>
            ))}
          </ul>
          {head?.sample ? <p className="cr-helper">{isAdmin ? "The search stops early for an administrator because there is too much to list. The routes below are a sample." : "The search stopped early, so this is not the full list."}</p> : null}
          <p className="cr-helper">Modeled from stored policies with this identity's credentials. It is not evidence that anything happened.</p>
        </section>
      ) : null}

      {routes.length > 0 ? (
        <section aria-label="How it gets there" className="space-y-3">
          <h3 className="cr-section-title">How it gets there</h3>
          <div className="hs-card flex flex-col gap-4 p-4 sm:flex-row">
            <div className="flex shrink-0 items-start">
              <div className="flex items-center gap-2 rounded-lg border border-cyan-500/50 bg-cyan-500/10 px-3 py-2">
                <KindIcon kind={kindOfArn} />
                <div>
                  <div className="text-[10px] font-medium uppercase tracking-wide text-slate-500">Starts as</div>
                  <div className="text-sm font-medium text-slate-900 dark:text-slate-100">{name}</div>
                </div>
              </div>
            </div>
            <ul className="min-w-0 flex-1 space-y-4 border-slate-300 sm:border-l sm:pl-5 dark:border-slate-700">
              {[...grouped.entries()].slice(0, showAll ? undefined : 4).map(([verb, list]) => (
                <li key={verb}>
                  <p className="mb-1.5 flex items-center gap-1.5 text-sm font-medium text-slate-800 dark:text-slate-200"><KindIcon kind="action" className="!h-4 !w-4 text-amber-600 dark:text-amber-400" />{cap(verb)}</p>
                  <ul className="flex flex-wrap gap-2">
                    {list.map((r) => (
                      <li key={r.targetArn} title={r.explanation} className="flex items-center gap-2 rounded-lg border border-slate-300 bg-slate-100/60 px-3 py-1.5 text-sm font-medium text-slate-900 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-100">
                        <KindIcon kind={r.targetArn.includes(":user/") ? "user" : r.targetArn.includes(":group/") ? "group" : r.targetArn.includes(":role/") ? "role" : "box"} className="text-slate-500" />
                        {r.target}
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
              {grouped.size > 4 ? <li><button type="button" className="text-xs font-medium text-cyan-800 underline dark:text-cyan-300" onClick={() => setShowAll((v) => !v)}>{showAll ? "Show fewer" : `Show all ${grouped.size} kinds`}</button></li> : null}
            </ul>
          </div>
          {report && furtherSteps(report) > 0 ? <p className="cr-helper">Once it has taken over other identities it can go {furtherSteps(report)} steps further. They are listed under Technical details.</p> : null}
        </section>
      ) : null}

      {reach.length > 0 ? (
        <section aria-label="What it can reach" className="space-y-3">
          <h3 className="cr-section-title">What it can reach</h3>
          <ul className="grid gap-3 sm:grid-cols-2">
            {reach.map((r) => (
              <li key={r.service} className="hs-card flex items-start gap-3 p-3">
                <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border ${r.level === "read" ? "border-sky-400/60 text-sky-700 dark:text-sky-300" : "border-rose-400/60 text-rose-700 dark:text-rose-300"}`}><KindIcon kind={r.service === "s3" ? "bucket" : r.service === "rds" ? "database" : "compute"} /></span>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{r.level === "read" ? (r.service === "s3" ? "Can read" : "Can list") : "Can change"} {r.count} {r.count === 1 ? r.noun.replace("databases", "database").replace(/s$/, "") : r.noun}</p>
                  {(r.items ?? []).length > 0 ? <p className="mt-0.5 break-all text-xs text-slate-600 dark:text-slate-300">{(r.items ?? []).map((i) => i.name).join(", ")}</p> : null}
                </div>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section aria-label="What to change" className="space-y-3">
        <h3 className="cr-section-title">What to change</h3>
        <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/5 p-4">
          <p className="text-sm text-slate-800 dark:text-slate-200">{fix || (routes.length === 0 ? "Nothing to change was found among the modeled routes." : "Review the permissions that let it change IAM or assume other roles.")}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {arn ? <Link className="hs-action-pill" to={`/access?scan_id=${enc(scanId)}&arn=${enc(arn)}&action=${isRole ? "sts:AssumeRole" : "iam:CreateAccessKey"}`}>Who can reach {name}?</Link> : null}
          {isUser ? <Link className="hs-action-pill" to={`/principals?scan_id=${enc(scanId)}&principal=${enc(arn)}`}>Open {name}</Link> : null}
          {isRole ? <Link className="hs-action-pill" to={`/identities?scan_id=${enc(scanId)}&aws=show&role=${enc(arn)}`}>Open {name}</Link> : null}
        </div>
      </section>
    </div>
  );
}
