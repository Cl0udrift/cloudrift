import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import { queryKeys } from "../api/queryKeys";
import type { PolicySource, PrincipalListItem, PrincipalPoliciesResponse } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import { SeverityBadge } from "../components/SeverityBadge";
import { EntityDrawer } from "../components/ui/EntityDrawer";
import { StateChip, SectionHeader } from "../components/ui/StatusChip";
import { TagList } from "../components/ui/TagList";
import { useScanContext } from "../hooks/useScanContext";
import { ageLabel, categoryLabel, capitalize, LEVEL, serviceLabel, severityTone, TECHNIQUE, utcLabel } from "../lib/identityLabels";
import { encodePrincipalId } from "../lib/principalId";
import { plural, principalReasons, sortByAttention } from "../lib/principalRisk";

type Tile = "all" | "admin" | "nomfa" | "keys" | "unknown" | "inline";

const BOUNDARY: Record<string, string> = {
  confirmed_absent: "No permissions boundary limits it.",
  present: "A permissions boundary limits it.",
};
const boundaryText = (s?: string) => BOUNDARY[s ?? ""] ?? "Whether a permissions boundary limits it was not checked.";

const isAdmin = (p: PrincipalListItem) => p.broad_candidates.includes("administrative_wildcard");
const noMfa = (p: PrincipalListItem) => p.kind === "user" && p.credentials_collected && p.console_enabled && !p.mfa_active;
const matches: Record<Tile, (p: PrincipalListItem) => boolean> = {
  all: () => true,
  admin: isAdmin,
  nomfa: noMfa,
  keys: (p) => p.key_issues > 0,
  unknown: (p) => p.kind === "user" && !p.credentials_collected,
  inline: (p) => (p.inline ?? []).length > 0
};

function TogglePill({ on, onClick, children }: { on: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button type="button" aria-pressed={on} onClick={onClick} className={`hs-action-pill ${on ? "!border-cyan-500 !bg-cyan-500/10 text-cyan-900 dark:text-cyan-100" : ""}`}>
      {children}
    </button>
  );
}

const USAGE: Record<string, string> = { person: "Person (console)", programmatic: "Programmatic (keys only)", no_credentials: "No sign-in", unknown: "Sign-in unknown" };

function Source({ s }: { s: PolicySource }) {
  return (
    <li className="hs-card-soft p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{s.policy_name}</span>
        <StateChip tone="info" glyph="" label={s.policy_type === "managed" ? "Managed policy" : s.policy_type === "inline" ? "Inline policy" : s.policy_type} />
        <StateChip tone={s.via === "group" ? "hyp" : "unk"} glyph="" label={s.via === "group" ? `From group ${s.group_name}` : "Attached to the user"} />
        {s.denies > 0 ? <StateChip tone="bad" glyph="⛔" label={`${s.denies} Deny`} title="An explicit Deny overrides any Allow from another policy" /> : null}
        {s.retrieval_status !== "ok" ? <StateChip tone="warn" glyph="!" label={`Document ${s.retrieval_status}`} /> : null}
      </div>
      {s.description ? <p className="mt-1 text-xs text-slate-600 dark:text-slate-300">Written in IAM: {s.description}</p> : null}
      <ul className="mt-2 space-y-1 font-mono text-xs text-slate-600 dark:text-slate-300">
        {s.statements.map((st, i) => (
          <li key={i}>
            <span className={st.effect === "Deny" ? "font-semibold text-red-600" : "font-semibold text-emerald-700"}>{st.effect}</span> {st.not_action ? "NOT " : ""}
            {st.actions.join(", ")} on {st.resources.join(", ") || "*"}
            {st.has_condition ? " (with conditions)" : ""}
          </li>
        ))}
      </ul>
    </li>
  );
}

function Detail({ scanId, item }: { scanId: string; item: PrincipalListItem }) {
  const query = useQuery({ queryKey: queryKeys.principalPolicies(scanId, item.arn), queryFn: () => apiClient.getPrincipalPolicies(scanId, item.arn) });
  if (query.isLoading) return <StatePanel>Loading…</StatePanel>;
  if (query.isError || !query.data) return <StatePanel intent="error" title="Failed to load">{formatQueryError(query.error)}</StatePanel>;
  return <DetailBody scanId={scanId} item={item} v={query.data} />;
}

function DetailBody({ scanId, item, v }: { scanId: string; item: PrincipalListItem; v: PrincipalPoliciesResponse }) {
  const enc = encodeURIComponent;
  const caps = v.capabilities ?? [];
  const reach = v.reach ?? [];
  const canReach = v.can_reach ?? [];
  const c = v.credentials;
  const isUser = v.kind === "user";
  return (
    <article className="space-y-5 [&>section]:border-t [&>section]:border-slate-200 [&>section]:pt-5 dark:[&>section]:border-slate-800">
      <header className="space-y-3">
        <p className="flex flex-wrap gap-1.5 text-xs">
          <span className="rounded-full border border-slate-300 px-2 py-0.5 dark:border-slate-700">{isUser ? "IAM user" : "IAM group"}</span>
          {isUser && item.usage ? <span className="rounded-full border border-slate-300 px-2 py-0.5 dark:border-slate-700">{USAGE[item.usage]}</span> : null}
          {v.groups.map((g) => <span key={g} className="rounded-full border border-slate-300 px-2 py-0.5 dark:border-slate-700">Member of {g}</span>)}
        </p>
        <p className="text-sm text-slate-700 dark:text-slate-300">
          {plural(v.sources.length, "policy", "policies")} {v.sources.length === 1 ? "applies" : "apply"}. {isUser ? boundaryText(v.boundary_status) : "A group cannot have a permissions boundary; its members can."}
          {v.has_deny ? " At least one policy has an explicit Deny, which beats every Allow." : ""}
        </p>
        <div className="flex flex-wrap gap-2">
          <Link className="hs-action-pill" to={`/access?arn=${enc(item.arn)}&action=${isUser ? "iam:AttachUserPolicy" : "iam:AttachGroupPolicy"}`}>Who can change its permissions?</Link>
          {isUser ? <Link className="hs-action-pill" to={`/blast-explorer?scan=${enc(scanId)}&principal=${enc(encodePrincipalId(item.arn, "iam_user", item.account_id))}&mode=attack_path`}>Escalation paths (Blast Explorer)</Link> : null}
        </div>
        {(v.findings ?? []).length > 0 ? (
          <section aria-label="Findings">
            <p className="cr-kpi-label mb-1">Findings on this {v.kind}</p>
            <ul className="space-y-1">
              {(v.findings ?? []).map((f) => (
                <li key={f.id} className="flex flex-wrap items-center gap-2 text-sm">
                  <StateChip tone={severityTone(f.severity)} glyph="●" label={capitalize(f.severity)} />
                  <Link className="text-cyan-800 underline dark:text-cyan-200" to={`/findings?scan_id=${enc(scanId)}&finding_id=${enc(f.id)}`}>{f.title}</Link>
                </li>
              ))}
            </ul>
          </section>
        ) : <p className="cr-helper">No finding above Info is recorded on this {v.kind} itself.</p>}
      </header>

      {!isUser ? (
        <section aria-label="Members" className="space-y-2">
          <SectionHeader title={`Members (${(v.members ?? []).length})`} hint="Everyone here gets this group's permissions in addition to their own." />
          {(v.members ?? []).length === 0 ? <p className="text-sm">No user is in this group.</p> : (
            <ul className="flex flex-wrap gap-2 text-sm">{(v.members ?? []).map((m) => <li key={m} className="rounded-full border border-slate-300 px-2 py-0.5 dark:border-slate-700">{m}</li>)}</ul>
          )}
        </section>
      ) : null}

      <section aria-label="Inline policies" className="space-y-2">
        <SectionHeader title={`Inline policies (${v.sources.filter((s) => s.policy_type === "inline").length})`} hint="An inline policy belongs to one identity only. It is access written for this identity (or its group) on top of shared managed policies, so it shows what extra was given." />
        {v.sources.filter((s) => s.policy_type === "inline").length === 0 ? <p className="text-sm">None. All of its access comes from shared managed policies.</p> : (
          <ul className="space-y-2">{v.sources.filter((s) => s.policy_type === "inline").map((s) => <Source key={`${s.via}-${s.policy_arn}`} s={s} />)}</ul>
        )}
      </section>

      <section aria-label="What it can do" className="space-y-2">
        <SectionHeader title="What it can do" hint="From every policy that applies, including its groups', per service. Explicit denies are not applied." />
        {caps.length === 0 ? <p className="text-sm">No allow statement was read. {v.capability_note}</p> : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-slate-500"><th className="pb-1 pr-3 font-normal">Service</th><th className="pb-1 pr-3 font-normal">Level</th><th className="pb-1 font-normal">On</th></tr></thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {caps.filter((x) => !(x.service === "s3-object-lambda" && caps.some((o) => o.service === "s3" && o.level === x.level))).map((x) => {
                const [tone, glyph, label] = LEVEL[x.level] ?? LEVEL.read;
                return (
                  <tr key={x.service} title={(x.actions ?? []).join(", ")}>
                    <td className="py-1.5 pr-3"><span className="block font-medium">{serviceLabel(x.service)}</span><span className="block text-xs text-slate-500">{x.policies.join(", ")}</span></td>
                    <td className="py-1.5 pr-3"><StateChip tone={tone} glyph={glyph} label={label} />{x.limited_by_boundary ? <span className="mt-1 block text-xs text-slate-500">narrowed by its boundary</span> : null}</td>
                    <td className="py-1.5">{x.scope}{x.conditional ? " · conditional" : ""}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {v.capability_note && caps.length > 0 ? <p className="cr-helper">{v.capability_note}</p> : null}
      </section>

      <section aria-label="If its credentials are stolen" className="space-y-2">
        <SectionHeader title={isUser ? "If its credentials are stolen" : "What its members can reach"} hint="From the policy text, for every resource the scan collected in this account." />
        {reach.length === 0 && canReach.length === 0 ? <p className="text-sm">No resource of the kinds Cloudrift counts (S3 buckets, EC2 instances, databases, Lambda functions) is covered account-wide.</p> : null}
        <ul className="space-y-2 text-sm">
          {reach.map((r) => (
            <li key={r.service}>
              <StateChip tone={r.level === "read" ? "info" : "bad"} glyph="●" label={`${r.level === "read" ? (r.service === "s3" ? "Can read" : "Can list") : "Can change"} ${r.count} ${r.count === 1 ? r.noun.replace("databases", "database").replace(/s$/, "") : r.noun}`} />
              {(r.items ?? []).length > 0 ? (
                <p className="mt-1 break-all text-xs text-slate-600 dark:text-slate-300">
                  {(r.items ?? []).map((it, n) => <span key={it.name}>{n > 0 ? ", " : ""}{it.hint ? <strong className="font-semibold text-amber-800 dark:text-amber-300">{it.name} ({it.hint})</strong> : it.name}</span>)}
                  {r.count > (r.items ?? []).length ? `, and ${r.count - (r.items ?? []).length} more` : ""}
                </p>
              ) : null}
            </li>
          ))}
        </ul>
        {isUser ? (
          <>
            {canReach.length > 0 ? (
              <div>
                <p className="cr-kpi-label mb-1">Can move to ({canReach.length}{canReach.length === 10 ? "+" : ""})</p>
                <ul className="space-y-0.5 text-sm">
                  {canReach.map((r) => <li key={r.arn}><span className="font-medium">{r.name}</span> <span className="text-xs text-slate-500">{TECHNIQUE[r.technique] ?? r.technique.toLowerCase().replace(/_/g, " ")}</span></li>)}
                </ul>
              </div>
            ) : null}
            <p className="text-sm">
              {caps.some((x) => x.service === "all services" && x.level === "full" && x.scope === "all resources") ? "Already has full access to every service, so there is nothing further to gain." : v.escalation === "VALIDATED_POSSIBLE" ? <strong>A way to gain more access was found: see the list above or open Blast Explorer.</strong> : v.escalation === "NONE_FOUND_IN_MODELED_TECHNIQUES" ? "No way to gain more access was found among the techniques Cloudrift models." : "Escalation was not assessed."}
            </p>
          </>
        ) : null}
      </section>

      {isUser ? (
        <section aria-label="Sign-in and keys" className="space-y-2">
          <SectionHeader title="Sign-in and keys" />
          {c ? (
            <>
              <p className="flex flex-wrap items-center gap-2 text-sm">
                <StateChip tone={c.console_enabled ? "info" : "unk"} glyph="" label={c.console_enabled ? "Console sign-in" : "No console sign-in"} />
                {c.console_enabled ? <StateChip tone={c.mfa_active ? "ok" : "bad"} glyph={c.mfa_active ? "✓" : "✕"} label={c.mfa_active ? "MFA on" : "No MFA"} /> : null}
                {c.password_last_used ? <span className="text-xs text-slate-600 dark:text-slate-300">Last signed in {ageLabel(c.password_last_used)}</span> : c.console_enabled ? <span className="text-xs text-slate-600 dark:text-slate-300">Never signed in</span> : null}
              </p>
              {c.keys.length === 0 ? <p className="text-sm">No access keys.</p> : (
                <ul className="space-y-1 text-sm">
                  {c.keys.map((k) => (
                    <li key={k.slot} className="flex flex-wrap items-center gap-2">
                      <StateChip tone={k.active ? "info" : "unk"} glyph="" label={k.active ? "Active key" : "Inactive key"} />
                      <span className="text-xs text-slate-600 dark:text-slate-300">
                        {k.slot.replace(/_/g, " ")}
                        {k.age_days !== undefined ? `, created ${ageLabel(k.last_rotated)}` : ""}
                        {k.last_used ? `, last used ${ageLabel(k.last_used)}${k.last_service && k.last_service !== "N/A" ? ` (${k.last_service})` : ""}` : k.active ? ", never used" : ""}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              {c.findings.map((f) => <p key={f} className="text-xs text-red-700 dark:text-red-300">⚠ {f}</p>)}
              <p className="cr-helper">
                {c.live_checked_at
                  ? `Last-used dates were checked with IAM at ${utcLabel(c.live_checked_at)}. Use after that is not shown.`
                  : `Last-used dates are from the IAM credential report generated at ${utcLabel(c.report_generated_at)}. AWS caches it for up to four hours, so use after that time is not shown. Turn on live key last use in the settings to check IAM directly.`}
              </p>
            </>
          ) : (
            <p className="flex items-start gap-2 text-sm text-amber-800 dark:text-amber-300"><span aria-hidden="true">?</span><span>Not known. {v.credential_note ?? "The credential report did not cover this user, so console sign-in, MFA and keys were not checked."}</span></p>
          )}
        </section>
      ) : null}

      <section aria-label="Ownership" className="space-y-2">
        <SectionHeader title="Ownership" />
        <p className="text-sm">{v.owner ? <>Owner: <span className="font-medium">{v.owner}</span>.</> : <span className="text-amber-800 dark:text-amber-300">No owner tag.</span>}{v.last_activity ? ` Last activity ${ageLabel(v.last_activity)}.` : isUser && c ? " No activity recorded." : ""}</p>
        {v.tags && Object.keys(v.tags).length > 0 ? <div><span className="cr-kpi-label mr-2">Tags</span><TagList tags={v.tags} /></div> : null}
      </section>

      <details className="hs-card-soft p-3">
        <summary className="hs-focus-ring cursor-pointer text-sm font-semibold text-slate-900 dark:text-slate-100">All policies behind this ({v.sources.length})</summary>
        {!v.complete ? <p role="status" className="mt-2 text-sm text-amber-800 dark:text-amber-300">This list may be incomplete: {v.notes.join("; ")}</p> : null}
        <ul className="mt-2 space-y-2">{v.sources.map((s) => <Source key={`${s.via}-${s.policy_arn}`} s={s} />)}</ul>
      </details>
    </article>
  );
}

/** IAM users and groups: who has standing access, how they sign in and what they can do. */
export function PrincipalsPage() {
  const { selectedScanId } = useScanContext();
  const query = useQuery({ queryKey: queryKeys.principals(selectedScanId), queryFn: () => apiClient.getPrincipals(selectedScanId as string), enabled: Boolean(selectedScanId) });
  const [params, setParams] = useSearchParams();
  const selected = params.get("principal");
  const patch = (key: string, value: string) =>
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value) next.set(key, value);
      else next.delete(key);
      return next;
    });
  const [needle, setNeedle] = useState("");
  const tile = (params.get("tile") as Tile) || "all";
  const kind = params.get("kind") ?? "";
  const withFindings = params.get("findings") === "true";
  const all = query.data?.items ?? [];
  const users = all.filter((p) => p.kind === "user");
  const counts: Record<Tile, number> = { all: all.length, admin: users.filter(matches.admin).length, nomfa: users.filter(matches.nomfa).length, keys: users.filter(matches.keys).length, unknown: users.filter(matches.unknown).length, inline: all.filter(matches.inline).length };
  const items = useMemo(() => {
    const n = needle.trim().toLowerCase();
    return sortByAttention(all).filter((i) => matches[tile](i) && (!kind || i.kind === kind) && (!withFindings || i.finding_count > 0) && (!n || `${i.name} ${i.account_id} ${i.groups.join(" ")} ${i.owner ?? ""}`.toLowerCase().includes(n)));
  }, [all, needle, tile, kind, withFindings]);
  const current = all.find((i) => i.arn === selected) ?? null;
  const defs: [Tile, string, string][] = [
    ["all", "Users and groups", `${plural(users.length, "user")} and ${plural(all.length - users.length, "group")}`],
    ["admin", "Administrators", "Administrator access, directly or through a group"],
    ["nomfa", "Console without MFA", "Can sign in with a password alone"],
    ["keys", "Old or unused keys", "An active key older than 90 days, never used or unused for 90 days"],
    ["unknown", "Credentials unknown", "Not in the credential report, so sign-in, MFA and keys are unchecked"],
    ["inline", "Has inline policy", "Access written for this identity alone, on top of shared policies"]
  ];
  return (
    <section className="space-y-4">
      <PageHeader
        title="Users & Groups"
        description="Who has standing access to this account, how they sign in, and what they can do."
        details="A user's access is the union of its own policies and its groups' policies, minus anything an explicit Deny blocks, and capped by a permissions boundary. Console, MFA and key data come from the IAM credential report, which AWS caches for up to four hours."
      />
      {!selectedScanId ? (
        <StatePanel>Select a scan first.</StatePanel>
      ) : query.isLoading ? (
        <StatePanel>Loading users and groups…</StatePanel>
      ) : query.isError ? (
        <StatePanel intent="error" title="Failed to load users and groups">{formatQueryError(query.error)}</StatePanel>
      ) : all.length === 0 ? (
        <StatePanel>No users or groups in this scan. {query.data?.note}</StatePanel>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
            {defs.map(([key, label, hint]) => (
              <button key={key} type="button" aria-pressed={tile === key} onClick={() => patch("tile", key === "all" ? "" : tile === key ? "" : key)} className={`hs-card hs-interactive-card flex h-full flex-col gap-1 p-4 text-left ${tile === key ? "border-cyan-500 ring-1 ring-cyan-500" : ""}`}>
                <p className="cr-kpi-label">{label}</p>
                <p className="cr-kpi-value">{counts[key]}</p>
                <p className="cr-helper">{hint}</p>
              </button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filters">
            <input className="hs-input !w-auto min-w-[16rem] flex-1" type="search" placeholder="Search name, group or owner" aria-label="Search users and groups" value={needle} onChange={(e) => setNeedle(e.target.value)} />
            <TogglePill on={kind === "user"} onClick={() => patch("kind", kind === "user" ? "" : "user")}>Users</TogglePill>
            <TogglePill on={kind === "group"} onClick={() => patch("kind", kind === "group" ? "" : "group")}>Groups</TogglePill>
            <TogglePill on={withFindings} onClick={() => patch("findings", withFindings ? "" : "true")}>Has findings</TogglePill>
          </div>
          {items.length === 0 ? <StatePanel intent="empty" title="Nothing matches">Clear the search or a filter.</StatePanel> : (
            <div className="hs-card max-h-[70vh] overflow-auto !p-0">
              <table className="w-full text-left text-sm">
                <thead className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                  <tr>
                    {["Name", "Findings", "Sign-in", "Access", "Inline policy", "Last activity", "Owner"].map((h, i) => (
                      <th key={h} scope="col" className={`sticky top-0 z-10 bg-slate-50 px-3 py-2.5 dark:bg-slate-900 ${i >= 5 ? "hidden lg:table-cell" : i >= 2 ? "hidden sm:table-cell" : ""}`}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {items.map((i) => (
                    <tr key={i.arn} onClick={() => patch("principal", i.arn)} className={`hs-interactive-row border-t border-slate-200 dark:border-slate-800 ${i.arn === selected ? "bg-cyan-500/10" : ""}`}>
                      <td className="max-w-[16rem] px-3 py-2.5">
                        <button type="button" title={i.arn} aria-current={i.arn === selected} className="hs-focus-ring block max-w-full truncate text-left font-medium text-slate-900 hover:underline dark:text-slate-100" onClick={(e) => { e.stopPropagation(); patch("principal", i.arn); }}>{i.name}</button>
                        <span className="block truncate text-xs text-slate-500">
                          {i.kind === "group" ? `Group · ${plural(i.members ?? 0, "member")}` : `${i.usage ? USAGE[i.usage] : "User"}${i.groups.length ? ` · ${i.groups.join(", ")}` : ""}`}
                        </span>
                      </td>
                      <td className="px-3 py-2.5">
                        {i.finding_count > 0 ? (
                          <span className="inline-flex items-center gap-1.5"><SeverityBadge severity={i.max_severity ?? "info"} /><span className="text-xs tabular-nums text-slate-600 dark:text-slate-400">{i.finding_count}</span></span>
                        ) : <span className="text-xs text-slate-500" title="No finding above Info names this identity. That does not mean it was assessed as safe.">none</span>}
                      </td>
                      <td className="hidden px-3 py-2.5 sm:table-cell">
                        {i.kind === "group" ? <span className="text-slate-400">—</span> : !i.credentials_collected ? (
                          <span className="cr-chip-state cr-tone-unk" title="Not in the credential report, so sign-in, MFA and keys were not checked">Unknown</span>
                        ) : (
                          <span className="flex flex-wrap gap-1">
                            {i.console_enabled ? <span className={`cr-chip-state ${i.mfa_active ? "cr-tone-ok" : "cr-tone-bad"}`}>{i.mfa_active ? "Console · MFA" : "Console · no MFA"}</span> : null}
                            {i.active_keys > 0 ? <span className={`cr-chip-state ${i.key_issues > 0 ? "cr-tone-warn" : "cr-tone-info"}`}>{plural(i.active_keys, "key")}{i.key_issues > 0 ? ` · ${i.key_issues} issue${i.key_issues === 1 ? "" : "s"}` : ""}</span> : null}
                            {!i.console_enabled && i.active_keys === 0 ? <span className="text-slate-400">none</span> : null}
                          </span>
                        )}
                      </td>
                      <td className="hidden px-3 py-2.5 sm:table-cell">
                        {isAdmin(i) ? <span className="cr-chip-state cr-tone-bad">Administrator</span>
                          : i.broad_candidates.length > 0 ? <span className="cr-chip-state cr-tone-warn" title="Declared in a policy document. Not evaluated access.">{categoryLabel(i.broad_candidates[0])}{i.broad_candidates.length > 1 ? ` +${i.broad_candidates.length - 1}` : ""}</span>
                          : <span className="text-xs text-slate-500">{plural(i.policy_count, "policy", "policies")}</span>}
                      </td>
                      <td className="hidden max-w-[14rem] px-3 py-2.5 sm:table-cell">
                        {(i.inline ?? []).length > 0 ? <span className="cr-chip-state cr-tone-warn" title={(i.inline ?? []).join("\n")}>{(i.inline ?? []).length === 1 ? (i.inline ?? [])[0] : `${(i.inline ?? []).length} inline`}</span> : <span className="text-slate-400">—</span>}
                      </td>
                      <td className="hidden whitespace-nowrap px-3 py-2.5 text-xs lg:table-cell" title={i.activity_as_of ? `${i.activity_live ? "Checked with IAM" : "From the credential report generated"} at ${utcLabel(i.activity_as_of)}${i.activity_live ? "" : ". Use after that time is not shown."}` : undefined}>{i.kind === "group" ? "—" : i.last_activity ? <>{ageLabel(i.last_activity)}{i.activity_live ? "" : <span className="text-slate-400"> *</span>}</> : i.credentials_collected ? "no activity" : "unknown"}</td>
                      <td className="hidden px-3 py-2.5 lg:table-cell">{i.owner || <span className="text-slate-400">—</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="cr-helper">Showing {items.length} of {all.length}. An asterisk on a last-activity date means it comes from the credential report, which can be up to four hours behind. {query.data?.note}</p>
          {current ? (
            <EntityDrawer title={current.name} onClose={() => patch("principal", "")}>
              <Detail scanId={selectedScanId} item={current} />
            </EntityDrawer>
          ) : null}
        </>
      )}
    </section>
  );
}
