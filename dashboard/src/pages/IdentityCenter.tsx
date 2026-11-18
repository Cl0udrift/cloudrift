import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import { queryKeys } from "../api/queryKeys";
import type { IdentityCenterPermissionSet, IdentityCenterPrincipal, IdentityCenterResponse } from "../api/types";
import { CountTile } from "../components/access/CallerCard";
import { PageHeader } from "../components/PageHeader";
import { ScanRequired } from "../components/ScanRequired";
import { StatePanel } from "../components/StatePanel";
import { StateChip } from "../components/ui/StatusChip";
import { useScanContext } from "../hooks/useScanContext";
import { plural } from "../lib/inventoryView";

type Tab = "people" | "sets" | "accounts";

/** Who reaches which account through IAM Identity Center, and with which permission sets. */
export function IdentityCenterPage() {
  const { selectedScanId } = useScanContext();
  const q = useQuery({
    queryKey: queryKeys.identityCenter(selectedScanId),
    queryFn: () => apiClient.getIdentityCenter(selectedScanId as string),
    enabled: Boolean(selectedScanId),
    staleTime: 60_000
  });
  const data = q.data;
  return (
    <section className="space-y-4">
      <PageHeader title="IAM Identity Center" description="Who can sign in to which account through single sign-on, and with which permission sets." />
      {!selectedScanId ? <ScanRequired /> : null}
      {q.isLoading ? <StatePanel>Loading Identity Center…</StatePanel> : null}
      {q.isError ? <StatePanel intent="error" title="Failed to load Identity Center"><pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(q.error)}</pre></StatePanel> : null}
      {data ? <Body data={data} /> : null}
    </section>
  );
}

function Body({ data }: { data: IdentityCenterResponse }) {
  if (data.state === "not_collected") {
    return (
      <StatePanel title="Identity Center was not collected in this scan">
        <p className="text-sm">{data.detail}</p>
        <p className="mt-2 text-sm"><Link className="underline" to={`/settings#cfg-${data.config_key ?? "scan.identity_center"}`}>Turn on “IAM Identity Center” in Settings</Link>, then scan again. It needs the organization management account (or the delegated administrator) and read access to sso and identitystore.</p>
      </StatePanel>
    );
  }
  if (data.state === "failed") {
    return <StatePanel intent="error" title="Identity Center could not be read"><p className="text-sm">{data.detail}</p></StatePanel>;
  }
  if (data.state === "no_instance") {
    return (
      <StatePanel title="No Identity Center instance was found">
        <p className="text-sm">{data.detail}</p>
        <p className="mt-2 text-xs text-slate-500">This does not show that nobody can sign in with single sign-on: the credential Cloudrift used may not be the account that owns the instance.</p>
      </StatePanel>
    );
  }
  return <Collected data={data} />;
}

function Collected({ data }: { data: IdentityCenterResponse }) {
  const [tab, setTab] = useState<Tab>("people");
  const [search, setSearch] = useState("");
  const users = data.principals.filter((p) => p.kind === "user");
  const groups = data.principals.filter((p) => p.kind === "group");
  const adminSets = data.permission_sets.filter((s) => s.administrative);
  const adminPeople = users.filter((p) => p.administrative_in.length > 0);
  const needle = search.trim().toLowerCase();
  const people = useMemo(
    () => data.principals.filter((p) => !needle || p.name.toLowerCase().includes(needle) || (p.display_name ?? "").toLowerCase().includes(needle) || p.assignments.some((a) => a.account_id.includes(needle) || a.permission_set.toLowerCase().includes(needle))),
    [data.principals, needle]
  );
  return (
    <>
      {data.state === "partial" ? <StatePanel title="Partly read"><p className="text-sm">{data.detail}</p></StatePanel> : null}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <CountTile label="Permission sets" value={data.permission_sets.length} tone="info" hint="Each set becomes a role in every account it is assigned to." />
        <CountTile label="Administrative sets" value={adminSets.length} tone={adminSets.length > 0 ? "hyp" : "info"} hint="Sets that allow every action on every resource." />
        <CountTile label="Users" value={users.length} tone="info" hint="Users with an assignment or in an assigned group." />
        <CountTile label="Users with admin access" value={adminPeople.length} tone={adminPeople.length > 0 ? "hyp" : "info"} hint="Directly or through a group." />
        <CountTile label="Accounts reached" value={data.accounts.length} tone="info" hint="Accounts with at least one assignment." />
      </div>
      <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="View">
        {([["people", `People and groups (${data.principals.length})`], ["sets", `Permission sets (${data.permission_sets.length})`], ["accounts", `Accounts (${data.accounts.length})`]] as [Tab, string][]).map(([id, label]) => (
          <button key={id} type="button" role="radio" aria-checked={tab === id} onClick={() => setTab(id)}
            className={`hs-focus-ring rounded-full border px-3 py-1 text-sm ${tab === id ? "border-cyan-500 bg-cyan-500/10 font-medium" : "border-slate-300 dark:border-slate-700"}`}>{label}</button>
        ))}
        {tab === "people" ? <input className="hs-input !w-auto min-w-[14rem] flex-1" placeholder="Search a person, group, account or permission set" value={search} aria-label="Search" onChange={(e) => setSearch(e.target.value)} /> : null}
      </div>
      {tab === "people" ? <PeopleList people={people} groupCount={groups.length} /> : null}
      {tab === "sets" ? <SetsList sets={data.permission_sets} /> : null}
      {tab === "accounts" ? <AccountsList data={data} /> : null}
      <div className="hs-card p-4 text-xs text-slate-600 dark:text-slate-400">
        {data.notes.map((n) => <p key={n} className="mt-1 first:mt-0">{n}</p>)}
      </div>
    </>
  );
}

function PeopleList({ people, groupCount }: { people: IdentityCenterPrincipal[]; groupCount: number }) {
  if (people.length === 0) return <StatePanel>Nothing matches.</StatePanel>;
  return (
    <ul className="space-y-2">
      {people.map((p) => (
        <li key={p.arn} className="hs-card p-4">
          <details>
            <summary className="hs-focus-ring flex cursor-pointer flex-wrap items-center justify-between gap-2 rounded">
              <span className="min-w-0">
                <span className="text-xs uppercase text-slate-500">{p.kind}</span>{" "}
                <span className="break-all font-semibold">{p.name}</span>
                {p.display_name && p.display_name !== p.name ? <span className="ml-2 text-xs text-slate-500">{p.display_name}</span> : null}
                {!p.name_read && p.kind === "user" ? <span className="ml-2 text-xs text-slate-500">(name not read: shown by id)</span> : null}
              </span>
              <span className="flex flex-wrap items-center gap-2 text-xs">
                {p.kind === "group" ? <span className="text-slate-500">{plural(p.members, "member")}</span> : null}
                <span className="text-slate-500">{plural(new Set(p.assignments.map((a) => a.account_id)).size, "account")}</span>
                {p.administrative_in.length > 0 ? <StateChip tone="hyp" glyph="◐" label={`Administrator in ${p.administrative_in.length}`} title={p.administrative_in.join(", ")} /> : null}
              </span>
            </summary>
            {p.groups.length > 0 ? <p className="mt-2 text-xs text-slate-500">Member of: {p.groups.join(", ")}</p> : null}
            {p.assignments.length === 0 ? <p className="mt-2 text-sm text-slate-500">No assignment found.</p> : (
              <table className="mt-3 w-full text-sm">
                <thead><tr className="text-left text-xs uppercase text-slate-500"><th className="py-1 pr-2">Account</th><th className="py-1 pr-2">Permission set</th><th className="py-1">Through</th></tr></thead>
                <tbody>
                  {p.assignments.map((a) => (
                    <tr key={`${a.account_id}-${a.permission_set_arn}-${a.via}`} className="border-t border-slate-200 dark:border-slate-800">
                      <td className="py-1 pr-2 font-mono text-xs">{a.account_id}</td>
                      <td className="py-1 pr-2">{a.permission_set}{a.administrative ? <span className="ml-2 text-xs font-medium">administrator</span> : null}</td>
                      <td className="py-1 text-xs text-slate-500">{a.via}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </details>
        </li>
      ))}
      {groupCount === 0 ? <li className="text-xs text-slate-500">No groups hold an assignment.</li> : null}
    </ul>
  );
}

function SetsList({ sets }: { sets: IdentityCenterPermissionSet[] }) {
  if (sets.length === 0) return <StatePanel>No permission sets were found.</StatePanel>;
  return (
    <ul className="space-y-2">
      {sets.map((s) => (
        <li key={s.arn} className="hs-card space-y-2 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-semibold">{s.name}</span>
            <span className="flex flex-wrap items-center gap-2 text-xs">
              <span className="text-slate-500">{plural(s.accounts.length, "account")} · {plural(s.assignments, "assignment")} · session {s.session_duration || "default"}</span>
              {s.administrative ? <StateChip tone="hyp" glyph="◐" label="Administrative" title={s.admin_reason} /> : null}
            </span>
          </div>
          {s.description ? <p className="text-sm text-slate-600 dark:text-slate-400">{s.description}</p> : null}
          {s.admin_reason ? <p className="text-xs">{s.admin_reason}.</p> : null}
          <p className="text-xs text-slate-500">
            Policies: {[...s.managed_policies.map((m) => m.name), ...s.customer_managed_policies.map((m) => `${m.name} (customer managed, not read)`), ...(s.has_inline_policy ? ["inline policy"] : [])].join(", ") || "none"}
          </p>
          {s.roles.length > 0 ? (
            <p className="text-xs text-slate-500">Becomes the role {s.roles.length === 1 ? "" : "(one per account) "}
              {s.roles.map((r, i) => <span key={r}>{i > 0 ? ", " : ""}<Link className="underline" to={`/identities?role=${encodeURIComponent(r)}`}>{r.split("/").pop()}</Link></span>)}
            </p>
          ) : null}
          {s.read_status !== "ok" ? <p className="text-xs text-slate-500">Partly read: {s.read_error}</p> : null}
        </li>
      ))}
    </ul>
  );
}

function AccountsList({ data }: { data: IdentityCenterResponse }) {
  if (data.accounts.length === 0) return <StatePanel>No account has an assignment.</StatePanel>;
  return (
    <div className="hs-card overflow-x-auto p-4">
      <table className="w-full text-sm">
        <thead><tr className="text-left text-xs uppercase text-slate-500"><th className="py-1 pr-2">Account</th><th className="py-1 pr-2">Permission sets</th><th className="py-1 pr-2">Users and groups</th><th className="py-1">With administrator</th></tr></thead>
        <tbody>
          {data.accounts.map((a) => (
            <tr key={a.account_id} className="border-t border-slate-200 dark:border-slate-800">
              <td className="py-1 pr-2 font-mono text-xs">{a.account_id}</td>
              <td className="py-1 pr-2 tabular-nums">{a.permission_sets}</td>
              <td className="py-1 pr-2 tabular-nums">{a.principals}</td>
              <td className="py-1 tabular-nums">{a.administrative_principals}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
