import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import { queryKeys } from "../api/queryKeys";
import type { PolicySource, PrincipalListItem } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import { StateChip } from "../components/ui/StatusChip";
import { useScanContext } from "../hooks/useScanContext";

function Source({ s }: { s: PolicySource }) {
  return (
    <li className="rounded border border-slate-200 p-3 text-sm dark:border-slate-700">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{s.policy_name}</span>
        <StateChip tone="info" glyph="" label={s.policy_type} />
        <StateChip tone={s.via === "group" ? "hyp" : "unk"} glyph="" label={s.via === "group" ? `via group ${s.group_name}` : "attached directly"} />
        {s.denies > 0 ? <StateChip tone="bad" glyph="⛔" label={`${s.denies} Deny`} title="An explicit Deny overrides any Allow from another policy" /> : null}
        {s.allows > 0 ? <StateChip tone="ok" glyph="✓" label={`${s.allows} Allow`} /> : null}
        {s.retrieval_status !== "ok" ? <StateChip tone="warn" glyph="!" label={`document ${s.retrieval_status}`} /> : null}
      </div>
      <ul className="mt-2 space-y-1 font-mono text-xs text-slate-600 dark:text-slate-300">
        {s.statements.map((st, i) => (
          <li key={i}>
            <span className={st.effect === "Deny" ? "font-semibold text-red-600" : "font-semibold text-emerald-700"}>{st.effect}</span>{" "}
            {st.not_action ? "NOT " : ""}
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
  if (query.isLoading) return <StatePanel>Loading policies…</StatePanel>;
  if (query.isError || !query.data) return <StatePanel intent="error" title="Failed to load policies">{formatQueryError(query.error)}</StatePanel>;
  const v = query.data;
  return (
    <div className="space-y-3">
      <p className="text-sm">
        <span className="font-semibold">{v.sources.length}</span> policies apply to {v.kind} <span className="font-mono">{v.name}</span>
        {v.groups.length ? <> (member of {v.groups.join(", ")})</> : null}. Permissions boundary: {v.boundary_status ?? "unknown"}.
      </p>
      {v.credentials ? (
        <div className="rounded border border-slate-200 p-3 text-sm dark:border-slate-700">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold">Credentials</span>
            <StateChip tone={v.credentials.console_enabled ? "info" : "unk"} glyph="" label={v.credentials.console_enabled ? "Console access" : "No console access"} />
            <StateChip tone={v.credentials.mfa_active ? "ok" : v.credentials.console_enabled ? "bad" : "unk"} glyph="" label={v.credentials.mfa_active ? "MFA on" : "No MFA"} />
          </div>
          {v.credentials.keys.length === 0 ? <p className="mt-1 text-xs text-slate-500">No access keys.</p> : (
            <ul className="mt-2 space-y-1 text-xs">
              {v.credentials.keys.map((k) => (
                <li key={k.slot}>
                  {k.slot.replace(/_/g, " ")}: {k.active ? "active" : "inactive"}
                  {k.age_days !== undefined ? `, rotated ${k.age_days} days ago` : ""}
                  {k.last_used ? `, last used ${k.last_used.slice(0, 10)}${k.last_service ? ` (${k.last_service})` : ""}` : k.active ? ", never used" : ""}
                </li>
              ))}
            </ul>
          )}
          {v.credentials.findings.map((f) => <p key={f} className="mt-1 text-xs text-red-700 dark:text-red-300">⚠ {f}</p>)}
        </div>
      ) : v.kind === "user" ? <p className="cr-helper">Console, MFA and access key data was not collected for this user.</p> : null}
      {v.has_deny ? <p className="text-sm text-red-700 dark:text-red-300">At least one policy has an explicit Deny. It wins over Allow statements in every other policy listed here.</p> : null}
      {!v.complete ? (
        <div role="status" className="rounded border border-amber-300 bg-amber-50 p-2 text-sm text-amber-950 dark:border-amber-800/60 dark:bg-amber-950/30 dark:text-amber-100">
          This list may be incomplete: {v.notes.join("; ")}
        </div>
      ) : null}
      <ul className="space-y-2">{v.sources.map((s) => <Source key={`${s.via}-${s.policy_arn}`} s={s} />)}</ul>
    </div>
  );
}

/** IAM users and groups, and exactly which policies apply to each and why. */
export function PrincipalsPage() {
  const { selectedScanId } = useScanContext();
  const query = useQuery({ queryKey: queryKeys.principals(selectedScanId), queryFn: () => apiClient.getPrincipals(selectedScanId as string), enabled: Boolean(selectedScanId) });
  const [selected, setSelected] = useState<string | null>(null);
  const items = query.data?.items ?? [];
  const current = items.find((i) => i.arn === selected) ?? null;
  return (
    <section className="space-y-4">
      <PageHeader
        title="Users & Groups"
        description="Which policies apply to each IAM user and group: attached directly, inherited from a group, inline or managed."
        details="A user's access is the union of its own policies and its groups' policies, minus anything an explicit Deny blocks, and capped by a permissions boundary."
      />
      {!selectedScanId ? (
        <StatePanel>Select a scan first.</StatePanel>
      ) : query.isLoading ? (
        <StatePanel>Loading users and groups…</StatePanel>
      ) : query.isError ? (
        <StatePanel intent="error" title="Failed to load users and groups">{formatQueryError(query.error)}</StatePanel>
      ) : items.length === 0 ? (
        <StatePanel>No users or groups in this scan. {query.data?.note}</StatePanel>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
          <ul className="max-h-[70vh] space-y-1 overflow-auto">
            {items.map((i) => (
              <li key={i.arn}>
                <button
                  type="button"
                  onClick={() => setSelected(i.arn)}
                  aria-pressed={i.arn === selected}
                  className={`w-full rounded border p-2 text-left text-sm ${i.arn === selected ? "border-cyan-500 bg-cyan-50 dark:bg-cyan-950/30" : "border-slate-200 dark:border-slate-700"}`}
                >
                  <span className="font-medium">{i.name}</span> <span className="text-xs text-slate-500">{i.kind} · {i.account_id}</span>
                  <div className="text-xs text-slate-500">
                    {i.policy_count} policies{i.groups.length ? ` · groups: ${i.groups.join(", ")}` : ""}
                    {i.has_deny ? " · has Deny" : ""}
                    {i.credentials_collected && i.console_enabled && !i.mfa_active ? " · console without MFA" : ""}
                    {i.credential_findings > 0 ? ` · ${i.credential_findings} credential findings` : ""}
                  </div>
                </button>
              </li>
            ))}
          </ul>
          <div>{current ? <Detail scanId={selectedScanId} item={current} /> : <StatePanel>Choose a user or group to see its policies.</StatePanel>}</div>
        </div>
      )}
    </section>
  );
}
