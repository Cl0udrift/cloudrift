import { useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import { queryKeys } from "../api/queryKeys";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import { StateChip, type Tone } from "../components/ui/StatusChip";
import { useScanContext } from "../hooks/useScanContext";

const statusChip: Record<string, [Tone, string, string]> = {
  VALIDATED_ALLOWED: ["bad", "●", "Can"],
  ALLOWED_PENDING_CONTROLS: ["warn", "◐", "Allowed by policies, org controls unchecked"],
  CONDITIONAL: ["warn", "◐", "Conditional"]
};

const ACTION_HELP: Record<string, string> = {
  "sts:AssumeRole": "assume this role",
  "iam:PassRole": "pass this role to a service",
  "iam:AttachUserPolicy": "attach a policy to this user",
  "iam:PutUserPolicy": "write an inline policy on this user",
  "iam:AttachGroupPolicy": "attach a policy to this group",
  "iam:PutGroupPolicy": "write an inline policy on this group",
  "iam:AddUserToGroup": "add users to this group",
  "iam:CreateAccessKey": "create an access key for this user",
  "iam:CreateLoginProfile": "set a console password for this user",
  "iam:UpdateLoginProfile": "change this user's console password",
  "iam:AttachRolePolicy": "attach a policy to this role",
  "iam:PutRolePolicy": "write an inline policy on this role",
  "iam:UpdateAssumeRolePolicy": "rewrite this role's trust policy"
};

/** "Who can do this to that?" asked of the stored policies. The reverse of looking at one identity. */
export function AccessExplorerPage() {
  const { selectedScanId } = useScanContext();
  const [params, setParams] = useSearchParams();
  const arn = params.get("arn") ?? "";
  const action = params.get("action") ?? "sts:AssumeRole";
  const set = (k: string, v: string) =>
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set(k, v);
      return next;
    });

  const roles = useQuery({ queryKey: ["access", "roles", selectedScanId], queryFn: () => apiClient.listIdentities(selectedScanId as string, { page: 1, page_size: 200 }), enabled: Boolean(selectedScanId), staleTime: 60_000 });
  const principals = useQuery({ queryKey: queryKeys.principals(selectedScanId), queryFn: () => apiClient.getPrincipals(selectedScanId as string), enabled: Boolean(selectedScanId), staleTime: 60_000 });
  const targets = useMemo(
    () => [
      ...(roles.data?.items ?? []).map((r) => ({ arn: r.role_arn, label: `role ${r.name}` })),
      ...(principals.data?.items ?? []).map((p) => ({ arn: p.arn, label: `${p.kind} ${p.name}` }))
    ],
    [roles.data, principals.data]
  );
  const result = useQuery({
    queryKey: queryKeys.whoCan(selectedScanId, action, arn),
    queryFn: () => apiClient.getWhoCan(selectedScanId as string, action, arn),
    enabled: Boolean(selectedScanId && arn && action),
    retry: false
  });

  return (
    <section className="space-y-4">
      <PageHeader
        title="Access Explorer"
        description="Who can do this to that? Ask the stored policies instead of opening identities one by one."
        details="Every user and role in the scan is checked against its own policies, permissions boundary and any collected SCPs. This shows what policies allow, not what anyone did."
      />
      {!selectedScanId ? (
        <StatePanel>Select a scan first.</StatePanel>
      ) : (
        <>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm">
              <span className="cr-kpi-label block">Target</span>
              <select className="hs-input min-w-[16rem] text-sm" value={arn} onChange={(e) => set("arn", e.target.value)} aria-label="Target identity">
                <option value="">Choose a user, group or role…</option>
                {targets.map((t) => <option key={t.arn} value={t.arn}>{t.label}</option>)}
              </select>
            </label>
            <label className="text-sm">
              <span className="cr-kpi-label block">Who can…</span>
              <select className="hs-input text-sm" value={action} onChange={(e) => set("action", e.target.value)} aria-label="Action">
                {Object.entries(ACTION_HELP).map(([a, help]) => <option key={a} value={a}>{help} ({a})</option>)}
              </select>
            </label>
          </div>
          {!arn ? (
            <StatePanel>Choose a target to see who can act on it.</StatePanel>
          ) : result.isLoading ? (
            <StatePanel>Checking every user and role…</StatePanel>
          ) : result.isError || !result.data ? (
            <StatePanel intent="error" title="Could not run this check">{formatQueryError(result.error)}</StatePanel>
          ) : (
            <div className="space-y-3 text-sm">
              <p>
                <span className="font-semibold">{result.data.allowed}</span> can, <span className="font-semibold">{result.data.possible}</span> more are allowed by policies with organization controls not checked.{" "}
                {result.data.evaluated} users and roles were checked; {result.data.unknown} could not be evaluated because their policy documents are missing.
              </p>
              {result.data.callers.length === 0 ? (
                <p className="cr-helper">No user or role in this scan was found able to do this.</p>
              ) : (
                <ul className="space-y-1">
                  {result.data.callers.map((c) => {
                    const [tone, glyph, label] = statusChip[c.status] ?? statusChip.CONDITIONAL;
                    return (
                      <li key={c.arn} className="flex flex-wrap items-center gap-2">
                        <StateChip tone={tone} glyph={glyph} label={label} title={c.reason} />
                        <span className="text-xs uppercase text-slate-500">{c.kind}</span>
                        {c.kind === "user" ? <Link className="font-mono text-xs underline" to={`/principals?principal=${encodeURIComponent(c.arn)}`}>{c.name}</Link> : <span className="font-mono text-xs">{c.name}</span>}
                        <span className="text-xs text-slate-500">{c.account_id}</span>
                      </li>
                    );
                  })}
                </ul>
              )}
              {result.data.notes.map((n) => <p key={n} className="cr-helper">{n}</p>)}
            </div>
          )}
        </>
      )}
    </section>
  );
}
