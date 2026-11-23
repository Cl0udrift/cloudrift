import { useEffect } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import { queryKeys } from "../api/queryKeys";
import { TargetPicker } from "../components/access/TargetPicker";
import { ActionPicker } from "../components/access/ActionPicker";
import { AnswerSummary, CallerCard, CallerFacts, CallerNote, callerLink, ObservedCallersList, UnknownCallersList } from "../components/access/CallerCard";
import { whoCanCsv } from "../lib/accessExport";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import { StateChip, type Tone } from "../components/ui/StatusChip";
import { useScanContext } from "../hooks/useScanContext";
import type { RoleAssumer } from "../api/types";
import { actionFits, actionsFor, kindOf, type TargetKind } from "../lib/accessActions";

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
  "iam:UpdateAssumeRolePolicy": "rewrite this role's trust policy",
  "s3:GetObject": "read objects in this bucket",
  "s3:PutObject": "write objects to this bucket",
  "s3:DeleteObject": "delete objects from this bucket",
  "secretsmanager:GetSecretValue": "read this secret",
  "kms:Decrypt": "decrypt with this key"
};

/** Administrators that reach the target the same way, listed as one row each under a shared route. */
function AdminGroups({ callers, verb }: { callers: RoleAssumer[]; verb: string }) {
  const groups = new Map<string, RoleAssumer[]>();
  for (const c of callers) groups.set(c.via || "directly", [...(groups.get(c.via || "directly") ?? []), c]);
  return (
    <section aria-label="Administrator access" className="hs-card space-y-3 p-4">
      <div>
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Administrator access ({callers.length})</h3>
        <p className="cr-helper">These can {verb} because they can do anything. That is expected; check that each of them should be an administrator.</p>
      </div>
      {Array.from(groups.entries()).map(([via, list]) => (
        <div key={via}>
          <p className="cr-kpi-label mb-1">{via === "directly" ? "Through their own policy" : `Through ${via}`}</p>
          <ul className="divide-y divide-slate-200 dark:divide-slate-800">
            {list.map((c) => (
              <li key={c.arn} className="space-y-1 py-2">
                <p className="text-sm">
                  <Link className="break-all font-medium underline" to={callerLink(c)}>{c.name}</Link>
                  {c.self ? <span className="ml-2 rounded bg-cyan-500/15 px-1.5 text-xs text-cyan-800 dark:text-cyan-300">the target itself</span> : null}
                  <span className="ml-2 text-xs text-slate-500">{c.kind}</span>
                </p>
                <CallerFacts caller={c} />
                <CallerNote caller={c} />
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}

/** Ready questions built from what this scan holds, riskiest first. */
function Starters({ scanId, onPick }: { scanId: string; onPick: (arn: string, action: string) => void }) {
  const q = useQuery({ queryKey: ["access", "suggestions", scanId], queryFn: () => apiClient.accessSuggestions(scanId), staleTime: 60_000 });
  const items = q.data?.items ?? [];
  if (q.isLoading) return <StatePanel>Looking for questions worth asking…</StatePanel>;
  if (items.length === 0) return <StatePanel>Choose a target to see who can act on it.</StatePanel>;
  return (
    <section aria-label="Questions worth asking" className="space-y-2">
      <h2 className="cr-section-title">Questions worth asking</h2>
      <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {items.map((s) => (
          <li key={`${s.action}-${s.arn}`}>
            <button type="button" onClick={() => onPick(s.arn, s.action)} className="hs-card hs-interactive-card flex h-full w-full flex-col gap-1 p-4 text-left">
              <span className="text-sm font-semibold">{s.title}</span>
              <span className="cr-helper">{s.why}</span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** "Who can do this to that?" asked of the stored policies. The reverse of looking at one identity. */
export function AccessExplorerPage() {
  const { selectedScanId } = useScanContext();
  const [params, setParams] = useSearchParams();
  const arn = params.get("arn") ?? "";
  const action = params.get("action") ?? "sts:AssumeRole";
  const chain = params.get("chain") === "true" && action === "sts:AssumeRole";
  const set = (updates: Record<string, string>) =>
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(updates)) next.set(k, v);
      return next;
    });

  const selectedTarget = useQuery({
    queryKey: ["access", "target", selectedScanId, arn],
    queryFn: () => apiClient.accessTargets(selectedScanId as string, { arn, limit: 1 }),
    enabled: Boolean(selectedScanId && arn),
    staleTime: 60_000
  });
  const targetItem = selectedTarget.data?.items[0];
  const targetKind: TargetKind | "" = targetItem ? kindOf(targetItem.kind) : "";
  const fits = actionFits(action, targetKind);
  const offered = actionsFor(targetKind);

  // A link or an old URL can pair an action with the wrong kind of target; move to one that fits.
  useEffect(() => {
    if (arn && targetKind && !fits && offered.length > 0) set({ action: offered[0] });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [arn, targetKind, fits]);

  const result = useQuery({
    queryKey: queryKeys.whoCan(selectedScanId, action, arn, chain),
    queryFn: () => apiClient.getWhoCan(selectedScanId as string, action, arn, chain),
    enabled: Boolean(selectedScanId && arn && action && fits),
    retry: false
  });

  const direct = (result.data?.callers ?? []).filter((c) => (c.depth ?? 1) <= 1);
  const indirect = (result.data?.callers ?? []).filter((c) => (c.depth ?? 1) > 1);
  const specific = direct.filter((c) => !c.admin);
  const admins = direct.filter((c) => c.admin);

  return (
    <section className="space-y-4">
      <PageHeader
        title="Access Explorer"
        description="Who can do this to that? Ask the stored policies instead of opening identities one by one."
        details="Every user and role in the scan, except AWS-managed service-linked roles, is checked against its own policies, permissions boundary and any collected SCPs. For identity-changing actions the target itself is checked too. This shows what policies allow, not what anyone did."
      />
      {!selectedScanId ? (
        <StatePanel>Select a scan first.</StatePanel>
      ) : (
        <>
          <div className="space-y-4">
            <div className="w-full text-sm sm:max-w-md">
              <span className="cr-kpi-label block">Target</span>
              <TargetPicker
                scanId={selectedScanId}
                value={arn}
                onSelect={(t) => set(actionFits(action, kindOf(t.kind)) ? { arn: t.arn } : { arn: t.arn, action: actionsFor(kindOf(t.kind))[0] })}
              />
            </div>
            <ActionPicker value={action} kind={targetKind} help={ACTION_HELP} onChange={(a) => set({ action: a })} />
            {action === "sts:AssumeRole" ? (
              <label className="flex w-fit cursor-pointer items-center gap-2 text-sm">
                <input type="checkbox" checked={chain} onChange={(e) => set({ chain: e.target.checked ? "true" : "" })} />
                Include chains: who can become this role through other roles (up to 3 steps)
              </label>
            ) : null}
          </div>
          <div aria-live="polite">
            {!arn ? (
              <Starters scanId={selectedScanId} onPick={(a, act) => set({ arn: a, action: act })} />
            ) : !fits ? (
              <StatePanel>Choose an action that applies to a {targetKind}.</StatePanel>
            ) : result.isLoading ? (
              <StatePanel>Checking every user and role…</StatePanel>
            ) : result.isError || !result.data ? (
              <StatePanel intent="error" title="Could not run this check">{formatQueryError(result.error)}</StatePanel>
            ) : (
              <div className="space-y-4 text-sm">
                <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                  Who can {ACTION_HELP[action] ?? action}{targetItem ? <>: <span className="break-all">{targetItem.name}</span></> : null}?
                </h2>
                <AnswerSummary callers={direct} unknown={result.data.unknown} verb={ACTION_HELP[action] ?? action} evaluated={result.data.evaluated} />
                {targetKind === "bucket" ? <p className="cr-helper">For a bucket the question is access to objects anywhere in it. Access limited to a prefix, and access the bucket policy gives to accounts outside this scan, are not listed.</p> : null}
                {result.data.callers.length === 0 ? (
                  (result.data.trust_summary ?? []).length > 0 ? (
                    <div className="hs-card space-y-1 p-4">
                      {(result.data.trust_summary ?? []).map((t) => <p key={t} className="text-sm">{t}</p>)}
                      <p className="cr-helper">So this role is reached by what its trust policy names, not by people or other roles in this account.</p>
                    </div>
                  ) : null
                ) : (
                  <>
                    {specific.length > 0 ? (
                      <section aria-label="Specific grants" className="space-y-2">
                        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Specific grants ({specific.length})</h3>
                        <p className="cr-helper">Not administrators. Each has a permission aimed at this target, so check that it is intended.</p>
                        <ul className="space-y-3">{specific.map((c) => <CallerCard key={c.arn} caller={c} verb={ACTION_HELP[action] ?? action} />)}</ul>
                      </section>
                    ) : null}
                    {admins.length > 0 ? <AdminGroups callers={admins} verb={ACTION_HELP[action] ?? action} /> : null}
                  </>
                )}
                {chain ? (
                  <section aria-label="Through other roles" className="hs-card space-y-2 p-4">
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Through other roles ({indirect.length})</h3>
                    <p className="cr-helper">Each can assume a role that can, step by step. A chain is only as strong as its weakest step.{result.data.chain_truncated ? " The search stopped at its limit, so this list is not complete." : ""}</p>
                    {indirect.length === 0 ? <p className="text-sm">No caller reaches it only through another role.</p> : (
                      <ul className="divide-y divide-slate-200 dark:divide-slate-800">
                        {indirect.map((c) => (
                          <li key={c.arn} className="space-y-1 py-2">
                            <p className="text-sm"><Link className="break-all font-medium underline" to={callerLink(c)}>{c.name}</Link> <span className="text-xs text-slate-500">{c.kind} · {c.depth} steps{c.status !== "VALIDATED_ALLOWED" ? " · likely, not certain" : ""}</span></p>
                            <p className="break-all text-xs text-slate-600 dark:text-slate-300">{(c.chain ?? []).join("  →  ")}</p>
                            <CallerFacts caller={c} />
                          </li>
                        ))}
                      </ul>
                    )}
                  </section>
                ) : null}
                <UnknownCallersList callers={result.data.unknown_callers} open={result.data.callers.length === 0} />
                <ObservedCallersList callers={result.data.observed ?? []} historyRead={result.data.history_read ?? false} />
                <div className="flex flex-wrap gap-3 text-xs">
                  <button type="button" className="hs-btn-default px-2 py-1" onClick={() => {
                    const blob = new Blob([whoCanCsv(result.data, targetItem?.name ?? arn)], { type: "text/csv" });
                    const url = URL.createObjectURL(blob);
                    const link = document.createElement("a");
                    link.href = url;
                    link.download = `who-can-${action.replace(/[^a-z0-9]+/gi, "-")}-${(targetItem?.name ?? "target").replace(/[^a-z0-9._-]+/gi, "-")}.csv`;
                    link.click();
                    URL.revokeObjectURL(url);
                  }}>Download CSV</button>
                  <button type="button" className="hs-btn-default px-2 py-1" onClick={() => void navigator.clipboard?.writeText(window.location.href)}>Copy link</button>
                </div>
                <details className="text-xs text-slate-500">
                  <summary className="cursor-pointer">About this result</summary>
                  {result.data.notes.map((n) => <p key={n} className="mt-1">{n}</p>)}
                </details>
              </div>
            )}
          </div>
        </>
      )}
    </section>
  );
}
