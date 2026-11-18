import { useEffect } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import { queryKeys } from "../api/queryKeys";
import { TargetPicker } from "../components/access/TargetPicker";
import { ActionPicker } from "../components/access/ActionPicker";
import { CallerCard, CountTile, ObservedCallersList, UnknownCallersList } from "../components/access/CallerCard";
import { whoCanCsv } from "../lib/accessExport";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import { StateChip, type Tone } from "../components/ui/StatusChip";
import { useScanContext } from "../hooks/useScanContext";
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
  "iam:UpdateAssumeRolePolicy": "rewrite this role's trust policy"
};

/** "Who can do this to that?" asked of the stored policies. The reverse of looking at one identity. */
export function AccessExplorerPage() {
  const { selectedScanId } = useScanContext();
  const [params, setParams] = useSearchParams();
  const arn = params.get("arn") ?? "";
  const action = params.get("action") ?? "sts:AssumeRole";
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
    queryKey: queryKeys.whoCan(selectedScanId, action, arn),
    queryFn: () => apiClient.getWhoCan(selectedScanId as string, action, arn),
    enabled: Boolean(selectedScanId && arn && action && fits),
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
          </div>
          <div aria-live="polite">
            {!arn ? (
              <StatePanel>Choose a target to see who can act on it.</StatePanel>
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
                <div className="grid grid-cols-3 gap-3">
                  <CountTile label="Can" value={result.data.allowed} tone="info" hint="Allowed by stored policy" />
                  <CountTile label="Probably" value={result.data.possible} tone="hyp" hint="Allowed, but organization controls were not checked" />
                  <CountTile label="Not checked" value={result.data.unknown} tone="unk" hint="Could not be decided: not allowed, not ruled out" />
                </div>
                <p className="cr-helper">{result.data.evaluated} users and roles were checked against stored policies.</p>
                {result.data.callers.length === 0 ? (
                  <p className="cr-helper">
                    No checked user or role was found able to do this.
                    {result.data.unknown > 0 ? ` ${result.data.unknown} could not be evaluated, so this is not a clear result.` : ""}
                  </p>
                ) : (
                  <ul className="space-y-3">
                    {result.data.callers.map((c) => <CallerCard key={c.arn} caller={c} verb={ACTION_HELP[action] ?? action} />)}
                  </ul>
                )}
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
