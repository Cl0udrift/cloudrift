import { useEffect } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import { queryKeys } from "../api/queryKeys";
import { TargetPicker } from "../components/access/TargetPicker";
import { whoCanCsv } from "../lib/accessExport";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import { StateChip, type Tone } from "../components/ui/StatusChip";
import { useScanContext } from "../hooks/useScanContext";
import { actionFits, actionsFor, kindOf, type TargetKind } from "../lib/accessActions";

// Access statuses, not risk verdicts: red is kept for findings.
const statusChip: Record<string, [Tone, string, string]> = {
  VALIDATED_ALLOWED: ["info", "●", "Can"],
  ALLOWED_PENDING_CONTROLS: ["hyp", "◐", "Allowed by policies, org controls unchecked"],
  CONDITIONAL: ["hyp", "◐", "Conditional"]
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
          <div className="flex flex-wrap items-end gap-3">
            <div className="w-full text-sm sm:w-auto">
              <span className="cr-kpi-label block">Target</span>
              <TargetPicker
                scanId={selectedScanId}
                value={arn}
                onSelect={(t) => set(actionFits(action, kindOf(t.kind)) ? { arn: t.arn } : { arn: t.arn, action: actionsFor(kindOf(t.kind))[0] })}
              />
            </div>
            <label className="w-full text-sm sm:w-auto">
              <span className="cr-kpi-label block">Who can…</span>
              <select className="hs-input w-full min-w-0 text-sm" value={action} onChange={(e) => set({ action: e.target.value })} aria-label="Action">
                {offered.map((a) => <option key={a} value={a}>{ACTION_HELP[a] ?? a} ({a})</option>)}
              </select>
            </label>
          </div>
          {targetKind ? <p className="cr-helper">Showing actions that apply to a {targetKind}.</p> : null}
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
              <div className="space-y-3 text-sm">
                <p>
                  <span className="font-semibold">{result.data.allowed}</span> can, <span className="font-semibold">{result.data.possible}</span> more are allowed by policies with organization controls not checked.{" "}
                  {result.data.evaluated} users and roles were checked{result.data.unknown > 0 ? `; ${result.data.unknown} could not be decided (listed below)` : ""}.
                </p>
                {result.data.callers.length === 0 ? (
                  <p className="cr-helper">
                    No checked user or role was found able to do this.
                    {result.data.unknown > 0 ? ` ${result.data.unknown} could not be evaluated, so this is not a clear result.` : ""}
                  </p>
                ) : (
                  <ul className="space-y-2">
                    {result.data.callers.map((c) => {
                      const [tone, glyph, label] = statusChip[c.status] ?? statusChip.CONDITIONAL;
                      return (
                        <li key={c.arn} className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <StateChip tone={tone} glyph={glyph} label={label} title={c.reason} />
                            <span className="text-xs uppercase text-slate-500">{c.kind}</span>
                            {c.kind === "user" ? <Link className="break-all font-mono text-xs underline" to={`/principals?principal=${encodeURIComponent(c.arn)}`}>{c.name}</Link> : <span className="break-all font-mono text-xs">{c.name}</span>}
                            <span className="text-xs text-slate-500">{c.account_id}</span>
                          </div>
                          {(c.paths ?? []).map((path, i) => (
                            <p key={i} className="mt-1 flex flex-wrap items-center gap-x-1 text-xs" aria-label={`Access path: ${path.steps.map((s) => s.label).join(", then ")}`}>
                              {path.steps.map((s, j) => (
                                <span key={j} className="inline-flex items-center gap-1">
                                  {j > 0 ? <span aria-hidden="true" className="text-slate-400">→</span> : null}
                                  <span className={s.kind === "caller" || s.kind === "target" ? "font-medium" : "rounded border border-slate-300 px-1 dark:border-slate-700"} title={s.detail}>{s.label}</span>
                                </span>
                              ))}
                            </p>
                          ))}
                          {c.reason_text || c.reason ? <p className="mt-0.5 text-xs text-slate-500">{c.reason_text || c.reason}</p> : null}
                        </li>
                      );
                    })}
                  </ul>
                )}
                {result.data.unknown_callers.length > 0 ? (
                  <details className="hs-card p-3" open={result.data.callers.length === 0}>
                    <summary className="hs-focus-ring cursor-pointer rounded font-medium">Not evaluated ({result.data.unknown_callers.length})</summary>
                    <p className="cr-helper mt-1">These could not be decided. They are not shown as allowed, and they are not ruled out.</p>
                    <ul className="mt-2 space-y-2">
                      {result.data.unknown_callers.map((c) => (
                        <li key={c.arn} className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <StateChip tone="unk" glyph="?" label="Unknown" title={c.reason} />
                            <span className="text-xs uppercase text-slate-500">{c.kind}</span>
                            <span className="break-all font-mono text-xs">{c.name}</span>
                            <span className="text-xs text-slate-500">{c.account_id}</span>
                          </div>
                          <p className="mt-0.5 text-xs text-slate-500">{c.reason_text}</p>
                        </li>
                      ))}
                    </ul>
                  </details>
                ) : null}
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
                {result.data.notes.map((n) => <p key={n} className="cr-helper">{n}</p>)}
              </div>
            )}
          </div>
        </>
      )}
    </section>
  );
}
