import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiClient } from "../../api/client";
import { formatQueryError } from "../../api/httpError";
import { queryKeys } from "../../api/queryKeys";

/**
 * Approve an outside account from the finding that names it, with a note saying who it is and why it is trusted.
 * The approval applies from the next scan; findings already written keep their rating.
 */
export function TrustApproval({ accountId }: { accountId: string }) {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: queryKeys.trustApprovals, queryFn: () => apiClient.getTrustApprovals() });
  const [note, setNote] = useState("");
  const [open, setOpen] = useState(false);
  const refresh = () => qc.invalidateQueries({ queryKey: queryKeys.trustApprovals });
  const approve = useMutation({ mutationFn: () => apiClient.approveTrustAccount(accountId, note), onSuccess: () => { setOpen(false); setNote(""); void refresh(); } });
  const remove = useMutation({ mutationFn: () => apiClient.removeTrustApproval(accountId), onSuccess: () => void refresh() });
  const existing = list.data?.items.find((a) => a.account_id === accountId);

  return (
    <div className="rounded-md border border-slate-200 bg-slate-50/70 p-3 text-sm dark:border-slate-800 dark:bg-slate-900/40">
      <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Approval</p>
      {existing ? (
        <div className="space-y-1">
          <p>Approved on {new Date(existing.approved_at).toLocaleDateString()}: {existing.note}</p>
          <p className="cr-helper">It applies from the next scan. This finding keeps its current rating until then.</p>
          <button type="button" className="hs-btn-default px-2 py-0.5 text-xs" disabled={remove.isPending} onClick={() => remove.mutate()}>Remove approval</button>
        </div>
      ) : open ? (
        <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); if (note.trim()) approve.mutate(); }}>
          <label className="block">
            <span className="cr-helper text-xs">Who owns account {accountId}, and why is it trusted?</span>
            <input className="hs-input mt-1 w-full" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Datadog, contract 4411, owner: platform team" autoFocus />
          </label>
          <div className="flex gap-2">
            <button type="submit" className="hs-btn-default px-2 py-1 text-xs" disabled={!note.trim() || approve.isPending}>Approve account</button>
            <button type="button" className="hs-btn-default px-2 py-1 text-xs" onClick={() => setOpen(false)}>Cancel</button>
          </div>
          {approve.isError ? <p className="cr-helper">{formatQueryError(approve.error)}</p> : null}
        </form>
      ) : (
        <button type="button" className="hs-btn-default px-2 py-1 text-xs" onClick={() => setOpen(true)}>Approve this account…</button>
      )}
    </div>
  );
}
