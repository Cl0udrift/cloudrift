import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiClient } from "../api/client";
import { formatQueryError } from "../api/httpError";
import { queryKeys } from "../api/queryKeys";
import type { BusinessSettings, LossRange } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { StatePanel } from "../components/StatePanel";
import { useScanContext } from "../hooks/useScanContext";

const pct = (v: number) => (v === 0 ? "" : String(Math.round(v * 1000) / 10));
const num = (v: number) => (v === 0 ? "" : String(v));

/** A low and a high figure side by side. */
function RangeInput({ label, hint, value, onChange, percent }: { label: string; hint?: string; value: LossRange; onChange: (r: LossRange) => void; percent?: boolean }) {
  const show = percent ? pct : num;
  const parse = (s: string) => (s === "" ? 0 : percent ? Number(s) / 100 : Number(s));
  return (
    <div>
      <p className="text-sm font-medium text-slate-800 dark:text-slate-100">{label}</p>
      {hint ? <p className="cr-helper">{hint}</p> : null}
      <div className="mt-1 flex items-center gap-2">
        <input aria-label={`${label}, low`} className="hs-input w-32" inputMode="decimal" placeholder="low" value={show(value.low)} onChange={(e) => onChange({ ...value, low: parse(e.target.value) })} />
        <span className="text-slate-400">to</span>
        <input aria-label={`${label}, high`} className="hs-input w-32" inputMode="decimal" placeholder="high" value={show(value.high)} onChange={(e) => onChange({ ...value, high: parse(e.target.value) })} />
        {percent ? <span className="text-xs text-slate-500">% a year</span> : null}
      </div>
    </div>
  );
}

/**
 * What AWS cannot tell Cloudrift: who owns each account, how fast findings must be fixed, and what a loss is worth
 * here. Everything built from these is labelled as the organization's own assumption.
 */
export function BusinessSettingsPage() {
  const qc = useQueryClient();
  const { scans } = useScanContext();
  const query = useQuery({ queryKey: queryKeys.business, queryFn: () => apiClient.getBusinessSettings() });
  const [draft, setDraft] = useState<BusinessSettings | null>(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    if (query.data && !draft) setDraft(query.data.settings);
  }, [query.data, draft]);

  const save = useMutation({
    mutationFn: (s: BusinessSettings) => apiClient.saveBusinessSettings(s),
    onSuccess: (r) => {
      setDraft(r.settings);
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2500);
      void qc.invalidateQueries();
    }
  });

  const knownAccounts = useMemo(() => Array.from(new Set(scans.flatMap((s) => s.account_ids ?? []))).sort(), [scans]);

  if (query.isLoading || !draft) return <StatePanel>Loading settings…</StatePanel>;
  if (query.isError) return <StatePanel intent="error" title="Settings unavailable"><pre className="whitespace-pre-wrap font-sans text-xs">{formatQueryError(query.error)}</pre></StatePanel>;

  const set = (patch: Partial<BusinessSettings>) => setDraft({ ...draft, ...patch });
  const owners = { ...draft.owners };
  const ownerAccounts = Array.from(new Set([...knownAccounts, ...Object.keys(owners)])).sort();
  const lossOn = draft.loss.store_cost.high > 0 && (draft.loss.likelihood_critical.high > 0 || draft.loss.likelihood_high.high > 0);

  return (
    <section className="space-y-6">
      <PageHeader
        title="Business settings"
        description="The three things AWS cannot tell us: who owns what, how fast a finding must be fixed, and what a loss is worth to you."
      />

      <div className="hs-card space-y-3 p-5">
        <h3 className="cr-section-title">Who owns each account</h3>
        <p className="cr-helper">A finding with no owner does not get fixed. A team name or a person is enough. An owner tag on the resource wins over what you enter here.</p>
        {ownerAccounts.length === 0 ? <p className="text-sm text-slate-500">No accounts yet. Run a scan first, or add one below.</p> : null}
        <ul className="space-y-2">
          {ownerAccounts.map((acct) => (
            <li key={acct} className="flex flex-wrap items-center gap-2">
              <code className="w-36 text-xs text-slate-600 dark:text-slate-300">{acct}</code>
              <input aria-label={`Owner of account ${acct}`} className="hs-input w-72" maxLength={120} placeholder="e.g. Platform team" value={owners[acct] ?? ""} onChange={(e) => set({ owners: { ...owners, [acct]: e.target.value } })} />
            </li>
          ))}
        </ul>
        <AddAccount onAdd={(acct) => set({ owners: { ...owners, [acct]: owners[acct] ?? "" } })} />
      </div>

      <div className="hs-card space-y-3 p-5">
        <h3 className="cr-section-title">How fast findings must be fixed</h3>
        <p className="cr-helper">A finding open longer than this is overdue. These are common starting points; set the ones your policy states. 0 turns the deadline off.</p>
        <div className="flex flex-wrap gap-4">
          {(["critical", "high", "medium"] as const).map((sev) => (
            <label key={sev} className="block">
              <span className="text-sm capitalize text-slate-800 dark:text-slate-100">{sev}</span>
              <span className="mt-1 flex items-center gap-2">
                <input className="hs-input w-24" inputMode="numeric" value={draft.fix_days[sev]} onChange={(e) => set({ fix_days: { ...draft.fix_days, [sev]: Number(e.target.value.replace(/\D/g, "")) } })} />
                <span className="text-xs text-slate-500">days</span>
              </span>
            </label>
          ))}
        </div>
      </div>

      <div className="hs-card space-y-4 p-5">
        <div>
          <h3 className="cr-section-title">Optional: a planning estimate of loss</h3>
          <p className="cr-helper mt-1">
            The page already shows measured money: what unused resources cost and what an administrator can reach. This section is for a different question and is optional. It turns risk into a planning figure the way a risk register does: how likely it is in a year, times what it costs if it happens, as a range. Cloudrift supplies what it can see (what an identity can reach, how serious the finding is). The money and the odds are yours. Leave these empty and no estimate appears. When filled in it is shown folded at the bottom of the Executive view, labelled as your assumption.
          </p>
        </div>
        <label className="block">
          <span className="text-sm text-slate-800 dark:text-slate-100">Currency</span>
          <input className="hs-input mt-1 w-24" maxLength={4} value={draft.loss.currency} onChange={(e) => set({ loss: { ...draft.loss, currency: e.target.value } })} />
        </label>
        <RangeInput label="Cost of one data store being breached" hint="A bucket, a database or a secret. Include response, notification, downtime and legal." value={draft.loss.store_cost} onChange={(r) => set({ loss: { ...draft.loss, store_cost: r } })} />
        <RangeInput label="Cost of a hostname being taken over" hint="A hijacked domain or subdomain: phishing, brand damage, response." value={draft.loss.hostname_cost} onChange={(r) => set({ loss: { ...draft.loss, hostname_cost: r } })} />
        <RangeInput percent label="Chance a critical finding is used, per year" value={draft.loss.likelihood_critical} onChange={(r) => set({ loss: { ...draft.loss, likelihood_critical: r } })} />
        <RangeInput percent label="Chance a high finding is used, per year" value={draft.loss.likelihood_high} onChange={(r) => set({ loss: { ...draft.loss, likelihood_high: r } })} />
        <p className="text-xs text-slate-600 dark:text-slate-300">{lossOn ? "On. A folded planning estimate appears at the bottom of the Executive view." : "Off until a data store cost and at least one chance are entered."}</p>
      </div>

      <div className="flex items-center gap-3">
        <button type="button" className="hs-btn-default px-3 py-1.5 text-sm" disabled={save.isPending} onClick={() => save.mutate(draft)}>{save.isPending ? "Saving…" : "Save"}</button>
        {saved ? <span className="text-sm text-emerald-700 dark:text-emerald-300">Saved</span> : null}
        {save.isError ? <span className="text-sm text-rose-700 dark:text-rose-300">{formatQueryError(save.error)}</span> : null}
      </div>
    </section>
  );
}

function AddAccount({ onAdd }: { onAdd: (acct: string) => void }) {
  const [v, setV] = useState("");
  const ok = /^[0-9]{12}$/.test(v);
  return (
    <form className="flex flex-wrap items-center gap-2" onSubmit={(e) => { e.preventDefault(); if (ok) { onAdd(v); setV(""); } }}>
      <input aria-label="Add an account" className="hs-input w-48" inputMode="numeric" maxLength={12} placeholder="Add a 12-digit account" value={v} onChange={(e) => setV(e.target.value.replace(/\D/g, ""))} />
      <button type="submit" className="hs-btn-default px-2 py-1 text-xs" disabled={!ok}>Add</button>
    </form>
  );
}
