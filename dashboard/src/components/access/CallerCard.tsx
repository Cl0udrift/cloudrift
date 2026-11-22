import { Link } from "react-router-dom";
import type { ObservedCaller, RoleAssumer, UnknownCaller } from "../../api/types";
import { accessSentence } from "../../lib/accessSentence";
import { StateChip, type Tone } from "../ui/StatusChip";
import { AccessFlow } from "./AccessFlow";

// Access statuses, not risk verdicts: red is kept for findings.
export const statusChip: Record<string, [Tone, string, string]> = {
  VALIDATED_ALLOWED: ["info", "●", "Can"],
  ALLOWED_PENDING_CONTROLS: ["hyp", "◐", "Allowed by policies, org controls unchecked"],
  CONDITIONAL: ["hyp", "◐", "Conditional"]
};

/** A big number with its meaning underneath. Colour is only the access status, never a risk score. */
export function CountTile({ label, value, tone, hint }: { label: string; value: number | string; tone: Tone; hint: string }) {
  return (
    <div className={`cr-tone-${tone} rounded-lg border p-3`} title={hint}>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      <div className="text-xs font-medium">{label}</div>
    </div>
  );
}

/** One person or role that can, with one sentence on why and the route drawn as boxes. */
export function CallerCard({ caller, verb }: { caller: RoleAssumer; verb: string }) {
  const [tone, glyph, label] = statusChip[caller.status] ?? statusChip.CONDITIONAL;
  return (
    <li className="hs-card space-y-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <span className="text-xs uppercase text-slate-500">{caller.kind}</span>{" "}
          {caller.kind === "user" ? <Link className="break-all text-base font-semibold underline" to={`/principals?principal=${encodeURIComponent(caller.arn)}`}>{caller.name}</Link> : <span className="break-all text-base font-semibold">{caller.name}</span>}
          <span className="ml-2 text-xs text-slate-500">{caller.account_id}</span>
        </div>
        <StateChip tone={tone} glyph={glyph} label={label} title={caller.reason} />
      </div>
      <p className="text-sm">{accessSentence(caller.name, verb, caller.paths?.[0])}</p>
      {caller.observed ? (
        <p className="text-sm font-medium" title={`CloudTrail history, last ${caller.observed.window_days} days`}>
          ✔ Seen doing this {caller.observed.count} {caller.observed.count === 1 ? "time" : "times"}, last on {caller.observed.last_seen.slice(0, 10)}
        </p>
      ) : null}
      {(caller.paths ?? []).map((path, i) => <AccessFlow key={i} steps={path.steps} />)}
      {(caller.paths?.length ?? 0) === 0 && (caller.reason_text || caller.reason) ? <p className="text-xs text-slate-500">{caller.reason_text || caller.reason}</p> : null}
    </li>
  );
}

/** Callers that could not be decided: listed, never shown as allowed, never ruled out. */
export function UnknownCallersList({ callers, open }: { callers: UnknownCaller[]; open: boolean }) {
  if (callers.length === 0) return null;
  return (
    <details className="hs-card p-4" open={open}>
      <summary className="hs-focus-ring cursor-pointer rounded font-medium">Not checked ({callers.length}): could not be decided</summary>
      <p className="cr-helper mt-1">They are not shown as allowed, and they are not ruled out.</p>
      <ul className="mt-2 divide-y divide-slate-200 dark:divide-slate-800">
        {callers.map((c) => (
          <li key={c.arn} className="py-2">
            <span className="text-xs uppercase text-slate-500">{c.kind}</span> <span className="break-all font-medium">{c.name}</span> <span className="text-xs text-slate-500">{c.account_id}</span>
            <p className="text-xs text-slate-500">{c.reason_text}</p>
          </li>
        ))}
      </ul>
    </details>
  );
}

/** Every caller seen assuming the role in CloudTrail history, including ones stored policy does not allow today. */
export function ObservedCallersList({ callers, historyRead }: { callers: ObservedCaller[]; historyRead: boolean }) {
  if (!historyRead) return null;
  return (
    <details className="hs-card p-4" open={callers.length > 0}>
      <summary className="hs-focus-ring cursor-pointer rounded font-medium">Seen assuming this role ({callers.length})</summary>
      <p className="cr-helper mt-1">From CloudTrail history. It shows the call was made, not that it was allowed today, and no entry does not mean it never happened.</p>
      {callers.length === 0 ? <p className="mt-2 text-sm text-slate-500">No AssumeRole call for this role in the history that was read.</p> : (
        <ul className="mt-2 divide-y divide-slate-200 dark:divide-slate-800">
          {callers.map((c) => (
            <li key={c.caller} className="py-2 text-sm">
              <span className="break-all font-medium">{c.name}</span> <span className="text-xs text-slate-500">{c.in_scan ? c.caller_type.replace("_", " ") : c.caller_type === "aws_service" ? "AWS service" : `${c.caller_type.replace("_", " ")}, not in this scan`}</span>
              <p className="text-xs text-slate-500">{c.count} {c.count === 1 ? "time" : "times"}, {c.first_seen.slice(0, 10)} to {c.last_seen.slice(0, 10)} (window {c.window_days} days)</p>
              {c.source_ips && c.source_ips.length > 0 ? <p className="text-xs text-slate-500">From {c.source_ips.join(", ")}</p> : null}
            </li>
          ))}
        </ul>
      )}
    </details>
  );
}
