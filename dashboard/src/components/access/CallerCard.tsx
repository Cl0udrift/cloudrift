import { Link } from "react-router-dom";
import type { ObservedCaller, RoleAssumer, UnknownCaller } from "../../api/types";
import { accessSentence } from "../../lib/accessSentence";
import { StateChip, type Tone } from "../ui/StatusChip";
import { ageLabel, capitalize, severityTone } from "../../lib/identityLabels";
import { AccessFlow } from "./AccessFlow";

/** A big number with its meaning underneath, for pages that show counts (Identity Center). */
export function CountTile({ label, value, tone, hint }: { label: string; value: number | string; tone: Tone; hint: string }) {
  return (
    <div className={`cr-tone-${tone} rounded-lg border p-3`} title={hint}>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      <div className="text-xs font-medium">{label}</div>
    </div>
  );
}

/**
 * The answer in one place: how many can, who they are in two numbers, and how many could not be checked. A caller either
 * can or is listed as unchecked; what could not be verified is a note on the caller, not a second kind of "can".
 */
export function AnswerSummary({ callers, unknown, verb, evaluated }: { callers: RoleAssumer[]; unknown: number; verb: string; evaluated: number }) {
  const n = callers.length;
  const admins = callers.filter((c) => c.admin).length;
  const noted = callers.filter((c) => c.note).length;
  return (
    <section aria-label="Answer" className="hs-card flex items-start gap-4 p-4">
      <p className="text-4xl font-semibold tabular-nums leading-none">{n}</p>
      <div className="min-w-0 space-y-1">
        <p className="text-base font-semibold">{n === 0 ? `Nobody in this scan can ${verb}.` : `${n === 1 ? "identity" : "identities"} can ${verb}.`}</p>
        {n > 0 ? <p className="cr-helper">{admins} {admins === 1 ? "administrator" : "administrators"} · {n - admins} with a specific grant</p> : null}
        {noted > 0 ? <p className="cr-helper">{noted} {noted === 1 ? "has" : "have"} a note: something Cloudrift could not read, and what it means for that answer.</p> : null}
        {unknown > 0 ? <p className="text-sm"><a className="underline" href="#undecided">{unknown} could not be checked</a>: they are not counted above.</p> : null}
        <p className="cr-helper">Checked {evaluated} users and roles against their stored policies.</p>
      </div>
    </section>
  );
}

/** What could not be verified for one caller, in a sentence. Shown only when there is something to say. */
export function CallerNote({ caller }: { caller: RoleAssumer }) {
  const text = caller.note || (caller.status === "CONDITIONAL" ? caller.reason_text || caller.reason : "");
  return text ? <p className="flex items-start gap-1.5 text-xs text-amber-800 dark:text-amber-300"><span aria-hidden="true">!</span><span>{text}</span></p> : null;
}

const USAGE_LABEL: Record<string, string> = { person: "Person", programmatic: "Programmatic", workload: "Runs a workload", role: "Role", unknown: "Sign-in unknown" };

/** Who the caller is and how risky it already looks, beside the route that gives it access. */
export function CallerFacts({ caller }: { caller: RoleAssumer }) {
  return (
    <p className="flex flex-wrap items-center gap-1.5 text-xs">
      {caller.usage ? <span className="rounded-full border border-slate-300 px-2 py-0.5 dark:border-slate-700">{USAGE_LABEL[caller.usage] ?? caller.usage}</span> : null}
      {caller.console_no_mfa ? <StateChip tone="bad" glyph="✕" label="Console, no MFA" /> : null}
      {(caller.key_issues ?? 0) > 0 ? <StateChip tone="warn" glyph="!" label={`${caller.key_issues} key issue${caller.key_issues === 1 ? "" : "s"}`} /> : null}
      {(caller.finding_count ?? 0) > 0 ? <StateChip tone={severityTone(caller.max_severity)} glyph="●" label={`${capitalize(caller.max_severity ?? "")} · ${caller.finding_count} finding${caller.finding_count === 1 ? "" : "s"}`} /> : null}
      {caller.last_activity ? <span className="text-slate-500">Last active {ageLabel(caller.last_activity)}</span> : null}
    </p>
  );
}

/** Where a caller's own page is: users on Users & Groups, roles on Identities. */
export const callerLink = (c: Pick<RoleAssumer, "kind" | "arn">) => (c.kind === "user" ? `/principals?principal=${encodeURIComponent(c.arn)}` : `/identities?aws=show&role=${encodeURIComponent(c.arn)}`);

/** One person or role that can, with one sentence on why and the route drawn as boxes. */
export function CallerCard({ caller, verb }: { caller: RoleAssumer; verb: string }) {
  return (
    <li className="hs-card space-y-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <span className="text-xs uppercase text-slate-500">{caller.kind}</span>{" "}
          <Link className="break-all text-base font-semibold underline" to={callerLink(caller)}>{caller.name}</Link>
          {caller.self ? <span className="ml-2 rounded bg-cyan-500/15 px-1.5 text-xs text-cyan-800 dark:text-cyan-300">the target itself</span> : null}
          <span className="ml-2 text-xs text-slate-500">{caller.account_id}</span>
        </div>
      </div>
      <CallerFacts caller={caller} />
      <p className="text-sm">{accessSentence(caller.name, verb, caller.paths?.[0])}</p>
      <CallerNote caller={caller} />
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
      <summary id="undecided" className="hs-focus-ring cursor-pointer rounded font-medium">Could not be checked ({callers.length})</summary>
      <p className="cr-helper mt-1">Not counted as able, and not ruled out. The reason for each is below.</p>
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
