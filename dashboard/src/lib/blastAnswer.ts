import type { IdentityAttackReport } from "../api/types";

export interface Route {
  kind: string;
  verb: string;
  target: string;
  targetArn: string;
  explanation: string;
}

const nameOf = (arn: string) => arn.slice(arn.lastIndexOf("/") + 1) || arn;

const VERB: Record<string, string> = {
  SELF_POLICY_GRANT: "grant itself any permission through",
  TRUST_REWRITE: "rewrite the trust policy of",
  USER_TAKEOVER: "create credentials for",
  GRANT_ON_REACHABLE_ROLE: "attach a policy to",
  SELF_GROUP_JOIN: "add itself to",
  ASSUME_ROLE: "assume"
};

const verbFor = (kind: string) => VERB[kind] ?? (kind.startsWith("PASS_ROLE") ? "run code as" : kind.toLowerCase().replace(/_/g, " "));

/** What the search found, as steps from the starting identity: one per kind and target, then the roles it can assume. */
export function routesOf(report: IdentityAttackReport): Route[] {
  const start = report.initial_principal;
  const out: Route[] = [];
  const seen = new Set<string>();
  const add = (kind: string, targetArn: string, explanation: string) => {
    const key = `${kind}|${targetArn}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, verb: verbFor(kind), target: targetArn === start ? "its own policies" : nameOf(targetArn), targetArn, explanation });
  };
  // Only steps the starting identity takes itself. What another identity could do after being taken over is further down
  // the chain, and is counted by furtherSteps, not shown as if the starting identity did it directly.
  for (const e of report.escalations ?? []) {
    if (e.source_principal !== start) continue;
    if (e.target_arn === start && e.kind !== "SELF_POLICY_GRANT") continue; // it cannot take over, or rewrite the trust of, itself
    add(e.kind, e.target_arn, e.explanation);
  }
  for (const t of report.transitions ?? []) {
    if (t.technique === "ASSUME_ROLE" && t.feasibility === "VALIDATED_POSSIBLE" && t.source_principal === start && t.target_arn !== start) add("ASSUME_ROLE", t.target_arn, `It can assume ${nameOf(t.target_arn)}.`);
  }
  return out;
}

/** Escalations that start from an identity the search reached, not from the starting identity. */
export function furtherSteps(report: IdentityAttackReport): number {
  return (report.escalations ?? []).filter((e) => e.source_principal !== report.initial_principal).length;
}

const list = (names: string[]) => (names.length <= 3 ? names.join(", ") : `${names.slice(0, 3).join(", ")} and ${names.length - 3} more`);
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export interface Headline {
  lines: string[];
  /** The search ran out of room, so the lines are a sample, not the whole answer. */
  sample: boolean;
  /** No way to gain more access was found. */
  none: boolean;
}

/**
 * The answer in plain statements: what the identity can do if its credentials are stolen. An administrator can already do
 * anything, so for it the routes are a sample and the lead line says so.
 */
export function headline(report: IdentityAttackReport, isAdmin: boolean): Headline {
  const routes = routesOf(report);
  const by = (kind: string) => routes.filter((r) => r.kind === kind).map((r) => r.target);
  const lines: string[] = [];
  if (isAdmin) lines.push("It is an administrator: it can already do anything in this account.");
  if (by("SELF_POLICY_GRANT").length > 0) lines.push("It can grant itself any permission, so it has full control of IAM.");
  const takeovers = by("USER_TAKEOVER");
  if (takeovers.length > 0) lines.push(`It can create credentials for ${plural(takeovers.length, "user")} and act as them: ${list(takeovers)}.`);
  const rewrites = by("TRUST_REWRITE");
  if (rewrites.length > 0) lines.push(`It can rewrite the trust policy of ${plural(rewrites.length, "role")} to become them: ${list(rewrites)}.`);
  const assumes = by("ASSUME_ROLE");
  if (assumes.length > 0) lines.push(`It can assume ${plural(assumes.length, "role")}: ${list(assumes)}.`);
  const grants = by("GRANT_ON_REACHABLE_ROLE");
  if (grants.length > 0) lines.push(`It can change the policies of ${plural(grants.length, "identity", "identities")} it can reach: ${list(grants)}.`);
  const joins = by("SELF_GROUP_JOIN");
  if (joins.length > 0) lines.push(`It can add itself to an administrator group: ${list(joins)}.`);
  const code = routes.filter((r) => r.kind.startsWith("PASS_ROLE")).map((r) => r.target);
  if (code.length > 0) lines.push(`It can run code as ${plural(code.length, "role")}: ${list(code)}.`);
  const readable = (report.impacted_resources ?? []).length;
  if (readable > 0) lines.push(`It can read ${plural(readable, "object or secret")} through the roles it can reach.`);
  const none = lines.length === 0 || (isAdmin && lines.length === 1);
  if (lines.length === 0) lines.push("No way to gain more access was found among the techniques Cloudrift models.");
  return { lines, sample: report.truncated, none };
}
