import type { PrincipalListItem } from "../api/types";

/** Why a user or group needs a look, from stored facts only. No score: each reason is a stored fact. */
export function principalReasons(p: PrincipalListItem): string[] {
  const out: string[] = [];
  if (p.broad_candidates.includes("administrative_wildcard")) out.push("administrative access");
  else if (p.broad_candidates.length > 0) out.push("broad permissions");
  if (p.credentials_collected && p.console_enabled && !p.mfa_active) out.push("console without MFA");
  // Only access key findings: console without MFA is already listed above and is not a key problem.
  if (p.key_issues > 0) out.push(`${p.key_issues} key ${p.key_issues === 1 ? "issue" : "issues"}`);
  if (p.kind === "user" && !p.credentials_collected) out.push("credentials unknown");
  return out;
}

/** Items that need attention first (more reasons, then admin), ties by name. */
export function sortByAttention(items: PrincipalListItem[]): PrincipalListItem[] {
  const weight = (p: PrincipalListItem) =>
    severityWeight(p.max_severity) * 4 + principalReasons(p).length * 2 + (p.broad_candidates.includes("administrative_wildcard") ? 3 : 0) + (p.credentials_collected && p.console_enabled && !p.mfa_active ? 2 : 0);
  return [...items].sort((a, b) => weight(b) - weight(a) || a.name.localeCompare(b.name));
}

const severityWeight = (s?: string) => ({ critical: 5, high: 4, medium: 3, low: 2 })[(s ?? "").toLowerCase() as "low"] ?? 0;

export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
