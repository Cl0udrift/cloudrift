import type { PrincipalListItem } from "../api/types";

/** Why a user or group needs a look, from stored facts only. No score: each reason is a stored fact. */
export function principalReasons(p: PrincipalListItem): string[] {
  const out: string[] = [];
  if (p.broad_candidates.includes("administrative_wildcard")) out.push("administrative access");
  else if (p.broad_candidates.length > 0) out.push("broad permissions");
  if (p.credentials_collected && p.console_enabled && !p.mfa_active) out.push("console without MFA");
  if (p.credential_findings > 0) out.push(`${p.credential_findings} key ${p.credential_findings === 1 ? "issue" : "issues"}`);
  return out;
}

/** Items that need attention first (more reasons, then admin), ties by name. */
export function sortByAttention(items: PrincipalListItem[]): PrincipalListItem[] {
  const weight = (p: PrincipalListItem) =>
    principalReasons(p).length * 2 + (p.broad_candidates.includes("administrative_wildcard") ? 3 : 0) + (p.credentials_collected && p.console_enabled && !p.mfa_active ? 2 : 0);
  return [...items].sort((a, b) => weight(b) - weight(a) || a.name.localeCompare(b.name));
}

export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
