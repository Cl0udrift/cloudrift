// Plain names for the declared-permission categories the API reports as slugs.
const CATEGORY: Record<string, string> = {
  administrative_wildcard: "Administrator access",
  broad_s3_access: "Broad S3 access",
  broad_assume_role: "Can assume any role",
  broad_passrole: "PassRole on any role",
  iam_policy_modification: "Can change IAM policies"
};

export const categoryLabel = (slug: string): string => CATEGORY[slug] ?? slug.replace(/_/g, " ");

const SEVERITY_TONE: Record<string, "bad" | "warn" | "info" | "unk"> = { critical: "bad", high: "bad", medium: "warn", low: "info" };
export const severityTone = (s?: string) => SEVERITY_TONE[(s ?? "").toLowerCase()] ?? "unk";
export const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

export const serviceLabel = (id: string) =>
  id === "all services" ? "Every service" : id.split("-").map((w) => (w.length <= 3 ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1))).join(" ");

export const LEVEL: Record<string, ["bad" | "warn" | "info", string, string]> = {
  full: ["bad", "●", "Full access"],
  write: ["warn", "◐", "Read and change"],
  read: ["info", "○", "Read only"]
};

/** "today", "12 days ago", "5 months ago" for an RFC 3339 time. Empty when it cannot be read. */
export function ageLabel(iso?: string): string {
  const days = iso ? Math.floor((Date.now() - Date.parse(iso)) / 86_400_000) : NaN;
  if (Number.isNaN(days)) return "";
  if (days < 1) return "today";
  if (days < 60) return `${days} days ago`;
  return days < 730 ? `${Math.round(days / 30)} months ago` : `${Math.round(days / 365)} years ago`;
}

export const TECHNIQUE: Record<string, string> = {
  GRANT_ROLE_POLICY: "can attach a policy to it",
  GRANT_USER_POLICY: "can attach a policy to it",
  GRANT_GROUP_POLICY: "can attach a policy to it",
  CREATE_POLICY_VERSION: "can rewrite its policy",
  ASSUME_ROLE: "can assume it",
  TAKEOVER_USER: "can create credentials for it",
  ADD_USER_TO_GROUP: "can add users to it"
};

/** "2026-11-22 04:09 UTC" for an RFC 3339 time. Empty when it cannot be read. */
export function utcLabel(iso?: string): string {
  const t = iso ? Date.parse(iso) : NaN;
  return Number.isNaN(t) ? "" : `${new Date(t).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}
