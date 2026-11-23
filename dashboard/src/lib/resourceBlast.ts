import type { InventoryDetail, WhoCanResponse } from "../api/types";

export interface Link {
  relation: string;
  name: string;
  type: string;
  id: string;
}

export const TYPE_WORD: Record<string, string> = {
  dns_record: "DNS record",
  cloudfront_dist: "CloudFront distribution",
  acm_cert: "certificate",
  s3_bucket: "bucket",
  secret: "secret",
  kms_key: "key",
  ec2_instance: "instance",
  load_balancer: "load balancer",
  rds_instance: "database",
  lambda_function: "function"
};
const word = (t?: string) => (t ? TYPE_WORD[t] ?? t.replace(/_/g, " ") : "resource");
export const nameOfId = (id: string) => id.slice(Math.max(id.lastIndexOf("/"), id.lastIndexOf(":")) + 1) || id;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const list = (names: string[]) => (names.length <= 3 ? names.join(", ") : `${names.slice(0, 3).join(", ")} and ${names.length - 3} more`);

/** The data actions a resource kind can be asked about, as who-can calls. */
export const DATA_ACTIONS: Record<string, [string, string][]> = {
  s3_bucket: [["s3:GetObject", "read objects in it"], ["s3:PutObject", "write objects to it"], ["s3:DeleteObject", "delete objects from it"]],
  secret: [["secretsmanager:GetSecretValue", "read it"]],
  kms_key: [["kms:Decrypt", "decrypt with it"]]
};

export interface ResourceAnswer {
  lines: string[];
  dependsOnIt: Link[];
  itDependsOn: Link[];
  takeover: boolean;
}

/**
 * What the scan says happens if this resource is hijacked, exposed or lost, in plain statements: who can use it, what
 * points at it, what it points at, and the findings that name it. Every line comes from a stored fact; nothing is guessed.
 */
export function describeResource(detail: InventoryDetail, who: Record<string, WhoCanResponse | undefined>): ResourceAnswer {
  const r = detail.resource;
  const lines: string[] = [];
  const links = detail.relationships.map((x): Link & { dir: string } => ({ relation: x.rel_type, name: nameOfId(x.other_id), type: x.other_type ?? "", id: x.other_id, dir: x.direction }));
  const incoming = links.filter((l) => l.dir === "incoming");
  const outgoing = links.filter((l) => l.dir === "outgoing");

  const actions = DATA_ACTIONS[r.resource_type] ?? [];
  const answered = actions.filter(([a]) => who[a]);
  if (answered.length > 0) {
    const none = answered.every(([a]) => who[a]!.callers.length === 0);
    const parts = answered.map(([a, verb]) => `${plural(who[a]!.callers.length, "identity", "identities")} can ${verb}`);
    lines.push(none ? `No user or role in this scan can ${answered.map(([, v]) => v).join(", ")}.` : `${parts.join(", ")}.`);
    const specific = [...new Set(answered.flatMap(([a]) => who[a]!.callers.filter((c) => !c.admin).map((c) => c.name)))];
    const admins = [...new Set(answered.flatMap(([a]) => who[a]!.callers.filter((c) => c.admin).map((c) => c.name)))];
    if (admins.length > 0) lines.push(`Administrators among them: ${list(admins)}.`);
    if (specific.length > 0) lines.push(`With a specific grant, not as administrators: ${list(specific)}.`);
  }
  if (r.internet_facing) lines.push(`It is reachable from the internet. ${r.exposure_detail ?? ""}`.trim());

  const dns = incoming.filter((l) => l.relation === "POINTS_TO" && l.type === "dns_record").map((l) => l.name);
  if (dns.length > 0) lines.push(`${plural(dns.length, "DNS name")} ${dns.length === 1 ? "points" : "point"} at it: ${list(dns)}.`);
  const cdn = incoming.filter((l) => l.relation === "FRONTS").map((l) => l.name);
  if (cdn.length > 0) lines.push(`It is served through ${plural(cdn.length, "CloudFront distribution")}: ${list(cdn)}.`);
  for (const l of outgoing.filter((x) => x.relation === "POINTS_TO" || x.relation === "FRONTS")) lines.push(`It ${l.relation === "FRONTS" ? "fronts" : "points at"} the ${word(l.type)} ${l.name}.`);
  const certs = outgoing.filter((l) => l.relation === "USES_CERT").map((l) => l.name);
  if (certs.length > 0) lines.push(`It uses the ${certs.length === 1 ? "certificate" : "certificates"} ${list(certs)}.`);
  const users = incoming.filter((l) => l.relation === "USES_CERT").map((l) => l.name);
  if (users.length > 0) lines.push(`${plural(users.length, "resource")} ${users.length === 1 ? "uses" : "use"} this certificate: ${list(users)}.`);

  const orphan = detail.findings.filter((f) => f.module === "orphaned_edge");
  if (orphan.length > 0) {
    lines.push(`Takeover risk: ${orphan[0].title}. Whoever claims it would receive what is sent to ${dns.length > 0 ? list(dns) : r.name}.`);
  }
  const others = detail.findings.filter((f) => f.module !== "orphaned_edge");
  if (others.length > 0) lines.push(`${plural(others.length, "finding")} on it: ${others[0].title}${others.length > 1 ? ` and ${others.length - 1} more` : ""}.`);
  lines.push(r.owner ? `Owner: ${r.owner}.` : "No owner tag.");
  return {
    lines,
    dependsOnIt: incoming.filter((l) => l.relation !== "OWNED_BY"),
    itDependsOn: outgoing.filter((l) => l.relation !== "OWNED_BY"),
    takeover: orphan.length > 0
  };
}
