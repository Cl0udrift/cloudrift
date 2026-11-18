import type { AccessPath } from "../api/types";

/** One plain sentence on why a caller can, from the first path. Names stored policy; never says the call happened. */
export function accessSentence(caller: string, verb: string, path?: AccessPath): string {
  if (!path || path.steps.length < 3) return `${caller} can ${verb}.`;
  const middle = path.steps.slice(1, -1);
  const group = middle.find((s) => s.kind === "group");
  const policy = middle.find((s) => s.kind === "policy");
  const trust = middle.find((s) => s.kind === "trust");
  if (trust) return `${caller} can ${verb} because the role's trust policy names it.`;
  if (group && policy) return `${caller} can ${verb} because it is in ${group.label}, which has the policy ${policy.label}.`;
  if (policy && policy.label.startsWith("inline policy")) return `${caller} can ${verb} because its own inline policy allows it.`;
  if (policy) return `${caller} can ${verb} because the policy ${policy.label} is attached to it.`;
  return `${caller} can ${verb}.`;
}
