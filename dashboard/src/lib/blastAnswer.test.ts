import { describe, expect, it } from "vitest";
import type { IdentityAttackReport } from "../api/types";
import { furtherSteps, headline, routesOf } from "./blastAnswer";

const base: IdentityAttackReport = {
  assumption: "", initial_principal: "arn:aws:iam::1:user/u", session_context_source: "assumed", validated_role_transitions: 0,
  conditional_role_transitions: 0, unknown_transitions: 0, denied_transitions: 0, cross_account_transitions: 0, truncated: false, states_explored: 1
};
const START = "arn:aws:iam::1:user/u";
const esc = (kind: string, target: string) => ({ kind, source_principal: START, target_arn: target, technique: kind, depth: 0, explanation: `${kind} ${target}` });

describe("blast answer", () => {
  it("lists one route per kind and target and the roles it can assume", () => {
    const r = routesOf({
      ...base,
      escalations: [esc("USER_TAKEOVER", "arn:aws:iam::1:user/bob"), esc("USER_TAKEOVER", "arn:aws:iam::1:user/bob")],
      transitions: [{ technique: "ASSUME_ROLE", source_principal: START, target_arn: "arn:aws:iam::1:role/R", status: "VALIDATED_ALLOWED", reason: "", same_account: true, feasibility: "VALIDATED_POSSIBLE", depth: 0 }]
    });
    expect(r.map((x) => `${x.kind}:${x.target}`)).toEqual(["USER_TAKEOVER:bob", "ASSUME_ROLE:R"]);
  });

  it("states what it can do in plain words, and says an administrator already can do anything", () => {
    const h = headline({ ...base, truncated: true, escalations: [esc("SELF_POLICY_GRANT", "arn:aws:iam::1:group/G"), esc("USER_TAKEOVER", "arn:aws:iam::1:user/bob")] }, true);
    expect(h.lines[0]).toMatch(/administrator/);
    expect(h.lines.join(" ")).toMatch(/full control of IAM/);
    expect(h.lines.join(" ")).toMatch(/credentials for 1 user and act as them: bob/);
    expect(h.sample).toBe(true);
  });

  it("lists only what the starting identity does itself, and never takes over or rewrites itself", () => {
    const bob = "arn:aws:iam::1:user/bob";
    const r = routesOf({
      ...base,
      escalations: [esc("USER_TAKEOVER", START), esc("SELF_POLICY_GRANT", START), { ...esc("SELF_POLICY_GRANT", bob), source_principal: bob }]
    });
    expect(r.map((x) => `${x.kind}:${x.target}`)).toEqual(["SELF_POLICY_GRANT:its own policies"]);
    expect(furtherSteps({ ...base, escalations: [{ ...esc("SELF_POLICY_GRANT", bob), source_principal: bob }] })).toBe(1);
  });

  it("says plainly when nothing was found", () => {
    const h = headline(base, false);
    expect(h.none).toBe(true);
    expect(h.lines[0]).toMatch(/No way to gain more access/);
  });
});
