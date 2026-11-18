import { describe, expect, it } from "vitest";
import type { AccessPath } from "../api/types";
import { accessSentence } from "./accessSentence";

const path = (...steps: [AccessPath["steps"][number]["kind"], string][]): AccessPath => ({ steps: steps.map(([kind, label]) => ({ kind, label })) });

describe("accessSentence", () => {
  it("explains a group route", () => {
    expect(accessSentence("alice", "assume this role", path(["caller", "alice"], ["group", "group Ops"], ["policy", "AssumeAny"], ["target", "t"])))
      .toBe("alice can assume this role because it is in group Ops, which has the policy AssumeAny.");
  });
  it("explains trust, inline and attached routes", () => {
    expect(accessSentence("bob", "x", path(["caller", "bob"], ["trust", "trust policy of t"], ["target", "t"]))).toContain("trust policy names it");
    expect(accessSentence("bob", "x", path(["caller", "bob"], ["policy", "inline policy on bob"], ["target", "t"]))).toContain("own inline policy");
    expect(accessSentence("bob", "x", path(["caller", "bob"], ["policy", "ReadAll"], ["target", "t"]))).toContain("policy ReadAll is attached");
  });
  it("falls back without a path", () => {
    expect(accessSentence("bob", "x")).toBe("bob can x.");
  });
});
