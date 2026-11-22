import { describe, expect, it } from "vitest";
import type { PrincipalListItem } from "../api/types";
import { plural, principalReasons, sortByAttention } from "./principalRisk";

const base: PrincipalListItem = {
  arn: "a", name: "a", kind: "user", account_id: "1", groups: [], policy_count: 0, has_deny: false, retrieval_status: "ok",
  broad_candidates: [], credentials_collected: true, console_enabled: false, mfa_active: false, active_keys: 0, credential_findings: 0, key_issues: 0, finding_count: 0
};

describe("principalRisk", () => {
  it("lists only stored facts as reasons", () => {
    expect(principalReasons(base)).toEqual([]);
    expect(principalReasons({ ...base, console_enabled: true })).toEqual(["console without MFA"]);
    // A user whose credential report was not collected is not "without MFA".
    expect(principalReasons({ ...base, credentials_collected: false, console_enabled: true })).toEqual(["credentials unknown"]);
    expect(principalReasons({ ...base, broad_candidates: ["administrative_wildcard"], key_issues: 1 })).toEqual(["administrative access", "1 key issue"]);
    // Console without MFA is one fact. It must not also be counted as a key issue.
    expect(principalReasons({ ...base, console_enabled: true, credential_findings: 1, key_issues: 0 })).toEqual(["console without MFA"]);
  });

  it("puts the riskiest first and keeps ties alphabetical", () => {
    const quiet = { ...base, arn: "q", name: "quiet" };
    const admin = { ...base, arn: "d", name: "admin", broad_candidates: ["administrative_wildcard"] };
    const alpha = { ...base, arn: "b", name: "alpha" };
    expect(sortByAttention([quiet, admin, alpha]).map((p) => p.name)).toEqual(["admin", "alpha", "quiet"]);
  });

  it("pluralizes", () => {
    expect(plural(1, "policy", "policies")).toBe("1 policy");
    expect(plural(2, "policy", "policies")).toBe("2 policies");
  });
});
