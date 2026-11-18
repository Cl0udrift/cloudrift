import { describe, expect, it } from "vitest";
import type { WhoCanResponse } from "../api/types";
import { whoCanCsv } from "./accessExport";

const data = {
  scan_id: "s", action: "sts:AssumeRole", target_arn: "arn:t", evaluated: 3, allowed: 1, possible: 0, unknown: 1, notes: [],
  callers: [{ arn: "arn:a", name: "=cmd|calc", kind: "user", account_id: "1", status: "VALIDATED_ALLOWED", reason: "x", reason_text: 'says "hi", ok',
    paths: [{ steps: [{ kind: "caller", label: "a" }, { kind: "group", label: "group G" }, { kind: "target", label: "t" }] }] }],
  unknown_callers: [{ arn: "arn:u", name: "u", kind: "role", account_id: "1", reason: "missing_identity_policy", reason_text: "no docs" }]
} as WhoCanResponse;

describe("whoCanCsv", () => {
  const lines = whoCanCsv(data, "target").trim().split("\n");
  it("lists callers then unknown callers, with the path", () => {
    expect(lines[1]).toBe("result,kind,name,arn,account,reason,path");
    expect(lines[2]).toContain("a > group G > t");
    expect(lines[3].startsWith("unknown,role,u,")).toBe(true);
  });
  it("quotes commas and quotes, and defuses spreadsheet formulas", () => {
    expect(lines[2]).toContain("'=cmd|calc");
    expect(lines[2]).toContain('"says ""hi"", ok"');
  });
});
