import { describe, expect, it } from "vitest";
import type { ScanListItem } from "../api/types";
import { baselineChoices, getPreviousScanIdForDiff } from "./scanOrder";

const scan = (id: string, accounts: string[]) => ({ scan_id: id, account_ids: accounts }) as ScanListItem;
// newest first
const scans = [scan("b2", ["2"]), scan("a2", ["1"]), scan("b1", ["2"]), scan("a1", ["1"])];

describe("diff baseline", () => {
  it("is the previous scan of the same accounts, skipping other accounts", () => {
    expect(getPreviousScanIdForDiff(scans, "a2")).toBe("a1");
    expect(getPreviousScanIdForDiff(scans, "b2")).toBe("b1");
  });
  it("is none for the first scan of an account", () => {
    expect(getPreviousScanIdForDiff(scans, "a1")).toBeNull();
  });
  it("lists same-account scans first and marks the rest", () => {
    const c = baselineChoices(scans, "a2");
    expect(c.map((x) => x.id)).toEqual(["a1", "b2", "b1"]);
    expect(c.map((x) => x.sameAccounts)).toEqual([true, false, false]);
  });
});
