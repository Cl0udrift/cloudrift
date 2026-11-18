import { describe, expect, it } from "vitest";
import { cov, plural } from "./inventoryView";

describe("inventoryView", () => {
  it("reads upper-case service coverage from the API", () => {
    expect(cov({ coverage: "COLLECTED" })).toBe("collected");
    expect(cov({ coverage: "NOT_RECORDED" })).toBe("not_recorded");
  });
  it("pluralises counts", () => {
    expect(plural(1, "service")).toBe("1 service");
    expect(plural(0, "region")).toBe("0 regions");
  });
});
