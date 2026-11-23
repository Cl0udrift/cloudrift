import { describe, expect, it } from "vitest";
import { formatUsd } from "./format";

describe("formatUsd", () => {
  it("shows a dash for zero, since no modeled figure exists", () => {
    expect(formatUsd(0)).toBe("—");
    expect(formatUsd(12.5)).toBe("$12.50");
  });
});
