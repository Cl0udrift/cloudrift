import { describe, expect, it } from "vitest";
import { formatMoney, formatMoneyRange } from "./money";

describe("money", () => {
  it("formats a range with its currency", () => {
    expect(formatMoneyRange(10_000, 160_000, "USD")).toMatch(/\$10K to \$160K/);
  });
  it("accepts a symbol instead of a code", () => {
    expect(formatMoney(2500, "kr")).toBe("kr2.5K");
  });
  it("keeps the cents on small amounts", () => {
    expect(formatMoney(0.5, "USD")).toBe("$0.50");
    expect(formatMoney(16.425, "USD")).toBe("$16.43");
    expect(formatMoney(79, "USD")).toBe("$79.00");
  });
  it("shows one figure when low equals high", () => {
    expect(formatMoneyRange(500, 500, "USD")).toBe("$500.00");
  });
});
