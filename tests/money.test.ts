/** Verifies multi-currency display without assuming two decimal places. */

import { describe, expect, it } from "vitest";

import { formatMoney, parseMajorAmount } from "../src/client/money";

describe("formatMoney", () => {
  it("formats two-decimal currencies such as ZWG and USD", () => {
    expect(formatMoney(12_345, "ZWG", 2, "en-ZW")).toContain("123.45");
    expect(formatMoney(12_345, "USD", 2, "en-US")).toBe("$123.45");
  });

  it("honours zero and three-decimal currency exponents", () => {
    expect(formatMoney(1_234, "JPY", 0, "ja-JP")).toContain("1,234");
    expect(formatMoney(1_234, "KWD", 3, "en-US")).toContain("1.234");
  });

  it("rejects unsafe amounts and unsupported exponents", () => {
    expect(() => formatMoney(Number.MAX_SAFE_INTEGER + 1, "USD", 2)).toThrow();
    expect(() => formatMoney(100, "USD", 5)).toThrow();
  });

  it("parses major-unit input using the configured exponent", () => {
    expect(parseMajorAmount("123.45", 2)).toBe(12_345);
    expect(parseMajorAmount("1234", 0)).toBe(1_234);
    expect(parseMajorAmount("1.2", 3)).toBe(1_200);
  });

  it("rejects excess precision, signs, and unsafe amounts", () => {
    expect(() => parseMajorAmount("1.001", 2)).toThrow("2 decimal places");
    expect(() => parseMajorAmount("-1", 2)).toThrow();
    expect(() => parseMajorAmount("9007199254740992", 0)).toThrow("too large");
  });
});
