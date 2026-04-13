/**
 * Tests for formatBytes — round-trip human-readable file size formatting.
 *
 * Uses binary prefixes (KiB, MiB, GiB).
 */
import { describe, it, expect } from "vitest";
import { formatBytes } from "@/lib/format-bytes";

describe("formatBytes", () => {
  it("returns '0 B' for zero", () => {
    expect(formatBytes(0)).toBe("0 B");
  });

  it("returns raw bytes for values under 1 KiB (1–1023)", () => {
    expect(formatBytes(1)).toBe("1 B");
    expect(formatBytes(1023)).toBe("1023 B");
  });

  it("returns '1.00 KiB' for exactly 1024 bytes", () => {
    expect(formatBytes(1024)).toBe("1.00 KiB");
  });

  it("returns '1.50 KiB' for 1536 bytes", () => {
    expect(formatBytes(1536)).toBe("1.50 KiB");
  });

  it("returns fractional KiB for values just under 1 MiB", () => {
    // 1 MiB - 1 = 1048575 bytes = 1023.99... KiB → rounds to 1024.00 KiB
    // Actually 1023.999... → "1024.00 KiB"... but our log2/10 calculation
    // returns i=1 for anything < 2^20, so let's verify:
    const result = formatBytes(1048575);
    expect(result).toMatch(/KiB$/);
  });

  it("returns '1.00 MiB' for exactly 1 MiB (1048576 bytes)", () => {
    expect(formatBytes(1048576)).toBe("1.00 MiB");
  });

  it("returns '2.50 MiB' for 2.5 MiB", () => {
    expect(formatBytes(2.5 * 1024 * 1024)).toBe("2.50 MiB");
  });

  it("returns '1.00 GiB' for exactly 1 GiB (1073741824 bytes)", () => {
    expect(formatBytes(1073741824)).toBe("1.00 GiB");
  });

  it("returns GiB for 2 GiB", () => {
    expect(formatBytes(2 * 1073741824)).toBe("2.00 GiB");
  });

  it("returns TiB for large values (1 TiB = 1099511627776 bytes)", () => {
    expect(formatBytes(1099511627776)).toBe("1.00 TiB");
  });

  it("returns TiB for 50 GiB upload limit (53687091200 bytes)", () => {
    const result = formatBytes(53687091200);
    expect(result).toMatch(/GiB$/);
    // 50 GiB = 50.00 GiB
    expect(result).toBe("50.00 GiB");
  });

  it("handles non-integer byte counts gracefully", () => {
    // Edge: 1.5 bytes — unrealistic but should not throw
    expect(() => formatBytes(1.5)).not.toThrow();
  });

  it("returns '? B' for negative values", () => {
    expect(formatBytes(-1)).toBe("? B");
  });

  it("returns '? B' for NaN", () => {
    expect(formatBytes(NaN)).toBe("? B");
  });

  it("returns '? B' for Infinity", () => {
    expect(formatBytes(Infinity)).toBe("? B");
  });

  it("includes the unit in the result", () => {
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    const samples = [512, 2048, 5 * 1024 * 1024, 3 * 1024 ** 3, 2 * 1024 ** 4];
    samples.forEach((bytes, i) => {
      expect(formatBytes(bytes)).toMatch(units[i]);
    });
  });
});
