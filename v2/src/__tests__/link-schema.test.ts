/**
 * Tests for link-schema.ts
 *
 * 10 tests: endpoint kind enums, source != target, weight bounds, directional 0|1.
 */
import { describe, it, expect } from "vitest";
import { linkFormSchema } from "@/lib/link-schema";

const VALID_LINK = {
  source_type: "entity" as const,
  source_id: "1",
  target_type: "entity" as const,
  target_id: "2",
  link_label: "employs",
  directional: 1,
  weight: 1.0,
  notes: "",
};

describe("linkFormSchema — valid cases", () => {
  it("accepts a valid directional entity-to-entity link", () => {
    expect(linkFormSchema.safeParse(VALID_LINK).success).toBe(true);
  });

  it("accepts a link from entity to evidence", () => {
    const result = linkFormSchema.safeParse({
      ...VALID_LINK,
      target_type: "evidence",
      target_id: "EV-001",
    });
    expect(result.success).toBe(true);
  });

  it("accepts directional = 0 (undirected)", () => {
    expect(
      linkFormSchema.safeParse({ ...VALID_LINK, directional: 0 }).success
    ).toBe(true);
  });

  it("accepts weight = 0 (minimum)", () => {
    expect(
      linkFormSchema.safeParse({ ...VALID_LINK, weight: 0 }).success
    ).toBe(true);
  });

  it("accepts weight = 1000 (maximum)", () => {
    expect(
      linkFormSchema.safeParse({ ...VALID_LINK, weight: 1000 }).success
    ).toBe(true);
  });

  it("accepts missing optional link_label", () => {
    const { link_label: _ignored, ...rest } = VALID_LINK;
    expect(linkFormSchema.safeParse(rest).success).toBe(true);
  });
});

describe("linkFormSchema — invalid cases", () => {
  it("rejects source == target (same type and id)", () => {
    const result = linkFormSchema.safeParse({
      ...VALID_LINK,
      target_id: "1", // same as source_id
    });
    expect(result.success).toBe(false);
  });

  it("rejects weight > 1000", () => {
    expect(
      linkFormSchema.safeParse({ ...VALID_LINK, weight: 1001 }).success
    ).toBe(false);
  });

  it("rejects link_label over 100 characters", () => {
    expect(
      linkFormSchema.safeParse({ ...VALID_LINK, link_label: "A".repeat(101) })
        .success
    ).toBe(false);
  });

  it("rejects invalid source_type enum value", () => {
    expect(
      linkFormSchema.safeParse({ ...VALID_LINK, source_type: "person" }).success
    ).toBe(false);
  });
});
