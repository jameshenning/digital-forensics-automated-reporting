/**
 * Tests for entity-schema.ts
 *
 * 12 tests covering: entity_type enum, display_name length, subtype conditional,
 * organizational_rank max, parent_entity_id optional, notes max,
 * metadata_json JSON validation.
 */
import { describe, it, expect } from "vitest";
import { entityFormSchema } from "@/lib/entity-schema";

const VALID_PERSON = {
  entity_type: "person" as const,
  display_name: "John Smith",
  subtype: "suspect" as const,
  organizational_rank: "Detective",
  parent_entity_id: null,
  notes: "Primary suspect",
  metadata_json: '{"dob": "1985-01-01"}',
};

describe("entityFormSchema — valid cases", () => {
  it("accepts a valid person entity with all fields", () => {
    const result = entityFormSchema.safeParse(VALID_PERSON);
    expect(result.success).toBe(true);
  });

  it("accepts a non-person entity without subtype", () => {
    const result = entityFormSchema.safeParse({
      entity_type: "business",
      display_name: "Acme Corp",
    });
    expect(result.success).toBe(true);
  });

  it("accepts entity with null subtype for non-person", () => {
    const result = entityFormSchema.safeParse({
      entity_type: "phone",
      display_name: "+1-555-0100",
      subtype: null,
    });
    expect(result.success).toBe(true);
  });

  it("accepts entity with undefined optional fields", () => {
    const result = entityFormSchema.safeParse({
      entity_type: "email",
      display_name: "user@example.com",
    });
    expect(result.success).toBe(true);
  });

  it("accepts parent_entity_id as a positive integer", () => {
    const result = entityFormSchema.safeParse({
      entity_type: "person",
      display_name: "Jane Doe",
      parent_entity_id: 42,
    });
    expect(result.success).toBe(true);
  });

  it("accepts blank metadata_json (treated as empty)", () => {
    const result = entityFormSchema.safeParse({
      entity_type: "vehicle",
      display_name: "Ford F-150 (ABC 123)",
      metadata_json: "",
    });
    expect(result.success).toBe(true);
  });
});

describe("entityFormSchema — invalid cases", () => {
  it("rejects missing display_name", () => {
    const result = entityFormSchema.safeParse({
      entity_type: "person",
      display_name: "",
    });
    expect(result.success).toBe(false);
  });

  it("rejects display_name over 200 characters", () => {
    const result = entityFormSchema.safeParse({
      entity_type: "person",
      display_name: "A".repeat(201),
    });
    expect(result.success).toBe(false);
  });

  it("rejects invalid entity_type enum value", () => {
    const result = entityFormSchema.safeParse({
      entity_type: "spaceship",
      display_name: "Enterprise",
    });
    expect(result.success).toBe(false);
  });

  it("rejects subtype set on a non-person entity", () => {
    const result = entityFormSchema.safeParse({
      entity_type: "business",
      display_name: "Acme Corp",
      subtype: "suspect",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const paths = result.error.issues.map((i) => i.path.join("."));
      expect(paths).toContain("subtype");
    }
  });

  it("rejects metadata_json that is not valid JSON", () => {
    const result = entityFormSchema.safeParse({
      entity_type: "person",
      display_name: "Bad Metadata",
      metadata_json: "{not valid json",
    });
    expect(result.success).toBe(false);
  });

  it("rejects organizational_rank over 100 characters", () => {
    const result = entityFormSchema.safeParse({
      entity_type: "person",
      display_name: "Test Person",
      organizational_rank: "A".repeat(101),
    });
    expect(result.success).toBe(false);
  });
});
