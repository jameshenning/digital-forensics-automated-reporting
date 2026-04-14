/**
 * Tests for link-analysis-enums.ts
 *
 * - Const tuple presence
 * - entityTypeColor returns non-empty class string for every EntityType + 'evidence'
 * - entityTypeIcon returns a non-empty string for every EntityType
 */
import { describe, it, expect } from "vitest";
import {
  ENTITY_TYPES,
  PERSON_SUBTYPES,
  EVENT_CATEGORIES,
  LINK_ENDPOINT_KINDS,
  entityTypeColor,
  entityTypeIcon,
} from "@/lib/link-analysis-enums";

describe("const tuples", () => {
  it("ENTITY_TYPES contains all 8 expected types", () => {
    expect(ENTITY_TYPES).toContain("person");
    expect(ENTITY_TYPES).toContain("business");
    expect(ENTITY_TYPES).toContain("phone");
    expect(ENTITY_TYPES).toContain("email");
    expect(ENTITY_TYPES).toContain("alias");
    expect(ENTITY_TYPES).toContain("address");
    expect(ENTITY_TYPES).toContain("account");
    expect(ENTITY_TYPES).toContain("vehicle");
    expect(ENTITY_TYPES).toHaveLength(8);
  });

  it("PERSON_SUBTYPES contains all 6 expected subtypes", () => {
    expect(PERSON_SUBTYPES).toContain("suspect");
    expect(PERSON_SUBTYPES).toContain("victim");
    expect(PERSON_SUBTYPES).toContain("witness");
    expect(PERSON_SUBTYPES).toContain("investigator");
    expect(PERSON_SUBTYPES).toContain("poi");
    expect(PERSON_SUBTYPES).toContain("other");
    expect(PERSON_SUBTYPES).toHaveLength(6);
  });

  it("EVENT_CATEGORIES contains all 5 expected categories", () => {
    expect(EVENT_CATEGORIES).toContain("observation");
    expect(EVENT_CATEGORIES).toContain("communication");
    expect(EVENT_CATEGORIES).toContain("movement");
    expect(EVENT_CATEGORIES).toContain("custodial");
    expect(EVENT_CATEGORIES).toContain("other");
    expect(EVENT_CATEGORIES).toHaveLength(5);
  });

  it("LINK_ENDPOINT_KINDS contains 'entity' and 'evidence'", () => {
    expect(LINK_ENDPOINT_KINDS).toContain("entity");
    expect(LINK_ENDPOINT_KINDS).toContain("evidence");
    expect(LINK_ENDPOINT_KINDS).toHaveLength(2);
  });
});

describe("entityTypeColor", () => {
  it.each([...ENTITY_TYPES, "evidence"] as const)(
    "returns non-empty bg class string for type '%s'",
    (type) => {
      const colors = entityTypeColor(type);
      expect(typeof colors.bg).toBe("string");
      expect(colors.bg.length).toBeGreaterThan(0);
      expect(colors.bg).toMatch(/^bg-/);
    }
  );

  it.each([...ENTITY_TYPES, "evidence"] as const)(
    "returns a non-empty hex color for type '%s'",
    (type) => {
      const colors = entityTypeColor(type);
      expect(typeof colors.hex).toBe("string");
      expect(colors.hex).toMatch(/^#[0-9a-fA-F]{6}$/);
    }
  );
});

describe("entityTypeIcon", () => {
  it.each(ENTITY_TYPES)(
    "returns a non-empty string icon name for type '%s'",
    (type) => {
      const icon = entityTypeIcon(type);
      expect(typeof icon).toBe("string");
      expect(icon.length).toBeGreaterThan(0);
    }
  );
});
