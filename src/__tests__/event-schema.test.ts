/**
 * Tests for event-schema.ts
 *
 * 10 tests: title length, datetime format, end >= start, category enum.
 */
import { describe, it, expect } from "vitest";
import { eventFormSchema } from "@/lib/event-schema";

const VALID_EVENT = {
  title: "Suspect observed at location",
  description: "Seen entering the building at 14:30",
  event_datetime: "2026-03-15T14:30",
  event_end_datetime: "2026-03-15T15:00",
  category: "observation" as const,
  related_entity_id: null,
  related_evidence_id: null,
};

describe("eventFormSchema — valid cases", () => {
  it("accepts a fully populated valid event", () => {
    expect(eventFormSchema.safeParse(VALID_EVENT).success).toBe(true);
  });

  it("accepts an event with only required fields", () => {
    expect(
      eventFormSchema.safeParse({
        title: "Minimal event",
        event_datetime: "2026-03-15T09:00",
      }).success
    ).toBe(true);
  });

  it("accepts event_end_datetime equal to event_datetime (boundary)", () => {
    expect(
      eventFormSchema.safeParse({
        ...VALID_EVENT,
        event_end_datetime: VALID_EVENT.event_datetime,
      }).success
    ).toBe(true);
  });

  it("accepts null category", () => {
    expect(
      eventFormSchema.safeParse({ ...VALID_EVENT, category: null }).success
    ).toBe(true);
  });

  it("accepts related_entity_id as a positive integer", () => {
    expect(
      eventFormSchema.safeParse({ ...VALID_EVENT, related_entity_id: 5 }).success
    ).toBe(true);
  });
});

describe("eventFormSchema — invalid cases", () => {
  it("rejects empty title", () => {
    expect(
      eventFormSchema.safeParse({ ...VALID_EVENT, title: "" }).success
    ).toBe(false);
  });

  it("rejects title over 200 characters", () => {
    expect(
      eventFormSchema.safeParse({ ...VALID_EVENT, title: "A".repeat(201) }).success
    ).toBe(false);
  });

  it("rejects description over 5000 characters", () => {
    expect(
      eventFormSchema.safeParse({
        ...VALID_EVENT,
        description: "A".repeat(5001),
      }).success
    ).toBe(false);
  });

  it("rejects event_end_datetime before event_datetime", () => {
    const result = eventFormSchema.safeParse({
      ...VALID_EVENT,
      event_end_datetime: "2026-03-15T13:00", // before 14:30
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const paths = result.error.issues.map((i) => i.path.join("."));
      expect(paths).toContain("event_end_datetime");
    }
  });

  it("rejects invalid category enum value", () => {
    expect(
      eventFormSchema.safeParse({ ...VALID_EVENT, category: "explosion" }).success
    ).toBe(false);
  });
});
