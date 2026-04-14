/**
 * Const tuples, icon helpers, and color helpers for the link-analysis domain.
 *
 * Feeds:
 *  - Zod schemas (z.enum(...))
 *  - <Select> option lists
 *  - Cytoscape node styling
 *  - Entity chip badges
 */

// ---------------------------------------------------------------------------
// Const tuples
// ---------------------------------------------------------------------------

export const ENTITY_TYPES = [
  "person",
  "business",
  "phone",
  "email",
  "alias",
  "address",
  "account",
  "vehicle",
] as const;
export type EntityTypeTuple = typeof ENTITY_TYPES;

export const PERSON_SUBTYPES = [
  "suspect",
  "victim",
  "witness",
  "investigator",
  "poi",
  "other",
] as const;
export type PersonSubtypeTuple = typeof PERSON_SUBTYPES;

export const EVENT_CATEGORIES = [
  "observation",
  "communication",
  "movement",
  "custodial",
  "other",
] as const;
export type EventCategoryTuple = typeof EVENT_CATEGORIES;

export const LINK_ENDPOINT_KINDS = ["entity", "evidence"] as const;
export type LinkEndpointKindTuple = typeof LINK_ENDPOINT_KINDS;

// ---------------------------------------------------------------------------
// Icon name helper (lucide-react icon names)
// ---------------------------------------------------------------------------

const ENTITY_TYPE_ICON_MAP: Record<(typeof ENTITY_TYPES)[number], string> = {
  person: "User",
  business: "Building2",
  phone: "Phone",
  email: "Mail",
  alias: "Tag",
  address: "MapPin",
  account: "CreditCard",
  vehicle: "Car",
};

/** Returns a lucide-react icon component name for a given entity type. */
export function entityTypeIcon(type: (typeof ENTITY_TYPES)[number]): string {
  return ENTITY_TYPE_ICON_MAP[type];
}

// ---------------------------------------------------------------------------
// Color palette helpers (Tailwind class names)
// ---------------------------------------------------------------------------

/**
 * Returns Tailwind background + text class names for entity type chips and
 * Cytoscape node labels.
 *
 * Colors mirror v1's `link_analysis.html` groupStyles palette.
 */
const ENTITY_TYPE_COLOR_MAP: Record<
  (typeof ENTITY_TYPES)[number] | "evidence",
  { bg: string; text: string; border: string; hex: string }
> = {
  person: {
    bg: "bg-blue-500",
    text: "text-white",
    border: "border-blue-700",
    hex: "#0096c7",
  },
  business: {
    bg: "bg-yellow-400",
    text: "text-black",
    border: "border-yellow-600",
    hex: "#ffc107",
  },
  phone: {
    bg: "bg-emerald-500",
    text: "text-black",
    border: "border-emerald-700",
    hex: "#20c997",
  },
  email: {
    bg: "bg-violet-600",
    text: "text-white",
    border: "border-violet-800",
    hex: "#6f42c1",
  },
  alias: {
    bg: "bg-pink-600",
    text: "text-white",
    border: "border-pink-800",
    hex: "#d63384",
  },
  address: {
    bg: "bg-orange-500",
    text: "text-black",
    border: "border-orange-700",
    hex: "#fd7e14",
  },
  account: {
    bg: "bg-indigo-600",
    text: "text-white",
    border: "border-indigo-800",
    hex: "#6610f2",
  },
  vehicle: {
    bg: "bg-red-600",
    text: "text-white",
    border: "border-red-800",
    hex: "#dc3545",
  },
  evidence: {
    bg: "bg-slate-400",
    text: "text-black",
    border: "border-slate-600",
    hex: "#adb5bd",
  },
};

export type EntityColorInfo = {
  bg: string;
  text: string;
  border: string;
  hex: string;
};

/** Returns Tailwind + hex color info for a given entity type (or 'evidence'). */
export function entityTypeColor(
  type: (typeof ENTITY_TYPES)[number] | "evidence"
): EntityColorInfo {
  return ENTITY_TYPE_COLOR_MAP[type];
}

// ---------------------------------------------------------------------------
// Event category color helper (matches v1 crime-line CSS)
// ---------------------------------------------------------------------------

const EVENT_CATEGORY_HEX_MAP: Record<
  (typeof EVENT_CATEGORIES)[number],
  string
> = {
  observation: "#0096c7",
  communication: "#20c997",
  movement: "#fd7e14",
  custodial: "#ffc107",
  other: "#6c757d",
};

export function eventCategoryHex(
  category: (typeof EVENT_CATEGORIES)[number]
): string {
  return EVENT_CATEGORY_HEX_MAP[category];
}
