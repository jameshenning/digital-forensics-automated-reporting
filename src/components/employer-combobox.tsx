/**
 * EmployerCombobox — multi-select combobox for linking a person to business
 * entities in the same case via "employs" entity_links.
 *
 * - Loads all `entity_type === "business"` entities from the case via
 *   `entitiesListForCase`.
 * - Supports selecting existing businesses (by entity_id) and adding new
 *   free-text names (which become stub business entities on save).
 * - Controlled: parent passes `value` + `onChange`; the combobox never stores
 *   any employer state itself.
 * - Validation (client-side, mirrors Rust rules):
 *     - Name cannot be blank after trim.
 *     - Name cannot start with '-' (CWE-88 hygiene).
 *     - Name cannot exceed 200 characters.
 *
 * No Popover/cmdk is available in this project (not in package.json), so the
 * dropdown is a plain absolutely-positioned div. Focus management is handled
 * via onBlur/onFocus to close when focus leaves the composite widget.
 */

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { X, ChevronsUpDown, Plus } from "lucide-react";

import { entitiesListForCase, type Entity } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EmployerSelection {
  selectedBusinessIds: number[];
  newBusinessNames: string[];
}

interface EmployerComboboxProps {
  caseId: string;
  value: EmployerSelection;
  onChange: (v: EmployerSelection) => void;
  disabled?: boolean;
}

// ---------------------------------------------------------------------------
// Validation helpers (mirror Rust rules)
// ---------------------------------------------------------------------------

const DISPLAY_NAME_MAX_LEN = 200;

function validateNewName(name: string): string | null {
  const trimmed = name.trim();
  if (trimmed.length === 0) return "Name cannot be blank.";
  if (trimmed.startsWith("-"))
    return "Name cannot start with '-' (safety rule).";
  if (trimmed.length > DISPLAY_NAME_MAX_LEN)
    return `Name must be at most ${DISPLAY_NAME_MAX_LEN} characters.`;
  return null;
}

// ---------------------------------------------------------------------------
// EmployerCombobox
// ---------------------------------------------------------------------------

export function EmployerCombobox({
  caseId,
  value,
  onChange,
  disabled = false,
}: EmployerComboboxProps) {
  const token = getToken() ?? "";

  const [open, setOpen] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const [nameError, setNameError] = React.useState<string | null>(null);

  // Ref for the whole widget so we can detect blur-outside to close the panel.
  const widgetRef = React.useRef<HTMLDivElement>(null);

  // Fetch all business entities for the case.
  const { data: allEntities = [] } = useQuery<Entity[]>({
    queryKey: queryKeys.entities.listForCase(caseId),
    queryFn: () => entitiesListForCase({ token, case_id: caseId }),
    enabled: !!token && !!caseId,
    staleTime: 30_000,
  });

  const businesses = React.useMemo(
    () => allEntities.filter((e) => e.entity_type === "business"),
    [allEntities],
  );

  // Filtered list based on the search box.
  const filtered = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return businesses;
    return businesses.filter((b) =>
      b.display_name.toLowerCase().includes(q),
    );
  }, [businesses, search]);

  // Whether the current search text exactly matches an existing business name.
  const searchMatchesExisting = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    return q.length > 0 && businesses.some(
      (b) => b.display_name.toLowerCase() === q,
    );
  }, [businesses, search]);

  // Whether to show the "Create new: …" row.
  const showCreateRow =
    search.trim().length > 0 &&
    !searchMatchesExisting &&
    !value.newBusinessNames.some(
      (n) => n.trim().toLowerCase() === search.trim().toLowerCase(),
    );

  // Close panel when focus leaves the widget.
  function handleBlur(e: React.FocusEvent<HTMLDivElement>) {
    if (!widgetRef.current?.contains(e.relatedTarget as Node)) {
      setOpen(false);
    }
  }

  function toggleBusiness(biz: Entity) {
    const id = biz.entity_id;
    const already = value.selectedBusinessIds.includes(id);
    onChange({
      ...value,
      selectedBusinessIds: already
        ? value.selectedBusinessIds.filter((x) => x !== id)
        : [...value.selectedBusinessIds, id],
    });
  }

  function addNewName(raw: string) {
    const trimmed = raw.trim();
    const err = validateNewName(trimmed);
    if (err) {
      setNameError(err);
      return;
    }
    // Don't add duplicates (case-insensitive).
    if (
      value.newBusinessNames.some(
        (n) => n.trim().toLowerCase() === trimmed.toLowerCase(),
      )
    ) {
      setSearch("");
      return;
    }
    setNameError(null);
    onChange({
      ...value,
      newBusinessNames: [...value.newBusinessNames, trimmed],
    });
    setSearch("");
    // Keep popover open — the user may want to add more.
  }

  function removeSelectedId(id: number) {
    onChange({
      ...value,
      selectedBusinessIds: value.selectedBusinessIds.filter((x) => x !== id),
    });
  }

  function removeNewName(name: string) {
    onChange({
      ...value,
      newBusinessNames: value.newBusinessNames.filter((n) => n !== name),
    });
  }

  function handleSearchKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      e.preventDefault();
      if (showCreateRow) {
        addNewName(search);
      }
    }
    if (e.key === "Escape") {
      setOpen(false);
    }
  }

  // Build display pills for the trigger button.
  const selectedBizNames = value.selectedBusinessIds.flatMap((id) => {
    const biz = businesses.find((b) => b.entity_id === id);
    return biz ? [biz.display_name] : [];
  });
  const allPillNames = [...selectedBizNames, ...value.newBusinessNames];

  const triggerLabel =
    allPillNames.length === 0
      ? "Select employers…"
      : allPillNames.length <= 2
        ? allPillNames.join(", ")
        : `${allPillNames.slice(0, 2).join(", ")} +${allPillNames.length - 2} more`;

  return (
    <div
      ref={widgetRef}
      className="relative"
      onBlur={handleBlur}
    >
      {/* Selected pills */}
      {allPillNames.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2">
          {value.selectedBusinessIds.map((id) => {
            const biz = businesses.find((b) => b.entity_id === id);
            if (!biz) return null;
            return (
              <Badge key={`id-${id}`} variant="secondary" className="gap-1">
                {biz.display_name}
                {!disabled && (
                  <button
                    type="button"
                    aria-label={`Remove ${biz.display_name}`}
                    onClick={() => removeSelectedId(id)}
                    className="rounded-sm opacity-70 hover:opacity-100"
                  >
                    <X className="h-3 w-3" />
                  </button>
                )}
              </Badge>
            );
          })}
          {value.newBusinessNames.map((name) => (
            <Badge key={`new-${name}`} variant="outline" className="gap-1">
              {name}
              <span className="text-[10px] text-muted-foreground ml-0.5">(new)</span>
              {!disabled && (
                <button
                  type="button"
                  aria-label={`Remove ${name}`}
                  onClick={() => removeNewName(name)}
                  className="rounded-sm opacity-70 hover:opacity-100"
                >
                  <X className="h-3 w-3" />
                </button>
              )}
            </Badge>
          ))}
        </div>
      )}

      {/* Trigger button */}
      <Button
        type="button"
        variant="outline"
        role="combobox"
        aria-expanded={open}
        disabled={disabled}
        onClick={() => setOpen((v) => !v)}
        className="w-full justify-between font-normal text-left"
      >
        <span className="truncate text-muted-foreground">
          {allPillNames.length === 0 ? triggerLabel : "Add more employers…"}
        </span>
        <ChevronsUpDown className="h-4 w-4 ml-2 shrink-0 opacity-50" />
      </Button>

      {/* Dropdown panel */}
      {open && (
        <div
          className={cn(
            "absolute z-50 mt-1 w-full rounded-md border bg-popover shadow-md",
            "max-h-72 flex flex-col",
          )}
        >
          {/* Search input */}
          <div className="p-2 border-b">
            <Input
              autoFocus
              placeholder="Search businesses or type a new name…"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setNameError(null);
              }}
              onKeyDown={handleSearchKeyDown}
              className="h-8 text-sm"
            />
            {nameError && (
              <p className="text-xs text-destructive mt-1">{nameError}</p>
            )}
          </div>

          {/* Scrollable list */}
          <div className="overflow-y-auto flex-1">
            {filtered.length === 0 && !showCreateRow && (
              <p className="px-3 py-6 text-sm text-muted-foreground text-center">
                No businesses found.
              </p>
            )}

            {filtered.map((biz) => {
              const selected = value.selectedBusinessIds.includes(biz.entity_id);
              return (
                <button
                  key={biz.entity_id}
                  type="button"
                  onClick={() => toggleBusiness(biz)}
                  className={cn(
                    "w-full flex items-center gap-2 px-3 py-2 text-sm text-left",
                    "hover:bg-accent hover:text-accent-foreground cursor-pointer",
                    selected && "bg-accent/50",
                  )}
                >
                  {/* Checkbox indicator */}
                  <span
                    className={cn(
                      "h-4 w-4 rounded border flex items-center justify-center shrink-0",
                      selected
                        ? "bg-primary border-primary text-primary-foreground"
                        : "border-input",
                    )}
                    aria-hidden="true"
                  >
                    {selected && (
                      <svg
                        viewBox="0 0 10 10"
                        className="h-3 w-3 fill-current"
                      >
                        <path d="M1.5 5l2.5 2.5 5-5" stroke="currentColor" strokeWidth="1.5" fill="none" />
                      </svg>
                    )}
                  </span>
                  <span className="truncate">{biz.display_name}</span>
                </button>
              );
            })}

            {/* Create new row */}
            {showCreateRow && (
              <button
                type="button"
                onClick={() => addNewName(search)}
                className={cn(
                  "w-full flex items-center gap-2 px-3 py-2 text-sm text-left",
                  "hover:bg-accent hover:text-accent-foreground cursor-pointer",
                  "border-t",
                )}
              >
                <Plus className="h-4 w-4 shrink-0 text-muted-foreground" />
                <span>
                  Create new:{" "}
                  <span className="font-medium">&quot;{search.trim()}&quot;</span>
                </span>
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
