/**
 * DrivePicker — Select component populated by drives_list Tauri command.
 *
 * Displays each drive as: "E: (4.2 GB free of 64 GB) — Removable — SANDISK ULTRA"
 *
 * Falls back to a plain text input when drives_list is unavailable (startup
 * race, Tauri not ready, etc.).
 *
 * Usage (inside react-hook-form FormField):
 *   <DrivePicker
 *     value={field.value}
 *     onChange={field.onChange}
 *     fallbackValue={field.value}
 *   />
 */

import { useQuery } from "@tanstack/react-query";
import { HardDrive } from "lucide-react";

import { drivesList } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

const MANUAL_VALUE = "__manual__";

/** Format bytes as a human-readable string (GB or MB). */
function fmtBytes(bytes: number): string {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(0)} MB`;
  return `${bytes} B`;
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface DrivePickerProps {
  value: string;
  onChange: (value: string) => void;
  /** Placeholder shown when nothing is selected */
  placeholder?: string;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function DrivePicker({
  value,
  onChange,
  placeholder = "Select a drive or enter a path",
}: DrivePickerProps) {
  const token = getToken() ?? "";

  const { data: drives, isError } = useQuery({
    queryKey: queryKeys.drives.list,
    queryFn: () => drivesList({ token }),
    enabled: !!token,
    retry: 1,
    staleTime: 30_000,
  });

  // Fall back to plain text input when drives_list is unavailable
  if (isError || !drives) {
    return (
      <Input
        type="text"
        placeholder="e.g. E:\\"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }

  // Map select value: a drive letter "E:" or MANUAL_VALUE for free-text
  const selectValue =
    drives.some((d) => d.letter === value.replace(/\\$/, ""))
      ? value.replace(/\\$/, "")
      : value
        ? MANUAL_VALUE
        : "";

  function handleSelectChange(newVal: string) {
    if (newVal === MANUAL_VALUE) {
      onChange(value); // keep existing text value
    } else {
      // Set to drive letter with trailing backslash
      onChange(`${newVal}\\`);
    }
  }

  return (
    <div className="space-y-2">
      <Select value={selectValue} onValueChange={handleSelectChange}>
        <SelectTrigger className="w-full">
          <div className="flex items-center gap-2">
            <HardDrive className="h-4 w-4 shrink-0 text-muted-foreground" />
            <SelectValue placeholder={placeholder} />
          </div>
        </SelectTrigger>
        <SelectContent>
          {drives.map((d) => (
            <SelectItem key={d.letter} value={d.letter}>
              <span className="font-mono text-xs">{d.letter}:</span>{" "}
              <span className="text-muted-foreground text-xs">
                ({fmtBytes(d.free_bytes)} free of {fmtBytes(d.total_bytes)}) — {d.drive_type}
                {d.label ? ` — ${d.label}` : ""}
              </span>
            </SelectItem>
          ))}
          <SelectItem value={MANUAL_VALUE}>
            <span className="text-muted-foreground italic">Enter path manually...</span>
          </SelectItem>
        </SelectContent>
      </Select>

      {/* Show text input when manual entry is selected or value doesn't match any drive */}
      {(selectValue === MANUAL_VALUE || (value && !drives.some((d) => `${d.letter}\\` === value))) && (
        <Input
          type="text"
          placeholder="e.g. E:\\"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          aria-label="Evidence drive path (manual entry)"
        />
      )}
    </div>
  );
}
