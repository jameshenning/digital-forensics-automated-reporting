/**
 * BusinessForm — add/edit a business entity with a logo upload and an
 * industry/sector dropdown. Used inside a Dialog from the BusinessesPanel.
 *
 * The logo picker opens a Tauri native file dialog filtered to image
 * extensions. The actual logo upload happens via `businessLogoUpload` AFTER
 * the entity row exists — so on create, the parent panel calls
 * `entity_add` first, then `business_logo_upload` with the returned
 * entity_id. On edit, the parent panel calls `entity_update` and
 * `business_logo_upload` in parallel.
 *
 * The industry dropdown writes a human-readable label string into
 * `organizational_rank`. When "other" is selected a custom text input is
 * revealed and its value is written instead. On mount in edit mode, the
 * stored value is mapped back to a known dropdown option if it matches one
 * of the BUSINESS_INDUSTRY_LABELS values; otherwise "other" is preselected
 * and the stored text is shown in the custom input.
 *
 * Validation: uses business-schema.ts (zod). See case-schema.ts for the
 * z.input<> vs z.infer<> gotcha.
 */

import React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { open as openFilePicker } from "@tauri-apps/plugin-dialog";
import { convertFileSrc } from "@tauri-apps/api/core";
import { Upload, X, Building2 } from "lucide-react";

import {
  businessFormSchema,
  type BusinessFormValues,
  BUSINESS_INDUSTRY_TYPES,
  BUSINESS_INDUSTRY_LABELS,
  type BusinessIndustryType,
} from "@/lib/business-schema";

import { BusinessIdentifierEditor } from "@/components/business-identifier-editor";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Map a stored `organizational_rank` string back to a known dropdown value.
 * If the stored string matches one of the human-readable labels, return the
 * corresponding key. Otherwise return "other" so the custom input is shown.
 */
function rankToDropdownValue(rank: string | undefined | null): BusinessIndustryType {
  if (!rank) return "other";
  for (const key of BUSINESS_INDUSTRY_TYPES) {
    if (BUSINESS_INDUSTRY_LABELS[key] === rank) return key;
  }
  // Stored value doesn't match any label — show as custom
  return "other";
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface BusinessFormProps {
  defaultValues?: Partial<BusinessFormValues>;
  /** Existing logo path if any — rendered as the current image in edit mode. */
  currentLogoPath?: string | null;
  /** Parent entity id when editing an existing business; null when adding a
   *  new one. Enables the multi-identifier editor once the parent row
   *  exists. */
  entityId?: number | null;
  isPending: boolean;
  onSubmit: (values: BusinessFormValues, pickedLogoPath: string | null) => void;
  onCancel: () => void;
  submitLabel?: string;
}

// ---------------------------------------------------------------------------
// BusinessForm
// ---------------------------------------------------------------------------

export function BusinessForm({
  defaultValues,
  currentLogoPath,
  entityId = null,
  isPending,
  onSubmit,
  onCancel,
  submitLabel = "Save",
}: BusinessFormProps) {
  // ── Industry dropdown state ──────────────────────────────────────────────
  // Derive the initial dropdown selection from the stored organizational_rank.
  const initialDropdownValue = rankToDropdownValue(defaultValues?.organizational_rank);
  const [industryDropdown, setIndustryDropdown] = React.useState<BusinessIndustryType>(
    initialDropdownValue,
  );
  // If initialDropdownValue is "other" AND there is a stored value, show it
  // in the custom text box; otherwise start empty.
  const initialCustomIndustry =
    initialDropdownValue === "other" && defaultValues?.organizational_rank
      ? defaultValues.organizational_rank
      : "";
  const [customIndustry, setCustomIndustry] = React.useState(initialCustomIndustry);

  // ── Logo picker state ────────────────────────────────────────────────────
  const [pickedLogoPath, setPickedLogoPath] = React.useState<string | null>(null);
  const [logoError, setLogoError] = React.useState<string | null>(null);

  async function handlePickLogo() {
    setLogoError(null);
    try {
      const result = await openFilePicker({
        multiple: false,
        directory: false,
        filters: [
          {
            name: "Image",
            extensions: ["jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff", "tif"],
          },
        ],
      });
      if (result === null) return;
      const path = typeof result === "string" ? result : (result as { path: string }).path;
      setPickedLogoPath(path);
    } catch (err) {
      setLogoError(
        err instanceof Error ? err.message : "Failed to open the file picker.",
      );
    }
  }

  function handleClearPickedLogo() {
    setPickedLogoPath(null);
  }

  // Preview URL for the logo. Prefers the just-picked logo over the stored one.
  const previewSrc: string | null = React.useMemo(() => {
    if (pickedLogoPath) {
      try {
        return convertFileSrc(pickedLogoPath);
      } catch {
        return null;
      }
    }
    if (currentLogoPath) {
      try {
        return convertFileSrc(currentLogoPath);
      } catch {
        return null;
      }
    }
    return null;
  }, [pickedLogoPath, currentLogoPath]);

  // ── Form setup ───────────────────────────────────────────────────────────
  const form = useForm<BusinessFormValues>({
    resolver: zodResolver(businessFormSchema),
    defaultValues: {
      display_name: "",
      organizational_rank: "",
      notes: "",
      ...defaultValues,
    },
  });

  function handleSubmit(values: BusinessFormValues) {
    // Resolve the final organizational_rank value from the dropdown state,
    // overriding whatever react-hook-form has for the (now hidden) field.
    let resolvedRank: string;
    if (industryDropdown === "other") {
      resolvedRank = customIndustry.trim();
    } else {
      resolvedRank = BUSINESS_INDUSTRY_LABELS[industryDropdown];
    }
    onSubmit({ ...values, organizational_rank: resolvedRank || undefined }, pickedLogoPath);
  }

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(handleSubmit)}
        className="space-y-5"
        noValidate
      >
        {/* Logo picker row */}
        <div className="flex items-center gap-4">
          <div className="h-24 w-24 rounded-full overflow-hidden bg-muted border flex items-center justify-center shrink-0">
            {previewSrc ? (
              <img
                src={previewSrc}
                alt="Business logo"
                className="h-full w-full object-cover"
              />
            ) : (
              <Building2 className="h-10 w-10 text-muted-foreground" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium">Logo</p>
            <p className="text-xs text-muted-foreground mb-2">
              JPG, PNG, GIF, WebP, BMP, or TIFF. Max 10 MiB. Stored outside the
              evidence tree.
            </p>
            <div className="flex gap-2 flex-wrap">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => void handlePickLogo()}
              >
                <Upload className="h-4 w-4 mr-1.5" />
                {pickedLogoPath || currentLogoPath ? "Replace logo" : "Upload logo"}
              </Button>
              {pickedLogoPath && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={handleClearPickedLogo}
                >
                  <X className="h-4 w-4 mr-1.5" />
                  Clear selection
                </Button>
              )}
            </div>
            {logoError && (
              <p className="text-xs text-destructive mt-1">{logoError}</p>
            )}
          </div>
        </div>

        {/* Display name */}
        <FormField
          control={form.control}
          name="display_name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>
                Business / Organization Name <span aria-hidden="true">*</span>
              </FormLabel>
              <FormControl>
                <Input placeholder="Acme Corporation" autoFocus {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Industry / Sector dropdown */}
        <div>
          <FormItem>
            <FormLabel>Industry / Sector</FormLabel>
            <Select
              value={industryDropdown}
              onValueChange={(v) => setIndustryDropdown(v as BusinessIndustryType)}
            >
              <FormControl>
                <SelectTrigger>
                  <SelectValue placeholder="Select industry (optional)" />
                </SelectTrigger>
              </FormControl>
              <SelectContent>
                {BUSINESS_INDUSTRY_TYPES.map((type) => (
                  <SelectItem key={type} value={type}>
                    {BUSINESS_INDUSTRY_LABELS[type]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FormDescription className="text-xs">
              Optional. Used as an industry or sector badge on the card.
            </FormDescription>
          </FormItem>

          {industryDropdown === "other" && (
            <div className="mt-2">
              <Input
                placeholder="Custom industry (e.g. Fintech, Biotech...)"
                value={customIndustry}
                onChange={(e) => setCustomIndustry(e.target.value)}
                maxLength={100}
              />
              <p className="text-xs text-muted-foreground mt-1">
                Enter the industry or sector not covered by the list above.
              </p>
            </div>
          )}
        </div>

        {/* Notes */}
        <FormField
          control={form.control}
          name="notes"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Notes</FormLabel>
              <FormControl>
                <Textarea
                  placeholder="Known associates, operational details, case relevance..."
                  rows={3}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Business identifiers — editor handles its own null case with an
            informational hint ("Save the business first ..."), so one
            unconditional render covers both add and edit modes. */}
        <div className="pt-2 border-t">
          <BusinessIdentifierEditor entityId={entityId ?? null} />
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button
            type="button"
            variant="ghost"
            onClick={onCancel}
            disabled={isPending}
          >
            Cancel
          </Button>
          <Button type="submit" disabled={isPending}>
            {isPending ? "Saving..." : submitLabel}
          </Button>
        </div>
      </form>
    </Form>
  );
}
