/**
 * PersonForm — add/edit a person entity with rich profile fields and an
 * optional photo upload. Used inside a Dialog from the PersonsPanel.
 *
 * The photo picker opens a Tauri native file dialog filtered to image
 * extensions. The actual photo upload happens via `personPhotoUpload` AFTER
 * the entity row exists — so on create, the parent panel calls
 * `entity_add` first, then `person_photo_upload` with the returned
 * entity_id. On edit, the parent panel calls `entity_update` and
 * `person_photo_upload` in parallel.
 *
 * Validation: uses person-schema.ts (zod). See case-schema.ts for the
 * z.input<> vs z.infer<> gotcha.
 */

import React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { open as openFilePicker } from "@tauri-apps/plugin-dialog";
import { convertFileSrc } from "@tauri-apps/api/core";
import { Upload, X, User } from "lucide-react";

import { PERSON_SUBTYPES } from "@/lib/link-analysis-enums";
import { personFormSchema, type PersonFormValues } from "@/lib/person-schema";

import { PersonIdentifierEditor } from "@/components/person-identifier-editor";
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
// Props
// ---------------------------------------------------------------------------

interface PersonFormProps {
  defaultValues?: Partial<PersonFormValues>;
  /** Existing photo path if any — rendered as the current image in edit mode. */
  currentPhotoPath?: string | null;
  /** Parent entity id when editing an existing person; null when adding a
   *  new one. Enables the multi-identifier editor once the parent row
   *  exists. */
  entityId?: number | null;
  isPending: boolean;
  onSubmit: (values: PersonFormValues, pickedPhotoPath: string | null) => void;
  onCancel: () => void;
  submitLabel?: string;
}

// ---------------------------------------------------------------------------
// PersonForm
// ---------------------------------------------------------------------------

export function PersonForm({
  defaultValues,
  currentPhotoPath,
  entityId,
  isPending,
  onSubmit,
  onCancel,
  submitLabel = "Save Person",
}: PersonFormProps) {
  const form = useForm<PersonFormValues>({
    resolver: zodResolver(personFormSchema),
    defaultValues: {
      display_name: "",
      subtype: null,
      organizational_rank: "",
      email: "",
      phone: "",
      username: "",
      employer: "",
      dob: "",
      notes: "",
      ...defaultValues,
    },
  });

  // Photo picker state — string path if user picked a new photo this session.
  const [pickedPhotoPath, setPickedPhotoPath] = React.useState<string | null>(null);
  const [photoError, setPhotoError] = React.useState<string | null>(null);

  async function handlePickPhoto() {
    setPhotoError(null);
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
      setPickedPhotoPath(path);
    } catch (err) {
      setPhotoError(
        err instanceof Error ? err.message : "Failed to open the file picker.",
      );
    }
  }

  function handleClearPickedPhoto() {
    setPickedPhotoPath(null);
  }

  // Preview URL for the image. Prefers the just-picked photo over the stored one.
  const previewSrc: string | null = React.useMemo(() => {
    if (pickedPhotoPath) {
      try {
        return convertFileSrc(pickedPhotoPath);
      } catch {
        return null;
      }
    }
    if (currentPhotoPath) {
      try {
        return convertFileSrc(currentPhotoPath);
      } catch {
        return null;
      }
    }
    return null;
  }, [pickedPhotoPath, currentPhotoPath]);

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit((values) => onSubmit(values, pickedPhotoPath))}
        className="space-y-5"
        noValidate
      >
        {/* Photo picker row */}
        <div className="flex items-center gap-4">
          <div className="h-24 w-24 rounded-full overflow-hidden bg-muted border flex items-center justify-center shrink-0">
            {previewSrc ? (
              <img
                src={previewSrc}
                alt="Person"
                className="h-full w-full object-cover"
              />
            ) : (
              <User className="h-10 w-10 text-muted-foreground" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium">Photo</p>
            <p className="text-xs text-muted-foreground mb-2">
              JPG, PNG, GIF, WebP, BMP, or TIFF. Max 10 MiB. Stored outside the
              evidence tree.
            </p>
            <div className="flex gap-2 flex-wrap">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => void handlePickPhoto()}
              >
                <Upload className="h-4 w-4 mr-1.5" />
                {pickedPhotoPath || currentPhotoPath ? "Replace photo" : "Upload photo"}
              </Button>
              {pickedPhotoPath && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={handleClearPickedPhoto}
                >
                  <X className="h-4 w-4 mr-1.5" />
                  Clear selection
                </Button>
              )}
            </div>
            {photoError && (
              <p className="text-xs text-destructive mt-1">{photoError}</p>
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
                Full name <span aria-hidden="true">*</span>
              </FormLabel>
              <FormControl>
                <Input placeholder="e.g. John Doe" autoFocus {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Subtype + organizational_rank */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="subtype"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Role in case</FormLabel>
                <Select
                  value={field.value ?? ""}
                  onValueChange={(v) => field.onChange(v === "" ? null : v)}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select role (optional)" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {PERSON_SUBTYPES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="organizational_rank"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Title / rank</FormLabel>
                <FormControl>
                  <Input placeholder="e.g. Senior Engineer" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Employer + username */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="employer"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Employer</FormLabel>
                <FormControl>
                  <Input placeholder="Company or organization" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="username"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Handle / username</FormLabel>
                <FormControl>
                  <Input placeholder="@handle or username" {...field} />
                </FormControl>
                <FormDescription>
                  Used as input for OSINT tools like Sherlock and WhatsMyName.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Email + phone */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="email"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Email</FormLabel>
                <FormControl>
                  <Input type="email" placeholder="name@example.com" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="phone"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Phone</FormLabel>
                <FormControl>
                  <Input type="tel" placeholder="+1 555-555-5555" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* DOB */}
        <FormField
          control={form.control}
          name="dob"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Date of birth</FormLabel>
              <FormControl>
                <Input type="date" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Notes */}
        <FormField
          control={form.control}
          name="notes"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Investigator notes</FormLabel>
              <FormControl>
                <Textarea
                  rows={4}
                  placeholder="Observations, context, relationship to the case..."
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Multi-valued OSINT identifiers (migration 0004).
            Only the `email`/`phone`/`username` fields above are the "primary"
            shortcut displayed on the card; the real source of truth for OSINT
            submission is this editor. */}
        <PersonIdentifierEditor entityId={entityId ?? null} />

        {/* Action buttons */}
        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" onClick={onCancel} disabled={isPending}>
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
