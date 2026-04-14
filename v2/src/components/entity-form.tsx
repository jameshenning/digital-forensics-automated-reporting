/**
 * EntityForm — add/edit form for an entity.
 *
 * Conditional rendering:
 *  - `subtype` field only visible when entity_type === 'person'
 *  - `organizational_rank` only visible when entity_type === 'person'
 *  - `parent_entity_id` Select is populated from entityList, excluding the
 *    current entity (edit mode).
 *
 * Props:
 *   defaultValues   — pre-populate for edit (undefined = new entity)
 *   entityList      — all entities for the case (for parent_entity_id Select)
 *   currentEntityId — the entity being edited (excluded from parent choices)
 *   isPending       — disables submit while mutation is in-flight
 *   onSubmit        — called with validated EntityFormValues
 *   onCancel        — cancel handler
 *   submitLabel     — primary button label
 */

import { useForm, Controller } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { entityFormSchema, type EntityFormValues } from "@/lib/entity-schema";
import { ENTITY_TYPES, PERSON_SUBTYPES } from "@/lib/link-analysis-enums";
import type { Entity } from "@/lib/bindings";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
  FormDescription,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface EntityFormProps {
  defaultValues?: Partial<EntityFormValues>;
  entityList?: Entity[];
  currentEntityId?: number;
  isPending: boolean;
  onSubmit: (values: EntityFormValues) => void;
  onCancel: () => void;
  submitLabel?: string;
}

export function EntityForm({
  defaultValues,
  entityList = [],
  currentEntityId,
  isPending,
  onSubmit,
  onCancel,
  submitLabel = "Add Entity",
}: EntityFormProps) {
  const form = useForm<EntityFormValues>({
    resolver: zodResolver(entityFormSchema),
    defaultValues: {
      entity_type: "person",
      display_name: "",
      subtype: null,
      organizational_rank: "",
      parent_entity_id: null,
      notes: "",
      metadata_json: "",
      ...defaultValues,
    },
  });

  const entityType = form.watch("entity_type");
  const isPerson = entityType === "person";

  // Entities available as parents — exclude the entity being edited
  const parentChoices = entityList.filter(
    (e) => currentEntityId == null || e.entity_id !== currentEntityId
  );

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" noValidate>
        {/* entity_type + display_name */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="entity_type"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Entity Type <span aria-hidden="true">*</span>
                </FormLabel>
                <Select
                  onValueChange={(val) => {
                    field.onChange(val);
                    // Clear person-only fields when switching away from person
                    if (val !== "person") {
                      form.setValue("subtype", null);
                      form.setValue("organizational_rank", "");
                    }
                  }}
                  defaultValue={field.value}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select type" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {ENTITY_TYPES.map((t) => (
                      <SelectItem key={t} value={t} className="capitalize">
                        {t.charAt(0).toUpperCase() + t.slice(1)}
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
            name="display_name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Display Name <span aria-hidden="true">*</span>
                </FormLabel>
                <FormControl>
                  <Input placeholder="Name or identifier" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Person-only fields */}
        {isPerson && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <FormField
              control={form.control}
              name="subtype"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Subtype</FormLabel>
                  <Select
                    onValueChange={(val) =>
                      field.onChange(val === "__none__" ? null : val)
                    }
                    value={field.value ?? "__none__"}
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select subtype" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="__none__">None</SelectItem>
                      {PERSON_SUBTYPES.map((s) => (
                        <SelectItem key={s} value={s} className="capitalize">
                          {s.charAt(0).toUpperCase() + s.slice(1)}
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
                  <FormLabel>Title / Rank</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="e.g. Detective, CEO, Sergeant"
                      {...field}
                      value={field.value ?? ""}
                    />
                  </FormControl>
                  <FormDescription>
                    Title or rank within their organization
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>
        )}

        {/* parent_entity_id */}
        <Controller
          control={form.control}
          name="parent_entity_id"
          render={({ field, fieldState }) => (
            <FormItem>
              <FormLabel>Parent Entity</FormLabel>
              <Select
                onValueChange={(val) =>
                  field.onChange(val === "__none__" ? null : parseInt(val, 10))
                }
                value={field.value != null ? String(field.value) : "__none__"}
              >
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="None (top-level)" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="__none__">None (top-level)</SelectItem>
                  {parentChoices.map((e) => (
                    <SelectItem key={e.entity_id} value={String(e.entity_id)}>
                      {e.display_name}
                      {e.entity_type !== "person"
                        ? ` (${e.entity_type})`
                        : ""}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormDescription>
                Assign a parent entity to model hierarchy (e.g. employee of a business).
                {currentEntityId != null &&
                  " The entity being edited is excluded to prevent cycles."}
              </FormDescription>
              {fieldState.error && (
                <p className="text-sm font-medium text-destructive">
                  {fieldState.error.message}
                </p>
              )}
            </FormItem>
          )}
        />

        {/* notes */}
        <FormField
          control={form.control}
          name="notes"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Notes</FormLabel>
              <FormControl>
                <Textarea
                  placeholder="Investigator notes about this entity…"
                  rows={3}
                  {...field}
                  value={field.value ?? ""}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* metadata_json */}
        <FormField
          control={form.control}
          name="metadata_json"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Metadata JSON</FormLabel>
              <FormControl>
                <Textarea
                  placeholder='{"key": "value"}'
                  rows={2}
                  className="font-mono text-xs"
                  {...field}
                  value={field.value ?? ""}
                />
              </FormControl>
              <FormDescription>
                Optional JSON object with additional structured attributes. Leave blank if not needed.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Actions */}
        <div className="flex gap-3 pt-2">
          <Button type="submit" disabled={isPending}>
            {isPending ? "Saving…" : submitLabel}
          </Button>
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </form>
    </Form>
  );
}
