/**
 * EventForm — add/edit form for a case event.
 *
 * Props:
 *   defaultValues   — pre-populate for edit
 *   entityList      — entities for the case (related_entity_id Select)
 *   evidenceList    — evidence items for the case (related_evidence_id Select)
 *   isPending
 *   onSubmit
 *   onCancel
 *   submitLabel
 */

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { eventFormSchema, type EventFormValues } from "@/lib/event-schema";
import { EVENT_CATEGORIES } from "@/lib/link-analysis-enums";
import type { Entity, Evidence } from "@/lib/bindings";

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
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface EventFormProps {
  defaultValues?: Partial<EventFormValues>;
  entityList?: Entity[];
  evidenceList?: Evidence[];
  isPending: boolean;
  onSubmit: (values: EventFormValues) => void;
  onCancel: () => void;
  submitLabel?: string;
}

function nowLocalStr(): string {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}T${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
}

export function EventForm({
  defaultValues,
  entityList = [],
  evidenceList = [],
  isPending,
  onSubmit,
  onCancel,
  submitLabel = "Add Event",
}: EventFormProps) {
  const form = useForm<EventFormValues>({
    resolver: zodResolver(eventFormSchema),
    defaultValues: {
      title: "",
      description: "",
      event_datetime: nowLocalStr(),
      event_end_datetime: null,
      category: null,
      related_entity_id: null,
      related_evidence_id: null,
      ...defaultValues,
    },
  });

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" noValidate>
        {/* title */}
        <FormField
          control={form.control}
          name="title"
          render={({ field }) => (
            <FormItem>
              <FormLabel>
                Title <span aria-hidden="true">*</span>
              </FormLabel>
              <FormControl>
                <Input placeholder="Brief description of the event" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* description */}
        <FormField
          control={form.control}
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Description</FormLabel>
              <FormControl>
                <Textarea
                  placeholder="Detailed account of the event…"
                  rows={3}
                  {...field}
                  value={field.value ?? ""}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* event_datetime + event_end_datetime */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="event_datetime"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Date / Time <span aria-hidden="true">*</span>
                </FormLabel>
                <FormControl>
                  <Input type="datetime-local" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="event_end_datetime"
            render={({ field }) => (
              <FormItem>
                <FormLabel>End Date / Time</FormLabel>
                <FormControl>
                  <Input
                    type="datetime-local"
                    {...field}
                    value={field.value ?? ""}
                    onChange={(e) =>
                      field.onChange(e.target.value || null)
                    }
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* category */}
        <FormField
          control={form.control}
          name="category"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Category</FormLabel>
              <Select
                onValueChange={(val) =>
                  field.onChange(val === "__none__" ? null : val)
                }
                value={field.value ?? "__none__"}
              >
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select category" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="__none__">None</SelectItem>
                  {EVENT_CATEGORIES.map((c) => (
                    <SelectItem key={c} value={c} className="capitalize">
                      {c.charAt(0).toUpperCase() + c.slice(1)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* related_entity_id + related_evidence_id */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="related_entity_id"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Related Entity</FormLabel>
                <Select
                  onValueChange={(val) =>
                    field.onChange(
                      val === "__none__" ? null : parseInt(val, 10)
                    )
                  }
                  value={field.value != null ? String(field.value) : "__none__"}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="None" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="__none__">None</SelectItem>
                    {entityList.map((e) => (
                      <SelectItem
                        key={e.entity_id}
                        value={String(e.entity_id)}
                      >
                        {e.display_name}
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
            name="related_evidence_id"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Related Evidence</FormLabel>
                <Select
                  onValueChange={(val) =>
                    field.onChange(val === "__none__" ? null : val)
                  }
                  value={field.value ?? "__none__"}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="None" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="__none__">None</SelectItem>
                    {evidenceList.map((e) => (
                      <SelectItem key={e.evidence_id} value={e.evidence_id}>
                        {e.evidence_id}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

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
