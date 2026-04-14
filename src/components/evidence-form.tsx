/**
 * EvidenceForm — add form for a new evidence item.
 *
 * There is no edit variant in Phase 3a (v1 doesn't let you edit evidence
 * either — only delete+readd).
 *
 * Props:
 *   isPending — disables submit while mutation is in-flight
 *   onSubmit  — called with validated EvidenceFormValues
 *   onCancel  — called when user clicks Cancel
 */

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { evidenceFormSchema, type EvidenceFormValues } from "@/lib/evidence-schema";

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

interface EvidenceFormProps {
  isPending: boolean;
  onSubmit: (values: EvidenceFormValues) => void;
  onCancel: () => void;
}

export function EvidenceForm({ isPending, onSubmit, onCancel }: EvidenceFormProps) {
  const now = new Date();
  // datetime-local format: YYYY-MM-DDTHH:MM
  const nowLocal = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}T${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;

  const form = useForm<EvidenceFormValues>({
    resolver: zodResolver(evidenceFormSchema),
    defaultValues: {
      evidence_id: "",
      description: "",
      collected_by: "",
      collection_datetime: nowLocal,
      location: "",
      status: "Collected",
      evidence_type: "",
      make_model: "",
      serial_number: "",
      storage_location: "",
    },
  });

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" noValidate>
        {/* Row 1: evidence_id */}
        <FormField
          control={form.control}
          name="evidence_id"
          render={({ field }) => (
            <FormItem>
              <FormLabel>
                Evidence ID <span aria-hidden="true">*</span>
              </FormLabel>
              <FormControl>
                <Input
                  placeholder="e.g. EV-2026-001"
                  className="font-mono"
                  {...field}
                />
              </FormControl>
              <FormDescription>
                Unique identifier for this evidence item. Letters, digits, '.', '_', '-' only.
              </FormDescription>
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
              <FormLabel>
                Description <span aria-hidden="true">*</span>
              </FormLabel>
              <FormControl>
                <Textarea
                  placeholder="Describe the evidence item…"
                  rows={3}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Row 2: collected_by + collection_datetime */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="collected_by"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Collected By <span aria-hidden="true">*</span>
                </FormLabel>
                <FormControl>
                  <Input placeholder="Examiner name" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="collection_datetime"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Collection Date/Time <span aria-hidden="true">*</span>
                </FormLabel>
                <FormControl>
                  <Input type="datetime-local" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Row 3: status + evidence_type */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="status"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Status</FormLabel>
                <FormControl>
                  <Input placeholder="Collected" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="evidence_type"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Evidence Type</FormLabel>
                <FormControl>
                  <Input placeholder="e.g. Hard Drive, USB, Phone" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Row 4: make_model + serial_number */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="make_model"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Make / Model</FormLabel>
                <FormControl>
                  <Input placeholder="e.g. Seagate Barracuda 2TB" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="serial_number"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Serial Number</FormLabel>
                <FormControl>
                  <Input className="font-mono" placeholder="S/N" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Row 5: location + storage_location */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="location"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Collection Location</FormLabel>
                <FormControl>
                  <Input placeholder="Where it was found / seized" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="storage_location"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Storage Location</FormLabel>
                <FormControl>
                  <Input placeholder="Current storage location" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Actions */}
        <div className="flex gap-3 pt-2">
          <Button type="submit" disabled={isPending}>
            {isPending ? "Adding…" : "Add Evidence"}
          </Button>
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </form>
    </Form>
  );
}
