/**
 * CustodyForm — used for both add and edit of a chain-of-custody event.
 *
 * Edit callers pass defaultValues to pre-populate.
 * custody_sequence is NOT a form field — it is backend-assigned and
 * shown only in the list view.
 *
 * Props:
 *   defaultValues — pre-populate for edit; undefined → all blank (new event)
 *   isPending     — disables submit while mutation is in-flight
 *   onSubmit      — called with validated CustodyFormValues
 *   onCancel      — called when user clicks Cancel
 *   submitLabel   — text on the primary button
 */

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { custodyFormSchema, type CustodyFormValues } from "@/lib/custody-schema";
import { CUSTODY_ACTIONS } from "@/lib/record-enums";

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

interface CustodyFormProps {
  defaultValues?: Partial<CustodyFormValues>;
  isPending: boolean;
  onSubmit: (values: CustodyFormValues) => void;
  onCancel: () => void;
  submitLabel?: string;
}

export function CustodyForm({
  defaultValues,
  isPending,
  onSubmit,
  onCancel,
  submitLabel = "Add Custody Event",
}: CustodyFormProps) {
  const now = new Date();
  const nowLocal = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}T${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;

  const form = useForm<CustodyFormValues>({
    resolver: zodResolver(custodyFormSchema),
    defaultValues: {
      action: "Seized",
      from_party: "",
      to_party: "",
      custody_datetime: nowLocal,
      location: "",
      purpose: "",
      notes: "",
      ...defaultValues,
    },
  });

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" noValidate>
        {/* Row 1: action + custody_datetime */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="action"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Action <span aria-hidden="true">*</span>
                </FormLabel>
                <Select onValueChange={field.onChange} defaultValue={field.value}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select action" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {CUSTODY_ACTIONS.map((a) => (
                      <SelectItem key={a} value={a}>
                        {a}
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
            name="custody_datetime"
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
        </div>

        {/* Row 2: from_party + to_party */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="from_party"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  From <span aria-hidden="true">*</span>
                </FormLabel>
                <FormControl>
                  <Input placeholder="Transferring party" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="to_party"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  To <span aria-hidden="true">*</span>
                </FormLabel>
                <FormControl>
                  <Input placeholder="Receiving party" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* location + purpose */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="location"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Location</FormLabel>
                <FormControl>
                  <Input placeholder="Transfer location" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="purpose"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Purpose</FormLabel>
                <FormControl>
                  <Input placeholder="Reason for transfer" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* notes */}
        <FormField
          control={form.control}
          name="notes"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Notes</FormLabel>
              <FormControl>
                <Textarea placeholder="Additional notes…" rows={3} {...field} />
              </FormControl>
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
