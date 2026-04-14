/**
 * HashForm — add form for a hash verification record.
 *
 * No edit or delete — hashes are append-only (matches v1 behavior).
 *
 * Features dynamic client-side length hint: when the user picks SHA256,
 * the hash_value FormDescription changes to "64 hex characters expected".
 * The zod refine validator also enforces the length on submit.
 *
 * Props:
 *   isPending — disables submit while mutation is in-flight
 *   onSubmit  — called with validated HashFormValues
 *   onCancel  — called when user clicks Cancel
 */

import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { hashFormSchema, type HashFormValues } from "@/lib/hash-schema";
import { HASH_ALGORITHMS, hashLengthFor } from "@/lib/record-enums";

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

interface HashFormProps {
  isPending: boolean;
  onSubmit: (values: HashFormValues) => void;
  onCancel: () => void;
}

export function HashForm({ isPending, onSubmit, onCancel }: HashFormProps) {
  const now = new Date();
  const nowLocal = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}T${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;

  const form = useForm<HashFormValues>({
    resolver: zodResolver(hashFormSchema),
    defaultValues: {
      algorithm: "SHA256",
      hash_value: "",
      verified_by: "",
      verification_datetime: nowLocal,
      notes: "",
    },
  });

  // Watch algorithm to update the dynamic description
  const algorithm = useWatch({ control: form.control, name: "algorithm" });
  const expectedLength = algorithm ? hashLengthFor(algorithm) : 64;

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" noValidate>
        {/* Row 1: algorithm + verified_by */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="algorithm"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Algorithm <span aria-hidden="true">*</span>
                </FormLabel>
                <Select onValueChange={field.onChange} defaultValue={field.value}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select algorithm" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {HASH_ALGORITHMS.map((a) => (
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
            name="verified_by"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Verified By <span aria-hidden="true">*</span>
                </FormLabel>
                <FormControl>
                  <Input placeholder="Examiner name" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* hash_value with dynamic length hint */}
        <FormField
          control={form.control}
          name="hash_value"
          render={({ field }) => (
            <FormItem>
              <FormLabel>
                Hash Value <span aria-hidden="true">*</span>
              </FormLabel>
              <FormControl>
                <Input
                  className="font-mono text-xs"
                  placeholder="Paste hex hash here…"
                  {...field}
                />
              </FormControl>
              <FormDescription>
                {expectedLength} hex characters expected for {algorithm ?? "selected algorithm"}.
                Uppercase is accepted and will be normalised on save.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* verification_datetime */}
        <FormField
          control={form.control}
          name="verification_datetime"
          render={({ field }) => (
            <FormItem>
              <FormLabel>
                Verification Date / Time <span aria-hidden="true">*</span>
              </FormLabel>
              <FormControl>
                <Input type="datetime-local" {...field} />
              </FormControl>
              <FormMessage />
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
                <Textarea placeholder="Optional notes about this verification…" rows={2} {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Actions */}
        <div className="flex gap-3 pt-2">
          <Button type="submit" disabled={isPending}>
            {isPending ? "Adding…" : "Add Hash"}
          </Button>
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </form>
    </Form>
  );
}
