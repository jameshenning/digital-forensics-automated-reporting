/**
 * CaseForm — shared form component for case create and edit.
 *
 * Renders all case fields with react-hook-form + zod validation.
 * The caller controls submission behaviour (create vs. update).
 *
 * Props:
 *   defaultValues — pre-populate for edit; undefined → all blank (new case)
 *   readonlyCaseId — true for edit form (case_id is immutable PK)
 *   isPending — disables the submit button while the mutation is in-flight
 *   onSubmit — called with validated CaseFormValues
 *   onCancel — called when the user clicks Cancel
 *   submitLabel — text on the primary button
 */

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { caseFormSchema, type CaseFormValues } from "@/lib/case-schema";
import { CASE_STATUSES, CASE_PRIORITIES } from "@/lib/case-enums";

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

interface CaseFormProps {
  defaultValues?: Partial<CaseFormValues>;
  readonlyCaseId?: boolean;
  isPending: boolean;
  onSubmit: (values: CaseFormValues) => void;
  onCancel: () => void;
  submitLabel?: string;
}

export function CaseForm({
  defaultValues,
  readonlyCaseId = false,
  isPending,
  onSubmit,
  onCancel,
  submitLabel = "Create Case",
}: CaseFormProps) {
  const form = useForm<CaseFormValues>({
    resolver: zodResolver(caseFormSchema),
    defaultValues: {
      case_id: "",
      case_name: "",
      description: "",
      investigator: "",
      agency: "",
      start_date: new Date().toISOString().slice(0, 10),
      end_date: "",
      status: "Active",
      priority: "Medium",
      classification: "",
      evidence_drive_path: "",
      tags_raw: "",
      ...defaultValues,
    },
  });

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className="space-y-6"
        noValidate
      >
        {/* Row 1: case_id + case_name */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <FormField
            control={form.control}
            name="case_id"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Case ID <span aria-hidden="true">*</span>
                </FormLabel>
                <FormControl>
                  <Input
                    placeholder="e.g. CASE-2026-0042"
                    {...field}
                    readOnly={readonlyCaseId}
                    disabled={readonlyCaseId}
                    className={
                      readonlyCaseId ? "bg-muted font-mono" : "font-mono"
                    }
                  />
                </FormControl>
                {readonlyCaseId && (
                  <FormDescription>Immutable — cannot be changed.</FormDescription>
                )}
                <FormMessage />
              </FormItem>
            )}
          />

          <div className="sm:col-span-2">
            <FormField
              control={form.control}
              name="case_name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    Case Name <span aria-hidden="true">*</span>
                  </FormLabel>
                  <FormControl>
                    <Input placeholder="Short descriptive name" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>
        </div>

        {/* Row 2: investigator + agency */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="investigator"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Investigator <span aria-hidden="true">*</span>
                </FormLabel>
                <FormControl>
                  <Input
                    placeholder="Examiner name"
                    {...field}
                    readOnly={readonlyCaseId}
                    disabled={readonlyCaseId}
                    className={readonlyCaseId ? "bg-muted" : ""}
                  />
                </FormControl>
                {readonlyCaseId && (
                  <FormDescription>
                    Immutable for chain-of-custody integrity.
                  </FormDescription>
                )}
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="agency"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Agency</FormLabel>
                <FormControl>
                  <Input placeholder="Organization" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Row 3: start_date + end_date + status + priority */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <FormField
            control={form.control}
            name="start_date"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Start Date <span aria-hidden="true">*</span>
                </FormLabel>
                <FormControl>
                  <Input type="date" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="end_date"
            render={({ field }) => (
              <FormItem>
                <FormLabel>End Date</FormLabel>
                <FormControl>
                  <Input type="date" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="status"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Status</FormLabel>
                <Select
                  onValueChange={field.onChange}
                  defaultValue={field.value}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select status" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {CASE_STATUSES.map((s) => (
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
            name="priority"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Priority</FormLabel>
                <Select
                  onValueChange={field.onChange}
                  defaultValue={field.value}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select priority" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {CASE_PRIORITIES.map((p) => (
                      <SelectItem key={p} value={p}>
                        {p}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Description */}
        <FormField
          control={form.control}
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Description</FormLabel>
              <FormControl>
                <Textarea
                  placeholder="Narrative describing the case scope, subjects, circumstances, and key details…"
                  rows={5}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Classification + Tags */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="classification"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Classification</FormLabel>
                <FormControl>
                  <Input
                    placeholder="e.g. Unclassified, CUI, Confidential"
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="tags_raw"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Tags</FormLabel>
                <FormControl>
                  <Input
                    placeholder="#forensics, drone, case-type"
                    {...field}
                  />
                </FormControl>
                <FormDescription>
                  Comma-separated; normalized (lowercased, deduped) on save.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Evidence Drive Path */}
        <FormField
          control={form.control}
          name="evidence_drive_path"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Evidence Drive Path</FormLabel>
              <FormControl>
                <Input placeholder="e.g. E:\" {...field} />
              </FormControl>
              <FormDescription>
                External drive letter or path where evidence files are stored.
                All evidence should reside on an external drive, not the primary
                system drive.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Action buttons */}
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
