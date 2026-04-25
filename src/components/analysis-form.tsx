/**
 * AnalysisForm — add form for an analysis note.
 *
 * evidence_id is a <Select> populated by the parent evidence list, with a
 * "Case-level (no specific evidence)" option at the top — identical pattern
 * to ToolForm.
 *
 * Props:
 *   evidenceList — list of Evidence items for the case
 *   isPending    — disables submit while mutation is in-flight
 *   onSubmit     — called with validated AnalysisFormValues
 *   onCancel     — called when user clicks Cancel
 */

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { analysisFormSchema, type AnalysisFormValues } from "@/lib/analysis-schema";
import { ANALYSIS_CATEGORIES, CONFIDENCE_LEVELS } from "@/lib/record-enums";
import type { Evidence } from "@/lib/bindings";

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

const CASE_LEVEL_VALUE = "__case_level__";

interface AnalysisFormProps {
  evidenceList: Evidence[];
  isPending: boolean;
  onSubmit: (values: AnalysisFormValues) => void;
  onCancel: () => void;
}

export function AnalysisForm({ evidenceList, isPending, onSubmit, onCancel }: AnalysisFormProps) {
  const form = useForm<AnalysisFormValues>({
    resolver: zodResolver(analysisFormSchema),
    defaultValues: {
      evidence_id: "",
      category: "Observation",
      finding: "",
      description: "",
      confidence_level: "Medium",
      created_by: "",
      method_reference: "",
      alternatives_considered: "",
      tool_version: "",
    },
  });

  const hasNoEvidence = evidenceList.length === 0;

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" noValidate>
        {/* evidence_id + category row */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="evidence_id"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Linked Evidence</FormLabel>
                <Select
                  onValueChange={field.onChange}
                  defaultValue={field.value || CASE_LEVEL_VALUE}
                  disabled={hasNoEvidence}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Case-level (no specific evidence)" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value={CASE_LEVEL_VALUE}>
                      Case-level (no specific evidence)
                    </SelectItem>
                    {evidenceList.map((e) => (
                      <SelectItem key={e.evidence_id} value={e.evidence_id}>
                        <span className="font-mono">{e.evidence_id}</span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {hasNoEvidence && (
                  <FormDescription>No evidence items exist yet.</FormDescription>
                )}
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="category"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Category <span aria-hidden="true">*</span>
                </FormLabel>
                <Select onValueChange={field.onChange} defaultValue={field.value}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select category" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {ANALYSIS_CATEGORIES.map((c) => (
                      <SelectItem key={c} value={c}>
                        {c}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* finding + confidence_level row */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="sm:col-span-2">
            <FormField
              control={form.control}
              name="finding"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    Finding <span aria-hidden="true">*</span>
                  </FormLabel>
                  <FormControl>
                    <Input placeholder="One-line summary of the finding…" {...field} />
                  </FormControl>
                  <FormDescription>Max 500 characters.</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          <FormField
            control={form.control}
            name="confidence_level"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Confidence</FormLabel>
                <Select onValueChange={field.onChange} defaultValue={field.value}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Medium" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {CONFIDENCE_LEVELS.map((l) => (
                      <SelectItem key={l} value={l}>
                        {l}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* description */}
        <FormField
          control={form.control}
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Detailed Description</FormLabel>
              <FormControl>
                <Textarea
                  placeholder="Supporting detail, methodology, artefacts referenced…"
                  rows={5}
                  {...field}
                />
              </FormControl>
              <FormDescription>Optional. Max 5000 characters.</FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* author — surfaced outside the advanced section because
             peer review depends on it */}
        <FormField
          control={form.control}
          name="created_by"
          render={({ field }) => (
            <FormItem>
              <FormLabel>
                Author
                <span
                  className="ml-1.5 text-xs font-normal text-amber-500/80"
                  aria-hidden="true"
                >
                  (recommended)
                </span>
              </FormLabel>
              <FormControl>
                <Input
                  placeholder="Examiner name or initials"
                  {...field}
                />
              </FormControl>
              <FormDescription>
                Peer review records the reviewer by name; the author
                line ties the finding to its examiner.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* advanced: validation & methodology */}
        <details className="rounded-md border px-3 py-2">
          <summary className="cursor-pointer text-sm font-medium text-muted-foreground select-none">
            Validation &amp; methodology (optional)
          </summary>
          <div className="mt-3 space-y-4">
            <FormField
              control={form.control}
              name="method_reference"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Method reference</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="e.g. NIST SP 800-86 §5.2, internal SOP-FRA-007"
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    SOP or standard your analysis followed. Cited in the
                    generated report so opposing counsel can trace your
                    method.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="tool_version"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Tool + version</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="e.g. exiftool 12.76, Autopsy 4.21.0"
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    The tool (with version) that produced this finding.
                    Mirrors identifier tool provenance.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="alternatives_considered"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Alternative explanations considered</FormLabel>
                  <FormControl>
                    <Textarea
                      placeholder="What other explanations did you examine and rule out, and why?"
                      rows={4}
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    Answers the "could this mean something else?"
                    question before someone else asks it.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>
        </details>

        {/* Actions */}
        <div className="flex gap-3 pt-2">
          <Button type="submit" disabled={isPending}>
            {isPending ? "Adding…" : "Add Note"}
          </Button>
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </form>
    </Form>
  );
}
