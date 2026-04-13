/**
 * ToolForm — add form for a tool usage record.
 *
 * evidence_id is a <Select> populated by the parent evidence list passed in
 * as a prop, with a "Case-wide (no specific evidence)" option at the top.
 * If no evidence exists, the Select is disabled with a hint.
 *
 * Props:
 *   evidenceList — list of Evidence items for the case (used to populate Select)
 *   isPending    — disables submit while mutation is in-flight
 *   onSubmit     — called with validated ToolFormValues
 *   onCancel     — called when user clicks Cancel
 */

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { toolFormSchema, type ToolFormValues } from "@/lib/tool-schema";
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

const CASE_WIDE_VALUE = "__case_wide__";

interface ToolFormProps {
  evidenceList: Evidence[];
  isPending: boolean;
  onSubmit: (values: ToolFormValues) => void;
  onCancel: () => void;
}

export function ToolForm({ evidenceList, isPending, onSubmit, onCancel }: ToolFormProps) {
  const now = new Date();
  const nowLocal = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}T${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;

  const form = useForm<ToolFormValues>({
    resolver: zodResolver(toolFormSchema),
    defaultValues: {
      evidence_id: "",
      tool_name: "",
      version: "",
      purpose: "",
      command_used: "",
      input_file: "",
      output_file: "",
      execution_datetime: nowLocal,
      operator: "",
    },
  });

  const hasNoEvidence = evidenceList.length === 0;

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" noValidate>
        {/* evidence_id select */}
        <FormField
          control={form.control}
          name="evidence_id"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Linked Evidence</FormLabel>
              <Select
                onValueChange={field.onChange}
                defaultValue={field.value || CASE_WIDE_VALUE}
                disabled={hasNoEvidence}
              >
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Case-wide (no specific evidence)" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value={CASE_WIDE_VALUE}>
                    Case-wide (no specific evidence)
                  </SelectItem>
                  {evidenceList.map((e) => (
                    <SelectItem key={e.evidence_id} value={e.evidence_id}>
                      <span className="font-mono">{e.evidence_id}</span>
                      {" — "}
                      <span className="text-muted-foreground truncate">{e.description}</span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {hasNoEvidence && (
                <FormDescription>
                  No evidence items exist yet. Add evidence first to link this tool run.
                </FormDescription>
              )}
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Row: tool_name + version */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="sm:col-span-2">
            <FormField
              control={form.control}
              name="tool_name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    Tool Name <span aria-hidden="true">*</span>
                  </FormLabel>
                  <FormControl>
                    <Input placeholder="e.g. FTK Imager, Volatility, Autopsy" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          <FormField
            control={form.control}
            name="version"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Version</FormLabel>
                <FormControl>
                  <Input placeholder="e.g. 4.7.1" className="font-mono" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* purpose */}
        <FormField
          control={form.control}
          name="purpose"
          render={({ field }) => (
            <FormItem>
              <FormLabel>
                Purpose <span aria-hidden="true">*</span>
              </FormLabel>
              <FormControl>
                <Input placeholder="What was this tool used for?" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* operator + execution_datetime */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="operator"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Operator <span aria-hidden="true">*</span>
                </FormLabel>
                <FormControl>
                  <Input placeholder="Who ran the tool?" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="execution_datetime"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Execution Date / Time</FormLabel>
                <FormControl>
                  <Input type="datetime-local" {...field} />
                </FormControl>
                <FormDescription>Leave blank to use current time.</FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* command_used */}
        <FormField
          control={form.control}
          name="command_used"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Command Used</FormLabel>
              <FormControl>
                <Textarea
                  className="font-mono text-xs"
                  placeholder="Full command line or script used…"
                  rows={2}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* input_file + output_file */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="input_file"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Input File</FormLabel>
                <FormControl>
                  <Input className="font-mono text-xs" placeholder="Path to input…" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="output_file"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Output File</FormLabel>
                <FormControl>
                  <Input className="font-mono text-xs" placeholder="Path to output…" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Actions */}
        <div className="flex gap-3 pt-2">
          <Button type="submit" disabled={isPending}>
            {isPending ? "Adding…" : "Add Tool Usage"}
          </Button>
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </form>
    </Form>
  );
}
