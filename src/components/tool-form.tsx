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

import React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Hash, Loader2, Check } from "lucide-react";

import { toolFormSchema, type ToolFormValues } from "@/lib/tool-schema";
import { fileComputeSha256, type Evidence } from "@/lib/bindings";
import { getToken } from "@/lib/session";

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
  /**
   * When set, the evidence_id is pre-populated and the select is hidden —
   * used when adding a tool inline under a specific evidence item, so the
   * operator doesn't have to pick the evidence they're already viewing.
   */
  lockedEvidenceId?: string;
}

// ---------------------------------------------------------------------------
// ComputeHashButton — sibling button next to the SHA-256 inputs that reads
// the file at the corresponding path field and fills the hash in.
// ---------------------------------------------------------------------------

type ComputeState =
  | { kind: "idle" }
  | { kind: "pending" }
  | { kind: "success" }
  | { kind: "error"; message: string };

interface ComputeHashButtonProps {
  /** The file path the operator typed. May be empty. */
  filePath: string;
  /** Called with the lowercase hex SHA-256 when the read succeeds. */
  onComputed: (hex: string) => void;
  /** What we're hashing — "input" | "output" — drives the aria-label only. */
  ariaSubject: string;
}

function ComputeHashButton({
  filePath,
  onComputed,
  ariaSubject,
}: ComputeHashButtonProps) {
  const [state, setState] = React.useState<ComputeState>({ kind: "idle" });

  // Reset Success state to Idle after 2 seconds (per UX spec).
  React.useEffect(() => {
    if (state.kind !== "success") return;
    const t = setTimeout(() => setState({ kind: "idle" }), 2000);
    return () => clearTimeout(t);
  }, [state]);

  async function handleClick() {
    const path = filePath.trim();
    if (path.length === 0) {
      setState({ kind: "error", message: "Enter a file path above first." });
      return;
    }
    const token = getToken();
    if (!token) {
      setState({ kind: "error", message: "Not logged in." });
      return;
    }
    setState({ kind: "pending" });
    try {
      const hex = await fileComputeSha256({ token, path });
      onComputed(hex);
      setState({ kind: "success" });
    } catch (err) {
      const msg =
        (err as { message?: string })?.message ??
        "File not found — check the path above.";
      setState({ kind: "error", message: msg });
    }
  }

  const ariaLabel =
    state.kind === "pending"
      ? `Computing SHA-256 for ${ariaSubject} file…`
      : `Compute SHA-256 for ${ariaSubject} file`;

  return (
    <div className="flex flex-col items-stretch sm:items-end shrink-0">
      <Button
        type="button"
        size="sm"
        variant="outline"
        disabled={state.kind === "pending"}
        onClick={() => void handleClick()}
        aria-label={ariaLabel}
        className="w-full sm:w-[6.5rem]"
      >
        {state.kind === "pending" ? (
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
        ) : state.kind === "success" ? (
          <>
            <Check className="h-4 w-4 mr-1.5" aria-hidden="true" />
            Computed
          </>
        ) : (
          <>
            <Hash className="h-4 w-4 mr-1.5" aria-hidden="true" />
            Compute
          </>
        )}
      </Button>
      {state.kind === "error" && (
        <p className="text-xs text-destructive mt-1" role="alert">
          {state.message}
        </p>
      )}
    </div>
  );
}

export function ToolForm({
  evidenceList,
  isPending,
  onSubmit,
  onCancel,
  lockedEvidenceId,
}: ToolFormProps) {
  const now = new Date();
  const nowLocal = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}T${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;

  const form = useForm<ToolFormValues>({
    resolver: zodResolver(toolFormSchema),
    defaultValues: {
      evidence_id: lockedEvidenceId ?? "",
      tool_name: "",
      version: "",
      purpose: "",
      command_used: "",
      input_file: "",
      output_file: "",
      execution_datetime: nowLocal,
      operator: "",
      input_sha256: "",
      output_sha256: "",
      environment_notes: "",
      reproduction_notes: "",
    },
  });

  const hasNoEvidence = evidenceList.length === 0;

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" noValidate>
        {/* evidence_id — hidden when locked to a specific evidence item */}
        {!lockedEvidenceId && (
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
                        <span className="text-muted-foreground truncate">
                          {e.description}
                        </span>
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
        )}
        {lockedEvidenceId && (
          <p className="text-xs text-muted-foreground">
            Linking to evidence{" "}
            <code className="font-mono">{lockedEvidenceId}</code>
          </p>
        )}

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

        {/* ─────────── Reproducibility ─────────── */}
        <div className="relative flex items-center gap-3 pt-2">
          <div className="flex-1 h-px bg-border" />
          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide whitespace-nowrap">
            Reproducibility
          </span>
          <div className="flex-1 h-px bg-border" />
        </div>
        <p className="text-xs text-muted-foreground -mt-1 mb-1">
          Helps a second examiner reproduce this tool run and arrive at the
          same result.
        </p>

        {/* Input file SHA-256 + Compute button */}
        <FormField
          control={form.control}
          name="input_sha256"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Input File SHA-256</FormLabel>
              <div className="flex flex-col items-stretch gap-2 sm:flex-row sm:items-start">
                <FormControl>
                  <Input
                    className="flex-1 min-w-0 font-mono text-xs"
                    placeholder="e.g. 3b4c5d6e…"
                    maxLength={64}
                    spellCheck={false}
                    autoCorrect="off"
                    autoCapitalize="off"
                    {...field}
                  />
                </FormControl>
                <ComputeHashButton
                  filePath={form.watch("input_file") ?? ""}
                  ariaSubject="input"
                  onComputed={(hex) => form.setValue("input_sha256", hex, { shouldValidate: true })}
                />
              </div>
              <FormDescription>
                SHA-256 of the input file at time of run. Use{" "}
                <span className="font-medium">Compute</span> to fill from the
                Input File path above.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Output file SHA-256 + Compute button */}
        <FormField
          control={form.control}
          name="output_sha256"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Output File SHA-256</FormLabel>
              <div className="flex flex-col items-stretch gap-2 sm:flex-row sm:items-start">
                <FormControl>
                  <Input
                    className="flex-1 min-w-0 font-mono text-xs"
                    placeholder="e.g. 9f8e7d6c…"
                    maxLength={64}
                    spellCheck={false}
                    autoCorrect="off"
                    autoCapitalize="off"
                    {...field}
                  />
                </FormControl>
                <ComputeHashButton
                  filePath={form.watch("output_file") ?? ""}
                  ariaSubject="output"
                  onComputed={(hex) => form.setValue("output_sha256", hex, { shouldValidate: true })}
                />
              </div>
              <FormDescription>
                SHA-256 of the output file. Lets the next examiner verify
                their result matches yours.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Environment notes */}
        <FormField
          control={form.control}
          name="environment_notes"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Environment Notes</FormLabel>
              <FormControl>
                <Textarea
                  rows={2}
                  className="text-sm resize-y"
                  placeholder="e.g. Kali 2026.1, WSL2 on Windows 11, exiftool from /usr/bin/exiftool, Perl 5.38"
                  {...field}
                />
              </FormControl>
              <FormDescription>
                OS, tool binary path, runtime versions — anything that affects
                determinism.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Reproduction notes */}
        <FormField
          control={form.control}
          name="reproduction_notes"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Reproduction Notes</FormLabel>
              <FormControl>
                <Textarea
                  rows={3}
                  className="text-sm resize-y"
                  placeholder="e.g. WARNING: --binary flag changed in v13.50, output format differs from older versions."
                  {...field}
                />
              </FormControl>
              <FormDescription>
                Case-specific tips, pitfalls, or version caveats for the next
                examiner.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

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
