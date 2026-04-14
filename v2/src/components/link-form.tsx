/**
 * LinkForm — add form for a link between two nodes.
 *
 * source_type and target_type drive which list (entities or evidence) populates
 * the source_id and target_id Selects.
 *
 * Props:
 *   entityList  — entities for the case
 *   evidenceList — evidence items for the case
 *   isPending
 *   onSubmit
 *   onCancel
 */

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { linkFormSchema, type LinkFormValues } from "@/lib/link-schema";
import { LINK_ENDPOINT_KINDS } from "@/lib/link-analysis-enums";
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
  FormDescription,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface LinkFormProps {
  entityList: Entity[];
  evidenceList: Evidence[];
  isPending: boolean;
  onSubmit: (values: LinkFormValues) => void;
  onCancel: () => void;
}

export function LinkForm({
  entityList,
  evidenceList,
  isPending,
  onSubmit,
  onCancel,
}: LinkFormProps) {
  const form = useForm<LinkFormValues>({
    resolver: zodResolver(linkFormSchema),
    defaultValues: {
      source_type: "entity",
      source_id: "",
      target_type: "entity",
      target_id: "",
      link_label: "",
      directional: 1,
      weight: 1.0,
      notes: "",
    },
  });

  const sourceType = form.watch("source_type");
  const targetType = form.watch("target_type");

  function nodeChoicesFor(kind: "entity" | "evidence") {
    if (kind === "entity") {
      return entityList.map((e) => ({
        id: String(e.entity_id),
        label: `${e.display_name} (${e.entity_type})`,
      }));
    }
    return evidenceList.map((e) => ({
      id: e.evidence_id,
      label: `${e.evidence_id} — ${e.description.slice(0, 60)}`,
    }));
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" noValidate>
        {/* Source row */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="source_type"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Source Type <span aria-hidden="true">*</span>
                </FormLabel>
                <Select
                  onValueChange={(val) => {
                    field.onChange(val);
                    form.setValue("source_id", "");
                  }}
                  defaultValue={field.value}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {LINK_ENDPOINT_KINDS.map((k) => (
                      <SelectItem key={k} value={k} className="capitalize">
                        {k.charAt(0).toUpperCase() + k.slice(1)}
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
            name="source_id"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Source <span aria-hidden="true">*</span>
                </FormLabel>
                <Select onValueChange={field.onChange} value={field.value}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select source" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {nodeChoicesFor(sourceType).map((c) => (
                      <SelectItem key={c.id} value={c.id}>
                        {c.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Target row */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="target_type"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Target Type <span aria-hidden="true">*</span>
                </FormLabel>
                <Select
                  onValueChange={(val) => {
                    field.onChange(val);
                    form.setValue("target_id", "");
                  }}
                  defaultValue={field.value}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {LINK_ENDPOINT_KINDS.map((k) => (
                      <SelectItem key={k} value={k} className="capitalize">
                        {k.charAt(0).toUpperCase() + k.slice(1)}
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
            name="target_id"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Target <span aria-hidden="true">*</span>
                </FormLabel>
                <Select onValueChange={field.onChange} value={field.value}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select target" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {nodeChoicesFor(targetType).map((c) => (
                      <SelectItem key={c.id} value={c.id}>
                        {c.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* link_label + directional + weight */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <FormField
            control={form.control}
            name="link_label"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Link Label</FormLabel>
                <FormControl>
                  <Input
                    placeholder="e.g. employs, owns, called"
                    {...field}
                    value={field.value ?? ""}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="directional"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Directional</FormLabel>
                <Select
                  onValueChange={(val) => field.onChange(parseInt(val, 10))}
                  value={String(field.value)}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="1">Yes (arrow)</SelectItem>
                    <SelectItem value="0">No (undirected)</SelectItem>
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="weight"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Weight</FormLabel>
                <FormControl>
                  <Input
                    type="number"
                    min={0}
                    max={1000}
                    step={0.1}
                    {...field}
                    onChange={(e) =>
                      field.onChange(parseFloat(e.target.value))
                    }
                  />
                </FormControl>
                <FormDescription>0–1000, default 1.0</FormDescription>
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
                <Textarea
                  placeholder="Investigator notes about this link…"
                  rows={3}
                  {...field}
                  value={field.value ?? ""}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Actions */}
        <div className="flex gap-3 pt-2">
          <Button type="submit" disabled={isPending}>
            {isPending ? "Saving…" : "Add Link"}
          </Button>
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </form>
    </Form>
  );
}
