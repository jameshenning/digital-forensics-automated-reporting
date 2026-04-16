/**
 * PersonIdentifierEditor — add, edit, delete OSINT-relevant identifiers for a
 * person entity. Embedded in PersonForm (edit mode) and PersonCard (display
 * mode).
 *
 * Identifiers live in their own table (migration 0004) so the lifecycle is
 * independent of the person form — each add/edit/delete hits the backend
 * immediately rather than waiting for a parent-form submit. That mirrors how
 * person photos work (personPhotoUpload is deferred to after the entity exists)
 * and means we don't have to batch-insert on person-create.
 *
 * Ordering: list_for_entity returns rows sorted by `kind ASC, created_at ASC`
 * so the component renders them grouped by kind in a stable order.
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Plus, Pencil, Trash2, Mail, AtSign, Phone, Link2, User } from "lucide-react";

import {
  personIdentifierList,
  personIdentifierAdd,
  personIdentifierUpdate,
  personIdentifierDelete,
  type PersonIdentifier,
  type PersonIdentifierInput,
  type PersonIdentifierKind,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import {
  personIdentifierFormSchema,
  type PersonIdentifierFormValues,
  PERSON_IDENTIFIER_KINDS,
} from "@/lib/person-schema";

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
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

// ─── Kind metadata ───────────────────────────────────────────────────────────

const KIND_META: Record<
  PersonIdentifierKind,
  { label: string; icon: React.ComponentType<{ className?: string }>; placeholder: string }
> = {
  email: { label: "Email", icon: Mail, placeholder: "name@example.com" },
  username: { label: "Username", icon: User, placeholder: "login name" },
  handle: { label: "Handle", icon: AtSign, placeholder: "@handle or u/handle" },
  phone: { label: "Phone", icon: Phone, placeholder: "+1 555-555-5555" },
  url: { label: "URL", icon: Link2, placeholder: "https://..." },
};

// ─── Props ───────────────────────────────────────────────────────────────────

interface PersonIdentifierEditorProps {
  /** Parent person entity id. When null (add-person flow), the editor
   *  renders an informational hint instead because identifiers cannot be
   *  attached until the parent row exists. */
  entityId: number | null;
  /** Display-only mode — renders the list with no add/edit/delete controls.
   *  Used on PersonCard. */
  readOnly?: boolean;
}

// ─── Component ───────────────────────────────────────────────────────────────

export function PersonIdentifierEditor({
  entityId,
  readOnly = false,
}: PersonIdentifierEditorProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();

  const [adding, setAdding] = React.useState(false);
  const [editing, setEditing] = React.useState<PersonIdentifier | null>(null);
  const [deleting, setDeleting] = React.useState<PersonIdentifier | null>(null);

  // Use a well-formed (but impossible) entity_id of -1 as the parked key for
  // the null case so the queryKey shape is uniform. `enabled` still gates the
  // fetch, so the queryFn never actually runs with -1.
  const { data, isLoading, isError, error } = useQuery<PersonIdentifier[]>({
    queryKey: queryKeys.personIdentifiers.listForEntity(entityId ?? -1),
    queryFn: () => personIdentifierList({ token, entity_id: entityId! }),
    enabled: !!token && entityId !== null,
  });

  const invalidateList = React.useCallback(() => {
    if (entityId === null) return;
    void queryClient.invalidateQueries({
      queryKey: queryKeys.personIdentifiers.listForEntity(entityId),
    });
  }, [queryClient, entityId]);

  const addMutation = useMutation({
    mutationFn: (input: PersonIdentifierInput) => {
      if (entityId === null) {
        return Promise.reject(
          new Error("Cannot add identifier without an entity_id"),
        );
      }
      return personIdentifierAdd({ token, entity_id: entityId, input });
    },
    onSuccess: () => {
      invalidateList();
      setAdding(false);
      toastSuccess("Identifier added.");
    },
    onError: toastError,
  });

  const updateMutation = useMutation({
    mutationFn: (args: { identifier_id: number; input: PersonIdentifierInput }) =>
      personIdentifierUpdate({
        token,
        identifier_id: args.identifier_id,
        input: args.input,
      }),
    onSuccess: () => {
      invalidateList();
      setEditing(null);
      toastSuccess("Identifier updated.");
    },
    onError: toastError,
  });

  const deleteMutation = useMutation({
    mutationFn: (identifier_id: number) =>
      personIdentifierDelete({ token, identifier_id }),
    onSuccess: () => {
      invalidateList();
      setDeleting(null);
      toastSuccess("Identifier removed.");
    },
    onError: toastError,
  });

  // Add-person flow — parent row doesn't exist yet.
  if (entityId === null) {
    return (
      <div className="rounded-md border border-dashed p-4 bg-muted/30">
        <p className="text-sm font-medium">OSINT identifiers</p>
        <p className="text-xs text-muted-foreground mt-1">
          Save the person first. You'll be able to add multiple emails,
          handles, phone numbers, and profile URLs to submit for OSINT after
          the person is created.
        </p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-2">
        <Skeleton className="h-5 w-32" />
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-12 w-full" />
      </div>
    );
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertDescription>
          {(error as Partial<{ message: string }>)?.message ??
            "Failed to load identifiers."}
        </AlertDescription>
      </Alert>
    );
  }

  const identifiers = data ?? [];
  const grouped = groupByKind(identifiers);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium">OSINT identifiers</p>
          <p className="text-xs text-muted-foreground">
            {identifiers.length === 0
              ? "No identifiers recorded yet."
              : `${identifiers.length} identifier${identifiers.length === 1 ? "" : "s"}` +
                " — submitted as a batch when you run OSINT on this person."}
          </p>
        </div>
        {!readOnly && !adding && (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => setAdding(true)}
          >
            <Plus className="h-4 w-4 mr-1.5" />
            Add identifier
          </Button>
        )}
      </div>

      {/* Inline add form */}
      {!readOnly && adding && (
        <IdentifierFormRow
          isPending={addMutation.isPending}
          onSubmit={(values) =>
            addMutation.mutate({
              kind: values.kind,
              value: values.value.trim(),
              platform: values.platform?.trim() || null,
              notes: values.notes?.trim() || null,
            })
          }
          onCancel={() => setAdding(false)}
        />
      )}

      {/* Grouped list */}
      {identifiers.length > 0 && (
        <div className="space-y-3">
          {(Object.keys(grouped) as PersonIdentifierKind[]).map((kind) => (
            <div key={kind} className="space-y-1.5">
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                {KIND_META[kind].label}
              </p>
              <div className="space-y-1.5">
                {grouped[kind]!.map((id) =>
                  editing?.identifier_id === id.identifier_id ? (
                    <IdentifierFormRow
                      key={id.identifier_id}
                      defaultValues={{
                        kind: id.kind,
                        value: id.value,
                        platform: id.platform ?? "",
                        notes: id.notes ?? "",
                      }}
                      isPending={updateMutation.isPending}
                      onSubmit={(values) =>
                        updateMutation.mutate({
                          identifier_id: id.identifier_id,
                          input: {
                            kind: values.kind,
                            value: values.value.trim(),
                            platform: values.platform?.trim() || null,
                            notes: values.notes?.trim() || null,
                          },
                        })
                      }
                      onCancel={() => setEditing(null)}
                    />
                  ) : (
                    <IdentifierRow
                      key={id.identifier_id}
                      identifier={id}
                      readOnly={readOnly}
                      onEdit={() => setEditing(id)}
                      onDelete={() => setDeleting(id)}
                    />
                  ),
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Delete confirmation */}
      <AlertDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove this identifier?</AlertDialogTitle>
            <AlertDialogDescription>
              The identifier will be soft-deleted (audit trail preserved) and
              removed from the active OSINT submission set for this person.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() =>
                deleting && deleteMutation.mutate(deleting.identifier_id)
              }
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? "Removing…" : "Remove"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// ─── Single-row display ──────────────────────────────────────────────────────

function IdentifierRow({
  identifier,
  readOnly,
  onEdit,
  onDelete,
}: {
  identifier: PersonIdentifier;
  readOnly: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const Icon = KIND_META[identifier.kind].icon;
  return (
    <div className="flex items-center gap-2 rounded-md border bg-card px-3 py-2">
      <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
      <div className="flex-1 min-w-0">
        <div className="flex items-baseline gap-2 flex-wrap">
          <span className="text-sm font-medium break-all">{identifier.value}</span>
          {identifier.platform && (
            <span className="text-xs text-muted-foreground">
              · {identifier.platform}
            </span>
          )}
        </div>
        {identifier.notes && (
          <p className="text-xs text-muted-foreground mt-0.5 break-words">
            {identifier.notes}
          </p>
        )}
      </div>
      {!readOnly && (
        <div className="flex gap-1 shrink-0">
          <Button
            type="button"
            size="icon"
            variant="ghost"
            className="h-7 w-7"
            onClick={onEdit}
            aria-label="Edit identifier"
          >
            <Pencil className="h-3.5 w-3.5" />
          </Button>
          <Button
            type="button"
            size="icon"
            variant="ghost"
            className="h-7 w-7 text-destructive hover:text-destructive"
            onClick={onDelete}
            aria-label="Remove identifier"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── Inline add/edit form row ────────────────────────────────────────────────

function IdentifierFormRow({
  defaultValues,
  isPending,
  onSubmit,
  onCancel,
}: {
  defaultValues?: Partial<PersonIdentifierFormValues>;
  isPending: boolean;
  onSubmit: (values: PersonIdentifierFormValues) => void;
  onCancel: () => void;
}) {
  const form = useForm<PersonIdentifierFormValues>({
    resolver: zodResolver(personIdentifierFormSchema),
    defaultValues: {
      kind: "email",
      value: "",
      platform: "",
      notes: "",
      ...defaultValues,
    },
  });

  const kindValue = form.watch("kind");
  const placeholder = KIND_META[kindValue as PersonIdentifierKind]?.placeholder ?? "";

  // HTML doesn't allow nested <form> elements. This row is rendered inside
  // the outer PersonForm's <form>, so we use a <div> here and trigger submit
  // explicitly via the Save button's onClick. Bug found on the Business
  // side 2026-04-16 — nested submits bubbled to the outer form, closing
  // the dialog without saving. Same fix applied here to prevent the
  // equivalent regression on the Person side.
  const triggerSubmit = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    void form.handleSubmit(onSubmit)();
  };

  return (
    <Form {...form}>
      <div
        className="rounded-md border bg-muted/40 p-3 space-y-3"
        onKeyDown={(e) => {
          if (e.key === "Enter" && e.target !== e.currentTarget) {
            const tag = (e.target as HTMLElement).tagName;
            if (tag === "INPUT") {
              e.preventDefault();
              void form.handleSubmit(onSubmit)();
            }
          }
        }}
      >
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[140px_1fr]">
          <FormField
            control={form.control}
            name="kind"
            render={({ field }) => (
              <FormItem>
                <FormLabel className="text-xs">Kind</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger className="h-9">
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {PERSON_IDENTIFIER_KINDS.map((k) => (
                      <SelectItem key={k} value={k}>
                        {KIND_META[k].label}
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
            name="value"
            render={({ field }) => (
              <FormItem>
                <FormLabel className="text-xs">Value</FormLabel>
                <FormControl>
                  <Input
                    className="h-9"
                    placeholder={placeholder}
                    autoFocus
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="platform"
          render={({ field }) => (
            <FormItem>
              <FormLabel className="text-xs">Platform (optional)</FormLabel>
              <FormControl>
                <Input
                  className="h-9"
                  placeholder="twitter, reddit, github, discord, gmail, ..."
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="notes"
          render={({ field }) => (
            <FormItem>
              <FormLabel className="text-xs">Notes (optional)</FormLabel>
              <FormControl>
                <Textarea
                  rows={2}
                  placeholder="Where did this identifier come from? Verified? Active?"
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="flex justify-end gap-2">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={onCancel}
            disabled={isPending}
          >
            Cancel
          </Button>
          <Button
            type="button"
            size="sm"
            disabled={isPending}
            onClick={triggerSubmit}
          >
            {isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
    </Form>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function groupByKind(
  items: PersonIdentifier[],
): Partial<Record<PersonIdentifierKind, PersonIdentifier[]>> {
  const out: Partial<Record<PersonIdentifierKind, PersonIdentifier[]>> = {};
  for (const item of items) {
    const list = out[item.kind] ?? [];
    list.push(item);
    out[item.kind] = list;
  }
  return out;
}
