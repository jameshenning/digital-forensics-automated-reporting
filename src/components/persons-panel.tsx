/**
 * PersonsPanel — case-scoped Persons management surface.
 *
 * Renders a responsive grid of PersonCards for every `entity_type === "person"`
 * row in the case. Handles:
 *   - Fetching entities via entityListForCase (filtered client-side to persons)
 *   - Add a new person via PersonForm in a Dialog (creates entity + uploads photo)
 *   - Edit a person via the same form pre-populated
 *   - Delete (soft) via AlertDialog confirmation
 *   - Clear photo (stub via personPhotoDelete)
 *   - Run OSINT button — stubbed in PR3; wired to ai_osint_person in PR6
 *
 * The generic EntitiesPanel in link-analysis still handles all other entity
 * types (business, phone, email, etc.). This panel is the specialized
 * person-only surface.
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, AlertCircle, Users } from "lucide-react";

import {
  entitiesListForCase,
  entityAdd,
  entityUpdate,
  entityDelete,
  personPhotoUpload,
  personPhotoDelete,
  aiOsintPerson,
  settingsGetAgentZero,
  type Entity,
  type EntityInput,
  type AppError,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import type { PersonFormValues } from "@/lib/person-schema";

import { PersonForm } from "@/components/person-form";
import { PersonCard } from "@/components/person-card";
import { AiConsentDialog } from "@/components/ai-consent-dialog";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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

// ---------------------------------------------------------------------------
// Helpers — convert PersonFormValues to an EntityInput
// ---------------------------------------------------------------------------

function formToInput(values: PersonFormValues): EntityInput {
  return {
    entity_type: "person",
    display_name: values.display_name.trim(),
    subtype: values.subtype ?? null,
    organizational_rank: values.organizational_rank?.trim() || null,
    parent_entity_id: null,
    notes: values.notes?.trim() || null,
    metadata_json: null,
    email: values.email?.trim() || null,
    phone: values.phone?.trim() || null,
    username: values.username?.trim() || null,
    employer: values.employer?.trim() || null,
    dob: values.dob?.trim() || null,
  };
}

function personToFormValues(person: Entity): Partial<PersonFormValues> {
  return {
    display_name: person.display_name,
    subtype: person.subtype,
    organizational_rank: person.organizational_rank ?? "",
    email: person.email ?? "",
    phone: person.phone ?? "",
    username: person.username ?? "",
    employer: person.employer ?? "",
    dob: person.dob ?? "",
    notes: person.notes ?? "",
  };
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface PersonsPanelProps {
  caseId: string;
}

// ---------------------------------------------------------------------------
// PersonsPanel
// ---------------------------------------------------------------------------

export function PersonsPanel({ caseId }: PersonsPanelProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();

  const [addOpen, setAddOpen] = React.useState(false);
  const [editPerson, setEditPerson] = React.useState<Entity | null>(null);
  const [deletePerson, setDeletePerson] = React.useState<Entity | null>(null);

  // OSINT state:
  //  - osintPersonId: which PersonCard's Run OSINT spinner is active
  //  - consentPending: entity_id awaiting OSINT consent; on acknowledge,
  //    we auto-retry ai_osint_person for that entity
  const [osintPersonId, setOsintPersonId] = React.useState<number | null>(null);
  const [consentPending, setConsentPending] = React.useState<number | null>(null);

  // Agent Zero URL — fetched once for the consent dialog copy
  const { data: agentZeroSettings } = useQuery({
    queryKey: queryKeys.agentZero.settings,
    queryFn: () => settingsGetAgentZero({ token }),
    enabled: !!token,
    refetchOnWindowFocus: false,
  });

  const { data, isLoading, isError, error } = useQuery<Entity[]>({
    queryKey: queryKeys.entities.listForCase(caseId),
    queryFn: () => entitiesListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const invalidatePersons = React.useCallback(() => {
    void queryClient.invalidateQueries({
      queryKey: queryKeys.entities.listForCase(caseId),
    });
  }, [queryClient, caseId]);

  // Add mutation — creates the entity, then uploads the photo if one was picked.
  const addMutation = useMutation({
    mutationFn: async (args: {
      input: EntityInput;
      pickedPhotoPath: string | null;
    }) => {
      const created = await entityAdd({ token, case_id: caseId, input: args.input });
      if (args.pickedPhotoPath) {
        await personPhotoUpload({
          token,
          entity_id: created.entity_id,
          source_path: args.pickedPhotoPath,
        });
      }
      return created;
    },
    onSuccess: () => {
      invalidatePersons();
      setAddOpen(false);
      toastSuccess("Person added.");
    },
    onError: toastError,
  });

  // Edit mutation — updates fields, then replaces photo if a new one was picked.
  const updateMutation = useMutation({
    mutationFn: async (args: {
      entity_id: number;
      input: EntityInput;
      pickedPhotoPath: string | null;
    }) => {
      const updated = await entityUpdate({
        token,
        case_id: caseId,
        entity_id: args.entity_id,
        input: args.input,
      });
      if (args.pickedPhotoPath) {
        await personPhotoUpload({
          token,
          entity_id: args.entity_id,
          source_path: args.pickedPhotoPath,
        });
      }
      return updated;
    },
    onSuccess: () => {
      invalidatePersons();
      setEditPerson(null);
      toastSuccess("Person updated.");
    },
    onError: toastError,
  });

  const deleteMutation = useMutation({
    mutationFn: (entity_id: number) =>
      entityDelete({ token, case_id: caseId, entity_id }),
    onSuccess: () => {
      invalidatePersons();
      setDeletePerson(null);
      toastSuccess("Person deleted.");
    },
    onError: toastError,
  });

  const clearPhotoMutation = useMutation({
    mutationFn: (entity_id: number) =>
      personPhotoDelete({ token, entity_id }),
    onSuccess: () => {
      invalidatePersons();
      toastSuccess("Photo cleared.");
    },
    onError: toastError,
  });

  // OSINT mutation — runs Agent Zero orchestration and refreshes both the
  // persons list (for metadata_json.osint_findings) and the tools tab query.
  const osintMutation = useMutation({
    mutationFn: (entity_id: number) => aiOsintPerson({ token, entity_id }),
    onMutate: (entity_id) => {
      setOsintPersonId(entity_id);
    },
    onSuccess: (summary) => {
      invalidatePersons();
      void queryClient.invalidateQueries({
        queryKey: queryKeys.tools.listForCase(caseId),
      });
      setOsintPersonId(null);
      const inserted = summary.tool_usage_rows_inserted;
      const tools = summary.tools_run;
      toastSuccess(
        `OSINT ${summary.status} — ${tools} tool run${tools === 1 ? "" : "s"}, ${inserted} logged to the Tools tab.`,
      );
    },
    onError: () => {
      // onError path is handled per-call inside handleRunOsint so we can
      // discriminate AiOsintConsentRequired from other errors and keep
      // track of which entity_id to retry after consent acknowledgment.
      // Reset the spinner here regardless.
      setOsintPersonId(null);
    },
  });

  function handleRunOsint(entity_id: number) {
    osintMutation.mutate(entity_id, {
      onError: (err) => {
        const code = (err as Partial<AppError>)?.code;
        if (code === "AiOsintConsentRequired") {
          setConsentPending(entity_id);
          return;
        }
        toastError(err);
      },
    });
  }

  function handleConsentAcknowledged() {
    const target = consentPending;
    setConsentPending(null);
    if (target !== null) {
      // Retry the OSINT run now that the backend has recorded consent.
      handleRunOsint(target);
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 2 }).map((_, i) => (
          <Skeleton key={i} className="h-64 w-full" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          {(error as Partial<{ message: string }>)?.message ?? "Failed to load persons."}
        </AlertDescription>
      </Alert>
    );
  }

  const persons = (data ?? []).filter((e) => e.entity_type === "person");

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {persons.length === 0
            ? "No persons recorded."
            : `${persons.length} person${persons.length === 1 ? "" : "s"} in this case`}
        </p>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1.5" />
          Add Person
        </Button>
      </div>

      {/* Grid of cards */}
      {persons.length === 0 ? (
        <div className="rounded-lg border-2 border-dashed p-12 text-center">
          <Users className="h-10 w-10 mx-auto text-muted-foreground/50 mb-3" />
          <p className="text-sm font-medium">No persons yet</p>
          <p className="text-xs text-muted-foreground mt-1">
            Add suspects, victims, witnesses, investigators, or persons of
            interest. Upload a photo and run OSINT tools to enrich the profile.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {persons.map((p) => (
            <PersonCard
              key={p.entity_id}
              person={p}
              onEdit={() => setEditPerson(p)}
              onDelete={() => setDeletePerson(p)}
              onClearPhoto={() => clearPhotoMutation.mutate(p.entity_id)}
              onRunOsint={() => handleRunOsint(p.entity_id)}
              osintPending={osintPersonId === p.entity_id}
            />
          ))}
        </div>
      )}

      {/* Add dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add a person</DialogTitle>
          </DialogHeader>
          <PersonForm
            isPending={addMutation.isPending}
            onSubmit={(values, pickedPhotoPath) =>
              addMutation.mutate({
                input: formToInput(values),
                pickedPhotoPath,
              })
            }
            onCancel={() => setAddOpen(false)}
            submitLabel="Add person"
          />
        </DialogContent>
      </Dialog>

      {/* Edit dialog */}
      <Dialog
        open={editPerson !== null}
        onOpenChange={(open) => !open && setEditPerson(null)}
      >
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit person</DialogTitle>
          </DialogHeader>
          {editPerson && (
            <PersonForm
              defaultValues={personToFormValues(editPerson)}
              currentPhotoPath={editPerson.photo_path}
              isPending={updateMutation.isPending}
              onSubmit={(values, pickedPhotoPath) =>
                updateMutation.mutate({
                  entity_id: editPerson.entity_id,
                  input: formToInput(values),
                  pickedPhotoPath,
                })
              }
              onCancel={() => setEditPerson(null)}
              submitLabel="Save changes"
            />
          )}
        </DialogContent>
      </Dialog>

      {/* OSINT consent dialog — shown on first Run OSINT click per install */}
      <AiConsentDialog
        open={consentPending !== null}
        scope="osint"
        agentZeroUrl={agentZeroSettings?.url ?? "http://localhost:5099"}
        onAcknowledge={handleConsentAcknowledged}
        onClose={() => setConsentPending(null)}
      />

      {/* Delete confirmation */}
      <AlertDialog
        open={deletePerson !== null}
        onOpenChange={(open) => !open && setDeletePerson(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Delete {deletePerson?.display_name ?? "person"}?
            </AlertDialogTitle>
            <AlertDialogDescription>
              The person will be soft-deleted and removed from the case view.
              Entity-link rows where this person is an endpoint will also be
              soft-deleted (audit trail preserved).
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() =>
                deletePerson && deleteMutation.mutate(deletePerson.entity_id)
              }
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? "Deleting…" : "Delete person"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
