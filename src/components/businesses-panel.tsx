/**
 * BusinessesPanel — case-scoped Businesses management surface.
 *
 * Renders a responsive grid of BusinessCards for every `entity_type === "business"`
 * row in the case. Handles:
 *   - Fetching entities via entityListForCase (filtered client-side to businesses)
 *   - Add a new business via BusinessForm in a Dialog
 *   - Edit a business via the same form pre-populated
 *   - Delete (soft) via AlertDialog confirmation
 *   - Run OSINT via aiOsintBusiness — dispatches whois/subfinder/theHarvester/
 *     spiderfoot clearnet plus dark-web tools when tor_enabled. Reuses the
 *     shared OSINT consent gate (scope="osint") so one acknowledgment covers
 *     both person and business OSINT.
 *   - Logo upload (migration 0005) — BusinessForm returns a pickedLogoPath;
 *     the panel uploads it via businessLogoUpload after entity create/update.
 *     BusinessCard shows a "Clear logo" button that calls businessLogoDelete.
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, AlertCircle, Building2 } from "lucide-react";

import {
  entitiesListForCase,
  entityAdd,
  entityUpdate,
  entityDelete,
  aiOsintBusiness,
  businessLogoUpload,
  businessLogoDelete,
  settingsGetAgentZero,
  type Entity,
  type EntityInput,
  type AppError,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import { type BusinessFormValues } from "@/lib/business-schema";

import { BusinessCard } from "@/components/business-card";
import { BusinessForm } from "@/components/business-form";
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
// Helpers — convert BusinessFormValues to an EntityInput
// ---------------------------------------------------------------------------

function formToInput(values: BusinessFormValues): EntityInput {
  return {
    entity_type: "business",
    display_name: values.display_name.trim(),
    subtype: null,
    organizational_rank: values.organizational_rank?.trim() || null,
    parent_entity_id: null,
    notes: values.notes?.trim() || null,
    metadata_json: null,
    // Person-specific columns — null for businesses
    email: null,
    phone: null,
    username: null,
    employer: null,
    dob: null,
  };
}

function businessToFormValues(business: Entity): Partial<BusinessFormValues> {
  return {
    display_name: business.display_name,
    organizational_rank: business.organizational_rank ?? "",
    notes: business.notes ?? "",
  };
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface BusinessesPanelProps {
  caseId: string;
}

// ---------------------------------------------------------------------------
// BusinessesPanel
// ---------------------------------------------------------------------------

export function BusinessesPanel({ caseId }: BusinessesPanelProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();

  const [addOpen, setAddOpen] = React.useState(false);
  const [editBusiness, setEditBusiness] = React.useState<Entity | null>(null);
  const [deleteBusiness, setDeleteBusiness] = React.useState<Entity | null>(null);

  // OSINT state:
  //  - osintBusinessId: which BusinessCard's Run OSINT spinner is active
  //  - consentPending: entity_id awaiting OSINT consent; on acknowledge,
  //    we auto-retry ai_osint_business for that entity
  const [osintBusinessId, setOsintBusinessId] = React.useState<number | null>(null);
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

  const invalidateBusinesses = React.useCallback(() => {
    void queryClient.invalidateQueries({
      queryKey: queryKeys.entities.listForCase(caseId),
    });
  }, [queryClient, caseId]);

  const addMutation = useMutation({
    mutationFn: async (args: {
      input: EntityInput;
      pickedLogoPath: string | null;
    }) => {
      const created = await entityAdd({ token, case_id: caseId, input: args.input });
      if (args.pickedLogoPath) {
        await businessLogoUpload({
          token,
          entity_id: created.entity_id,
          source_path: args.pickedLogoPath,
        });
      }
      return created;
    },
    onSuccess: () => {
      invalidateBusinesses();
      setAddOpen(false);
      toastSuccess("Business added.");
    },
    onError: toastError,
  });

  const updateMutation = useMutation({
    mutationFn: async (args: {
      entity_id: number;
      input: EntityInput;
      pickedLogoPath: string | null;
    }) => {
      const updated = await entityUpdate({
        token,
        case_id: caseId,
        entity_id: args.entity_id,
        input: args.input,
      });
      if (args.pickedLogoPath) {
        await businessLogoUpload({
          token,
          entity_id: args.entity_id,
          source_path: args.pickedLogoPath,
        });
      }
      return updated;
    },
    onSuccess: () => {
      invalidateBusinesses();
      setEditBusiness(null);
      toastSuccess("Business updated.");
    },
    onError: toastError,
  });

  const clearLogoMutation = useMutation({
    mutationFn: (entity_id: number) =>
      businessLogoDelete({ token, entity_id }),
    onSuccess: () => {
      invalidateBusinesses();
      toastSuccess("Logo cleared.");
    },
    onError: toastError,
  });

  const deleteMutation = useMutation({
    mutationFn: (entity_id: number) =>
      entityDelete({ token, case_id: caseId, entity_id }),
    onSuccess: () => {
      invalidateBusinesses();
      setDeleteBusiness(null);
      toastSuccess("Business deleted.");
    },
    onError: toastError,
  });

  // OSINT mutation — runs Agent Zero orchestration and refreshes both the
  // businesses list (for metadata_json.osint_findings) and the tools tab query.
  const osintMutation = useMutation({
    mutationFn: (entity_id: number) => aiOsintBusiness({ token, entity_id }),
    onMutate: (entity_id) => {
      setOsintBusinessId(entity_id);
    },
    onSuccess: (summary, entity_id) => {
      invalidateBusinesses();
      void queryClient.invalidateQueries({
        queryKey: queryKeys.tools.listForCase(caseId),
      });
      // Refresh the business identifier editor so auto-discovered rows
      // show up immediately — OsintRunSummary.identifiers_auto_inserted
      // counts new rows that insert_discovered_batch wrote into
      // business_identifiers.
      void queryClient.invalidateQueries({
        queryKey: queryKeys.businessIdentifiers.listForEntity(entity_id),
      });
      setOsintBusinessId(null);
      const inserted = summary.tool_usage_rows_inserted;
      const tools = summary.tools_run;
      const ids = summary.identifiers_submitted;
      const autoAdded = summary.identifiers_auto_inserted;
      const headlineBase =
        ids === 0
          ? `OSINT ${summary.status} — name-only submission, ${tools} tool run${tools === 1 ? "" : "s"}, ${inserted} logged.`
          : `OSINT ${summary.status} — ${ids} identifier${ids === 1 ? "" : "s"} submitted, ${tools} tool run${tools === 1 ? "" : "s"}, ${inserted} logged.`;
      const autoFragment =
        autoAdded > 0
          ? ` ${autoAdded} new identifier${autoAdded === 1 ? "" : "s"} auto-added from findings.`
          : "";
      const headline = `${headlineBase}${autoFragment}`;
      const msg = summary.notes ? `${headline} ${summary.notes}` : headline;
      toastSuccess(msg);
    },
    onError: () => {
      // onError path is handled per-call inside handleRunOsint so we can
      // discriminate AiOsintConsentRequired from other errors and keep
      // track of which entity_id to retry after consent acknowledgment.
      // Reset the spinner here regardless.
      setOsintBusinessId(null);
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
          {(error as Partial<{ message: string }>)?.message ?? "Failed to load businesses."}
        </AlertDescription>
      </Alert>
    );
  }

  const businesses = (data ?? []).filter((e) => e.entity_type === "business");

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {businesses.length === 0
            ? "No businesses recorded."
            : `${businesses.length} business${businesses.length === 1 ? "" : "es"} in this case`}
        </p>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1.5" />
          Add Business
        </Button>
      </div>

      {/* Grid of cards */}
      {businesses.length === 0 ? (
        <div className="rounded-lg border-2 border-dashed p-12 text-center">
          <Building2 className="h-10 w-10 mx-auto text-muted-foreground/50 mb-3" />
          <p className="text-sm font-medium">No businesses yet</p>
          <p className="text-xs text-muted-foreground mt-1">
            Add companies, organizations, or other business entities involved in
            this case. Record domains, EINs, registration numbers, and more.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {businesses.map((b) => (
            <BusinessCard
              key={b.entity_id}
              business={b}
              onEdit={() => setEditBusiness(b)}
              onDelete={() => setDeleteBusiness(b)}
              onRunOsint={() => handleRunOsint(b.entity_id)}
              onClearLogo={() => clearLogoMutation.mutate(b.entity_id)}
              osintPending={osintBusinessId === b.entity_id}
            />
          ))}
        </div>
      )}

      {/* Add dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add a business</DialogTitle>
          </DialogHeader>
          <BusinessForm
            isPending={addMutation.isPending}
            onSubmit={(values, pickedLogoPath) =>
              addMutation.mutate({ input: formToInput(values), pickedLogoPath })
            }
            onCancel={() => setAddOpen(false)}
            submitLabel="Add business"
          />
        </DialogContent>
      </Dialog>

      {/* Edit dialog */}
      <Dialog
        open={editBusiness !== null}
        onOpenChange={(open) => !open && setEditBusiness(null)}
      >
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit business</DialogTitle>
          </DialogHeader>
          {editBusiness && (
            <BusinessForm
              defaultValues={businessToFormValues(editBusiness)}
              currentLogoPath={editBusiness.photo_path}
              entityId={editBusiness.entity_id}
              isPending={updateMutation.isPending}
              onSubmit={(values, pickedLogoPath) =>
                updateMutation.mutate({
                  entity_id: editBusiness.entity_id,
                  input: formToInput(values),
                  pickedLogoPath,
                })
              }
              onCancel={() => setEditBusiness(null)}
              submitLabel="Save changes"
            />
          )}
        </DialogContent>
      </Dialog>

      {/* OSINT consent dialog — shown on first Run OSINT click per install.
          Scope "osint" is shared between persons and businesses — one
          acknowledgment covers both entity types. */}
      <AiConsentDialog
        open={consentPending !== null}
        scope="osint"
        agentZeroUrl={agentZeroSettings?.url ?? "http://localhost:5099"}
        onAcknowledge={handleConsentAcknowledged}
        onClose={() => setConsentPending(null)}
      />

      {/* Delete confirmation */}
      <AlertDialog
        open={deleteBusiness !== null}
        onOpenChange={(open) => !open && setDeleteBusiness(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Delete {deleteBusiness?.display_name ?? "business"}?
            </AlertDialogTitle>
            <AlertDialogDescription>
              The business will be soft-deleted and removed from the case view.
              Entity-link rows and business identifiers where this business is an
              endpoint will also be soft-deleted (audit trail preserved).
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() =>
                deleteBusiness && deleteMutation.mutate(deleteBusiness.entity_id)
              }
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? "Deleting…" : "Delete business"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
