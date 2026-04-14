/**
 * EntitiesPanel — list + CRUD for entities on a case.
 *
 * Entities are grouped by entity_type.
 * Each card shows: display_name, subtype badge (if person),
 * organizational_rank, parent entity name.
 * Per-card actions: Edit (dialog), Delete (AlertDialog).
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2, User, Building2, Phone, Mail, Tag, MapPin, CreditCard, Car } from "lucide-react";

import {
  entitiesListForCase,
  entityAdd,
  entityUpdate,
  entityDelete,
} from "@/lib/bindings";
import type { Entity, EntityInput } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import { entityTypeColor } from "@/lib/link-analysis-enums";
import type { EntityFormValues } from "@/lib/entity-schema";

import { Button } from "@/components/ui/button";
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
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { EntityForm } from "@/components/entity-form";

const ENTITY_TYPE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  person: User,
  business: Building2,
  phone: Phone,
  email: Mail,
  alias: Tag,
  address: MapPin,
  account: CreditCard,
  vehicle: Car,
};

interface EntitiesPanelProps {
  caseId: string;
}

export function EntitiesPanel({ caseId }: EntitiesPanelProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();

  const [addOpen, setAddOpen] = React.useState(false);
  const [editEntity, setEditEntity] = React.useState<Entity | null>(null);

  const { data: entities = [], isLoading } = useQuery({
    queryKey: queryKeys.entities.listForCase(caseId),
    queryFn: () => entitiesListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const addMutation = useMutation({
    mutationFn: (input: EntityInput) =>
      entityAdd({ token, case_id: caseId, input }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.entities.listForCase(caseId),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.graph.forCase(caseId, { entity_types: null, include_evidence: true }),
      });
      toastSuccess("Entity added.");
      setAddOpen(false);
    },
    onError: toastError,
  });

  const updateMutation = useMutation({
    mutationFn: ({
      entity_id,
      input,
    }: {
      entity_id: number;
      input: EntityInput;
    }) => entityUpdate({ token, case_id: caseId, entity_id, input }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.entities.listForCase(caseId),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.graph.forCase(caseId, { entity_types: null, include_evidence: true }),
      });
      toastSuccess("Entity updated.");
      setEditEntity(null);
    },
    onError: toastError,
  });

  const deleteMutation = useMutation({
    mutationFn: (entity_id: number) =>
      entityDelete({ token, case_id: caseId, entity_id }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.entities.listForCase(caseId),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.graph.forCase(caseId, { entity_types: null, include_evidence: true }),
      });
      toastSuccess("Entity deleted.");
    },
    onError: toastError,
  });

  function handleAdd(values: EntityFormValues) {
    const input: EntityInput = {
      entity_type: values.entity_type,
      display_name: values.display_name,
      subtype: (values.subtype as Entity["subtype"]) ?? null,
      organizational_rank: values.organizational_rank?.trim() || null,
      parent_entity_id: values.parent_entity_id ?? null,
      notes: values.notes?.trim() || null,
      metadata_json: values.metadata_json?.trim() || null,
    };
    addMutation.mutate(input);
  }

  function handleUpdate(values: EntityFormValues) {
    if (!editEntity) return;
    const input: EntityInput = {
      entity_type: values.entity_type,
      display_name: values.display_name,
      subtype: (values.subtype as Entity["subtype"]) ?? null,
      organizational_rank: values.organizational_rank?.trim() || null,
      parent_entity_id: values.parent_entity_id ?? null,
      notes: values.notes?.trim() || null,
      metadata_json: values.metadata_json?.trim() || null,
    };
    updateMutation.mutate({ entity_id: editEntity.entity_id, input });
  }

  // Group by entity_type
  const grouped = new Map<string, Entity[]>();
  for (const entity of entities) {
    const group = grouped.get(entity.entity_type) ?? [];
    group.push(entity);
    grouped.set(entity.entity_type, group);
  }

  // Name lookup for parent display
  const entityById = new Map(entities.map((e) => [e.entity_id, e]));

  if (isLoading) {
    return <p className="text-sm text-muted-foreground py-4">Loading entities…</p>;
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1" />
          Add Entity
        </Button>
      </div>

      {entities.length === 0 && (
        <p className="text-sm text-muted-foreground py-4 text-center">
          No entities yet. Add suspects, businesses, phones, emails, and other
          relevant actors to build the network.
        </p>
      )}

      {Array.from(grouped.entries()).map(([type, group]) => {
        const Icon = ENTITY_TYPE_ICONS[type] ?? User;
        const colors = entityTypeColor(type as Parameters<typeof entityTypeColor>[0]);
        return (
          <div key={type}>
            <div className="flex items-center gap-2 mb-2">
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium capitalize ${colors.bg} ${colors.text}`}
              >
                <Icon className="h-3 w-3" />
                {type}
              </span>
              <span className="text-xs text-muted-foreground">
                {group.length} {group.length === 1 ? "entity" : "entities"}
              </span>
            </div>
            <div className="space-y-2 pl-4">
              {group.map((entity) => {
                const parent = entity.parent_entity_id != null
                  ? entityById.get(entity.parent_entity_id)
                  : null;
                return (
                  <div
                    key={entity.entity_id}
                    className="flex items-start justify-between rounded-md border px-3 py-2 text-sm gap-3"
                  >
                    <div className="min-w-0">
                      <p className="font-medium truncate">{entity.display_name}</p>
                      <div className="flex flex-wrap gap-1.5 mt-1">
                        {entity.subtype && (
                          <span className="inline-flex items-center rounded-full border px-2 py-0.5 text-xs capitalize text-muted-foreground">
                            {entity.subtype}
                          </span>
                        )}
                        {entity.organizational_rank && (
                          <span className="text-xs text-muted-foreground">
                            {entity.organizational_rank}
                          </span>
                        )}
                        {parent && (
                          <span className="text-xs text-muted-foreground">
                            child of {parent.display_name}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="flex gap-1 shrink-0">
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-7 w-7"
                        onClick={() => setEditEntity(entity)}
                        aria-label={`Edit ${entity.display_name}`}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-7 w-7 text-destructive hover:text-destructive"
                            aria-label={`Delete ${entity.display_name}`}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Delete entity?</AlertDialogTitle>
                            <AlertDialogDescription>
                              <strong>{entity.display_name}</strong> will be
                              soft-deleted. Any links connected to this entity
                              will no longer appear in the graph.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() =>
                                deleteMutation.mutate(entity.entity_id)
                              }
                              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                            >
                              Delete
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {/* Add dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Entity</DialogTitle>
          </DialogHeader>
          <EntityForm
            entityList={entities}
            isPending={addMutation.isPending}
            onSubmit={handleAdd}
            onCancel={() => setAddOpen(false)}
          />
        </DialogContent>
      </Dialog>

      {/* Edit dialog */}
      <Dialog
        open={editEntity != null}
        onOpenChange={(open) => { if (!open) setEditEntity(null); }}
      >
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Entity</DialogTitle>
          </DialogHeader>
          {editEntity && (
            <EntityForm
              defaultValues={{
                entity_type: editEntity.entity_type,
                display_name: editEntity.display_name,
                subtype: editEntity.subtype ?? undefined,
                organizational_rank: editEntity.organizational_rank ?? "",
                parent_entity_id: editEntity.parent_entity_id ?? null,
                notes: editEntity.notes ?? "",
                metadata_json: editEntity.metadata_json ?? "",
              }}
              entityList={entities}
              currentEntityId={editEntity.entity_id}
              isPending={updateMutation.isPending}
              onSubmit={handleUpdate}
              onCancel={() => setEditEntity(null)}
              submitLabel="Save Changes"
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
