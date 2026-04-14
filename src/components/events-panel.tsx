/**
 * EventsPanel — list + add/edit/delete for case events.
 *
 * Events are sorted by event_datetime ascending.
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2 } from "lucide-react";

import {
  eventsListForCase,
  entitiesListForCase,
  evidenceListForCase,
  eventAdd,
  eventUpdate,
  eventDelete,
} from "@/lib/bindings";
import type { CaseEvent, EventInput } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import { eventCategoryHex, EVENT_CATEGORIES } from "@/lib/link-analysis-enums";
import type { EventFormValues } from "@/lib/event-schema";

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
import { EventForm } from "@/components/event-form";

interface EventsPanelProps {
  caseId: string;
}

function fmtDatetime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Convert ISO to datetime-local string for defaultValues */
function toDatetimeLocal(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function EventsPanel({ caseId }: EventsPanelProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();

  const [addOpen, setAddOpen] = React.useState(false);
  const [editEvent, setEditEvent] = React.useState<CaseEvent | null>(null);

  const { data: rawEvents = [], isLoading } = useQuery({
    queryKey: queryKeys.events.listForCase(caseId),
    queryFn: () => eventsListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const { data: entities = [] } = useQuery({
    queryKey: queryKeys.entities.listForCase(caseId),
    queryFn: () => entitiesListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const { data: evidenceList = [] } = useQuery({
    queryKey: queryKeys.evidence.listForCase(caseId),
    queryFn: () => evidenceListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const entityById = new Map(entities.map((e) => [e.entity_id, e.display_name]));

  // Sort by event_datetime ascending
  const events = [...rawEvents].sort(
    (a, b) => new Date(a.event_datetime).getTime() - new Date(b.event_datetime).getTime()
  );

  const addMutation = useMutation({
    mutationFn: (input: EventInput) =>
      eventAdd({ token, case_id: caseId, input }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.events.listForCase(caseId),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.crimeLine.forCase(caseId, { start: null, end: null }),
      });
      toastSuccess("Event added.");
      setAddOpen(false);
    },
    onError: toastError,
  });

  const updateMutation = useMutation({
    mutationFn: ({ event_id, input }: { event_id: number; input: EventInput }) =>
      eventUpdate({ token, case_id: caseId, event_id, input }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.events.listForCase(caseId),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.crimeLine.forCase(caseId, { start: null, end: null }),
      });
      toastSuccess("Event updated.");
      setEditEvent(null);
    },
    onError: toastError,
  });

  const deleteMutation = useMutation({
    mutationFn: (event_id: number) =>
      eventDelete({ token, case_id: caseId, event_id }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.events.listForCase(caseId),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.crimeLine.forCase(caseId, { start: null, end: null }),
      });
      toastSuccess("Event deleted.");
    },
    onError: toastError,
  });

  function formValuesToInput(values: EventFormValues): EventInput {
    return {
      title: values.title,
      description: values.description?.trim() || null,
      event_datetime: values.event_datetime,
      event_end_datetime: values.event_end_datetime?.trim() || null,
      category: (values.category as CaseEvent["category"]) ?? null,
      related_entity_id: values.related_entity_id ?? null,
      related_evidence_id: values.related_evidence_id ?? null,
    };
  }

  if (isLoading) {
    return <p className="text-sm text-muted-foreground py-4">Loading events…</p>;
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1" />
          Add Event
        </Button>
      </div>

      {events.length === 0 && (
        <p className="text-sm text-muted-foreground py-4 text-center">
          No events yet. Add observations, communications, movements, and other
          case events to build the crime-line timeline.
        </p>
      )}

      <div className="space-y-2">
        {events.map((evt) => {
          const catHex =
            evt.category && (EVENT_CATEGORIES as readonly string[]).includes(evt.category)
              ? eventCategoryHex(evt.category as (typeof EVENT_CATEGORIES)[number])
              : undefined;
          const relatedEntity =
            evt.related_entity_id != null
              ? entityById.get(evt.related_entity_id)
              : null;

          return (
            <div
              key={evt.event_id}
              className="flex items-start justify-between rounded-md border px-3 py-2 text-sm gap-3"
              style={
                catHex
                  ? { borderLeftWidth: "3px", borderLeftColor: catHex }
                  : undefined
              }
            >
              <div className="min-w-0 flex-1">
                <p className="font-semibold truncate">{evt.title}</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {fmtDatetime(evt.event_datetime)}
                  {evt.event_end_datetime &&
                    ` — ${fmtDatetime(evt.event_end_datetime)}`}
                </p>
                <div className="flex flex-wrap gap-1.5 mt-1">
                  {evt.category && (
                    <span
                      className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize text-white"
                      style={{ backgroundColor: catHex ?? "#6c757d" }}
                    >
                      {evt.category}
                    </span>
                  )}
                  {relatedEntity && (
                    <span className="text-xs text-muted-foreground">
                      Entity: {relatedEntity}
                    </span>
                  )}
                  {evt.related_evidence_id && (
                    <span className="text-xs text-muted-foreground font-mono">
                      Ev: {evt.related_evidence_id}
                    </span>
                  )}
                </div>
              </div>
              <div className="flex gap-1 shrink-0">
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-7 w-7"
                  onClick={() => setEditEvent(evt)}
                  aria-label={`Edit event: ${evt.title}`}
                >
                  <Pencil className="h-3.5 w-3.5" />
                </Button>
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-7 w-7 text-destructive hover:text-destructive"
                      aria-label={`Delete event: ${evt.title}`}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Delete event?</AlertDialogTitle>
                      <AlertDialogDescription>
                        <strong>{evt.title}</strong> will be permanently
                        removed from the crime-line.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction
                        onClick={() => deleteMutation.mutate(evt.event_id)}
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

      {/* Add dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Case Event</DialogTitle>
          </DialogHeader>
          <EventForm
            entityList={entities}
            evidenceList={evidenceList}
            isPending={addMutation.isPending}
            onSubmit={(values) => addMutation.mutate(formValuesToInput(values))}
            onCancel={() => setAddOpen(false)}
          />
        </DialogContent>
      </Dialog>

      {/* Edit dialog */}
      <Dialog
        open={editEvent != null}
        onOpenChange={(open) => { if (!open) setEditEvent(null); }}
      >
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Event</DialogTitle>
          </DialogHeader>
          {editEvent && (
            <EventForm
              defaultValues={{
                title: editEvent.title,
                description: editEvent.description ?? "",
                event_datetime: toDatetimeLocal(editEvent.event_datetime),
                event_end_datetime: editEvent.event_end_datetime
                  ? toDatetimeLocal(editEvent.event_end_datetime)
                  : null,
                category: editEvent.category ?? null,
                related_entity_id: editEvent.related_entity_id ?? null,
                related_evidence_id: editEvent.related_evidence_id ?? null,
              }}
              entityList={entities}
              evidenceList={evidenceList}
              isPending={updateMutation.isPending}
              onSubmit={(values) =>
                updateMutation.mutate({
                  event_id: editEvent.event_id,
                  input: formValuesToInput(values),
                })
              }
              onCancel={() => setEditEvent(null)}
              submitLabel="Save Changes"
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
