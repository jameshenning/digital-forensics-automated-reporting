/**
 * LinksPanel — flat list + add/delete for entity/evidence links.
 *
 * Each row shows: <source> —[label]-> <target>
 * No edit variant (matches v1 behavior).
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, ArrowRight, Minus } from "lucide-react";

import {
  linksListForCase,
  entitiesListForCase,
  evidenceListForCase,
  linkAdd,
  linkDelete,
} from "@/lib/bindings";
import type { Link, LinkInput } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import type { LinkFormValues } from "@/lib/link-schema";

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
import { LinkForm } from "@/components/link-form";

interface LinksPanelProps {
  caseId: string;
}

export function LinksPanel({ caseId }: LinksPanelProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();

  const [addOpen, setAddOpen] = React.useState(false);

  const { data: links = [], isLoading } = useQuery({
    queryKey: queryKeys.links.listForCase(caseId),
    queryFn: () => linksListForCase({ token, case_id: caseId }),
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

  const entityById = new Map(entities.map((e) => [String(e.entity_id), e.display_name]));
  const evidenceById = new Map(evidenceList.map((e) => [e.evidence_id, e.evidence_id]));

  function nodeName(type: Link["source_type"], id: string): string {
    if (type === "entity") return entityById.get(id) ?? `entity:${id}`;
    return evidenceById.get(id) ?? `evidence:${id}`;
  }

  const addMutation = useMutation({
    mutationFn: (input: LinkInput) =>
      linkAdd({ token, case_id: caseId, input }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.links.listForCase(caseId),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.graph.forCase(caseId, { entity_types: null, include_evidence: true }),
      });
      toastSuccess("Link added.");
      setAddOpen(false);
    },
    onError: toastError,
  });

  const deleteMutation = useMutation({
    mutationFn: (link_id: number) =>
      linkDelete({ token, case_id: caseId, link_id }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.links.listForCase(caseId),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.graph.forCase(caseId, { entity_types: null, include_evidence: true }),
      });
      toastSuccess("Link deleted.");
    },
    onError: toastError,
  });

  function handleAdd(values: LinkFormValues) {
    const input: LinkInput = {
      source_type: values.source_type,
      source_id: values.source_id,
      target_type: values.target_type,
      target_id: values.target_id,
      link_label: values.link_label?.trim() || null,
      directional: values.directional ?? 1,
      weight: values.weight ?? 1.0,
      notes: values.notes?.trim() || null,
    };
    addMutation.mutate(input);
  }

  if (isLoading) {
    return <p className="text-sm text-muted-foreground py-4">Loading links…</p>;
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1" />
          Add Link
        </Button>
      </div>

      {links.length === 0 && (
        <p className="text-sm text-muted-foreground py-4 text-center">
          No links yet. Connect entities and evidence to build the relationship graph.
        </p>
      )}

      <div className="space-y-2">
        {links.map((link) => {
          const srcName = nodeName(link.source_type, link.source_id);
          const tgtName = nodeName(link.target_type, link.target_id);
          const Arrow = link.directional ? ArrowRight : Minus;

          return (
            <div
              key={link.link_id}
              className="flex items-center justify-between rounded-md border px-3 py-2 text-sm gap-3"
            >
              <div className="flex items-center gap-2 min-w-0 flex-wrap">
                <span className="font-medium truncate max-w-[140px]">
                  {srcName}
                </span>
                <Arrow className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                {link.link_label && (
                  <span className="text-xs text-muted-foreground italic">
                    [{link.link_label}]
                  </span>
                )}
                <Arrow className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                <span className="font-medium truncate max-w-[140px]">
                  {tgtName}
                </span>
                {link.weight !== 1 && (
                  <span className="text-xs text-muted-foreground">
                    w={link.weight}
                  </span>
                )}
              </div>
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button
                    size="icon"
                    variant="ghost"
                    className="h-7 w-7 text-destructive hover:text-destructive shrink-0"
                    aria-label="Delete link"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>Delete link?</AlertDialogTitle>
                    <AlertDialogDescription>
                      The link between <strong>{srcName}</strong> and{" "}
                      <strong>{tgtName}</strong> will be permanently removed from
                      the graph.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction
                      onClick={() => deleteMutation.mutate(link.link_id)}
                      className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                    >
                      Delete
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </div>
          );
        })}
      </div>

      {/* Add dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Link</DialogTitle>
          </DialogHeader>
          <LinkForm
            entityList={entities}
            evidenceList={evidenceList}
            isPending={addMutation.isPending}
            onSubmit={handleAdd}
            onCancel={() => setAddOpen(false)}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}
