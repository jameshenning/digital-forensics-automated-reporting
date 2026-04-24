/**
 * NodeInspector — slide-in side panel that shows entity / evidence /
 * identifier context when an investigator clicks a node on the link
 * analysis graph. Single Tauri round-trip per click via `node_inspector`.
 *
 * The graph is the *question*, this panel is the *answer* — the graph
 * shows you the connections, the inspector tells you what each node is.
 *
 * Three render paths driven by `payload.kind`:
 *   - "entity"     → photo/icon, type+subtype, identifiers list, link counts
 *   - "evidence"   → description, status, custody summary, link/hash counts
 *   - "identifier" → kind+value, source tool badge, list of all owners
 *   - "not_found"  → friendly empty state (stale node id after soft-delete)
 *
 * Open/close is controlled by the parent route via `nodeId`. Passing
 * `null` collapses the sheet without unmounting the underlying graph.
 */

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Building2, FileBox, Network, User, Tag, Users } from "lucide-react";

import { nodeInspector } from "@/lib/bindings";
import type {
  EntityIdentifier,
  IdentifierOwner,
  InspectorPayload,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { entityTypeColor, identifierKindHex } from "@/lib/link-analysis-enums";

import { Badge } from "@/components/ui/badge";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { SourceToolBadge } from "@/components/source-tool-badge";

interface NodeInspectorProps {
  caseId: string;
  /** When non-null, the sheet is open and shows that node's data. */
  nodeId: string | null;
  onClose: () => void;
}

export function NodeInspector({ caseId, nodeId, onClose }: NodeInspectorProps) {
  const token = getToken() ?? "";

  const { data, isLoading, isError } = useQuery({
    queryKey: nodeId
      ? queryKeys.inspector.forNode(caseId, nodeId)
      : ["inspector-disabled"],
    queryFn: () =>
      nodeInspector({ token, case_id: caseId, node_id: nodeId! }),
    enabled: !!token && !!nodeId,
    refetchOnWindowFocus: false,
  });

  return (
    <Sheet open={!!nodeId} onOpenChange={(open) => !open && onClose()}>
      <SheetContent
        side="right"
        className="w-full sm:max-w-md overflow-y-auto"
        aria-describedby={undefined}
      >
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            {data ? (
              <InspectorTitle payload={data} />
            ) : (
              <span className="text-muted-foreground">Loading…</span>
            )}
          </SheetTitle>
        </SheetHeader>

        <div className="mt-4">
          {isLoading && <InspectorSkeleton />}
          {isError && (
            <p className="text-sm text-destructive">
              Failed to load node details.
            </p>
          )}
          {data && data.kind === "not_found" && (
            <p className="text-sm text-muted-foreground">
              This node is no longer available — it may have been removed
              from the case after the graph was last refreshed.
            </p>
          )}
          {data && data.kind === "entity" && <EntityBody view={data} />}
          {data && data.kind === "evidence" && <EvidenceBody view={data} />}
          {data && data.kind === "identifier" && (
            <IdentifierBody view={data} />
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

// ─── Title row ──────────────────────────────────────────────────────────────

function InspectorTitle({ payload }: { payload: InspectorPayload }) {
  if (payload.kind === "entity") {
    const Icon = payload.entity_type === "business" ? Building2 : User;
    return (
      <span className="flex items-center gap-2">
        <Icon className="h-4 w-4" />
        {payload.display_name}
      </span>
    );
  }
  if (payload.kind === "evidence") {
    return (
      <span className="flex items-center gap-2">
        <FileBox className="h-4 w-4" />
        <span className="font-mono text-sm">{payload.evidence.evidence_id}</span>
      </span>
    );
  }
  if (payload.kind === "identifier") {
    return (
      <span className="flex items-center gap-2">
        <Tag className="h-4 w-4" />
        <span className="capitalize text-sm">{payload.identifier_kind}</span>
        <span className="font-mono text-xs text-muted-foreground truncate">
          {payload.value}
        </span>
      </span>
    );
  }
  return <span>Node details</span>;
}

// ─── Entity ─────────────────────────────────────────────────────────────────

function EntityBody({
  view,
}: {
  view: Extract<InspectorPayload, { kind: "entity" }>;
}) {
  const typeColors = entityTypeColor(
    view.entity_type as Parameters<typeof entityTypeColor>[0]
  );

  return (
    <div className="space-y-4">
      {view.photo_path && (
        <img
          src={view.photo_path}
          alt={view.display_name}
          className="w-32 h-32 rounded object-cover border"
        />
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Badge
          variant="outline"
          style={{
            backgroundColor: typeColors.hex,
            color: "#fff",
            borderColor: typeColors.hex,
          }}
          className="capitalize"
        >
          {view.entity_type}
        </Badge>
        {view.subtype && (
          <Badge variant="secondary" className="capitalize">
            {view.subtype}
          </Badge>
        )}
      </div>

      <CountRow
        items={[
          {
            label: "linked entit" + (view.linked_entity_count === 1 ? "y" : "ies"),
            count: view.linked_entity_count,
            icon: Network,
          },
          {
            label:
              "linked evidence item" +
              (view.linked_evidence_count === 1 ? "" : "s"),
            count: view.linked_evidence_count,
            icon: FileBox,
          },
        ]}
      />

      {(view.email ||
        view.phone ||
        view.username ||
        view.employer ||
        view.dob) && (
        <KeyValueList
          rows={[
            { label: "Email", value: view.email },
            { label: "Phone", value: view.phone },
            { label: "Username", value: view.username },
            { label: "Employer", value: view.employer },
            { label: "DOB", value: view.dob },
          ].filter((r) => !!r.value)}
        />
      )}

      {view.identifiers.length > 0 && (
        <section>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">
            Identifiers ({view.identifiers.length})
          </h3>
          <ul className="space-y-2">
            {view.identifiers.map((ident) => (
              <IdentifierRow key={ident.identifier_id} ident={ident} />
            ))}
          </ul>
        </section>
      )}

      {view.notes && (
        <section>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">
            Notes
          </h3>
          <p className="text-sm whitespace-pre-wrap">{view.notes}</p>
        </section>
      )}
    </div>
  );
}

function IdentifierRow({ ident }: { ident: EntityIdentifier }) {
  return (
    <li className="flex items-start gap-2 text-sm">
      <span
        className="inline-block h-2 w-2 mt-1.5 shrink-0 rotate-45"
        style={{ backgroundColor: identifierKindHex(ident.kind) }}
        aria-hidden
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-xs break-all">{ident.value}</span>
          {ident.platform && (
            <Badge variant="outline" className="text-[10px] py-0 px-1.5">
              {ident.platform}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-2 mt-0.5">
          <span className="text-[10px] uppercase text-muted-foreground tracking-wide">
            {ident.kind}
          </span>
          {ident.discovered_via_tool && (
            <SourceToolBadge toolName={ident.discovered_via_tool} />
          )}
        </div>
      </div>
    </li>
  );
}

// ─── Evidence ───────────────────────────────────────────────────────────────

function EvidenceBody({
  view,
}: {
  view: Extract<InspectorPayload, { kind: "evidence" }>;
}) {
  const ev = view.evidence;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline" className="capitalize">
          {ev.status}
        </Badge>
        {ev.evidence_type && (
          <Badge variant="secondary" className="capitalize">
            {ev.evidence_type}
          </Badge>
        )}
      </div>

      <p className="text-sm whitespace-pre-wrap">{ev.description}</p>

      <CountRow
        items={[
          {
            label:
              "linked entit" + (view.linked_entity_count === 1 ? "y" : "ies"),
            count: view.linked_entity_count,
            icon: Users,
          },
          {
            label:
              "hash verification" +
              (view.hash_verification_count === 1 ? "" : "s"),
            count: view.hash_verification_count,
            icon: Tag,
          },
        ]}
      />

      <KeyValueList
        rows={[
          { label: "Collected by", value: ev.collected_by },
          { label: "Collection time", value: ev.collection_datetime },
          { label: "Location", value: ev.location },
          { label: "Make / model", value: ev.make_model },
          { label: "Serial", value: ev.serial_number },
          { label: "Storage", value: ev.storage_location },
        ].filter((r) => !!r.value)}
      />

      {view.latest_custody && (
        <section>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">
            Latest custody
          </h3>
          <div className="rounded-md border p-3 text-sm space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className="capitalize">
                {view.latest_custody.action}
              </Badge>
              <span className="text-xs text-muted-foreground">
                {view.latest_custody.custody_datetime}
              </span>
            </div>
            <p>
              <span className="text-muted-foreground">From:</span>{" "}
              {view.latest_custody.from_party}
            </p>
            <p>
              <span className="text-muted-foreground">To:</span>{" "}
              {view.latest_custody.to_party}
            </p>
            {view.latest_custody.location && (
              <p>
                <span className="text-muted-foreground">Location:</span>{" "}
                {view.latest_custody.location}
              </p>
            )}
          </div>
        </section>
      )}
    </div>
  );
}

// ─── Identifier ─────────────────────────────────────────────────────────────

function IdentifierBody({
  view,
}: {
  view: Extract<InspectorPayload, { kind: "identifier" }>;
}) {
  const isShared = view.owners.length >= 2;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge
          variant="outline"
          style={{
            backgroundColor: identifierKindHex(view.identifier_kind),
            color: "#fff",
            borderColor: identifierKindHex(view.identifier_kind),
          }}
          className="capitalize"
        >
          {view.identifier_kind}
        </Badge>
        {view.platform && (
          <Badge variant="secondary">{view.platform}</Badge>
        )}
        {view.discovered_via_tool && (
          <SourceToolBadge toolName={view.discovered_via_tool} />
        )}
        {isShared && (
          <Badge
            variant="outline"
            className="border-amber-500/60 text-amber-700 dark:text-amber-300"
          >
            shared by {view.owners.length}
          </Badge>
        )}
      </div>

      <div>
        <p className="text-xs uppercase tracking-wide text-muted-foreground mb-1">
          Value
        </p>
        <p className="font-mono text-sm break-all">{view.value}</p>
      </div>

      <section>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">
          {isShared
            ? "Owners (cross-entity connection)"
            : "Owner"}
        </h3>
        <ul className="space-y-1.5">
          {view.owners.map((o) => (
            <OwnerRow key={`${o.entity_type}-${o.entity_id}`} owner={o} />
          ))}
        </ul>
      </section>

      {view.notes && (
        <section>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">
            Notes
          </h3>
          <p className="text-sm whitespace-pre-wrap">{view.notes}</p>
        </section>
      )}
    </div>
  );
}

function OwnerRow({ owner }: { owner: IdentifierOwner }) {
  const Icon = owner.entity_type === "business" ? Building2 : User;
  return (
    <li className="flex items-center gap-2 text-sm">
      <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      <span className="truncate">{owner.display_name}</span>
      <Badge variant="secondary" className="ml-auto text-[10px] capitalize">
        {owner.entity_type}
      </Badge>
    </li>
  );
}

// ─── Shared sub-components ──────────────────────────────────────────────────

function CountRow({
  items,
}: {
  items: Array<{ label: string; count: number; icon: React.ComponentType<{ className?: string }> }>;
}) {
  return (
    <div className="grid grid-cols-2 gap-2">
      {items.map(({ label, count, icon: Icon }) => (
        <div
          key={label}
          className="flex items-center gap-2 rounded-md border bg-card px-3 py-2"
        >
          <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
          <div className="min-w-0">
            <div className="text-base font-semibold leading-tight">{count}</div>
            <div className="text-[10px] uppercase text-muted-foreground tracking-wide truncate">
              {label}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function KeyValueList({
  rows,
}: {
  rows: Array<{ label: string; value: string | null | undefined }>;
}) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1.5 text-sm">
      {rows.map(({ label, value }) => (
        <React.Fragment key={label}>
          <dt className="text-xs uppercase text-muted-foreground tracking-wide self-center">
            {label}
          </dt>
          <dd className="break-all">{value}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

function InspectorSkeleton() {
  return (
    <div className="space-y-3">
      <Skeleton className="h-6 w-3/4" />
      <Skeleton className="h-4 w-full" />
      <Skeleton className="h-4 w-5/6" />
      <Skeleton className="h-20 w-full" />
    </div>
  );
}
