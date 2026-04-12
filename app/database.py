"""
DFARS Desktop - SQLite database manager.

Ported from the original DFARS Flask app. Changes from the original:
- Schema file is loaded from the app package (not the workdir)
- Database path is resolved via app.paths (not hardcoded)
- Default report template is inserted from Python, not from the SQL file
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import (
    AnalysisNote,
    Case,
    CaseEvent,
    ChainOfCustody,
    Entity,
    EntityLink,
    Evidence,
    HashVerification,
    ToolUsage,
)
from .paths import schema_path


class ForensicsDatabase:
    """Manages the SQLite database for digital forensics case management."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.connection: sqlite3.Connection | None = None
        self.connect()
        self.initialize_database()

    # ─── Connection ────────────────────────────────────────────

    def connect(self) -> None:
        self.connection = sqlite3.connect(
            self.db_path,
            detect_types=0,
            check_same_thread=False,
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")

    def close(self) -> None:
        if self.connection:
            self.connection.close()
            self.connection = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def initialize_database(self) -> None:
        """Create tables from the bundled schema SQL if they don't exist."""
        sql_path = schema_path()
        if not sql_path.exists():
            raise FileNotFoundError(f"Schema file not found at {sql_path}")
        schema_sql = sql_path.read_text(encoding="utf-8")
        assert self.connection is not None
        self.connection.executescript(schema_sql)
        self.connection.commit()

    # ─── Case management ──────────────────────────────────────

    def create_case(self, case: Case) -> str:
        assert self.connection is not None
        self.connection.execute(
            """
            INSERT OR REPLACE INTO cases (
                case_id, case_name, description, investigator, agency,
                start_date, end_date, status, priority, classification
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case.case_id, case.case_name, case.description, case.investigator,
                case.agency, case.start_date, case.end_date, case.status,
                case.priority, case.classification,
            ),
        )
        self.connection.commit()
        return case.case_id

    def get_case(self, case_id: str) -> Optional[Case]:
        assert self.connection is not None
        row = self.connection.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        return Case.from_dict(dict(row)) if row else None

    def update_case(self, case: Case) -> bool:
        assert self.connection is not None
        cursor = self.connection.execute(
            """
            UPDATE cases SET
                case_name = ?, description = ?, investigator = ?, agency = ?,
                start_date = ?, end_date = ?, status = ?, priority = ?,
                classification = ?, updated_at = CURRENT_TIMESTAMP
            WHERE case_id = ?
            """,
            (
                case.case_name, case.description, case.investigator, case.agency,
                case.start_date, case.end_date, case.status, case.priority,
                case.classification, case.case_id,
            ),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def list_cases(self, limit: int = 100, offset: int = 0) -> List[Case]:
        assert self.connection is not None
        rows = self.connection.execute(
            "SELECT * FROM cases ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [Case.from_dict(dict(row)) for row in rows]

    # ─── Evidence ─────────────────────────────────────────────

    def add_evidence(self, evidence: Evidence) -> str:
        assert self.connection is not None
        self.connection.execute(
            """
            INSERT OR REPLACE INTO evidence (
                evidence_id, case_id, description, collected_by,
                collection_datetime, location, status, evidence_type,
                make_model, serial_number, storage_location
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence.evidence_id, evidence.case_id, evidence.description,
                evidence.collected_by, evidence.collection_datetime, evidence.location,
                evidence.status, evidence.evidence_type, evidence.make_model,
                evidence.serial_number, evidence.storage_location,
            ),
        )
        self.connection.commit()
        return evidence.evidence_id

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        assert self.connection is not None
        row = self.connection.execute(
            "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        return Evidence.from_dict(dict(row)) if row else None

    def get_evidence_for_case(self, case_id: str) -> List[Evidence]:
        assert self.connection is not None
        rows = self.connection.execute(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY collection_datetime",
            (case_id,),
        ).fetchall()
        return [Evidence.from_dict(dict(row)) for row in rows]

    # ─── Chain of custody ─────────────────────────────────────

    def add_custody_event(self, custody: ChainOfCustody) -> int:
        assert self.connection is not None
        cursor = self.connection.execute(
            """
            INSERT OR REPLACE INTO chain_of_custody (
                evidence_id, custody_sequence, action, from_party, to_party,
                location, custody_datetime, purpose, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                custody.evidence_id, custody.custody_sequence, custody.action,
                custody.from_party, custody.to_party, custody.location,
                custody.custody_datetime, custody.purpose, custody.notes,
            ),
        )
        self.connection.commit()
        return cursor.lastrowid or 0

    def get_custody_chain(self, evidence_id: str) -> List[ChainOfCustody]:
        assert self.connection is not None
        rows = self.connection.execute(
            """
            SELECT * FROM chain_of_custody
            WHERE evidence_id = ?
            ORDER BY custody_sequence
            """,
            (evidence_id,),
        ).fetchall()
        return [ChainOfCustody.from_dict(dict(row)) for row in rows]

    def get_next_custody_sequence(self, evidence_id: str) -> int:
        assert self.connection is not None
        row = self.connection.execute(
            "SELECT MAX(custody_sequence) FROM chain_of_custody WHERE evidence_id = ?",
            (evidence_id,),
        ).fetchone()
        return (row[0] or 0) + 1

    def get_all_custody_for_case(self, case_id: str) -> List[ChainOfCustody]:
        results: List[ChainOfCustody] = []
        for evidence in self.get_evidence_for_case(case_id):
            results.extend(self.get_custody_chain(evidence.evidence_id))
        return results

    # ─── Hash verification ────────────────────────────────────

    def add_hash_verification(self, hash_ver: HashVerification) -> int:
        assert self.connection is not None
        cursor = self.connection.execute(
            """
            INSERT OR REPLACE INTO hash_verification (
                evidence_id, algorithm, hash_value, verified_by,
                verification_datetime, notes
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                hash_ver.evidence_id, hash_ver.algorithm, hash_ver.hash_value,
                hash_ver.verified_by, hash_ver.verification_datetime, hash_ver.notes,
            ),
        )
        self.connection.commit()
        return cursor.lastrowid or 0

    def get_hash_verifications(self, evidence_id: str) -> List[HashVerification]:
        assert self.connection is not None
        rows = self.connection.execute(
            """
            SELECT * FROM hash_verification
            WHERE evidence_id = ?
            ORDER BY verification_datetime
            """,
            (evidence_id,),
        ).fetchall()
        return [HashVerification.from_dict(dict(row)) for row in rows]

    def get_all_hashes_for_case(self, case_id: str) -> List[HashVerification]:
        results: List[HashVerification] = []
        for evidence in self.get_evidence_for_case(case_id):
            results.extend(self.get_hash_verifications(evidence.evidence_id))
        return results

    # ─── Tool usage ───────────────────────────────────────────

    def log_tool_usage(self, tool_usage: ToolUsage) -> int:
        assert self.connection is not None
        cursor = self.connection.execute(
            """
            INSERT OR REPLACE INTO tool_usage (
                case_id, tool_name, version, purpose, command_used,
                input_file, output_file, operator
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tool_usage.case_id, tool_usage.tool_name, tool_usage.version,
                tool_usage.purpose, tool_usage.command_used, tool_usage.input_file,
                tool_usage.output_file, tool_usage.operator,
            ),
        )
        self.connection.commit()
        return cursor.lastrowid or 0

    def get_tool_usage_for_case(self, case_id: str) -> List[ToolUsage]:
        assert self.connection is not None
        rows = self.connection.execute(
            """
            SELECT * FROM tool_usage
            WHERE case_id = ?
            ORDER BY execution_datetime
            """,
            (case_id,),
        ).fetchall()
        return [ToolUsage.from_dict(dict(row)) for row in rows]

    # ─── Analysis notes ───────────────────────────────────────

    def add_analysis_note(self, note: AnalysisNote) -> int:
        assert self.connection is not None
        cursor = self.connection.execute(
            """
            INSERT OR REPLACE INTO analysis_notes (
                case_id, evidence_id, category, finding, description,
                confidence_level
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                note.case_id, note.evidence_id, note.category, note.finding,
                note.description, note.confidence_level,
            ),
        )
        self.connection.commit()
        return cursor.lastrowid or 0

    def get_analysis_notes(
        self, case_id: str, evidence_id: Optional[str] = None
    ) -> List[AnalysisNote]:
        assert self.connection is not None
        if evidence_id:
            rows = self.connection.execute(
                """
                SELECT * FROM analysis_notes
                WHERE case_id = ? AND evidence_id = ?
                ORDER BY created_at
                """,
                (case_id, evidence_id),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT * FROM analysis_notes
                WHERE case_id = ?
                ORDER BY created_at
                """,
                (case_id,),
            ).fetchall()
        return [AnalysisNote.from_dict(dict(row)) for row in rows]

    # ─── Tags ────────────────────────────────────────────────

    def add_tag(self, case_id: str, tag: str) -> None:
        assert self.connection is not None
        self.connection.execute(
            "INSERT OR IGNORE INTO case_tags (case_id, tag) VALUES (?, ?)",
            (case_id, tag),
        )
        self.connection.commit()

    def get_tags_for_case(self, case_id: str) -> List[str]:
        assert self.connection is not None
        rows = self.connection.execute(
            "SELECT tag FROM case_tags WHERE case_id = ?", (case_id,)
        ).fetchall()
        return [row[0] for row in rows]

    def remove_tag(self, case_id: str, tag: str) -> None:
        assert self.connection is not None
        self.connection.execute(
            "DELETE FROM case_tags WHERE case_id = ? AND tag = ?",
            (case_id, tag),
        )
        self.connection.commit()

    # ─── Statistics ──────────────────────────────────────────

    def get_case_statistics(self, case_id: str) -> Dict[str, Any]:
        assert self.connection is not None
        stats: Dict[str, Any] = {}

        row = self.connection.execute(
            "SELECT COUNT(*) FROM evidence WHERE case_id = ?", (case_id,)
        ).fetchone()
        stats["evidence_count"] = row[0]

        row = self.connection.execute(
            """
            SELECT COUNT(*) FROM chain_of_custody coc
            JOIN evidence e ON coc.evidence_id = e.evidence_id
            WHERE e.case_id = ?
            """,
            (case_id,),
        ).fetchone()
        stats["custody_count"] = row[0]

        row = self.connection.execute(
            """
            SELECT COUNT(*) FROM hash_verification hv
            JOIN evidence e ON hv.evidence_id = e.evidence_id
            WHERE e.case_id = ?
            """,
            (case_id,),
        ).fetchone()
        stats["hash_count"] = row[0]

        rows = self.connection.execute(
            "SELECT DISTINCT tool_name FROM tool_usage WHERE case_id = ?",
            (case_id,),
        ).fetchall()
        stats["tools_used"] = [row[0] for row in rows]

        row = self.connection.execute(
            "SELECT COUNT(*) FROM analysis_notes WHERE case_id = ?", (case_id,)
        ).fetchone()
        stats["analysis_notes_count"] = row[0]

        return stats

    def get_global_stats(self) -> Dict[str, Any]:
        assert self.connection is not None
        stats: Dict[str, Any] = {}
        stats["total_cases"] = self.connection.execute(
            "SELECT COUNT(*) FROM cases"
        ).fetchone()[0]
        stats["active_cases"] = self.connection.execute(
            "SELECT COUNT(*) FROM cases WHERE status = 'Active'"
        ).fetchone()[0]
        stats["total_evidence"] = self.connection.execute(
            "SELECT COUNT(*) FROM evidence"
        ).fetchone()[0]
        stats["total_notes"] = self.connection.execute(
            "SELECT COUNT(*) FROM analysis_notes"
        ).fetchone()[0]
        return stats

    # ─── Entities ────────────────────────────────────────────

    def create_entity(self, entity: Entity) -> int:
        assert self.connection is not None
        cursor = self.connection.execute(
            """
            INSERT INTO entities (
                case_id, entity_type, display_name, subtype,
                organizational_rank, parent_entity_id, notes, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entity.case_id, entity.entity_type, entity.display_name,
                entity.subtype or None, entity.organizational_rank or None,
                entity.parent_entity_id, entity.notes or None,
                entity.metadata_json or None,
            ),
        )
        self.connection.commit()
        return cursor.lastrowid or 0

    def get_entity(self, entity_id: int) -> Optional[Entity]:
        assert self.connection is not None
        row = self.connection.execute(
            "SELECT * FROM entities WHERE entity_id = ?", (entity_id,)
        ).fetchone()
        return Entity.from_dict(dict(row)) if row else None

    def list_entities(
        self,
        case_id: str,
        types: Optional[List[str]] = None,
        include_deleted: bool = False,
    ) -> List[Entity]:
        assert self.connection is not None
        # Distinguish absent filter (None → all types) from empty filter
        # ([] → no results). Callers pass [] to explicitly hide everything.
        if types is not None and len(types) == 0:
            return []
        sql = "SELECT * FROM entities WHERE case_id = ?"
        params: List[Any] = [case_id]
        if not include_deleted:
            sql += " AND is_deleted = 0"
        if types:
            placeholders = ",".join("?" * len(types))
            sql += f" AND entity_type IN ({placeholders})"
            params.extend(types)
        sql += " ORDER BY entity_type, display_name"
        rows = self.connection.execute(sql, params).fetchall()
        return [Entity.from_dict(dict(row)) for row in rows]

    def update_entity(self, entity: Entity) -> bool:
        assert self.connection is not None
        if entity.entity_id is None:
            return False
        cursor = self.connection.execute(
            """
            UPDATE entities SET
                entity_type = ?, display_name = ?, subtype = ?,
                organizational_rank = ?, parent_entity_id = ?,
                notes = ?, metadata_json = ?, updated_at = CURRENT_TIMESTAMP
            WHERE entity_id = ?
            """,
            (
                entity.entity_type, entity.display_name,
                entity.subtype or None, entity.organizational_rank or None,
                entity.parent_entity_id, entity.notes or None,
                entity.metadata_json or None, entity.entity_id,
            ),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def soft_delete_entity(self, entity_id: int) -> bool:
        assert self.connection is not None
        cursor = self.connection.execute(
            "UPDATE entities SET is_deleted = 1, updated_at = CURRENT_TIMESTAMP "
            "WHERE entity_id = ?",
            (entity_id,),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    # ─── Entity links ────────────────────────────────────────

    def create_link(self, link: EntityLink) -> int:
        assert self.connection is not None
        cursor = self.connection.execute(
            """
            INSERT INTO entity_links (
                case_id, source_type, source_id, target_type, target_id,
                link_label, directional, weight, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                link.case_id, link.source_type, link.source_id,
                link.target_type, link.target_id, link.link_label or None,
                link.directional, link.weight, link.notes or None,
            ),
        )
        self.connection.commit()
        return cursor.lastrowid or 0

    def get_link(self, link_id: int) -> Optional[EntityLink]:
        assert self.connection is not None
        row = self.connection.execute(
            "SELECT * FROM entity_links WHERE link_id = ?", (link_id,)
        ).fetchone()
        return EntityLink.from_dict(dict(row)) if row else None

    def list_links(
        self, case_id: str, include_deleted: bool = False
    ) -> List[EntityLink]:
        assert self.connection is not None
        sql = "SELECT * FROM entity_links WHERE case_id = ?"
        if not include_deleted:
            sql += " AND is_deleted = 0"
        sql += " ORDER BY created_at"
        rows = self.connection.execute(sql, (case_id,)).fetchall()
        return [EntityLink.from_dict(dict(row)) for row in rows]

    def soft_delete_link(self, link_id: int) -> bool:
        assert self.connection is not None
        cursor = self.connection.execute(
            "UPDATE entity_links SET is_deleted = 1 WHERE link_id = ?",
            (link_id,),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    # ─── Case events (Crime Line) ────────────────────────────

    def create_event(self, event: CaseEvent) -> int:
        assert self.connection is not None
        cursor = self.connection.execute(
            """
            INSERT INTO case_events (
                case_id, title, description, event_datetime,
                event_end_datetime, category, related_entity_id,
                related_evidence_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.case_id, event.title, event.description or None,
                event.event_datetime, event.event_end_datetime,
                event.category or None, event.related_entity_id,
                event.related_evidence_id,
            ),
        )
        self.connection.commit()
        return cursor.lastrowid or 0

    def get_event(self, event_id: int) -> Optional[CaseEvent]:
        assert self.connection is not None
        row = self.connection.execute(
            "SELECT * FROM case_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        return CaseEvent.from_dict(dict(row)) if row else None

    def list_events(
        self,
        case_id: str,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        include_deleted: bool = False,
    ) -> List[CaseEvent]:
        assert self.connection is not None
        sql = "SELECT * FROM case_events WHERE case_id = ?"
        params: List[Any] = [case_id]
        if not include_deleted:
            sql += " AND is_deleted = 0"
        if start is not None:
            sql += " AND event_datetime >= ?"
            params.append(start)
        if end is not None:
            sql += " AND event_datetime <= ?"
            params.append(end)
        sql += " ORDER BY event_datetime"
        rows = self.connection.execute(sql, params).fetchall()
        return [CaseEvent.from_dict(dict(row)) for row in rows]

    def soft_delete_event(self, event_id: int) -> bool:
        assert self.connection is not None
        cursor = self.connection.execute(
            "UPDATE case_events SET is_deleted = 1 WHERE event_id = ?",
            (event_id,),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    # ─── Graph payload (Link Analysis) ───────────────────────

    def get_case_graph(
        self,
        case_id: str,
        entity_types: Optional[List[str]] = None,
        include_evidence: bool = True,
    ) -> Dict[str, Any]:
        """
        Build a vis-network-ready graph payload for a case.

        Returns {"nodes": [...], "edges": [...]}. Node IDs are
        namespaced as "entity:<int>" or "evidence:<str>" so they
        never collide across tables. Each node carries a 'group'
        (entity_type or 'evidence') for per-type styling, and
        person nodes carry a computed 'level' (0 = top of the
        organizational hierarchy) so vis-network's hierarchical
        layout mode can consume the same payload without refetch.
        """
        entities = self.list_entities(case_id, types=entity_types)

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        # Compute hierarchy level for persons by walking parent chain.
        parent_of: Dict[int, Optional[int]] = {
            e.entity_id: e.parent_entity_id
            for e in entities
            if e.entity_type == "person" and e.entity_id is not None
        }

        def level_of(eid: int) -> int:
            depth, current, seen = 0, eid, set()
            while current in parent_of and parent_of[current] is not None:
                if current in seen:
                    return depth  # cycle guard
                seen.add(current)
                current = parent_of[current]  # type: ignore[assignment]
                depth += 1
            return depth

        for e in entities:
            node: Dict[str, Any] = {
                "id": f"entity:{e.entity_id}",
                "label": e.display_name,
                "group": e.entity_type,
            }
            title_parts = [f"{e.entity_type}"]
            if e.subtype:
                title_parts.append(e.subtype)
            if e.organizational_rank:
                title_parts.append(f"rank: {e.organizational_rank}")
            if e.notes:
                title_parts.append(e.notes[:120])
            node["title"] = " · ".join(title_parts)
            if e.entity_type == "person" and e.entity_id is not None:
                node["level"] = level_of(e.entity_id)
            nodes.append(node)

            # Implicit parent -> child edge, visually distinct from user-authored links
            if e.entity_type == "person" and e.parent_entity_id:
                edges.append({
                    "from": f"entity:{e.parent_entity_id}",
                    "to": f"entity:{e.entity_id}",
                    "label": "reports to",
                    "arrows": "to",
                    "dashes": True,
                    "color": {"color": "#5c6b7a"},
                    "implicit": True,
                })

        # Optionally project evidence rows into the graph as nodes
        if include_evidence:
            for ev in self.get_evidence_for_case(case_id):
                nodes.append({
                    "id": f"evidence:{ev.evidence_id}",
                    "label": ev.evidence_id,
                    "group": "evidence",
                    "title": f"evidence · {ev.evidence_type or ''} · {ev.description[:120]}".strip(" ·"),
                })

        # User-authored links
        for lk in self.list_links(case_id):
            edges.append({
                "from": f"{lk.source_type}:{lk.source_id}",
                "to": f"{lk.target_type}:{lk.target_id}",
                "label": lk.link_label or "",
                "arrows": "to" if lk.directional else "",
            })

        return {"nodes": nodes, "edges": edges}

    # ─── Crime Line timeline payload ─────────────────────────

    def get_case_timeline(
        self,
        case_id: str,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Build a vis-timeline-ready payload for a case's Crime Line.

        Returns {"items": [...], "groups": [...]}. Items union:
          - investigator-authored case_events
          - evidence.collection_datetime (projection)
          - chain_of_custody.custody_datetime (projection)
          - hash_verification.verification_datetime (projection)
          - tool_usage.execution_datetime (projection)
          - analysis_notes.created_at (projection)
        Each item is namespaced by source so the client can color /
        group independently. Start and end bound all sources.
        """
        def in_range(dt_val: Optional[datetime]) -> bool:
            if dt_val is None:
                return False
            if start is not None and dt_val < start:
                return False
            if end is not None and dt_val > end:
                return False
            return True

        def iso(dt_val: Optional[datetime]) -> Optional[str]:
            if dt_val is None:
                return None
            if isinstance(dt_val, datetime):
                return dt_val.isoformat()
            return str(dt_val)

        items: List[Dict[str, Any]] = []

        # 1. Investigator-authored events
        for ev in self.list_events(case_id, start=start, end=end):
            item: Dict[str, Any] = {
                "id": f"event:{ev.event_id}",
                "group": "event",
                "content": ev.title,
                "start": iso(ev.event_datetime),
                "title": (ev.description or ev.title)[:240],
                "className": f"crime-evt-{(ev.category or 'other').lower()}",
            }
            if ev.event_end_datetime:
                item["end"] = iso(ev.event_end_datetime)
                item["type"] = "range"
            items.append(item)

        # 2. Evidence collection
        for e in self.get_evidence_for_case(case_id):
            if not in_range(e.collection_datetime):
                continue
            items.append({
                "id": f"evidence:{e.evidence_id}",
                "group": "evidence",
                "content": f"{e.evidence_id} collected",
                "start": iso(e.collection_datetime),
                "title": f"{e.description[:150]} — {e.collected_by}",
                "className": "crime-evidence",
            })

        # 3. Chain of custody transfers
        for c in self.get_all_custody_for_case(case_id):
            if not in_range(c.custody_datetime):
                continue
            items.append({
                "id": f"custody:{c.evidence_id}-{c.custody_sequence}",
                "group": "custody",
                "content": f"{c.action}: {c.from_party} → {c.to_party}",
                "start": iso(c.custody_datetime),
                "title": f"{c.evidence_id} · {(c.purpose or '')[:120]}",
                "className": "crime-custody",
            })

        # 4. Hash verifications
        for h in self.get_all_hashes_for_case(case_id):
            if not in_range(h.verification_datetime):
                continue
            items.append({
                "id": f"hash:{h.evidence_id}-{h.algorithm}-{iso(h.verification_datetime)}",
                "group": "hash",
                "content": f"{h.algorithm} verified",
                "start": iso(h.verification_datetime),
                "title": f"{h.evidence_id} · {h.hash_value[:32]}...",
                "className": "crime-hash",
            })

        # 5. Tool usage
        for t in self.get_tool_usage_for_case(case_id):
            if not in_range(t.execution_datetime):
                continue
            items.append({
                "id": f"tool:{t.tool_name}-{iso(t.execution_datetime)}",
                "group": "tool",
                "content": f"{t.tool_name}",
                "start": iso(t.execution_datetime),
                "title": f"{t.purpose or ''} · {t.operator or ''}",
                "className": "crime-tool",
            })

        # 6. Analysis notes
        for n in self.get_analysis_notes(case_id):
            if not in_range(n.created_at):
                continue
            items.append({
                "id": f"note:{case_id}-{iso(n.created_at)}-{n.category}",
                "group": "analysis",
                "content": f"{n.category}: {n.finding[:40]}",
                "start": iso(n.created_at),
                "title": (n.description or n.finding)[:200],
                "className": "crime-analysis",
            })

        groups = [
            {"id": "event",    "content": "Investigator Events"},
            {"id": "evidence", "content": "Evidence Collected"},
            {"id": "custody",  "content": "Custody Transfers"},
            {"id": "hash",     "content": "Hash Verified"},
            {"id": "tool",     "content": "Tool Executions"},
            {"id": "analysis", "content": "Analysis Notes"},
        ]

        return {"items": items, "groups": groups}
