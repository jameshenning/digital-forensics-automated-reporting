"""
DFARS Desktop - Data models.

Dataclasses for cases, evidence, chain of custody, hash verification,
tool usage, and analysis notes. Ported from the original DFARS Flask app.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional


def _parse_dt(value):
    """Best-effort parse of an ISO-8601 string into a datetime."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _serialize_dt(value):
    """Serialize a datetime to an ISO-8601 string if present."""
    if isinstance(value, datetime):
        return value.isoformat()
    return value


@dataclass
class Case:
    """Represents a digital forensics case."""
    case_id: str
    case_name: str
    description: str = ""
    investigator: str = ""
    agency: str = ""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    status: str = "Active"
    priority: str = "Medium"
    classification: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        for field in ("start_date", "end_date", "created_at", "updated_at"):
            data[field] = _parse_dt(data.get(field))
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        data = asdict(self)
        for field in ("start_date", "end_date", "created_at", "updated_at"):
            data[field] = _serialize_dt(data[field])
        return data


@dataclass
class Evidence:
    """Represents a piece of digital evidence."""
    evidence_id: str
    case_id: str
    description: str
    collected_by: str
    collection_datetime: datetime
    location: str = ""
    status: str = "Collected"
    evidence_type: str = ""
    make_model: str = ""
    serial_number: str = ""
    storage_location: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Evidence":
        data["collection_datetime"] = _parse_dt(data.get("collection_datetime")) or datetime.now()
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        data = asdict(self)
        data["collection_datetime"] = _serialize_dt(data["collection_datetime"])
        return data


@dataclass
class ChainOfCustody:
    """Represents a chain of custody event."""
    evidence_id: str
    custody_sequence: int
    action: str
    from_party: str
    to_party: str
    location: str = ""
    custody_datetime: Optional[datetime] = None
    purpose: str = ""
    notes: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "ChainOfCustody":
        data["custody_datetime"] = _parse_dt(data.get("custody_datetime"))
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        data = asdict(self)
        data["custody_datetime"] = _serialize_dt(data["custody_datetime"])
        return data


@dataclass
class HashVerification:
    """Represents a hash verification record."""
    evidence_id: str
    algorithm: str
    hash_value: str
    verified_by: str
    verification_datetime: Optional[datetime] = None
    notes: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "HashVerification":
        data["verification_datetime"] = _parse_dt(data.get("verification_datetime"))
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        data = asdict(self)
        data["verification_datetime"] = _serialize_dt(data["verification_datetime"])
        return data


@dataclass
class ToolUsage:
    """Represents tool usage in an investigation."""
    case_id: str
    tool_name: str
    version: str = ""
    purpose: str = ""
    command_used: str = ""
    input_file: str = ""
    output_file: str = ""
    execution_datetime: Optional[datetime] = None
    operator: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "ToolUsage":
        data["execution_datetime"] = _parse_dt(data.get("execution_datetime"))
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        data = asdict(self)
        data["execution_datetime"] = _serialize_dt(data["execution_datetime"])
        return data


@dataclass
class AnalysisNote:
    """Represents an analysis note or finding."""
    case_id: str
    evidence_id: Optional[str] = None
    category: str = ""
    finding: str = ""
    description: str = ""
    confidence_level: str = "Medium"
    created_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: dict) -> "AnalysisNote":
        data["created_at"] = _parse_dt(data.get("created_at"))
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        data = asdict(self)
        data["created_at"] = _serialize_dt(data["created_at"])
        return data


# ─── Link analysis: entities, links, events ─────────────────
#
# Investigator-curated annotation data powering the Link Analysis
# and Crime Line views. Unlike the forensic records above, these
# are editable (soft-delete) because they represent analytical
# judgment, not legally significant chain-of-custody evidence.


@dataclass
class Entity:
    """
    A person, business, phone, email, alias, or other entity of
    interest within a case. Polymorphic — the entity_type field
    discriminates between types and drives per-type fields.
    """
    case_id: str
    entity_type: str
    display_name: str
    entity_id: Optional[int] = None
    subtype: str = ""                   # for person: suspect/victim/witness/investigator/poi/other
    organizational_rank: str = ""       # for person: title ("Boss", "Lieutenant")
    parent_entity_id: Optional[int] = None
    notes: str = ""
    metadata_json: str = ""
    is_deleted: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: dict) -> "Entity":
        for field in ("created_at", "updated_at"):
            data[field] = _parse_dt(data.get(field))
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        data = asdict(self)
        for field in ("created_at", "updated_at"):
            data[field] = _serialize_dt(data[field])
        return data


@dataclass
class EntityLink:
    """
    A relationship between two entities (or between an entity and an
    evidence row). Generic — source_type/target_type distinguish
    whether each endpoint is 'entity' or 'evidence'.
    """
    case_id: str
    source_type: str
    source_id: str
    target_type: str
    target_id: str
    link_id: Optional[int] = None
    link_label: str = ""
    directional: int = 1
    weight: float = 1.0
    notes: str = ""
    is_deleted: int = 0
    created_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: dict) -> "EntityLink":
        data["created_at"] = _parse_dt(data.get("created_at"))
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        data = asdict(self)
        data["created_at"] = _serialize_dt(data["created_at"])
        return data


@dataclass
class CaseEvent:
    """
    An investigator-authored timeline event. Complements the
    auto-generated timestamps already attached to evidence, custody,
    hash, tool, and analysis records.
    """
    case_id: str
    title: str
    event_datetime: datetime
    event_id: Optional[int] = None
    description: str = ""
    event_end_datetime: Optional[datetime] = None
    category: str = ""
    related_entity_id: Optional[int] = None
    related_evidence_id: Optional[str] = None
    is_deleted: int = 0
    created_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: dict) -> "CaseEvent":
        for field in ("event_datetime", "event_end_datetime", "created_at"):
            data[field] = _parse_dt(data.get(field))
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})

    def to_dict(self) -> dict:
        data = asdict(self)
        for field in ("event_datetime", "event_end_datetime", "created_at"):
            data[field] = _serialize_dt(data[field])
        return data
