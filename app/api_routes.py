"""
DFARS Desktop - REST API blueprint (/api/v1).

External integrations (Agent Zero plugin, scripts, other tools) push
data into DFARS Desktop through this API. All endpoints require a
bearer token in the Authorization header — generate one from the
Security page in the DFARS UI.

Auth:    Authorization: Bearer dfars_<32-bytes-base64>
Format:  All bodies are JSON.
Errors:  Standard HTTP codes — 200/201 success, 400 bad input,
         401 missing/invalid token, 404 not found, 422 validation,
         500 internal.

Append-only by design: evidence, custody events, hash verifications,
tool usage, and analysis notes can be CREATED via the API but not
edited or deleted, matching forensic best practice. Cases themselves
support PATCH for metadata updates (status, description, priority).
"""

from __future__ import annotations

from datetime import datetime
from functools import wraps
from typing import Any, Callable

from flask import Blueprint, current_app, jsonify, request

from . import api_tokens
from .models import (
    AnalysisNote,
    Case,
    ChainOfCustody,
    Evidence,
    HashVerification,
    ToolUsage,
)
from .paths import reports_dir

api_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")


# ─── Helpers ────────────────────────────────────────────────


def _db():
    return current_app.config["DFARS_DB"]


def _report_gen():
    return current_app.config["DFARS_REPORT_GEN"]


def _bearer_token() -> str | None:
    """Extract the bearer token from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    return auth[7:].strip()


def require_token(f: Callable) -> Callable:
    """Decorator: require a valid API token. Stashes the token row on g."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = _bearer_token()
        if not token:
            return jsonify(error="Authorization Bearer token required"), 401
        verified = api_tokens.verify(token)
        if not verified:
            return jsonify(error="Invalid or revoked API token"), 401
        # Stash on Flask's request-local for downstream handlers if they care
        request.api_token = verified  # type: ignore[attr-defined]
        return f(*args, **kwargs)
    return wrapper


def _json_body() -> dict[str, Any]:
    """Parse JSON body. Returns {} on missing/invalid."""
    try:
        body = request.get_json(silent=True)
        if isinstance(body, dict):
            return body
    except Exception:
        pass
    return {}


def _parse_dt(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _err(message: str, status: int):
    return jsonify(error=message), status


# ─── Health ────────────────────────────────────────────────


@api_bp.route("/whoami", methods=["GET"])
@require_token
def whoami():
    """Verify a token is valid and return the associated user."""
    tok = request.api_token  # type: ignore[attr-defined]
    return jsonify(
        username=tok["username"],
        token_id=tok["id"],
        token_name=tok["name"],
        last_used_at=tok["last_used_at"],
    )


# ─── Cases ────────────────────────────────────────────────


@api_bp.route("/cases", methods=["GET"])
@require_token
def list_cases():
    cases = _db().list_cases()
    return jsonify(cases=[c.to_dict() for c in cases])


@api_bp.route("/cases", methods=["POST"])
@require_token
def create_case():
    body = _json_body()
    required = ("case_id", "case_name", "investigator")
    missing = [k for k in required if not body.get(k)]
    if missing:
        return _err(f"Missing required fields: {', '.join(missing)}", 422)

    if _db().get_case(body["case_id"]) is not None:
        return _err(f"Case {body['case_id']} already exists", 409)

    try:
        case = Case(
            case_id=body["case_id"],
            case_name=body["case_name"],
            description=body.get("description", ""),
            investigator=body["investigator"],
            agency=body.get("agency", ""),
            start_date=_parse_dt(body.get("start_date")) or datetime.now(),
            end_date=_parse_dt(body.get("end_date")),
            status=body.get("status", "Active"),
            priority=body.get("priority", "Medium"),
            classification=body.get("classification", ""),
        )
        _db().create_case(case)
        for tag in body.get("tags") or []:
            if isinstance(tag, str) and tag.strip():
                _db().add_tag(case.case_id, tag.strip())
    except Exception as e:
        return _err(f"Failed to create case: {e}", 500)

    return jsonify(_full_case(case.case_id)), 201


@api_bp.route("/cases/<case_id>", methods=["GET"])
@require_token
def get_case(case_id):
    case = _db().get_case(case_id)
    if not case:
        return _err(f"Case {case_id} not found", 404)
    return jsonify(_full_case(case_id))


@api_bp.route("/cases/<case_id>", methods=["PATCH"])
@require_token
def update_case(case_id):
    case = _db().get_case(case_id)
    if not case:
        return _err(f"Case {case_id} not found", 404)

    body = _json_body()
    # Whitelist mutable fields. case_id and investigator are immutable
    # for forensic integrity; created_at is server-managed.
    for field in ("case_name", "description", "agency", "status",
                  "priority", "classification"):
        if field in body and body[field] is not None:
            setattr(case, field, body[field])
    for field in ("start_date", "end_date"):
        if field in body:
            setattr(case, field, _parse_dt(body[field]))

    try:
        _db().update_case(case)
    except Exception as e:
        return _err(f"Failed to update case: {e}", 500)

    # Replace tags if provided (set semantics, not append)
    if "tags" in body and isinstance(body["tags"], list):
        existing = set(_db().get_tags_for_case(case_id))
        wanted = {t.strip() for t in body["tags"] if isinstance(t, str) and t.strip()}
        for t in existing - wanted:
            _db().remove_tag(case_id, t)
        for t in wanted - existing:
            _db().add_tag(case_id, t)

    return jsonify(_full_case(case_id))


# ─── Evidence ─────────────────────────────────────────────


@api_bp.route("/cases/<case_id>/evidence", methods=["POST"])
@require_token
def add_evidence(case_id):
    if not _db().get_case(case_id):
        return _err(f"Case {case_id} not found", 404)

    body = _json_body()
    required = ("evidence_id", "description", "collected_by")
    missing = [k for k in required if not body.get(k)]
    if missing:
        return _err(f"Missing required fields: {', '.join(missing)}", 422)

    try:
        evidence = Evidence(
            evidence_id=body["evidence_id"],
            case_id=case_id,
            description=body["description"],
            collected_by=body["collected_by"],
            collection_datetime=_parse_dt(body.get("collection_datetime")) or datetime.now(),
            location=body.get("location", ""),
            status=body.get("status", "Collected"),
            evidence_type=body.get("evidence_type", ""),
            make_model=body.get("make_model", ""),
            serial_number=body.get("serial_number", ""),
            storage_location=body.get("storage_location", ""),
        )
        _db().add_evidence(evidence)
    except Exception as e:
        return _err(f"Failed to add evidence: {e}", 500)

    return jsonify(evidence=evidence.to_dict()), 201


# ─── Chain of custody ─────────────────────────────────────


@api_bp.route("/cases/<case_id>/custody", methods=["POST"])
@require_token
def add_custody(case_id):
    if not _db().get_case(case_id):
        return _err(f"Case {case_id} not found", 404)

    body = _json_body()
    required = ("evidence_id", "action", "from_party", "to_party")
    missing = [k for k in required if not body.get(k)]
    if missing:
        return _err(f"Missing required fields: {', '.join(missing)}", 422)

    if not _db().get_evidence(body["evidence_id"]):
        return _err(f"Evidence {body['evidence_id']} not found", 404)

    try:
        custody = ChainOfCustody(
            evidence_id=body["evidence_id"],
            custody_sequence=_db().get_next_custody_sequence(body["evidence_id"]),
            action=body["action"],
            from_party=body["from_party"],
            to_party=body["to_party"],
            location=body.get("location", ""),
            custody_datetime=_parse_dt(body.get("custody_datetime")) or datetime.now(),
            purpose=body.get("purpose", ""),
            notes=body.get("notes", ""),
        )
        _db().add_custody_event(custody)
    except Exception as e:
        return _err(f"Failed to add custody event: {e}", 500)

    return jsonify(custody=custody.to_dict()), 201


# ─── Hash verification ────────────────────────────────────


@api_bp.route("/cases/<case_id>/hashes", methods=["POST"])
@require_token
def add_hash(case_id):
    if not _db().get_case(case_id):
        return _err(f"Case {case_id} not found", 404)

    body = _json_body()
    required = ("evidence_id", "algorithm", "hash_value", "verified_by")
    missing = [k for k in required if not body.get(k)]
    if missing:
        return _err(f"Missing required fields: {', '.join(missing)}", 422)

    if not _db().get_evidence(body["evidence_id"]):
        return _err(f"Evidence {body['evidence_id']} not found", 404)

    try:
        h = HashVerification(
            evidence_id=body["evidence_id"],
            algorithm=body["algorithm"],
            hash_value=body["hash_value"],
            verified_by=body["verified_by"],
            verification_datetime=_parse_dt(body.get("verification_datetime"))
            or datetime.now(),
            notes=body.get("notes", ""),
        )
        _db().add_hash_verification(h)
    except Exception as e:
        return _err(f"Failed to add hash verification: {e}", 500)

    return jsonify(hash=h.to_dict()), 201


# ─── Tool usage ──────────────────────────────────────────


@api_bp.route("/cases/<case_id>/tools", methods=["POST"])
@require_token
def add_tool(case_id):
    if not _db().get_case(case_id):
        return _err(f"Case {case_id} not found", 404)

    body = _json_body()
    required = ("tool_name", "purpose")
    missing = [k for k in required if not body.get(k)]
    if missing:
        return _err(f"Missing required fields: {', '.join(missing)}", 422)

    try:
        tool = ToolUsage(
            case_id=case_id,
            tool_name=body["tool_name"],
            version=body.get("version", ""),
            purpose=body["purpose"],
            command_used=body.get("command_used", ""),
            input_file=body.get("input_file", ""),
            output_file=body.get("output_file", ""),
            operator=body.get("operator", ""),
        )
        _db().log_tool_usage(tool)
    except Exception as e:
        return _err(f"Failed to log tool usage: {e}", 500)

    return jsonify(tool=tool.to_dict()), 201


# ─── Analysis notes ──────────────────────────────────────


@api_bp.route("/cases/<case_id>/analysis", methods=["POST"])
@require_token
def add_analysis(case_id):
    if not _db().get_case(case_id):
        return _err(f"Case {case_id} not found", 404)

    body = _json_body()
    required = ("category", "finding")
    missing = [k for k in required if not body.get(k)]
    if missing:
        return _err(f"Missing required fields: {', '.join(missing)}", 422)

    evidence_id = body.get("evidence_id")
    if evidence_id and not _db().get_evidence(evidence_id):
        return _err(f"Evidence {evidence_id} not found", 404)

    try:
        note = AnalysisNote(
            case_id=case_id,
            evidence_id=evidence_id or None,
            category=body["category"],
            finding=body["finding"],
            description=body.get("description", ""),
            confidence_level=body.get("confidence_level", "Medium"),
        )
        _db().add_analysis_note(note)
    except Exception as e:
        return _err(f"Failed to add analysis note: {e}", 500)

    return jsonify(note=note.to_dict()), 201


# ─── Reports ─────────────────────────────────────────────


@api_bp.route("/cases/<case_id>/report", methods=["GET"])
@require_token
def generate_report(case_id):
    if not _db().get_case(case_id):
        return _err(f"Case {case_id} not found", 404)

    fmt = request.args.get("format", "markdown").lower()
    save = request.args.get("save", "false").lower() in ("1", "true", "yes")

    try:
        if fmt == "json":
            content = _report_gen().generate_json_report(case_id)
        else:
            content = _report_gen().generate_report(case_id, fmt)
    except Exception as e:
        return _err(f"Failed to generate report: {e}", 500)

    if save:
        try:
            saved_path = _report_gen().save_report(case_id, fmt, reports_dir())
        except Exception as e:
            return _err(f"Failed to save report: {e}", 500)
        return jsonify(content=content, saved_path=saved_path), 200

    return jsonify(content=content), 200


# ─── Internal: full case payload ─────────────────────────


def _full_case(case_id: str) -> dict:
    """
    Build a complete case payload (case + all related records). Used as
    the response body for create_case / get_case / update_case so the
    caller always gets a consistent view.
    """
    db = _db()
    case = db.get_case(case_id)
    if not case:
        return {}
    return {
        "case": case.to_dict(),
        "tags": db.get_tags_for_case(case_id),
        "evidence": [e.to_dict() for e in db.get_evidence_for_case(case_id)],
        "custody": [c.to_dict() for c in db.get_all_custody_for_case(case_id)],
        "hashes": [h.to_dict() for h in db.get_all_hashes_for_case(case_id)],
        "tools": [t.to_dict() for t in db.get_tool_usage_for_case(case_id)],
        "analysis": [n.to_dict() for n in db.get_analysis_notes(case_id)],
        "stats": db.get_case_statistics(case_id),
    }
