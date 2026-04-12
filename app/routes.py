"""
DFARS Desktop - HTTP routes (Flask blueprint).

All DFARS UI routes ported from the original app.py. The only behavioral
differences are:
- Routes live in a blueprint instead of the module-level `app`
- `db` and `report_gen` are resolved from `current_app.config` instead of
  module-level globals (so tests and the desktop shell can swap them)
- `reports_dir` comes from `app.paths` instead of the workdir
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from . import audit, file_metadata
from .drives import is_drive_present, list_external_drives, validate_evidence_drive


def _user() -> str:
    """Return the current session username for audit logging."""
    return session.get("username", "UNKNOWN")
from .models import (
    AnalysisNote,
    Case,
    CaseEvent,
    CaseShare,
    ChainOfCustody,
    Entity,
    EntityLink,
    Evidence,
    EvidenceAnalysis,
    EvidenceFile,
    HashVerification,
    ToolUsage,
)
from .paths import evidence_files_dir, reports_dir

bp = Blueprint("dfars", __name__)


def _db():
    return current_app.config["DFARS_DB"]


# ── Evidence drive helpers ───────────────────────────────────


@bp.route("/api/internal/drives", methods=["GET"])
def api_list_drives():
    """Return available external drives as JSON for the drive selector."""
    drives = list_external_drives()
    return jsonify(drives=[
        {
            "letter": d.letter,
            "root": d.root,
            "label": d.label,
            "type": d.type_label,
            "free_gb": round(d.free_gb, 1),
            "total_gb": round(d.total_gb, 1),
            "display": d.display_name,
        }
        for d in drives
    ])


def _report_gen():
    return current_app.config["DFARS_REPORT_GEN"]


def _parse_dt_form(value: str | None) -> datetime | None:
    """Parse a datetime-local form field into a datetime, or None if empty."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M")
    except ValueError:
        return None


def _parse_date_form(value: str | None) -> datetime | None:
    """Parse a date form field into a datetime at midnight, or None if empty."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return None


# ── Dashboard ─────────────────────────────────────────────────


@bp.route("/")
def dashboard():
    audit.log_auth(_user(), audit.DASHBOARD_VIEWED, "Dashboard accessed")
    cases = _db().list_cases()
    stats = _db().get_global_stats()
    return render_template("dashboard.html", cases=cases, stats=stats)


# ── Case CRUD ─────────────────────────────────────────────────


@bp.route("/case/new", methods=["GET", "POST"])
def new_case():
    if request.method == "POST":
        # Validate evidence drive before creating the case
        evidence_drive = request.form.get("evidence_drive_path", "").strip()
        if not evidence_drive:
            flash("An external evidence drive must be selected. Evidence must not reside on the primary system drive.", "danger")
            return render_template("case_form.html", now=datetime.now().strftime("%Y-%m-%d"))

        ok, msg = validate_evidence_drive(evidence_drive)
        if not ok:
            flash(f"Evidence drive validation failed: {msg}", "danger")
            return render_template("case_form.html", now=datetime.now().strftime("%Y-%m-%d"))

        try:
            case = Case(
                case_id=request.form["case_id"],
                case_name=request.form["case_name"],
                description=request.form.get("description", ""),
                investigator=request.form["investigator"],
                agency=request.form.get("agency", ""),
                start_date=_parse_date_form(request.form.get("start_date")) or datetime.now(),
                status=request.form.get("status", "Active"),
                priority=request.form.get("priority", "Medium"),
                classification=request.form.get("classification", ""),
                evidence_drive_path=evidence_drive,
            )
            _db().create_case(case)

            tags = request.form.get("tags", "")
            for tag in tags.split(","):
                tag = tag.strip()
                if tag:
                    _db().add_tag(case.case_id, tag)

            audit.log_case(case.case_id, _user(), audit.CASE_CREATED,
                           f"Name={case.case_name!r} Investigator={case.investigator!r} "
                           f"Priority={case.priority} Drive={evidence_drive}")
            flash(f"Case {case.case_id} created. Evidence drive: {evidence_drive}", "success")
            return redirect(url_for("dfars.view_case", case_id=case.case_id))
        except Exception as e:
            flash(f"Error: {e}", "danger")
    return render_template("case_form.html", now=datetime.now().strftime("%Y-%m-%d"))


@bp.route("/case/<case_id>")
def view_case(case_id):
    db = _db()
    case = db.get_case(case_id)
    if not case:
        flash("Case not found.", "danger")
        return redirect(url_for("dfars.dashboard"))

    audit.log_case(case_id, _user(), audit.CASE_VIEWED, "Case detail page opened")
    entities = db.list_entities(case_id)
    # Quick lookup table so the link/event forms can resolve entity_id
    # to a human-readable label without another round trip.
    entity_lookup = {e.entity_id: e for e in entities}

    evidence_list = db.get_evidence_for_case(case_id)
    files_by_evidence = {
        ev.evidence_id: db.list_evidence_files(ev.evidence_id)
        for ev in evidence_list
    }
    latest_analysis_by_evidence = {
        ev.evidence_id: db.get_latest_evidence_analysis(ev.evidence_id)
        for ev in evidence_list
    }

    # Evidence drive status
    drive_path = case.evidence_drive_path or ""
    drive_present = is_drive_present(drive_path) if drive_path else False

    # Collect known custody parties for auto-suggest in the custody form
    custody_list = db.get_all_custody_for_case(case_id)
    known_parties = sorted({case.investigator} | {
        p for c in custody_list
        for p in (c.from_party, c.to_party) if p
    })
    known_locations = sorted({
        c.location for c in custody_list if c.location
    })

    return render_template(
        "case_detail.html",
        case=case,
        evidence=evidence_list,
        custody=custody_list,
        hashes=db.get_all_hashes_for_case(case_id),
        tools=db.get_tool_usage_for_case(case_id),
        analysis=db.get_analysis_notes(case_id),
        tags=db.get_tags_for_case(case_id),
        stats=db.get_case_statistics(case_id),
        entities=entities,
        entity_lookup=entity_lookup,
        links=db.list_links(case_id),
        events=db.list_events(case_id),
        files_by_evidence=files_by_evidence,
        latest_analysis_by_evidence=latest_analysis_by_evidence,
        evidence_drive_path=drive_path,
        evidence_drive_present=drive_present,
        known_parties=known_parties,
        known_locations=known_locations,
        shares=db.list_shares(case_id),
    )


@bp.route("/case/<case_id>/edit", methods=["GET", "POST"])
def edit_case(case_id):
    """
    Edit case metadata. Append-only forensic records (evidence, custody,
    hashes, tools, analysis) intentionally cannot be edited or deleted —
    those should be added as superseding records when corrections are needed.
    """
    db = _db()
    case = db.get_case(case_id)
    if not case:
        flash("Case not found.", "danger")
        return redirect(url_for("dfars.dashboard"))

    if request.method == "POST":
        try:
            case.case_name = request.form.get("case_name", case.case_name).strip()
            case.description = request.form.get("description", "")
            case.agency = request.form.get("agency", "")
            case.status = request.form.get("status", case.status)
            case.priority = request.form.get("priority", case.priority)
            case.classification = request.form.get("classification", "")

            # Evidence drive — validate if changed
            new_drive = request.form.get("evidence_drive_path", "").strip()
            if new_drive and new_drive != case.evidence_drive_path:
                ok, msg = validate_evidence_drive(new_drive)
                if not ok:
                    flash(f"Evidence drive validation failed: {msg}", "danger")
                    return render_template(
                        "case_edit.html", case=case,
                        tags=", ".join(db.get_tags_for_case(case_id)),
                    )
            case.evidence_drive_path = new_drive or case.evidence_drive_path

            start = _parse_date_form(request.form.get("start_date"))
            if start:
                case.start_date = start
            end = _parse_date_form(request.form.get("end_date"))
            case.end_date = end  # may be None to clear

            db.update_case(case)
            audit.log_case(case_id, _user(), audit.CASE_EDITED,
                           f"Name={case.case_name!r} Status={case.status} "
                           f"Priority={case.priority} Drive={case.evidence_drive_path or 'N/A'}")

            # Tags: replace set with submitted (set semantics)
            wanted = {
                t.strip()
                for t in (request.form.get("tags", "") or "").split(",")
                if t.strip()
            }
            existing = set(db.get_tags_for_case(case_id))
            for t in existing - wanted:
                db.remove_tag(case_id, t)
            for t in wanted - existing:
                db.add_tag(case_id, t)

            flash("Case updated.", "success")
            return redirect(url_for("dfars.view_case", case_id=case_id))
        except Exception as e:
            flash(f"Error: {e}", "danger")

    return render_template(
        "case_edit.html",
        case=case,
        tags=", ".join(db.get_tags_for_case(case_id)),
    )


# ── Evidence ──────────────────────────────────────────────────


@bp.route("/case/<case_id>/evidence", methods=["POST"])
def add_evidence(case_id):
    try:
        evidence = Evidence(
            evidence_id=request.form["evidence_id"],
            case_id=case_id,
            description=request.form["description"],
            collected_by=request.form["collected_by"],
            collection_datetime=_parse_dt_form(request.form.get("collection_datetime"))
            or datetime.now(),
            location=request.form.get("location", ""),
            status=request.form.get("status", "Collected"),
            evidence_type=request.form.get("evidence_type", ""),
            make_model=request.form.get("make_model", ""),
            serial_number=request.form.get("serial_number", ""),
            storage_location=request.form.get("storage_location", ""),
        )
        _db().add_evidence(evidence)
        audit.log_case(case_id, _user(), audit.EVIDENCE_ADDED,
                       f"ID={evidence.evidence_id} Desc={evidence.description!r} "
                       f"Type={evidence.evidence_type} CollectedBy={evidence.collected_by}")
        flash(f"Evidence {evidence.evidence_id} added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")


@bp.route("/case/<case_id>/evidence/<evidence_id>/delete", methods=["POST"])
def delete_evidence(case_id, evidence_id):
    """
    Delete an evidence item and all its child records (files,
    custody, hashes, analyses, tool runs). Requires a justification
    of at least 25 characters. The deletion and the justification are
    permanently recorded in the audit log.
    """
    db = _db()
    ev = _resolve_evidence(case_id, evidence_id)
    if not ev:
        flash("Evidence not found for this case.", "warning")
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")

    justification = (request.form.get("justification") or "").strip()
    if len(justification) < 25:
        flash("Justification must be at least 25 characters.", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")

    snapshot = (
        f"ID={ev.evidence_id} Desc={ev.description!r} Type={ev.evidence_type} "
        f"CollectedBy={ev.collected_by} Location={ev.location} "
        f"Make/Model={ev.make_model} Serial={ev.serial_number} "
        f"Storage={ev.storage_location} Status={ev.status}"
    )

    try:
        counts = db.delete_evidence(evidence_id)
        cascade_summary = ", ".join(
            f"{k}={v}" for k, v in counts.items() if v
        ) or "no child rows"
        audit.log_case(case_id, _user(), audit.EVIDENCE_DELETED,
                       f"{snapshot} | CASCADE: {cascade_summary} | "
                       f"JUSTIFICATION: {justification}")
        flash(f"Evidence {evidence_id} and all related records deleted.", "success")
    except Exception as e:
        flash(f"Error deleting evidence: {e}", "danger")

    return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")


# ── Chain of Custody ──────────────────────────────────────────


@bp.route("/case/<case_id>/custody", methods=["POST"])
def add_custody(case_id):
    try:
        evidence_id = request.form["evidence_id"]
        custody = ChainOfCustody(
            evidence_id=evidence_id,
            custody_sequence=_db().get_next_custody_sequence(evidence_id),
            action=request.form["action"],
            from_party=request.form.get("from_party", ""),
            to_party=request.form.get("to_party", ""),
            location=request.form.get("location", ""),
            custody_datetime=_parse_dt_form(request.form.get("custody_datetime"))
            or datetime.now(),
            purpose=request.form.get("purpose", ""),
            notes=request.form.get("notes", ""),
        )
        _db().add_custody_event(custody)
        audit.log_case(case_id, _user(), audit.CUSTODY_ADDED,
                       f"Evidence={evidence_id} Action={custody.action} "
                       f"From={custody.from_party} To={custody.to_party}")
        flash("Custody event added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#custody")


@bp.route("/case/<case_id>/custody/<int:custody_id>/edit", methods=["POST"])
def edit_custody(case_id, custody_id):
    """Edit a custody event. Requires a justification narrative (min 25 chars)."""
    db = _db()
    existing = db.get_custody_event(custody_id)
    if not existing:
        flash("Custody event not found.", "warning")
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#custody")

    justification = (request.form.get("justification") or "").strip()
    if len(justification) < 25:
        flash("Justification must be at least 25 characters.", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#custody")

    # Capture old values for audit
    old_vals = (f"Action={existing.action} From={existing.from_party} "
                f"To={existing.to_party} Location={existing.location} "
                f"Purpose={existing.purpose}")

    try:
        existing.action = request.form.get("action", existing.action)
        existing.from_party = request.form.get("from_party", existing.from_party)
        existing.to_party = request.form.get("to_party", existing.to_party)
        existing.location = request.form.get("location", existing.location)
        existing.purpose = request.form.get("purpose", existing.purpose)
        dt = _parse_dt_form(request.form.get("custody_datetime"))
        if dt:
            existing.custody_datetime = dt
        existing.notes = request.form.get("notes", existing.notes)

        db.update_custody_event(existing)

        new_vals = (f"Action={existing.action} From={existing.from_party} "
                    f"To={existing.to_party} Location={existing.location} "
                    f"Purpose={existing.purpose}")

        audit.log_case(case_id, _user(), audit.CUSTODY_EDITED,
                       f"CustodyID={custody_id} Evidence={existing.evidence_id} "
                       f"BEFORE: {old_vals} | AFTER: {new_vals} | "
                       f"JUSTIFICATION: {justification}")
        flash("Custody event updated.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")

    return redirect(url_for("dfars.view_case", case_id=case_id) + "#custody")


@bp.route("/case/<case_id>/custody/<int:custody_id>/delete", methods=["POST"])
def delete_custody(case_id, custody_id):
    """Delete a custody event. Requires a justification narrative (min 25 chars)."""
    db = _db()
    existing = db.get_custody_event(custody_id)
    if not existing:
        flash("Custody event not found.", "warning")
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#custody")

    justification = (request.form.get("justification") or "").strip()
    if len(justification) < 25:
        flash("Justification must be at least 25 characters.", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#custody")

    deleted_vals = (f"Action={existing.action} From={existing.from_party} "
                    f"To={existing.to_party} Seq={existing.custody_sequence} "
                    f"Evidence={existing.evidence_id}")

    try:
        db.delete_custody_event(custody_id)
        audit.log_case(case_id, _user(), audit.CUSTODY_DELETED,
                       f"CustodyID={custody_id} {deleted_vals} | "
                       f"JUSTIFICATION: {justification}")
        flash("Custody event deleted.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")

    return redirect(url_for("dfars.view_case", case_id=case_id) + "#custody")


# ── Hash Verification ─────────────────────────────────────────


@bp.route("/case/<case_id>/hash", methods=["POST"])
def add_hash(case_id):
    try:
        hash_ver = HashVerification(
            evidence_id=request.form["evidence_id"],
            algorithm=request.form["algorithm"],
            hash_value=request.form["hash_value"],
            verified_by=request.form["verified_by"],
            verification_datetime=_parse_dt_form(request.form.get("verification_datetime"))
            or datetime.now(),
            notes=request.form.get("notes", ""),
        )
        _db().add_hash_verification(hash_ver)
        audit.log_case(case_id, _user(), audit.HASH_ADDED,
                       f"Evidence={hash_ver.evidence_id} Algo={hash_ver.algorithm} "
                       f"Value={hash_ver.hash_value[:16]}... VerifiedBy={hash_ver.verified_by}")
        flash("Hash verification added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#hashes")


# ── Tool Usage ────────────────────────────────────────────────


@bp.route("/case/<case_id>/tools", methods=["POST"])
def add_tool(case_id):
    try:
        tool = ToolUsage(
            case_id=case_id,
            tool_name=request.form["tool_name"],
            version=request.form.get("version", ""),
            purpose=request.form["purpose"],
            command_used=request.form.get("command_used", ""),
            input_file=request.form.get("input_file", ""),
            output_file=request.form.get("output_file", ""),
            operator=request.form.get("operator", ""),
        )
        _db().log_tool_usage(tool)
        audit.log_case(case_id, _user(), audit.TOOL_LOGGED,
                       f"Tool={tool.tool_name} Version={tool.version} "
                       f"Purpose={tool.purpose!r} Operator={tool.operator}")
        flash("Tool usage logged.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#tools")


# ── Analysis Notes ────────────────────────────────────────────


@bp.route("/case/<case_id>/analysis", methods=["POST"])
def add_analysis(case_id):
    try:
        note = AnalysisNote(
            case_id=case_id,
            evidence_id=request.form.get("evidence_id") or None,
            category=request.form["category"],
            finding=request.form["finding"],
            description=request.form.get("description", ""),
            confidence_level=request.form.get("confidence_level", "Medium"),
        )
        _db().add_analysis_note(note)
        audit.log_case(case_id, _user(), audit.ANALYSIS_ADDED,
                       f"Category={note.category} Finding={note.finding!r} "
                       f"Confidence={note.confidence_level} Evidence={note.evidence_id or 'N/A'}")
        flash("Analysis note added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#analysis")


# ── Scan evidence drive & auto-analyze ───────────────────────


@bp.route("/case/<case_id>/scan-drive", methods=["POST"])
def scan_evidence_drive(case_id):
    """
    Walk the case's evidence drive directory, register every file
    in-place (no copy), compute SHA-256 hashes, extract metadata,
    and create evidence + hash + custody + tool records automatically.
    """
    db = _db()
    case = db.get_case(case_id)
    if not case:
        flash("Case not found.", "danger")
        return redirect(url_for("dfars.dashboard"))

    drive_path = case.evidence_drive_path
    if not drive_path:
        flash("No evidence drive configured. Edit the case to set one.", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id))

    if not is_drive_present(drive_path):
        flash(f"Evidence drive {drive_path} is not connected.", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id))

    from .drives import evidence_dir_on_drive
    scan_root = evidence_dir_on_drive(drive_path, case_id)

    if not scan_root.exists():
        # Create the directory so the user knows where to put files
        scan_root.mkdir(parents=True, exist_ok=True)
        flash(
            f"Evidence directory created at {scan_root}. "
            f"Place evidence files there and scan again.",
            "info",
        )
        audit.log_case(case_id, _user(), audit.CASE_VIEWED,
                       f"Scan: created empty evidence directory at {scan_root}")
        return redirect(url_for("dfars.view_case", case_id=case_id))

    # Folders to skip — these are DFARS administrative data, not evidence
    _SKIP_DIRS = {"_shares", ".dfars", "__pycache__", ".git"}

    # Collect all files recursively, excluding DFARS system folders
    all_files = [
        f for f in scan_root.rglob("*")
        if f.is_file() and not (_SKIP_DIRS & set(f.relative_to(scan_root).parts))
    ]
    if not all_files:
        flash(f"No files found in {scan_root}. Place evidence files there and scan again.", "info")
        return redirect(url_for("dfars.view_case", case_id=case_id))

    # Get existing evidence file paths so we don't re-ingest
    existing_evidence = db.get_evidence_for_case(case_id)
    existing_paths = set()
    for ev in existing_evidence:
        for ef in db.list_evidence_files(ev.evidence_id):
            existing_paths.add(ef.stored_path)

    ingested = 0
    skipped = 0
    investigator = case.investigator or _user()

    for filepath in all_files:
        stored_path_str = str(filepath)

        # Skip already-ingested files
        if stored_path_str in existing_paths:
            skipped += 1
            continue

        # Generate a deterministic evidence ID from the relative path
        rel = filepath.relative_to(scan_root)
        parts = list(rel.parts)
        # Use the top-level subfolder as evidence group, or filename for root-level files
        if len(parts) > 1:
            evidence_id = f"{case_id}-{parts[0]}"
            evidence_desc = f"Evidence group: {parts[0]}"
        else:
            safe_stem = "".join(c if c.isalnum() or c in "-_." else "_" for c in filepath.stem)
            evidence_id = f"{case_id}-{safe_stem}"
            evidence_desc = f"File: {filepath.name}"

        # Create evidence record if it doesn't exist
        existing_ev = db.get_evidence(evidence_id)
        if not existing_ev:
            evidence = Evidence(
                evidence_id=evidence_id,
                case_id=case_id,
                description=evidence_desc,
                collected_by=investigator,
                collection_datetime=datetime.now(),
                location=str(scan_root),
                status="Collected",
                evidence_type=file_metadata.guess_mime(filepath.name),
                storage_location=str(filepath.parent),
            )
            db.add_evidence(evidence)
            audit.log_case(case_id, _user(), audit.EVIDENCE_ADDED,
                           f"[AUTO-SCAN] ID={evidence_id} File={filepath.name}")

            # Chain of custody — initial acquisition
            custody = ChainOfCustody(
                evidence_id=evidence_id,
                custody_sequence=1,
                action="Acquired",
                from_party="Evidence Drive",
                to_party=investigator,
                location=str(scan_root),
                custody_datetime=datetime.now(),
                purpose="Automated ingestion from evidence drive scan",
            )
            db.add_custody_event(custody)
            audit.log_case(case_id, _user(), audit.CUSTODY_ADDED,
                           f"[AUTO-SCAN] Evidence={evidence_id} Action=Acquired")

        # Compute SHA-256 hash
        try:
            sha256 = file_metadata.sha256_of(filepath)
            size = filepath.stat().st_size
            mime = file_metadata.guess_mime(filepath.name)
            metadata = file_metadata.extract_metadata(filepath, mime)
        except Exception as e:
            audit.log_case(case_id, _user(), audit.FILE_UPLOADED,
                           f"[AUTO-SCAN] FAILED to hash {filepath.name}: {e}")
            continue

        # Register the file (in-place, no copy)
        ef = EvidenceFile(
            evidence_id=evidence_id,
            original_filename=filepath.name,
            stored_path=stored_path_str,
            sha256=sha256,
            size_bytes=size,
            mime_type=mime,
            metadata_json=json.dumps(metadata),
        )
        db.add_evidence_file(ef)

        # Hash verification record
        hash_ver = HashVerification(
            evidence_id=evidence_id,
            algorithm="SHA-256",
            hash_value=sha256,
            verified_by="DFARS Auto-Scan",
            verification_datetime=datetime.now(),
            notes=f"Computed during evidence drive scan of {filepath.name} ({size} bytes)",
        )
        db.add_hash_verification(hash_ver)
        audit.log_case(case_id, _user(), audit.HASH_ADDED,
                       f"[AUTO-SCAN] Evidence={evidence_id} SHA-256={sha256[:16]}... File={filepath.name}")

        ingested += 1

    # Log tool usage for the scan itself
    if ingested > 0:
        tool = ToolUsage(
            case_id=case_id,
            tool_name="DFARS Auto-Scan",
            version="1.0.0",
            purpose="Automated evidence drive scan and file ingestion",
            command_used=f"scan-drive on {scan_root}",
            operator=_user(),
        )
        db.log_tool_usage(tool)
        audit.log_case(case_id, _user(), audit.TOOL_LOGGED,
                       f"[AUTO-SCAN] Ingested {ingested} files, skipped {skipped} duplicates from {scan_root}")

    flash(
        f"Scan complete: {ingested} file(s) ingested, {skipped} already registered. "
        f"Hashes computed and chain of custody recorded.",
        "success" if ingested > 0 else "info",
    )
    return redirect(url_for("dfars.view_case", case_id=case_id))


@bp.route("/case/<case_id>/auto-analyze", methods=["POST"])
def auto_analyze_all(case_id):
    """
    Trigger Agent Zero AI analysis on all evidence items that don't
    have a completed analysis yet. Results auto-populate analysis notes.
    """
    from . import agent_zero_client

    db = _db()
    case = db.get_case(case_id)
    if not case:
        flash("Case not found.", "danger")
        return redirect(url_for("dfars.dashboard"))

    if not agent_zero_client.is_configured():
        flash("Agent Zero is not configured. Set it up in Security settings.", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id))

    evidence_list = db.get_evidence_for_case(case_id)
    analyzed = 0
    failed = 0

    for ev in evidence_list:
        # Skip evidence that already has a completed analysis
        latest = db.get_latest_evidence_analysis(ev.evidence_id)
        if latest and latest.status == "completed":
            continue

        files = db.list_evidence_files(ev.evidence_id)
        files_payload = []
        for f in files:
            try:
                meta = json.loads(f.metadata_json) if f.metadata_json else {}
            except Exception:
                meta = {}
            files_payload.append({
                "file_id": f.file_id,
                "original_filename": f.original_filename,
                "sha256": f.sha256,
                "size_bytes": f.size_bytes,
                "mime_type": f.mime_type,
                "metadata": meta,
            })

        payload = {
            "case": case.to_dict(),
            "evidence": ev.to_dict(),
            "files": files_payload,
            "osint_narrative": f"Automated analysis of evidence {ev.evidence_id}: {ev.description}",
        }
        snapshot_ids = json.dumps([f.file_id for f in files])

        try:
            result = agent_zero_client.analyze_evidence(payload)
            ea = EvidenceAnalysis(
                evidence_id=ev.evidence_id,
                osint_narrative=payload["osint_narrative"],
                files_snapshot_json=snapshot_ids,
                report_markdown=result.get("report_markdown", ""),
                tools_used=result.get("tools_used", ""),
                platforms_used=result.get("platforms_used", ""),
                status="completed",
            )
            db.add_evidence_analysis(ea)

            # Auto-populate an analysis note from the AI result
            if result.get("report_markdown"):
                summary = result["report_markdown"][:500]
                note = AnalysisNote(
                    case_id=case_id,
                    evidence_id=ev.evidence_id,
                    category="AI Forensic Analysis",
                    finding=f"Agent Zero analysis of {ev.evidence_id}",
                    description=result["report_markdown"],
                    confidence_level="Medium",
                )
                db.add_analysis_note(note)
                audit.log_case(case_id, _user(), audit.ANALYSIS_ADDED,
                               f"[AUTO-ANALYZE] Evidence={ev.evidence_id} AI analysis note created")

            audit.log_case(case_id, _user(), audit.AI_ANALYZE_EVIDENCE,
                           f"[AUTO-ANALYZE] Evidence={ev.evidence_id} Status=completed")
            analyzed += 1

        except agent_zero_client.AgentZeroError as e:
            ea = EvidenceAnalysis(
                evidence_id=ev.evidence_id,
                osint_narrative=payload["osint_narrative"],
                files_snapshot_json=snapshot_ids,
                status="failed",
                error_message=str(e),
            )
            db.add_evidence_analysis(ea)
            audit.log_case(case_id, _user(), audit.AI_ANALYZE_EVIDENCE,
                           f"[AUTO-ANALYZE] Evidence={ev.evidence_id} FAILED: {e}")
            failed += 1

        except Exception as e:
            audit.log_case(case_id, _user(), audit.AI_ANALYZE_EVIDENCE,
                           f"[AUTO-ANALYZE] Evidence={ev.evidence_id} ERROR: {e}")
            failed += 1

    # Log tool usage
    if analyzed > 0 or failed > 0:
        tool = ToolUsage(
            case_id=case_id,
            tool_name="Agent Zero AI Analysis",
            version="1.0.0",
            purpose="Automated forensic + OSINT analysis of all evidence items",
            command_used=f"auto-analyze on case {case_id}",
            operator=_user(),
        )
        db.log_tool_usage(tool)

    flash(
        f"Auto-analysis complete: {analyzed} item(s) analyzed"
        + (f", {failed} failed" if failed else "")
        + ". Results saved as analysis notes.",
        "success" if analyzed > 0 else ("warning" if failed else "info"),
    )
    return redirect(url_for("dfars.view_case", case_id=case_id))


# ── Evidence files & AI analysis ──────────────────────────────


def _resolve_evidence(case_id: str, evidence_id: str):
    """
    Look up an evidence row and confirm it belongs to the given case.
    Returns the Evidence object or None.
    """
    db = _db()
    if not db.get_case(case_id):
        return None
    ev = db.get_evidence(evidence_id)
    if not ev or ev.case_id != case_id:
        return None
    return ev


@bp.route("/case/<case_id>/evidence/<evidence_id>/files", methods=["POST"])
def upload_evidence_files(case_id, evidence_id):
    db = _db()
    ev = _resolve_evidence(case_id, evidence_id)
    if not ev:
        flash("Evidence not found for this case.", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")

    # Enforce evidence drive requirement
    case = db.get_case(case_id)
    drive_path = case.evidence_drive_path if case else ""
    if drive_path and not is_drive_present(drive_path):
        flash(
            f"Evidence drive ({drive_path}) is not connected. "
            f"Connect the external drive and try again.",
            "danger",
        )
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")
    if not drive_path:
        flash(
            "No evidence drive configured for this case. "
            "Edit the case to set an external evidence drive before uploading files.",
            "danger",
        )
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")

    target_dir = evidence_files_dir(case_id, evidence_id, drive_path)
    target_dir.mkdir(parents=True, exist_ok=True)

    uploaded = request.files.getlist("files")
    if not uploaded:
        flash("No files selected.", "warning")
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")

    saved = 0
    skipped: list[str] = []
    for f in uploaded:
        if not f or not f.filename:
            continue
        safe_name = secure_filename(f.filename)
        if not safe_name:
            safe_name = f"upload_{uuid.uuid4().hex[:8]}.bin"
        unique_name = f"{uuid.uuid4().hex[:8]}_{safe_name}"
        stored_path = target_dir / unique_name

        try:
            f.save(stored_path)
        except Exception as e:
            skipped.append(f"{f.filename} (save failed: {e})")
            continue

        try:
            size = stored_path.stat().st_size
            sha256 = file_metadata.sha256_of(stored_path)
            mime = file_metadata.guess_mime(safe_name)
            metadata = file_metadata.extract_metadata(stored_path, mime)
        except Exception as e:
            stored_path.unlink(missing_ok=True)
            skipped.append(f"{f.filename} (metadata failed: {e})")
            continue

        ef = EvidenceFile(
            evidence_id=evidence_id,
            original_filename=safe_name,
            stored_path=str(stored_path),
            sha256=sha256,
            size_bytes=size,
            mime_type=mime,
            metadata_json=json.dumps(metadata),
        )
        db.add_evidence_file(ef)
        saved += 1

    if saved:
        audit.log_case(case_id, _user(), audit.FILE_UPLOADED,
                       f"Evidence={evidence_id} Files={saved} uploaded to {drive_path}")
        flash(f"Uploaded {saved} file(s) to {evidence_id}.", "success")
    if skipped:
        flash("Skipped: " + "; ".join(skipped[:5]), "warning")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")


@bp.route(
    "/case/<case_id>/evidence/<evidence_id>/files/<int:file_id>/delete",
    methods=["POST"],
)
def delete_evidence_file(case_id, evidence_id, file_id):
    db = _db()
    ev = _resolve_evidence(case_id, evidence_id)
    if not ev:
        flash("Evidence not found for this case.", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")

    ef = db.get_evidence_file(file_id)
    if not ef or ef.evidence_id != evidence_id:
        flash("File not found.", "warning")
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")

    if db.soft_delete_evidence_file(file_id):
        audit.log_case(case_id, _user(), audit.FILE_DELETED,
                       f"Evidence={evidence_id} File={ef.original_filename!r} SHA256={ef.sha256[:16]}...")
        flash(f"File '{ef.original_filename}' removed from {evidence_id}.", "success")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")


@bp.route("/case/<case_id>/evidence/<evidence_id>/analyze", methods=["POST"])
def analyze_evidence(case_id, evidence_id):
    """
    Synchronously run an Agent Zero forensic + OSINT analysis on the
    file metadata + investigator narrative for one evidence item. The
    result is stored as a new evidence_analyses row regardless of
    success or failure (failures keep the input narrative for retry).
    """
    from . import agent_zero_client

    db = _db()
    ev = _resolve_evidence(case_id, evidence_id)
    if not ev:
        flash("Evidence not found for this case.", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")

    osint_narrative = (request.form.get("osint_narrative") or "").strip()
    files = db.list_evidence_files(evidence_id)
    if not files and not osint_narrative:
        flash(
            "Provide an OSINT narrative or attach at least one file before running analysis.",
            "warning",
        )
        return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")

    case_obj = db.get_case(case_id)
    files_payload = []
    for f in files:
        try:
            metadata = json.loads(f.metadata_json) if f.metadata_json else {}
        except Exception:
            metadata = {}
        files_payload.append({
            "file_id": f.file_id,
            "original_filename": f.original_filename,
            "sha256": f.sha256,
            "size_bytes": f.size_bytes,
            "mime_type": f.mime_type,
            "metadata": metadata,
        })

    payload = {
        "case": case_obj.to_dict() if case_obj else {},
        "evidence": ev.to_dict(),
        "files": files_payload,
        "osint_narrative": osint_narrative,
    }
    snapshot_ids = json.dumps([f.file_id for f in files])

    try:
        result = agent_zero_client.analyze_evidence(payload)
        ea = EvidenceAnalysis(
            evidence_id=evidence_id,
            osint_narrative=osint_narrative,
            files_snapshot_json=snapshot_ids,
            report_markdown=result.get("report_markdown", ""),
            tools_used=result.get("tools_used", ""),
            platforms_used=result.get("platforms_used", ""),
            status="completed",
        )
        db.add_evidence_analysis(ea)
        audit.log_case(case_id, _user(), audit.AI_ANALYZE_EVIDENCE,
                       f"Evidence={evidence_id} Status=completed Files={len(files)}")
        flash(f"Analysis completed for {evidence_id}.", "success")
    except agent_zero_client.AgentZeroError as e:
        ea = EvidenceAnalysis(
            evidence_id=evidence_id,
            osint_narrative=osint_narrative,
            files_snapshot_json=snapshot_ids,
            status="failed",
            error_message=str(e),
        )
        db.add_evidence_analysis(ea)
        audit.log_case(case_id, _user(), audit.AI_ANALYZE_EVIDENCE,
                       f"Evidence={evidence_id} Status=FAILED Error={e}")
        flash(f"Agent Zero analysis failed: {e}", "danger")
    except Exception as e:
        flash(f"Unexpected error during analysis: {e}", "danger")

    return redirect(url_for("dfars.view_case", case_id=case_id) + "#evidence")


@bp.route("/case/<case_id>/evidence/<evidence_id>/forensic-analyze", methods=["POST"])
def forensic_analyze_evidence(case_id, evidence_id):
    """
    Combined Analyze Evidence flow:
    1. Agent Zero downloads evidence files and runs Kali forensic tools.
    2. Agent Zero synthesizes the tool output + investigator narrative
       into a final AI Evidence Narrative report.
    3. Tool Usage rows are auto-populated with operator, version, command,
       input_file, and output_file for SWGDE-compliant record keeping.
    Returns JSON for the async progress UI.
    """
    from . import agent_zero_client

    db = _db()
    ev = _resolve_evidence(case_id, evidence_id)
    if not ev:
        return jsonify(error="Evidence not found for this case."), 404

    if not agent_zero_client.is_configured():
        return jsonify(error="Agent Zero is not configured. Set it up in Security settings."), 400

    files = db.list_evidence_files(evidence_id)
    if not files:
        return jsonify(error="No files attached to this evidence. Upload or scan files first."), 400

    # Investigator-supplied Evidence Narrative (optional but used by AI synthesis)
    evidence_narrative = ""
    if request.is_json:
        evidence_narrative = (request.get_json(silent=True) or {}).get("evidence_narrative", "") or ""
    else:
        evidence_narrative = request.form.get("evidence_narrative", "") or ""
    evidence_narrative = evidence_narrative.strip()
    operator = _user()

    # Read the Agent Zero plugin's DFARS API token so it can download files
    from . import config as app_config
    cfg = app_config.load()
    dfars_port = cfg.get("actual_port") or cfg.get("preferred_port") or 5099
    dfars_url = f"http://host.docker.internal:{dfars_port}"

    az_token = ""
    for config_path in [
        Path("C:/Users/jhenn/agent-zero/agent-zero/usr/plugins/_dfars_integration/config.yaml"),
        Path("C:/Users/jhenn/agent-zero/agent-zero/usr/plugins/_dfars_integration/default_config.yaml"),
    ]:
        if config_path.exists():
            import yaml
            try:
                plugin_cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
                if plugin_cfg.get("api_token"):
                    az_token = plugin_cfg["api_token"]
                    break
            except Exception:
                pass

    if not az_token:
        return jsonify(error=(
            "Agent Zero plugin does not have a DFARS API token. "
            "Generate a token in Security > API Tokens, then set api_token "
            "in the _dfars_integration plugin config.yaml and restart Agent Zero."
        )), 400

    files_payload = [{
        "file_id": f.file_id,
        "original_filename": f.original_filename,
        "sha256": f.sha256,
        "size_bytes": f.size_bytes,
        "mime_type": f.mime_type,
        "download_url": f"/api/v1/cases/{case_id}/evidence/{evidence_id}/files/{f.file_id}/download",
    } for f in files]

    payload = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "dfars_api_url": dfars_url,
        "dfars_api_token": az_token,
        "files": files_payload,
    }

    audit.log_case(case_id, _user(), audit.FORENSIC_ANALYZE,
                   f"Evidence={evidence_id} Files={len(files)} — Sending to Agent Zero for Kali tool analysis")

    try:
        result = agent_zero_client.forensic_analyze(payload)

        # ── Filter to only SUCCESSFUL tool runs ──────────────────
        # Agent Zero already filters most failed/no-match attempts; do
        # one more pass here as defense-in-depth so the UI Tool Usage
        # section never shows tools that didn't produce useful output.
        raw_tools_run = result.get("tools_run", [])
        tools_run = [
            t for t in raw_tools_run
            if t.get("success", True) is not False
            and "no match" not in t.get("purpose", "").lower()
            and "FAILED" not in t.get("purpose", "")
            and " attempt" not in t.get("purpose", "").lower()
        ]
        findings = result.get("findings", [])

        # Determine the primary input filename for tool entries that
        # don't already specify one (most non-cracker tools)
        primary_input = files[0].original_filename if files else ""

        # Wipe any prior tool rows for THIS evidence so a re-run shows
        # the fresh tools, not the stale ones from a previous pass.
        # Other evidence in the same case is untouched.
        db.delete_tool_usage_for_evidence(evidence_id)

        for tool_info in tools_run:
            tool = ToolUsage(
                case_id=case_id,
                evidence_id=evidence_id,
                tool_name=tool_info.get("tool", "unknown"),
                version=tool_info.get("version", ""),
                purpose=tool_info.get("purpose", "Forensic analysis"),
                command_used=tool_info.get("command", ""),
                input_file=tool_info.get("input_file") or primary_input,
                output_file=tool_info.get("output_file", ""),
                operator=operator,
            )
            db.log_tool_usage(tool)

        for finding in findings:
            note = AnalysisNote(
                case_id=case_id,
                evidence_id=evidence_id,
                category=finding.get("category", "Forensic Tool Analysis"),
                finding=finding.get("finding", ""),
                description=finding.get("description", ""),
                confidence_level=finding.get("confidence", "Medium"),
            )
            if note.finding:
                db.add_analysis_note(note)

        # ── Fetch any prior analysis row for this evidence ───────
        # Each evidence item should end up with EXACTLY ONE row in
        # evidence_analyses. When the user clicks Analyze Evidence
        # multiple times on the same evidence, we feed the previous
        # narrative + report back into the AI so the new output is a
        # unified report covering BOTH the old and new findings, then
        # delete the old row and insert the new one.
        previous_analysis = db.get_latest_evidence_analysis(evidence_id)
        previous_narrative = (previous_analysis.osint_narrative or "").strip() if previous_analysis else ""
        previous_report = (previous_analysis.report_markdown or "").strip() if previous_analysis else ""

        # ── AI Evidence Narrative synthesis ──────────────────────
        # Combine the previous report + current tool output +
        # investigator narrative into a single unified report.
        report_markdown = result.get("report_markdown", "")
        ai_narrative_section = ""
        ai_error = ""
        try:
            files_payload_for_narrative = []
            for f in files:
                try:
                    metadata = json.loads(f.metadata_json) if f.metadata_json else {}
                except Exception:
                    metadata = {}
                files_payload_for_narrative.append({
                    "file_id": f.file_id,
                    "original_filename": f.original_filename,
                    "sha256": f.sha256,
                    "size_bytes": f.size_bytes,
                    "mime_type": f.mime_type,
                    "metadata": metadata,
                })

            case_obj = db.get_case(case_id)
            tool_summary_for_ai = "\n".join(
                f"- {t.get('tool', '?')} ({t.get('purpose', '')})"
                for t in tools_run
            )
            findings_for_ai = "\n".join(
                f"- [{f.get('confidence', 'Medium')}] {f.get('finding', '')}: {f.get('description', '')}"
                for f in findings
            )

            # Build a combined input that includes the prior report
            # so the AI knows to integrate it into the new narrative.
            sections = []
            if previous_report:
                sections.append(
                    "PREVIOUS ANALYSIS REPORT (integrate this into the new "
                    "report — do not lose any prior findings, hashes, tool "
                    "results, or context. Build on it, do not replace it):\n\n"
                    + previous_report
                )
            if previous_narrative and previous_narrative != evidence_narrative:
                sections.append(
                    "PREVIOUS INVESTIGATOR NARRATIVE:\n" + previous_narrative
                )
            if evidence_narrative:
                sections.append(
                    "CURRENT INVESTIGATOR NARRATIVE:\n" + evidence_narrative
                )
            sections.append(
                "FORENSIC TOOLS SUCCESSFULLY RUN IN THIS PASS:\n"
                + (tool_summary_for_ai or "(none)")
            )
            sections.append(
                "FINDINGS FROM THIS PASS:\n"
                + (findings_for_ai or "(none)")
            )
            sections.append(
                "RAW TOOL REPORT FROM THIS PASS:\n" + report_markdown
            )
            sections.append(
                "INSTRUCTIONS: Produce ONE unified Evidence Narrative report "
                "for this single evidence item. Merge the previous analysis "
                "with the new tool output and findings. Do not duplicate "
                "sections or facts. Preserve every hash, tool name, and "
                "finding from both the previous report and the new pass. "
                "The output replaces the previous report entirely."
            )
            combined_narrative_input = "\n\n---\n\n".join(sections)

            ai_payload = {
                "case": case_obj.to_dict() if case_obj else {},
                "evidence": ev.to_dict(),
                "files": files_payload_for_narrative,
                "osint_narrative": combined_narrative_input,
            }
            ai_result = agent_zero_client.analyze_evidence(ai_payload)
            ai_narrative_section = ai_result.get("report_markdown", "") or ""
        except agent_zero_client.AgentZeroError as e:
            ai_error = f"AI narrative synthesis failed: {e}"
        except Exception as e:
            ai_error = f"AI narrative synthesis error: {e}"

        # Build the final combined report: AI narrative on top, tool report below
        if ai_narrative_section:
            final_report = (
                "## Evidence Narrative\n\n"
                + ai_narrative_section
                + "\n\n---\n\n"
                + "## Forensic Tool Analysis (latest pass)\n\n"
                + report_markdown
            )
        else:
            final_report = (
                ("## Evidence Narrative\n\n" + (evidence_narrative or previous_narrative or "_No investigator narrative provided._")
                 + ("\n\n_" + ai_error + "_" if ai_error else "")
                 + "\n\n---\n\n")
                + "## Forensic Tool Analysis (latest pass)\n\n"
                + report_markdown
            )

        # ── Replace any prior analysis row for this evidence ─────
        # One row per evidence_id, always. The new row contains the
        # unified report covering all runs to date.
        db.delete_evidence_analyses_for_evidence(evidence_id)

        ea = EvidenceAnalysis(
            evidence_id=evidence_id,
            osint_narrative=evidence_narrative or previous_narrative,
            files_snapshot_json=json.dumps([f.file_id for f in files]),
            report_markdown=final_report,
            tools_used=", ".join(t.get("tool", "") for t in tools_run),
            platforms_used="Kali Linux + Agent Zero AI",
            status="completed" if result.get("status") == "completed" else "partial",
            error_message=result.get("error", "") or ai_error,
        )
        db.add_evidence_analysis(ea)

        audit.log_case(case_id, _user(), audit.FORENSIC_ANALYZE,
                       f"Evidence={evidence_id} COMPLETED — {len(tools_run)} successful tools, "
                       f"{len(findings)} findings, AI narrative={'yes' if ai_narrative_section else 'no'}")

        return jsonify(
            status="completed",
            tools_count=len(tools_run),
            findings_count=len(findings),
            tools_run=[t.get("tool", "") + ": " + t.get("purpose", "") for t in tools_run],
            findings_summary=[f.get("finding", "")[:120] for f in findings],
            report_preview=final_report,  # full report — no truncation
            raw_tool_output=result.get("raw_tool_output", ""),
        )

    except agent_zero_client.AgentZeroError as e:
        audit.log_case(case_id, _user(), audit.FORENSIC_ANALYZE,
                       f"Evidence={evidence_id} FAILED: {e}")
        return jsonify(error=str(e)), 502
    except Exception as e:
        audit.log_case(case_id, _user(), audit.FORENSIC_ANALYZE,
                       f"Evidence={evidence_id} ERROR: {e}")
        return jsonify(error=str(e)), 500


@bp.route("/case/<case_id>/evidence/<evidence_id>/analysis/<int:analysis_id>/save",
          methods=["POST"])
def save_analysis_report(case_id, evidence_id, analysis_id):
    """
    Save investigator edits to the AI-generated Evidence Narrative report.
    Per requirement: this edit is NOT audited so the investigator can
    refine the report freely without polluting the audit trail.
    """
    db = _db()
    ev = _resolve_evidence(case_id, evidence_id)
    if not ev:
        return jsonify(error="Evidence not found for this case."), 404

    payload = request.get_json(silent=True) or {}
    new_text = (payload.get("report_markdown") or "").strip()
    if not new_text:
        return jsonify(error="Report cannot be empty."), 400

    try:
        db.update_evidence_analysis_report(analysis_id, new_text)
        return jsonify(status="saved")
    except Exception as e:
        return jsonify(error=str(e)), 500


# ── Share / Print records ────────────────────────────────────


def _generate_record_md(db, case, record_type: str, record_id: str) -> tuple[str, str]:
    """
    Generate a Markdown document for a single record and return
    (markdown_text, one_line_summary).
    """
    ts = datetime.now().isoformat()
    header = (
        f"# DFARS Record Export\n\n"
        f"- **Case**: {case.case_id} — {case.case_name}\n"
        f"- **Investigator**: {case.investigator}\n"
        f"- **Record Type**: {record_type}\n"
        f"- **Record ID**: {record_id}\n"
        f"- **Exported**: {ts}\n\n---\n\n"
    )

    body = ""
    summary = ""

    if record_type == "evidence":
        ev = db.get_evidence(record_id)
        if ev:
            summary = f"Evidence {ev.evidence_id}: {ev.description[:80]}"
            body = (
                f"## Evidence: {ev.evidence_id}\n\n"
                f"| Field | Value |\n|---|---|\n"
                f"| Description | {ev.description} |\n"
                f"| Type | {ev.evidence_type} |\n"
                f"| Collected By | {ev.collected_by} |\n"
                f"| Collection Date | {ev.collection_datetime} |\n"
                f"| Location | {ev.location} |\n"
                f"| Status | {ev.status} |\n"
                f"| Make/Model | {ev.make_model} |\n"
                f"| Serial Number | {ev.serial_number} |\n"
                f"| Storage Location | {ev.storage_location} |\n"
            )

    elif record_type == "custody":
        cust = db.get_custody_event(int(record_id))
        if cust:
            summary = f"Custody #{cust.custody_sequence} ({cust.action}) on {cust.evidence_id}"
            body = (
                f"## Chain of Custody Event\n\n"
                f"| Field | Value |\n|---|---|\n"
                f"| Evidence | {cust.evidence_id} |\n"
                f"| Sequence | {cust.custody_sequence} |\n"
                f"| Action | {cust.action} |\n"
                f"| From | {cust.from_party} |\n"
                f"| To | {cust.to_party} |\n"
                f"| Date/Time | {cust.custody_datetime} |\n"
                f"| Location | {cust.location} |\n"
                f"| Purpose | {cust.purpose} |\n"
                f"| Notes | {cust.notes} |\n"
            )

    elif record_type == "hash":
        # record_id is hash_id — need a lookup
        row = db.connection.execute(
            "SELECT * FROM hash_verification WHERE hash_id = ?", (int(record_id),)
        ).fetchone()
        if row:
            h = HashVerification.from_dict(dict(row))
            summary = f"Hash {h.algorithm} on {h.evidence_id}: {h.hash_value[:24]}..."
            body = (
                f"## Hash Verification\n\n"
                f"| Field | Value |\n|---|---|\n"
                f"| Evidence | {h.evidence_id} |\n"
                f"| Algorithm | {h.algorithm} |\n"
                f"| Hash Value | `{h.hash_value}` |\n"
                f"| Verified By | {h.verified_by} |\n"
                f"| Verification Date | {h.verification_datetime} |\n"
                f"| Notes | {h.notes} |\n"
            )

    elif record_type == "tool":
        row = db.connection.execute(
            "SELECT * FROM tool_usage WHERE tool_id = ?", (int(record_id),)
        ).fetchone()
        if row:
            t = ToolUsage.from_dict(dict(row))
            summary = f"Tool: {t.tool_name} {t.version} — {t.purpose[:60]}"
            body = (
                f"## Tool Usage\n\n"
                f"| Field | Value |\n|---|---|\n"
                f"| Tool | {t.tool_name} |\n"
                f"| Version | {t.version} |\n"
                f"| Purpose | {t.purpose} |\n"
                f"| Command | `{t.command_used}` |\n"
                f"| Input | {t.input_file} |\n"
                f"| Output | {t.output_file} |\n"
                f"| Operator | {t.operator} |\n"
                f"| Date | {t.execution_datetime} |\n"
            )

    elif record_type == "analysis":
        row = db.connection.execute(
            "SELECT * FROM analysis_notes WHERE note_id = ?", (int(record_id),)
        ).fetchone()
        if row:
            n = AnalysisNote.from_dict(dict(row))
            summary = f"Analysis: {n.category} — {n.finding[:60]}"
            body = (
                f"## Analysis Note\n\n"
                f"| Field | Value |\n|---|---|\n"
                f"| Category | {n.category} |\n"
                f"| Confidence | {n.confidence_level} |\n"
                f"| Evidence | {n.evidence_id or 'N/A'} |\n\n"
                f"### Finding\n\n{n.finding}\n\n"
                f"### Description\n\n{n.description}\n"
            )

    if not body:
        body = f"*Record {record_type}/{record_id} not found.*\n"
        summary = f"{record_type}/{record_id} (not found)"

    footer = (
        f"\n---\n\n"
        f"*Exported from DFARS Desktop | Case {case.case_id} | {ts}*\n"
    )

    return header + body + footer, summary


@bp.route("/case/<case_id>/share", methods=["POST"])
def share_record(case_id):
    """Generate a .md export for a record, hash it, log it, email or print."""
    import hashlib
    import os
    import subprocess

    db = _db()
    case = db.get_case(case_id)
    if not case:
        flash("Case not found.", "danger")
        return redirect(url_for("dfars.dashboard"))

    record_type = request.form.get("record_type", "").strip()
    record_id = request.form.get("record_id", "").strip()
    action = request.form.get("share_action", "").strip()
    recipient = request.form.get("recipient", "").strip()
    narrative = request.form.get("narrative", "").strip()

    if not record_type or not record_id or action not in ("email", "print"):
        flash("Invalid share request.", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id))

    if len(narrative) < 25:
        flash("Share narrative must be at least 25 characters.", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id))

    if action == "email" and not recipient:
        flash("Email recipient is required.", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id))

    # Generate the .md
    md_text, summary = _generate_record_md(db, case, record_type, record_id)

    # Hash the content
    file_hash = hashlib.sha256(md_text.encode("utf-8")).hexdigest()

    # Append the hash to the document itself
    md_text += f"\n**Document SHA-256**: `{file_hash}`\n"

    # Save to AppData shares folder — NOT on the evidence drive.
    # Share exports are administrative records, not evidence. Keeping
    # them out of DFARS_Evidence prevents Scan Drive from ingesting them.
    from .paths import data_dir
    share_dir = data_dir() / "shares" / case_id

    share_dir.mkdir(parents=True, exist_ok=True)
    safe_type = "".join(c if c.isalnum() or c in "-_" else "_" for c in record_type)
    safe_id = "".join(c if c.isalnum() or c in "-_." else "_" for c in record_id)
    ts_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_type}_{safe_id}_{action}_{ts_slug}.md"
    file_path = share_dir / filename
    file_path.write_text(md_text, encoding="utf-8")

    # Build the share record (not saved yet — only on success)
    share = CaseShare(
        case_id=case_id,
        record_type=record_type,
        record_id=record_id,
        record_summary=summary,
        action=action,
        recipient=recipient,
        file_path=str(file_path),
        file_hash=file_hash,
        narrative=narrative,
        shared_by=_user(),
    )

    # Attempt the action — only log the share on success
    succeeded = False

    if action == "email":
        from . import mailer
        try:
            mailer.send_record(
                to_address=recipient,
                case_id=case_id,
                case_name=case.case_name,
                record_type=record_type,
                record_summary=summary,
                md_file_path=str(file_path),
                file_hash=file_hash,
                narrative=narrative,
                sender_name=_user(),
            )
            succeeded = True
            db.add_share(share)
            audit.log_case(case_id, _user(), audit.RECORD_SHARED,
                           f"EMAIL SENT to {recipient} | Type={record_type} ID={record_id} "
                           f"Hash={file_hash[:16]}... "
                           f"Subject=[DFARS] {case_id} — {case.case_name} — {record_type}: {summary} | "
                           f"NARRATIVE: {narrative}")
            flash(
                f"Email sent to {recipient} with {record_type} record attached. "
                f"SHA-256: {file_hash[:24]}...",
                "success",
            )
        except mailer.MailerError as e:
            # Audit the failure but do NOT create a share record
            audit.log_case(case_id, _user(), audit.RECORD_SHARED,
                           f"EMAIL FAILED to {recipient} | Type={record_type} ID={record_id} "
                           f"Error={e} | NARRATIVE: {narrative}")
            flash(f"Email failed: {e}. File saved at {file_path}", "danger")
    else:
        try:
            os.startfile(str(file_path))
            succeeded = True
            db.add_share(share)
            audit.log_case(case_id, _user(), audit.RECORD_PRINTED,
                           f"PRINT/EXPORT opened | Type={record_type} ID={record_id} "
                           f"Hash={file_hash[:16]}... File={file_path} | "
                           f"NARRATIVE: {narrative}")
            flash(f"File opened for printing: {file_path}", "success")
        except Exception as e:
            # Audit the failure but do NOT create a share record
            audit.log_case(case_id, _user(), audit.RECORD_PRINTED,
                           f"PRINT/EXPORT FAILED | Type={record_type} ID={record_id} "
                           f"Error={e} | NARRATIVE: {narrative}")
            flash(f"Could not open file: {e}. Saved at {file_path}", "warning")

    # Clean up the .md file if the action failed (don't leave orphans)
    if not succeeded:
        try:
            file_path.unlink(missing_ok=True)
        except Exception:
            pass

    return redirect(url_for("dfars.view_case", case_id=case_id) + "#shares")


# ── Link Analysis ─────────────────────────────────────────────


@bp.route("/case/<case_id>/link-analysis")
def link_analysis(case_id):
    db = _db()
    case = db.get_case(case_id)
    if not case:
        flash("Case not found.", "danger")
        return redirect(url_for("dfars.dashboard"))
    audit.log_case(case_id, _user(), audit.LINK_ANALYSIS_VIEWED, "Link Analysis page opened")
    return render_template("link_analysis.html", case=case)


# ── Entities ──────────────────────────────────────────────────


@bp.route("/case/<case_id>/entities", methods=["POST"])
def add_entity(case_id):
    try:
        parent_raw = request.form.get("parent_entity_id") or ""
        parent_id = int(parent_raw) if parent_raw.strip().isdigit() else None
        entity = Entity(
            case_id=case_id,
            entity_type=request.form["entity_type"],
            display_name=request.form["display_name"].strip(),
            subtype=request.form.get("subtype", "").strip(),
            organizational_rank=request.form.get("organizational_rank", "").strip(),
            parent_entity_id=parent_id,
            notes=request.form.get("notes", ""),
            metadata_json=request.form.get("metadata_json", ""),
        )
        if not entity.display_name:
            raise ValueError("Display name is required.")
        _db().create_entity(entity)
        audit.log_case(case_id, _user(), audit.ENTITY_ADDED,
                       f"Type={entity.entity_type} Name={entity.display_name!r} Subtype={entity.subtype}")
        flash(f"Entity '{entity.display_name}' added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#entities")


@bp.route("/case/<case_id>/entities/<int:entity_id>/delete", methods=["POST"])
def delete_entity(case_id, entity_id):
    try:
        if _db().soft_delete_entity(entity_id):
            audit.log_case(case_id, _user(), audit.ENTITY_DELETED, f"EntityID={entity_id}")
            flash("Entity removed.", "success")
        else:
            flash("Entity not found.", "warning")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#entities")


# ── Entity Links ──────────────────────────────────────────────


def _split_endpoint(value: str) -> tuple[str, str]:
    """
    Parse a combined "entity:<id>" / "evidence:<id>" form value into a
    (type, id) tuple. Raises ValueError on anything else.
    """
    if not value or ":" not in value:
        raise ValueError(f"Invalid endpoint: {value!r}")
    kind, rest = value.split(":", 1)
    if kind not in ("entity", "evidence") or not rest:
        raise ValueError(f"Invalid endpoint: {value!r}")
    return kind, rest


@bp.route("/case/<case_id>/links", methods=["POST"])
def add_link(case_id):
    try:
        src_type, src_id = _split_endpoint(request.form.get("source", ""))
        tgt_type, tgt_id = _split_endpoint(request.form.get("target", ""))
        link = EntityLink(
            case_id=case_id,
            source_type=src_type,
            source_id=src_id,
            target_type=tgt_type,
            target_id=tgt_id,
            link_label=request.form.get("link_label", "").strip(),
            directional=1 if request.form.get("directional") == "1" else 0,
            notes=request.form.get("notes", ""),
        )
        _db().create_link(link)
        audit.log_case(case_id, _user(), audit.LINK_ADDED,
                       f"Source={src_type}:{src_id} Target={tgt_type}:{tgt_id} Label={link.link_label!r}")
        flash("Link added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#links")


@bp.route("/case/<case_id>/links/<int:link_id>/delete", methods=["POST"])
def delete_link(case_id, link_id):
    try:
        if _db().soft_delete_link(link_id):
            audit.log_case(case_id, _user(), audit.LINK_DELETED, f"LinkID={link_id}")
            flash("Link removed.", "success")
        else:
            flash("Link not found.", "warning")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#links")


# ── Case Events (Crime Line) ──────────────────────────────────


@bp.route("/case/<case_id>/events", methods=["POST"])
def add_event(case_id):
    try:
        ent_raw = request.form.get("related_entity_id") or ""
        ent_id = int(ent_raw) if ent_raw.strip().isdigit() else None
        evi_id = request.form.get("related_evidence_id") or None
        event = CaseEvent(
            case_id=case_id,
            title=request.form["title"].strip(),
            description=request.form.get("description", ""),
            event_datetime=_parse_dt_form(request.form.get("event_datetime"))
            or datetime.now(),
            event_end_datetime=_parse_dt_form(request.form.get("event_end_datetime")),
            category=request.form.get("category", "").strip(),
            related_entity_id=ent_id,
            related_evidence_id=evi_id,
        )
        if not event.title:
            raise ValueError("Event title is required.")
        _db().create_event(event)
        audit.log_case(case_id, _user(), audit.EVENT_ADDED,
                       f"Title={event.title!r} Category={event.category} DateTime={event.event_datetime}")
        flash(f"Event '{event.title}' added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#events")


@bp.route("/case/<case_id>/events/<int:event_id>/delete", methods=["POST"])
def delete_event(case_id, event_id):
    try:
        if _db().soft_delete_event(event_id):
            audit.log_case(case_id, _user(), audit.EVENT_DELETED, f"EventID={event_id}")
            flash("Event removed.", "success")
        else:
            flash("Event not found.", "warning")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#events")


# ── Report Generation ─────────────────────────────────────────


@bp.route("/case/<case_id>/report/<fmt>")
def download_report(case_id, fmt):
    try:
        filepath = _report_gen().save_report(case_id, fmt, reports_dir())
        audit.log_case(case_id, _user(), audit.REPORT_DOWNLOADED, f"Format={fmt} Path={filepath}")
        mimetype = "application/json" if fmt == "json" else "text/markdown"
        return send_file(filepath, as_attachment=True, mimetype=mimetype)
    except Exception as e:
        flash(f"Error generating report: {e}", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id))


@bp.route("/case/<case_id>/report/preview")
def preview_report(case_id):
    try:
        audit.log_case(case_id, _user(), audit.REPORT_PREVIEWED, "Report preview opened")
        report = _report_gen().generate_report(case_id, "markdown")
        case = _db().get_case(case_id)
        return render_template("report_preview.html", case=case, report=report)
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id))


# ── API ───────────────────────────────────────────────────────


@bp.route("/api/health")
def health():
    from . import __version__
    return jsonify({"status": "ok", "system": "DFARS Desktop", "version": __version__})


# ── Internal AI helpers (DFARS UI → Agent Zero) ──────────────
#
# These endpoints are called by JavaScript in the DFARS UI (case form's
# "Enhance with AI" / "Auto-Classify" buttons). They proxy to the Agent
# Zero plugin's /api/dfars_* endpoints using the configured X-API-KEY,
# and return JSON to the browser.
#
# Auth: session-only — these are NOT in /api/v1/* (those are bearer-token
# external APIs). The before_request hook in flask_app.py protects them
# behind the normal login flow.


def _require_session() -> jsonify | None:
    if not session.get("username"):
        return jsonify(error="Not authenticated"), 401
    return None


@bp.route("/api/internal/ai/enhance", methods=["POST"])
def ai_enhance():
    err = _require_session()
    if err:
        return err
    from . import agent_zero_client

    body = request.get_json(silent=True) or {}
    text = (body.get("text") or "").strip()
    if not text:
        return jsonify(error="Missing 'text'"), 400

    try:
        enhanced = agent_zero_client.enhance_description(text)
    except agent_zero_client.AgentZeroError as e:
        return jsonify(error=str(e)), 502
    audit.log_auth(_user(), audit.AI_ENHANCE, f"Description enhanced ({len(text)} chars)")
    return jsonify(enhanced=enhanced)


@bp.route("/api/internal/ai/classify", methods=["POST"])
def ai_classify():
    err = _require_session()
    if err:
        return err
    from . import agent_zero_client

    body = request.get_json(silent=True) or {}
    text = (body.get("text") or "").strip()
    if not text:
        return jsonify(error="Missing 'text'"), 400

    try:
        result = agent_zero_client.classify_case(text)
    except agent_zero_client.AgentZeroError as e:
        return jsonify(error=str(e)), 502
    audit.log_auth(_user(), audit.AI_CLASSIFY, f"Classification={result.get('classification', '?')}")
    return jsonify(result)


@bp.route("/api/internal/cases/<case_id>/graph", methods=["GET"])
def internal_case_graph(case_id):
    """
    Session-gated graph payload for the Link Analysis page. The
    link_analysis.html template calls this via fetch() to populate
    the vis-network view. Not a public API — use /api/v1/... for
    external integrations.
    """
    err = _require_session()
    if err:
        return err

    db = _db()
    if not db.get_case(case_id):
        return jsonify(error=f"Case {case_id} not found"), 404

    # types semantics:
    #   absent        -> None  (no filter, return all entity types)
    #   "none" or ""  -> []    (explicit empty filter, return no entities)
    #   comma list    -> [...] (only those types)
    types_arg = request.args.get("types")
    if types_arg is None:
        types = None
    elif types_arg.strip() in ("", "none"):
        types = []
    else:
        types = [t.strip() for t in types_arg.split(",") if t.strip()]
    include_evidence = request.args.get("include_evidence", "1") not in ("0", "false", "no")

    try:
        graph = db.get_case_graph(case_id, entity_types=types, include_evidence=include_evidence)
    except Exception as e:
        return jsonify(error=str(e)), 500
    return jsonify(graph)


@bp.route("/api/internal/cases/<case_id>/crime-line", methods=["GET"])
def internal_case_crime_line(case_id):
    """
    Session-gated timeline payload for the Link Analysis page's
    Crime Line view. Returns {items, groups} shaped for vis-timeline.
    """
    err = _require_session()
    if err:
        return err

    db = _db()
    if not db.get_case(case_id):
        return jsonify(error=f"Case {case_id} not found"), 404

    start = _parse_date_form(request.args.get("start"))
    end = _parse_date_form(request.args.get("end"))

    try:
        payload = db.get_case_timeline(case_id, start=start, end=end)
    except Exception as e:
        return jsonify(error=str(e)), 500
    return jsonify(payload)


@bp.route("/api/internal/ai/summarize/<case_id>", methods=["POST"])
def ai_summarize(case_id):
    err = _require_session()
    if err:
        return err
    from . import agent_zero_client

    db = _db()
    case = db.get_case(case_id)
    if not case:
        return jsonify(error=f"Case {case_id} not found"), 404

    payload = {
        "case": case.to_dict(),
        "evidence": [e.to_dict() for e in db.get_evidence_for_case(case_id)],
        "custody": [c.to_dict() for c in db.get_all_custody_for_case(case_id)],
        "hashes": [h.to_dict() for h in db.get_all_hashes_for_case(case_id)],
        "tools": [t.to_dict() for t in db.get_tool_usage_for_case(case_id)],
        "analysis": [n.to_dict() for n in db.get_analysis_notes(case_id)],
    }

    try:
        result = agent_zero_client.summarize_case(payload)
    except agent_zero_client.AgentZeroError as e:
        return jsonify(error=str(e)), 502
    audit.log_case(case_id, _user(), audit.AI_SUMMARIZE, "AI case summary generated via Agent Zero")
    return jsonify(result)
