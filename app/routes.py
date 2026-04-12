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

from datetime import datetime

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
from .paths import reports_dir

bp = Blueprint("dfars", __name__)


def _db():
    return current_app.config["DFARS_DB"]


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
    cases = _db().list_cases()
    stats = _db().get_global_stats()
    return render_template("dashboard.html", cases=cases, stats=stats)


# ── Case CRUD ─────────────────────────────────────────────────


@bp.route("/case/new", methods=["GET", "POST"])
def new_case():
    if request.method == "POST":
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
            )
            _db().create_case(case)

            tags = request.form.get("tags", "")
            for tag in tags.split(","):
                tag = tag.strip()
                if tag:
                    _db().add_tag(case.case_id, tag)

            flash(f"Case {case.case_id} created.", "success")
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

    entities = db.list_entities(case_id)
    # Quick lookup table so the link/event forms can resolve entity_id
    # to a human-readable label without another round trip.
    entity_lookup = {e.entity_id: e for e in entities}

    return render_template(
        "case_detail.html",
        case=case,
        evidence=db.get_evidence_for_case(case_id),
        custody=db.get_all_custody_for_case(case_id),
        hashes=db.get_all_hashes_for_case(case_id),
        tools=db.get_tool_usage_for_case(case_id),
        analysis=db.get_analysis_notes(case_id),
        tags=db.get_tags_for_case(case_id),
        stats=db.get_case_statistics(case_id),
        entities=entities,
        entity_lookup=entity_lookup,
        links=db.list_links(case_id),
        events=db.list_events(case_id),
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

            start = _parse_date_form(request.form.get("start_date"))
            if start:
                case.start_date = start
            end = _parse_date_form(request.form.get("end_date"))
            case.end_date = end  # may be None to clear

            db.update_case(case)

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
        flash(f"Evidence {evidence.evidence_id} added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
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
        flash("Custody event added.", "success")
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
        flash("Analysis note added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#analysis")


# ── Link Analysis ─────────────────────────────────────────────


@bp.route("/case/<case_id>/link-analysis")
def link_analysis(case_id):
    db = _db()
    case = db.get_case(case_id)
    if not case:
        flash("Case not found.", "danger")
        return redirect(url_for("dfars.dashboard"))
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
        flash(f"Entity '{entity.display_name}' added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#entities")


@bp.route("/case/<case_id>/entities/<int:entity_id>/delete", methods=["POST"])
def delete_entity(case_id, entity_id):
    try:
        if _db().soft_delete_entity(entity_id):
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
        flash("Link added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#links")


@bp.route("/case/<case_id>/links/<int:link_id>/delete", methods=["POST"])
def delete_link(case_id, link_id):
    try:
        if _db().soft_delete_link(link_id):
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
        flash(f"Event '{event.title}' added.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("dfars.view_case", case_id=case_id) + "#events")


@bp.route("/case/<case_id>/events/<int:event_id>/delete", methods=["POST"])
def delete_event(case_id, event_id):
    try:
        if _db().soft_delete_event(event_id):
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
        mimetype = "application/json" if fmt == "json" else "text/markdown"
        return send_file(filepath, as_attachment=True, mimetype=mimetype)
    except Exception as e:
        flash(f"Error generating report: {e}", "danger")
        return redirect(url_for("dfars.view_case", case_id=case_id))


@bp.route("/case/<case_id>/report/preview")
def preview_report(case_id):
    try:
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
    return jsonify(result)
