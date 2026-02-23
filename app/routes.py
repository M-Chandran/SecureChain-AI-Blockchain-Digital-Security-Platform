
from __future__ import annotations

import csv
import json
import zipfile
from datetime import datetime, timezone
from functools import wraps
from io import BytesIO, StringIO
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional

import segno
from werkzeug.utils import secure_filename
from flask import (
    Blueprint,
    Response,
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

from .ai_engine import (
    build_assistant_reply,
    build_security_snapshot,
    generate_certificate_pdf,
    generate_report_pdf,
    get_analysis,
    initialize_analysis_storage,
    quick_risk_signal,
    submit_analysis_job,
)
from .alerts import list_alerts, mark_alerts_read, push_alert, push_alert_to_admins
from .api_access import create_api_key, list_api_keys, revoke_api_key, validate_api_key
from .auth import (
    grant_delegated_admin,
    get_all_users,
    get_user_by_id,
    get_user_by_username,
    has_delegated_scope,
    login_required,
    revoke_delegated_admin,
    role_required,
    set_user_email_verified,
    set_user_role,
    set_user_status,
    sync_auth_context,
    user_2fa_secret,
)
from .blockchain import (
    blockchain_health,
    create_block,
    find_blocks_by_verification_id,
    load_chain,
    validate_chain,
)
from .jobs import enqueue_job, get_job_queue
from .monitoring import export_events_ndjson, monitoring_metrics, read_events, uptime_seconds
from .policy import update_policy
from .security import (
    LoginAttemptLimiter,
    allowed_file,
    allowed_mime,
    calculate_sha256,
    decrypt_bytes,
    encrypt_bytes,
    file_size_mb,
    generate_verification_id,
    log_activity,
    sanitize_text,
    verify_totp_code,
)


main_bp = Blueprint("main", __name__)

RECORD_FIELDS = [
    "verification_id",
    "owner_id",
    "owner_username",
    "original_filename",
    "stored_filename",
    "file_hash",
    "file_size",
    "mime_type",
    "uploaded_at",
    "version",
    "quick_risk",
    "share_link",
    "qr_path",
    "status",
]

TRANSFER_FIELDS = [
    "transfer_id",
    "verification_id",
    "from_owner_id",
    "from_owner_username",
    "to_owner_id",
    "to_owner_username",
    "timestamp",
    "note",
]

INCIDENT_FIELDS = [
    "incident_id",
    "verification_id",
    "created_by",
    "created_by_username",
    "assignee",
    "severity",
    "status",
    "title",
    "description",
    "created_at",
    "updated_at",
    "resolution_note",
]

INTEGRITY_SCAN_FIELDS = [
    "scan_id",
    "run_at",
    "run_by",
    "run_by_username",
    "total_records",
    "passed_records",
    "failed_records",
    "issue_summary_json",
]

NOTE_FIELDS = [
    "note_id",
    "verification_id",
    "author_id",
    "author_username",
    "created_at",
    "note_text",
]

WATCHLIST_FIELDS = [
    "watch_id",
    "user_id",
    "verification_id",
    "note",
    "created_at",
]

PREFERENCE_FIELDS = [
    "user_id",
    "email_alerts",
    "digest_hour_utc",
    "risk_notify_min",
    "chatbot_mode",
    "updated_at",
]

REVIEW_REQUEST_FIELDS = [
    "request_id",
    "verification_id",
    "requester_id",
    "requester_username",
    "record_owner_id",
    "status",
    "reason",
    "admin_id",
    "admin_username",
    "admin_note",
    "created_at",
    "updated_at",
]

DRIVE_FIELDS = [
    "drive_id",
    "user_id",
    "username",
    "folder",
    "original_filename",
    "stored_filename",
    "file_hash",
    "file_size",
    "mime_type",
    "uploaded_at",
    "status",
    "admin_id",
    "admin_username",
    "admin_note",
    "verified_at",
    "verification_id",
]

TWO_FACTOR_REVIEW_FIELDS = [
    "request_id",
    "user_id",
    "username",
    "otp_code",
    "otp_validated",
    "otp_validated_at",
    "force_approved",
    "force_approved_at",
    "force_approved_by",
    "status",
    "reason",
    "submitted_at",
    "reviewed_at",
    "reviewed_by",
    "reviewed_by_username",
    "decision_note",
]

_records_lock = Lock()
_transfers_lock = Lock()
_incidents_lock = Lock()
_scans_lock = Lock()
_notes_lock = Lock()
_watchlist_lock = Lock()
_preferences_lock = Lock()
_review_requests_lock = Lock()
_drive_lock = Lock()
_profiles_lock = Lock()
_two_factor_reviews_lock = Lock()

PUBLIC_INTAKE_USER_ID = "public_intake"


def init_route_storage(app) -> None:
    _ensure_csv_schema(Path(app.config["RECORDS_CSV"]), RECORD_FIELDS)
    _ensure_csv_schema(Path(app.config["TRANSFERS_CSV"]), TRANSFER_FIELDS)
    _ensure_csv_schema(Path(app.config["INCIDENTS_CSV"]), INCIDENT_FIELDS)
    _ensure_csv_schema(Path(app.config["INTEGRITY_SCANS_CSV"]), INTEGRITY_SCAN_FIELDS)
    _ensure_csv_schema(Path(app.config["RECORD_NOTES_CSV"]), NOTE_FIELDS)
    _ensure_csv_schema(Path(app.config["WATCHLIST_CSV"]), WATCHLIST_FIELDS)
    _ensure_csv_schema(Path(app.config["USER_PREFERENCES_CSV"]), PREFERENCE_FIELDS)
    _ensure_csv_schema(Path(app.config["REVIEW_REQUESTS_CSV"]), REVIEW_REQUEST_FIELDS)
    _ensure_csv_schema(Path(app.config["TWO_FACTOR_REVIEW_CSV"]), TWO_FACTOR_REVIEW_FIELDS)
    _ensure_csv_schema(Path(app.config["USER_DRIVE_CSV"]), DRIVE_FIELDS)
    _ensure_json_storage(Path(app.config["USER_PROFILES_JSON"]), default_obj={})
    initialize_analysis_storage(Path(app.config["ANALYSIS_JSON"]))


def admin_or_delegated_required(scope: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            sync_auth_context()
            if "user_id" not in session:
                return redirect(url_for("auth.login"))
            if session.get("role") == "admin":
                return view(*args, **kwargs)

            user = get_user_by_id(session["user_id"])
            if user and has_delegated_scope(user, scope):
                return view(*args, **kwargs)

            flash(
                "Admin permission required. Submit manual 2FA request for delegated access.",
                "error",
            )
            portal = "admin" if session.get("role") == "admin" else "user"
            return redirect(url_for("main.dashboard", portal=portal))

        return wrapped

    return decorator


def _current_portal_from_request() -> str:
    portal = request.args.get("portal", "").strip().lower()
    if portal in {"admin", "user"}:
        return portal
    path = (request.path or "").lower()
    if path.startswith("/dashboard/admin") or path.startswith("/admin"):
        return "admin"
    if path.startswith("/dashboard/user"):
        return "user"
    return "admin" if session.get("role") == "admin" else "user"


def _dashboard_url_for_current_context() -> str:
    portal = _current_portal_from_request()
    if portal == "admin":
        return url_for("main.admin_dashboard", portal="admin")
    user_id = session.get("user_id", "")
    if user_id:
        return url_for("main.user_dashboard", user_id=user_id, portal="user")
    return url_for("main.dashboard", portal="user")


@main_bp.app_context_processor
def inject_portal_context() -> Dict[str, str]:
    return {"active_portal": _current_portal_from_request()}


@main_bp.route("/")
def index():
    if "user_id" in session:
        return redirect(_dashboard_url_for_current_context())
    records = _read_records(Path(current_app.config["RECORDS_CSV"]))
    health = blockchain_health(Path(current_app.config["BLOCKCHAIN_JSON"]))
    return render_template(
        "index.html",
        verified_count=len(records),
        health=health,
        protection_score=_calculate_protection_score(records),
    )


@main_bp.route("/dashboard")
@login_required
def dashboard():
    return redirect(_dashboard_url_for_current_context())


@main_bp.route("/dashboard/user")
@main_bp.route("/dashboard/user/<user_id>")
@login_required
def user_dashboard(user_id: str | None = None):
    current_user_id = session["user_id"]
    is_admin = session.get("role") == "admin"

    if not user_id:
        if is_admin:
            return redirect(url_for("main.admin_dashboard", portal="admin"))
        user = get_user_by_id(current_user_id)
        if not user:
            return redirect(url_for("auth.logout"))
        return _render_user_dashboard(target_user=user, admin_view=False)

    target_user = get_user_by_id(user_id)
    if not target_user:
        return render_template("error.html", title="Not Found", message="User dashboard not found.", code=404), 404

    if not is_admin and user_id != current_user_id:
        return render_template("error.html", title="Forbidden", message="Access denied.", code=403), 403

    return _render_user_dashboard(target_user=target_user, admin_view=is_admin and user_id != current_user_id)


@main_bp.route("/dashboard/admin")
@role_required("admin")
def admin_dashboard():
    return _render_admin_dashboard()

@main_bp.route("/upload", methods=["POST"])
@main_bp.route("/upload/batch", methods=["POST"])
@login_required
def upload_document():
    if session.get("role") != "user":
        flash("Only user accounts can upload. Admins must verify from the queue.", "error")
        return redirect(url_for("main.admin_dashboard"))

    policy = _policy()
    max_daily = int(policy["max_daily_uploads_per_user"])
    uploads_today = _uploads_count_today(session["user_id"])
    if uploads_today >= max_daily:
        flash("Daily upload limit reached by policy.", "error")
        push_alert(
            session["user_id"],
            severity="warning",
            category="policy",
            title="Upload Blocked by Policy",
            message="Daily upload cap reached for this account.",
        )
        return redirect(_dashboard_url_for_current_context())

    incoming_files = [item for item in request.files.getlist("document") if item and item.filename]
    if not incoming_files:
        flash("Select one or more documents to upload.", "error")
        return redirect(_dashboard_url_for_current_context())

    remaining_quota = max_daily - uploads_today
    skipped_by_quota = 0
    if len(incoming_files) > remaining_quota:
        skipped_by_quota = len(incoming_files) - remaining_quota
        incoming_files = incoming_files[:remaining_quota]

    if not incoming_files:
        flash("No upload quota available for today.", "error")
        return redirect(_dashboard_url_for_current_context())

    folder_raw = request.form.get("folder", "root")
    folder = _normalize_drive_folder(folder_raw)
    drive_file = Path(current_app.config["USER_DRIVE_CSV"])
    existing_verified_records = _read_records(Path(current_app.config["RECORDS_CSV"]))
    existing_drive = _read_drive_items(drive_file)

    results = {
        "uploaded": 0,
        "duplicates": 0,
        "blocked": 0,
        "empty": 0,
        "pending_admin_review": 0,
    }
    created_ids: List[str] = []

    for incoming in incoming_files:
        filename = incoming.filename.strip()
        if not filename:
            results["empty"] += 1
            continue

        if not allowed_file(filename):
            results["blocked"] += 1
            log_activity(session["user_id"], "upload", "failed", f"File type blocked: {filename}")
            continue
        if not allowed_mime(incoming.mimetype):
            results["blocked"] += 1
            log_activity(session["user_id"], "upload", "failed", f"MIME blocked: {incoming.mimetype} for {filename}")
            continue

        content = incoming.read()
        if not content:
            results["empty"] += 1
            log_activity(session["user_id"], "upload", "failed", f"Empty file: {filename}")
            continue

        file_hash = calculate_sha256(content)
        duplicate = next(
            (
                row for row in existing_verified_records if row["owner_id"] == session["user_id"] and row["file_hash"] == file_hash
            ),
            None,
        )
        if not duplicate:
            duplicate = next(
                (
                    row
                    for row in existing_drive
                    if row["user_id"] == session["user_id"]
                    and row["file_hash"] == file_hash
                    and row["status"] in {"pending", "approved"}
                ),
                None,
            )
        if duplicate:
            results["duplicates"] += 1
            log_activity(
                session["user_id"],
                "upload",
                "failed",
                f"Duplicate hash blocked: {filename}",
            )
            continue

        drive_id = generate_verification_id()
        stored_name = _save_drive_encrypted_file(
            user_id=session["user_id"],
            folder=folder,
            original_filename=filename,
            drive_id=drive_id,
            content=content,
        )
        drive_row = {
            "drive_id": drive_id,
            "user_id": session["user_id"],
            "username": session["username"],
            "folder": folder,
            "original_filename": filename,
            "stored_filename": stored_name,
            "file_hash": file_hash,
            "file_size": str(len(content)),
            "mime_type": incoming.mimetype,
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
            "admin_id": "",
            "admin_username": "",
            "admin_note": "",
            "verified_at": "",
            "verification_id": "",
        }

        _append_drive_item(drive_file, drive_row)
        existing_drive.append(drive_row)
        results["uploaded"] += 1
        results["pending_admin_review"] += 1
        created_ids.append(drive_id)

        log_activity(
            session["user_id"],
            "upload",
            "success",
            f"{filename} ({file_size_mb(len(content))} MB) DRIVE={drive_id} folder={folder} status=pending",
        )

    if results["uploaded"] > 0:
        first_ids = ", ".join(created_ids[:3])
        suffix = f" (first IDs: {first_ids})" if first_ids else ""
        flash(
            f"Drive upload complete. {results['uploaded']} file(s) submitted for admin verification.{suffix}",
            "success",
        )
        push_alert_to_admins(
            severity="info",
            category="verification",
            title="New User Uploads Pending Verification",
            message=f"{session['username']} uploaded {results['uploaded']} document(s) to secure drive.",
        )
    else:
        flash("No files were uploaded. Review checks and try again.", "error")

    if results["duplicates"] > 0:
        flash(f"{results['duplicates']} duplicate file(s) skipped by hash check.", "error")
    if results["blocked"] > 0:
        flash(f"{results['blocked']} file(s) blocked by type or MIME policy.", "error")
    if results["empty"] > 0:
        flash(f"{results['empty']} empty file(s) skipped.", "error")
    if skipped_by_quota > 0:
        flash(f"{skipped_by_quota} file(s) skipped due to daily upload quota.", "error")

    return redirect(_dashboard_url_for_current_context())


@main_bp.route("/upload/public", methods=["GET", "POST"])
def public_upload():
    if request.method == "GET":
        return render_template("public_upload.html")

    submitter_name = sanitize_text(request.form.get("submitter_name", "Public User"), max_length=60) or "Public User"
    submitter_email = sanitize_text(request.form.get("submitter_email", ""), max_length=120).lower()
    folder_raw = request.form.get("folder", "public/intake")
    folder = _normalize_drive_folder(folder_raw)

    incoming_files = [item for item in request.files.getlist("document") if item and item.filename]
    if not incoming_files:
        flash("Select one or more documents to upload.", "error")
        return redirect(url_for("main.public_upload"))

    max_files = 12
    skipped_overflow = 0
    if len(incoming_files) > max_files:
        skipped_overflow = len(incoming_files) - max_files
        incoming_files = incoming_files[:max_files]

    display_name = submitter_name
    if submitter_email:
        display_name = f"{submitter_name} <{submitter_email}>"
    display_name = sanitize_text(display_name, max_length=80) or "Public User"

    drive_file = Path(current_app.config["USER_DRIVE_CSV"])
    existing_verified_records = _read_records(Path(current_app.config["RECORDS_CSV"]))
    existing_drive = _read_drive_items(drive_file)

    results = {
        "uploaded": 0,
        "duplicates": 0,
        "blocked": 0,
        "empty": 0,
    }
    created_ids: List[str] = []

    for incoming in incoming_files:
        filename = incoming.filename.strip()
        if not filename:
            results["empty"] += 1
            continue

        if not allowed_file(filename):
            results["blocked"] += 1
            log_activity("anonymous", "public_upload", "failed", f"File type blocked: {filename}")
            continue
        if not allowed_mime(incoming.mimetype):
            results["blocked"] += 1
            log_activity(
                "anonymous",
                "public_upload",
                "failed",
                f"MIME blocked: {incoming.mimetype} for {filename}",
            )
            continue

        content = incoming.read()
        if not content:
            results["empty"] += 1
            log_activity("anonymous", "public_upload", "failed", f"Empty file: {filename}")
            continue

        file_hash = calculate_sha256(content)
        duplicate = next((row for row in existing_verified_records if row["file_hash"] == file_hash), None)
        if not duplicate:
            duplicate = next(
                (
                    row
                    for row in existing_drive
                    if row["file_hash"] == file_hash and row["status"] in {"pending", "approved"}
                ),
                None,
            )
        if duplicate:
            results["duplicates"] += 1
            log_activity(
                "anonymous",
                "public_upload",
                "failed",
                f"Duplicate hash blocked: {filename}",
            )
            continue

        drive_id = generate_verification_id()
        stored_name = _save_drive_encrypted_file(
            user_id=PUBLIC_INTAKE_USER_ID,
            folder=folder,
            original_filename=filename,
            drive_id=drive_id,
            content=content,
        )
        drive_row = {
            "drive_id": drive_id,
            "user_id": PUBLIC_INTAKE_USER_ID,
            "username": display_name,
            "folder": folder,
            "original_filename": filename,
            "stored_filename": stored_name,
            "file_hash": file_hash,
            "file_size": str(len(content)),
            "mime_type": incoming.mimetype,
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
            "admin_id": "",
            "admin_username": "",
            "admin_note": "",
            "verified_at": "",
            "verification_id": "",
        }

        _append_drive_item(drive_file, drive_row)
        existing_drive.append(drive_row)
        created_ids.append(drive_id)
        results["uploaded"] += 1

        log_activity(
            "anonymous",
            "public_upload",
            "success",
            f"{filename} ({file_size_mb(len(content))} MB) DRIVE={drive_id} folder={folder}",
        )

    if results["uploaded"] > 0:
        first_ids = ", ".join(created_ids[:3])
        suffix = f" (first IDs: {first_ids})" if first_ids else ""
        flash(
            f"Public upload complete. {results['uploaded']} file(s) submitted for admin verification.{suffix}",
            "success",
        )
        submitter = submitter_name if submitter_name else "Public User"
        if submitter_email:
            submitter = f"{submitter} ({submitter_email})"
        push_alert_to_admins(
            severity="warning",
            category="verification",
            title="New Public Upload Pending Verification",
            message=f"{submitter} submitted {results['uploaded']} document(s) via public upload.",
        )
    else:
        flash("No files were uploaded. Review checks and try again.", "error")

    if results["duplicates"] > 0:
        flash(f"{results['duplicates']} duplicate file(s) skipped by hash check.", "error")
    if results["blocked"] > 0:
        flash(f"{results['blocked']} file(s) blocked by type or MIME policy.", "error")
    if results["empty"] > 0:
        flash(f"{results['empty']} empty file(s) skipped.", "error")
    if skipped_overflow > 0:
        flash(f"{skipped_overflow} file(s) skipped. Public upload limit is {max_files} files/request.", "error")

    return redirect(url_for("main.public_upload"))


@main_bp.route("/drive/<drive_id>/delete", methods=["POST"])
@login_required
def delete_drive_item(drive_id: str):
    rows = _read_drive_items(Path(current_app.config["USER_DRIVE_CSV"]))
    target = next((row for row in rows if row["drive_id"] == drive_id), None)
    if not target:
        flash("Drive item not found.", "error")
        return redirect(_dashboard_url_for_current_context())
    if target["user_id"] != session["user_id"]:
        flash("You can only delete your own drive items.", "error")
        return redirect(_dashboard_url_for_current_context())
    if target["status"] != "pending":
        flash("Only pending drive items can be deleted.", "error")
        return redirect(_dashboard_url_for_current_context())

    try:
        stored_path = Path(current_app.config["UPLOAD_DIR"]) / target["stored_filename"]
        if stored_path.exists():
            stored_path.unlink()
    except OSError:
        pass

    rows = [row for row in rows if row["drive_id"] != drive_id]
    _write_drive_items(Path(current_app.config["USER_DRIVE_CSV"]), rows)
    log_activity(session["user_id"], "drive_delete", "success", f"DRIVE={drive_id}")
    flash("Drive item deleted.", "success")
    return redirect(url_for("main.user_dashboard", user_id=session["user_id"]))


@main_bp.route("/admin/drive/<drive_id>/decision", methods=["POST"])
@role_required("admin")
def admin_drive_decision(drive_id: str):
    decision = request.form.get("decision", "").strip().lower()
    if decision not in {"approve", "reject"}:
        flash("Invalid decision.", "error")
        return redirect(url_for("main.admin_dashboard"))

    admin_note = sanitize_text(request.form.get("admin_note", ""), max_length=220)
    drive_path = Path(current_app.config["USER_DRIVE_CSV"])
    drive_rows = _read_drive_items(drive_path)
    target = next((row for row in drive_rows if row["drive_id"] == drive_id), None)
    if not target:
        flash("Drive item not found.", "error")
        return redirect(url_for("main.admin_dashboard"))
    if target["status"] != "pending":
        flash("Drive item already processed.", "error")
        return redirect(url_for("main.admin_dashboard"))

    target["admin_id"] = session["user_id"]
    target["admin_username"] = session["username"]
    target["admin_note"] = admin_note
    target["verified_at"] = datetime.now(timezone.utc).isoformat()

    if decision == "reject":
        target["status"] = "rejected"
        _write_drive_items(drive_path, drive_rows)
        push_alert(
            target["user_id"],
            severity="warning",
            category="verification",
            title="Document Rejected by Admin",
            message=f"Drive item {drive_id} was rejected. Review admin note.",
        )
        log_activity(session["user_id"], "admin_drive_decision", "success", f"DRIVE={drive_id} rejected")
        flash("Drive item rejected.", "success")
        return redirect(url_for("main.admin_dashboard"))

    # decision == approve
    records_path = Path(current_app.config["RECORDS_CSV"])
    existing_records = _read_records(records_path)
    verification_id = _next_verification_id()
    version = _compute_next_version(existing_records, target["user_id"], target["original_filename"])
    file_size = int(target.get("file_size", "0") or 0)
    quick_risk = int(quick_risk_signal(target["original_filename"], file_size, target["mime_type"])["quick_risk"])
    share_link = url_for("main.public_verify", verification_id=verification_id, _external=True)
    qr_path = _generate_qr_code(verification_id, share_link)

    record = {
        "verification_id": verification_id,
        "owner_id": target["user_id"],
        "owner_username": target["username"],
        "original_filename": target["original_filename"],
        "stored_filename": target["stored_filename"],
        "file_hash": target["file_hash"],
        "file_size": target["file_size"],
        "mime_type": target["mime_type"],
        "uploaded_at": target["uploaded_at"],
        "version": str(version),
        "quick_risk": str(quick_risk),
        "share_link": share_link,
        "qr_path": qr_path,
        "status": "active",
    }
    _append_record(records_path, record)
    create_block(
        chain_file=Path(current_app.config["BLOCKCHAIN_JSON"]),
        file_hash=target["file_hash"],
        owner_id=target["user_id"],
        verification_id=verification_id,
        record_type="admin_verify_upload",
    )
    chain_valid, _ = validate_chain(Path(current_app.config["BLOCKCHAIN_JSON"]))
    analysis_job_id = enqueue_job(
        "ai_analysis",
        {
            "verification_id": verification_id,
            "record": record,
            "chain_valid": chain_valid,
        },
        requested_by=session["user_id"],
    )
    if not analysis_job_id:
        submit_analysis_job(Path(current_app.config["ANALYSIS_JSON"]), verification_id, record, chain_valid)
    else:
        enqueue_job(
            "report_pdf",
            {"verification_id": verification_id},
            requested_by=session["user_id"],
        )
        enqueue_job(
            "certificate_pdf",
            {"verification_id": verification_id},
            requested_by=session["user_id"],
        )

    target["status"] = "approved"
    target["verification_id"] = verification_id
    _write_drive_items(drive_path, drive_rows)
    push_alert(
        target["user_id"],
        severity="info",
        category="verification",
        title="Document Verified by Admin",
        message=f"Drive item {drive_id} approved as VID {verification_id}.",
        verification_id=verification_id,
    )
    log_activity(
        session["user_id"],
        "admin_drive_decision",
        "success",
        f"DRIVE={drive_id} approved VID={verification_id} job={analysis_job_id or 'inline'}",
    )
    flash(f"Drive item approved and verified. VID: {verification_id}", "success")
    return redirect(url_for("main.admin_dashboard"))


@main_bp.route("/record/<verification_id>")
@login_required
def record_detail(verification_id: str):
    verification_id = verification_id.upper()
    record = _record_by_verification_id(verification_id)
    if not record:
        return render_template("error.html", title="Not Found", message="Record not found.", code=404), 404
    if session["role"] != "admin" and record["owner_id"] != session["user_id"]:
        return render_template("error.html", title="Forbidden", message="Access denied.", code=403), 403

    all_records = _read_records(Path(current_app.config["RECORDS_CSV"]))
    versions = [
        row
        for row in all_records
        if row["original_filename"].lower() == record["original_filename"].lower()
        and row["owner_id"] == record["owner_id"]
    ]
    versions = sorted(versions, key=lambda r: r["uploaded_at"], reverse=True)
    blocks = list(reversed(find_blocks_by_verification_id(Path(current_app.config["BLOCKCHAIN_JSON"]), verification_id)))
    transfers = [
        row
        for row in _read_transfers(Path(current_app.config["TRANSFERS_CSV"]))
        if row["verification_id"].upper() == verification_id
    ]
    transfers = sorted(transfers, key=lambda t: t["timestamp"], reverse=True)
    analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), verification_id)
    notes = _notes_for_verification(verification_id)
    incidents = _incidents_for_verification(verification_id)
    watchlist_item = _watchlist_item(session["user_id"], verification_id)
    review_requests = _review_requests_for_record_for_session(verification_id)

    return render_template(
        "record_detail.html",
        record=record,
        versions=versions,
        blocks=blocks,
        transfers=transfers,
        analysis=analysis,
        notes=notes,
        incidents=incidents,
        watchlist_item=watchlist_item,
        review_requests=review_requests,
    )

@main_bp.route("/verify", methods=["GET", "POST"])
def public_verify():
    verification_id = request.args.get("verification_id", "").strip() or request.form.get(
        "verification_id", ""
    ).strip()
    verification_id = verification_id.upper()
    result = None
    if verification_id:
        result = _verification_payload(verification_id)
        status = "success" if result.get("exists") and not result.get("tamper_detected") else "failed"
        log_activity(session.get("user_id", "anonymous"), "public_verify", status, f"VID={verification_id}")
    return render_template("verify_public.html", verification_id=verification_id, result=result)


@main_bp.route("/verify/batch", methods=["GET", "POST"])
@admin_or_delegated_required("verify_batch")
def batch_verify():
    raw_ids = request.args.get("verification_ids", "").strip()
    if request.method == "POST":
        raw_ids = request.form.get("verification_ids", "").strip()

    parsed_ids = _parse_verification_ids(raw_ids, limit=50)
    results: List[Dict[str, object]] = []
    stats = {"total": 0, "authentic": 0, "tampered": 0, "missing": 0}

    if parsed_ids:
        for verification_id in parsed_ids:
            payload = _verification_payload(verification_id)
            exists = bool(payload.get("exists"))
            tamper = bool(payload.get("tamper_detected")) if exists else True
            row = {
                "verification_id": verification_id,
                "exists": exists,
                "tamper_detected": tamper,
                "risk_percentage": payload.get("risk_percentage", "Pending"),
                "authenticity_score": payload.get("authenticity_score", "Pending"),
                "chain_valid": payload.get("chain_valid", False),
                "integrity_match": payload.get("integrity_match", False),
                "record": payload.get("record", {}),
            }
            results.append(row)

        stats["total"] = len(results)
        stats["authentic"] = len([row for row in results if row["exists"] and not row["tamper_detected"]])
        stats["tampered"] = len([row for row in results if row["exists"] and row["tamper_detected"]])
        stats["missing"] = len([row for row in results if not row["exists"]])
        log_activity(session["user_id"], "batch_verify", "success", f"count={len(results)}")

    return render_template(
        "batch_verify.html",
        verification_ids=raw_ids,
        results=results,
        stats=stats,
    )


@main_bp.route("/user/portfolio/export.csv")
@login_required
def export_portfolio_csv():
    if session.get("role") != "user":
        return render_template("error.html", title="Forbidden", message="User portfolio export is only available for user accounts.", code=403), 403

    records = sorted(
        _records_for_session(_read_records(Path(current_app.config["RECORDS_CSV"]))),
        key=lambda row: row["uploaded_at"],
        reverse=True,
    )
    export_rows: List[Dict[str, str]] = []
    for row in records:
        analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), row["verification_id"])
        export_rows.append(
            {
                "verification_id": row["verification_id"],
                "file_name": row["original_filename"],
                "owner_username": row["owner_username"],
                "status": row["status"],
                "version": row["version"],
                "uploaded_at": row["uploaded_at"],
                "file_hash": row["file_hash"],
                "quick_risk": row["quick_risk"],
                "risk_percentage": analysis.get("risk_percentage", row.get("quick_risk", "")),
                "authenticity_score": analysis.get("authenticity_score", "Pending"),
                "fraud_indicator": analysis.get("fraud_indicator", "Pending"),
                "share_link": row["share_link"],
            }
        )

    buffer_text = StringIO()
    writer = csv.DictWriter(
        buffer_text,
        fieldnames=[
            "verification_id",
            "file_name",
            "owner_username",
            "status",
            "version",
            "uploaded_at",
            "file_hash",
            "quick_risk",
            "risk_percentage",
            "authenticity_score",
            "fraud_indicator",
            "share_link",
        ],
    )
    writer.writeheader()
    writer.writerows(export_rows)
    payload = buffer_text.getvalue().encode("utf-8")
    log_activity(session["user_id"], "portfolio_export_csv", "success", f"rows={len(export_rows)}")
    return send_file(
        BytesIO(payload),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"securechain_portfolio_{session['username']}.csv",
    )


@main_bp.route("/api/verify/<verification_id>")
def api_verify(verification_id: str):
    payload = _verification_payload(verification_id.upper())
    status = "success" if payload.get("exists") and not payload.get("tamper_detected") else "failed"
    log_activity("anonymous", "api_verify", status, f"VID={verification_id.upper()}")
    return jsonify(payload)


@main_bp.route("/api/external/verify/<verification_id>")
def api_external_verify(verification_id: str):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else ""
    key = validate_api_key(token, required_scope="verify:read")
    if not key:
        return jsonify({"status": "error", "message": "Invalid API key."}), 401
    payload = _verification_payload(verification_id.upper())
    payload["integration"] = {"key_id": key["key_id"], "label": key["label"]}
    return jsonify(payload)


@main_bp.route("/api/upload/check", methods=["POST"])
@login_required
def api_upload_check():
    if session.get("role") != "user":
        return jsonify({"status": "error", "message": "Upload check is available for user accounts only."}), 403

    incoming_files = [item for item in request.files.getlist("document") if item and item.filename]
    if not incoming_files:
        return jsonify({"status": "error", "message": "No files attached."}), 400

    all_records = _read_records(Path(current_app.config["RECORDS_CSV"]))
    drive_rows = _read_drive_items(Path(current_app.config["USER_DRIVE_CSV"]))
    rows: List[Dict[str, object]] = []
    for incoming in incoming_files[:30]:
        filename = incoming.filename.strip()
        content = incoming.read()
        size_bytes = len(content)
        ext_ok = bool(filename and allowed_file(filename))
        mime_ok = bool(incoming.mimetype and allowed_mime(incoming.mimetype))
        not_empty = size_bytes > 0
        file_hash = calculate_sha256(content) if not_empty else ""
        duplicate = None
        if file_hash:
            duplicate = next(
                (
                    row
                    for row in all_records
                    if row["owner_id"] == session["user_id"] and row["file_hash"] == file_hash
                ),
                None,
            )
        if file_hash and not duplicate:
            duplicate = next(
                (
                    row
                    for row in drive_rows
                    if row["user_id"] == session["user_id"]
                    and row["file_hash"] == file_hash
                    and row["status"] in {"pending", "approved"}
                ),
                None,
            )
        quick_risk = 0
        suggested_status = "blocked"
        if ext_ok and mime_ok and not_empty:
            quick_risk = int(quick_risk_signal(filename, size_bytes, incoming.mimetype)["quick_risk"])
            suggested_status = "quarantined" if quick_risk >= int(_policy()["quarantine_threshold"]) else "active"

        rows.append(
            {
                "filename": filename,
                "mime_type": incoming.mimetype,
                "size_bytes": size_bytes,
                "size_mb": file_size_mb(size_bytes),
                "extension_allowed": ext_ok,
                "mime_allowed": mime_ok,
                "not_empty": not_empty,
                "duplicate": bool(duplicate),
                "duplicate_verification_id": duplicate["verification_id"] if duplicate else "",
                "duplicate_drive_id": duplicate.get("drive_id", "") if duplicate else "",
                "quick_risk": quick_risk,
                "suggested_status": suggested_status,
                "accepted": ext_ok and mime_ok and not_empty and not duplicate,
            }
        )

    accepted = len([row for row in rows if row["accepted"]])
    blocked = len(rows) - accepted
    return jsonify(
        {
            "status": "ok",
            "summary": {"total": len(rows), "accepted": accepted, "blocked": blocked},
            "checks": rows,
        }
    )


@main_bp.route("/blockchain")
@login_required
def blockchain_explorer():
    chain = list(reversed(load_chain(Path(current_app.config["BLOCKCHAIN_JSON"]))))
    health = blockchain_health(Path(current_app.config["BLOCKCHAIN_JSON"]))
    return render_template("blockchain.html", chain=chain, health=health)


@main_bp.route("/assistant")
@login_required
def assistant():
    records = _records_for_session(_read_records(Path(current_app.config["RECORDS_CSV"])))
    records = sorted(records, key=lambda r: r["uploaded_at"], reverse=True)
    return render_template("assistant.html", records=records[:25])


@main_bp.route("/support")
def support():
    if "user_id" not in session:
        flash("Support Bot is now merged into AI Copilot. Login to continue.", "error")
        return redirect(url_for("auth.login"))
    return redirect(url_for("main.assistant"))


@main_bp.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    payload = request.get_json(silent=True) or {}
    question = sanitize_text(payload.get("message", ""), max_length=300)
    verification_id = sanitize_text(payload.get("verification_id", ""), max_length=30).upper()
    if not question:
        return jsonify({"status": "error", "message": "Message is required."}), 400

    chatbot_mode = _user_preferences(session["user_id"]).get("chatbot_mode", "assistive")
    context: Dict[str, str] = {"verification_id": verification_id}

    if verification_id:
        record = _record_by_verification_id(verification_id)
        if not record:
            context["record_found"] = "0"
        elif session.get("role") == "admin" or record["owner_id"] == session["user_id"]:
            analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), verification_id)
            blocks = find_blocks_by_verification_id(Path(current_app.config["BLOCKCHAIN_JSON"]), verification_id)
            chain_valid, issues = validate_chain(Path(current_app.config["BLOCKCHAIN_JSON"]))
            latest_block = blocks[-1] if blocks else None
            integrity_match = bool(latest_block and latest_block.get("file_hash") == record.get("file_hash"))

            context.update(
                {
                    "record_found": "1",
                    "owner_username": record.get("owner_username", ""),
                    "record_status": record.get("status", ""),
                    "file_name": record.get("original_filename", ""),
                    "quick_risk": record.get("quick_risk", ""),
                    "chain_valid": "1" if chain_valid else "0",
                    "integrity_match": "1" if integrity_match else "0",
                    "tamper_detected": "1" if ((not chain_valid) or (not integrity_match)) else "0",
                    "issues_count": str(len(issues)),
                }
            )
            if analysis.get("status") == "complete":
                context.update(
                    {
                        "risk_percentage": str(analysis.get("risk_percentage", "")),
                        "authenticity_score": str(analysis.get("authenticity_score", "")),
                        "fraud_indicator": str(analysis.get("fraud_indicator", "")),
                    }
                )
        else:
            context["access_limited"] = "1"

    response = build_assistant_reply(
        question,
        context=context,
        user_role=session.get("role", "user"),
        mode=chatbot_mode,
    )
    log_activity(session["user_id"], "assistant_chat", "success", question)
    return jsonify({"status": "ok", **response})


@main_bp.route("/api/support-chat", methods=["POST"])
def api_support_chat():
    return jsonify(
        {
            "status": "error",
            "message": "Support Bot has been retired. Use AI Copilot from /assistant.",
        }
    ), 410

@main_bp.route("/report/<verification_id>.pdf")
@login_required
def download_report(verification_id: str):
    verification_id = verification_id.upper()
    record = _record_by_verification_id(verification_id)
    if not record:
        return render_template("error.html", title="Not Found", message="Record not found.", code=404), 404
    if session["role"] != "admin" and record["owner_id"] != session["user_id"]:
        return render_template("error.html", title="Forbidden", message="Access denied.", code=403), 403
    queue_obj = get_job_queue()
    if queue_obj:
        latest = queue_obj.latest_completed("report_pdf", verification_id)
        if latest:
            artifact_path = queue_obj.artifact_path(str(latest.get("job_id", "")))
            if artifact_path:
                result = latest.get("result", {})
                download_name = f"security_report_{verification_id}.pdf"
                if isinstance(result, dict):
                    download_name = str(result.get("download_name", download_name))
                return send_file(
                    artifact_path,
                    mimetype="application/pdf",
                    as_attachment=True,
                    download_name=download_name,
                )

        job_id = enqueue_job("report_pdf", {"verification_id": verification_id}, requested_by=session["user_id"])
        if job_id:
            flash(f"Report generation queued ({job_id}). Refresh in a few seconds.", "success")
            return redirect(request.referrer or url_for("main.record_detail", verification_id=verification_id))

    analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), verification_id)
    chain_valid, _ = validate_chain(Path(current_app.config["BLOCKCHAIN_JSON"]))
    if analysis.get("status") != "complete":
        analysis = {
            "risk_percentage": "Pending",
            "authenticity_score": "Pending",
            "fraud_indicator": "Pending",
            "security_summary": "AI analysis is still processing.",
            "explanation": "Please retry in a few moments.",
        }
    pdf_buffer = generate_report_pdf(record=record, analysis=analysis, chain_valid=chain_valid)
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"security_report_{verification_id}.pdf",
    )


@main_bp.route("/certificate/<verification_id>.pdf")
def download_certificate(verification_id: str):
    if not bool(_policy()["public_certificate_enabled"]) and "user_id" not in session:
        return render_template("error.html", title="Forbidden", message="Public certificates are disabled.", code=403), 403
    verification_id = verification_id.upper()
    record = _record_by_verification_id(verification_id)
    if not record:
        return render_template("error.html", title="Not Found", message="Record not found.", code=404), 404
    blocks = find_blocks_by_verification_id(Path(current_app.config["BLOCKCHAIN_JSON"]), verification_id)
    if not blocks:
        return render_template("error.html", title="Not Found", message="No blockchain block found.", code=404), 404

    if "user_id" in session:
        if session.get("role") != "admin" and record["owner_id"] != session.get("user_id"):
            return render_template("error.html", title="Forbidden", message="Access denied.", code=403), 403
        queue_obj = get_job_queue()
        if queue_obj:
            latest = queue_obj.latest_completed("certificate_pdf", verification_id)
            if latest:
                artifact_path = queue_obj.artifact_path(str(latest.get("job_id", "")))
                if artifact_path:
                    result = latest.get("result", {})
                    download_name = f"certificate_{verification_id}.pdf"
                    if isinstance(result, dict):
                        download_name = str(result.get("download_name", download_name))
                    return send_file(
                        artifact_path,
                        mimetype="application/pdf",
                        as_attachment=True,
                        download_name=download_name,
                    )
            job_id = enqueue_job("certificate_pdf", {"verification_id": verification_id}, requested_by=session["user_id"])
            if job_id:
                flash(f"Certificate generation queued ({job_id}). Refresh in a few seconds.", "success")
                return redirect(request.referrer or url_for("main.record_detail", verification_id=verification_id))

    chain_valid, _ = validate_chain(Path(current_app.config["BLOCKCHAIN_JSON"]))
    pdf_buffer = generate_certificate_pdf(record, blocks[-1], chain_valid)
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"certificate_{verification_id}.pdf",
    )


@main_bp.route("/jobs/<job_id>")
@login_required
def job_status(job_id: str):
    queue_obj = get_job_queue()
    if not queue_obj:
        return jsonify({"status": "error", "message": "Job queue unavailable"}), 503

    job = queue_obj.get(job_id)
    if not job:
        return jsonify({"status": "error", "message": "Job not found"}), 404
    if session.get("role") != "admin" and job.get("requested_by") != session["user_id"]:
        return jsonify({"status": "error", "message": "Access denied"}), 403

    result = job.get("result", {})
    download_url = ""
    if isinstance(result, dict) and result.get("artifact_name"):
        download_url = url_for("main.download_job_artifact", job_id=job_id)

    return jsonify(
        {
            "status": "ok",
            "job": {
                "job_id": job.get("job_id"),
                "job_type": job.get("job_type"),
                "state": job.get("status"),
                "error": job.get("error", ""),
                "created_at": job.get("created_at", ""),
                "started_at": job.get("started_at", ""),
                "finished_at": job.get("finished_at", ""),
                "download_url": download_url,
            },
        }
    )


@main_bp.route("/jobs/<job_id>/download")
@login_required
def download_job_artifact(job_id: str):
    queue_obj = get_job_queue()
    if not queue_obj:
        return render_template("error.html", title="Unavailable", message="Job queue unavailable.", code=503), 503

    job = queue_obj.get(job_id)
    if not job:
        return render_template("error.html", title="Not Found", message="Job not found.", code=404), 404
    if session.get("role") != "admin" and job.get("requested_by") != session["user_id"]:
        return render_template("error.html", title="Forbidden", message="Access denied.", code=403), 403

    artifact_path = queue_obj.artifact_path(job_id)
    if not artifact_path:
        return render_template("error.html", title="Not Ready", message="Artifact is not ready yet.", code=409), 409

    result = job.get("result", {})
    download_name = artifact_path.name
    mimetype = "application/octet-stream"
    if isinstance(result, dict):
        download_name = str(result.get("download_name", download_name))
        mimetype = str(result.get("content_type", mimetype))
    return send_file(artifact_path, mimetype=mimetype, as_attachment=True, download_name=download_name)


@main_bp.route("/transfer/<verification_id>", methods=["POST"])
@login_required
def transfer_record(verification_id: str):
    verification_id = verification_id.upper()
    target_username = request.form.get("target_username", "").strip()
    note = sanitize_text(request.form.get("note", ""), max_length=180)
    record = _record_by_verification_id(verification_id)
    if not record:
        flash("Verification record not found.", "error")
        return redirect(_dashboard_url_for_current_context())
    if session["role"] != "admin" and record["owner_id"] != session["user_id"]:
        flash("You can only transfer your own records.", "error")
        return redirect(_dashboard_url_for_current_context())
    target_user = get_user_by_username(target_username)
    if not target_user:
        flash("Target user does not exist.", "error")
        return redirect(_dashboard_url_for_current_context())
    if target_user["account_status"] != "active":
        flash("Target user account is not active.", "error")
        return redirect(_dashboard_url_for_current_context())

    from_owner_id = record["owner_id"]
    from_owner_username = record["owner_username"]
    rows = _read_records(Path(current_app.config["RECORDS_CSV"]))
    for row in rows:
        if row["verification_id"] == verification_id:
            row["owner_id"] = target_user["user_id"]
            row["owner_username"] = target_user["username"]
            break
    _write_records(Path(current_app.config["RECORDS_CSV"]), rows)

    _append_transfer(
        Path(current_app.config["TRANSFERS_CSV"]),
        {
            "transfer_id": generate_verification_id(),
            "verification_id": verification_id,
            "from_owner_id": from_owner_id,
            "from_owner_username": from_owner_username,
            "to_owner_id": target_user["user_id"],
            "to_owner_username": target_user["username"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": note or "Ownership updated",
        },
    )
    create_block(
        chain_file=Path(current_app.config["BLOCKCHAIN_JSON"]),
        file_hash=record["file_hash"],
        owner_id=target_user["user_id"],
        verification_id=verification_id,
        record_type="transfer",
    )
    push_alert(target_user["user_id"], "info", "ownership", "Ownership Received", f"VID {verification_id} transferred to you.", verification_id)
    flash("Ownership transferred successfully.", "success")
    return redirect(_dashboard_url_for_current_context())


@main_bp.route("/watchlist/add/<verification_id>", methods=["POST"])
@login_required
def watchlist_add(verification_id: str):
    verification_id = verification_id.upper()
    record = _record_by_verification_id(verification_id)
    if not record:
        flash("Record not found.", "error")
        return redirect(_dashboard_url_for_current_context())
    if session["role"] != "admin" and record["owner_id"] != session["user_id"]:
        flash("Access denied for this record.", "error")
        return redirect(_dashboard_url_for_current_context())

    note = sanitize_text(request.form.get("note", ""), max_length=120)
    existing = _watchlist_item(session["user_id"], verification_id)
    if existing:
        flash("Record is already in your watchlist.", "error")
    else:
        _append_watchlist(
            Path(current_app.config["WATCHLIST_CSV"]),
            {
                "watch_id": generate_verification_id(),
                "user_id": session["user_id"],
                "verification_id": verification_id,
                "note": note or "Priority monitoring enabled",
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        log_activity(session["user_id"], "watchlist_add", "success", f"VID={verification_id}")
        flash("Added to watchlist.", "success")
    return redirect(request.referrer or _dashboard_url_for_current_context())


@main_bp.route("/watchlist/remove/<verification_id>", methods=["POST"])
@login_required
def watchlist_remove(verification_id: str):
    verification_id = verification_id.upper()
    watchlist_path = Path(current_app.config["WATCHLIST_CSV"])
    rows = _read_watchlist(watchlist_path)
    filtered = [
        row
        for row in rows
        if not (row["user_id"] == session["user_id"] and row["verification_id"].upper() == verification_id)
    ]
    if len(filtered) == len(rows):
        flash("Watchlist record not found.", "error")
    else:
        _write_watchlist(watchlist_path, filtered)
        log_activity(session["user_id"], "watchlist_remove", "success", f"VID={verification_id}")
        flash("Removed from watchlist.", "success")
    return redirect(request.referrer or _dashboard_url_for_current_context())


@main_bp.route("/preferences", methods=["POST"])
@login_required
def update_preferences():
    email_alerts = bool(request.form.get("email_alerts"))
    chatbot_mode = request.form.get("chatbot_mode", "assistive").strip().lower()
    if chatbot_mode not in {"assistive", "strict", "concise"}:
        chatbot_mode = "assistive"
    try:
        digest_hour = int(request.form.get("digest_hour_utc", 9))
    except (TypeError, ValueError):
        digest_hour = 9
    digest_hour = max(0, min(23, digest_hour))
    try:
        risk_notify_min = int(request.form.get("risk_notify_min", 65))
    except (TypeError, ValueError):
        risk_notify_min = 65
    risk_notify_min = max(1, min(99, risk_notify_min))

    _upsert_preferences(
        Path(current_app.config["USER_PREFERENCES_CSV"]),
        {
            "user_id": session["user_id"],
            "email_alerts": "1" if email_alerts else "0",
            "digest_hour_utc": str(digest_hour),
            "risk_notify_min": str(risk_notify_min),
            "chatbot_mode": chatbot_mode,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    log_activity(
        session["user_id"],
        "preferences_update",
        "success",
        f"digest={digest_hour} risk_min={risk_notify_min} chatbot={chatbot_mode}",
    )
    flash("Preferences updated.", "success")
    return redirect(request.referrer or _dashboard_url_for_current_context())


@main_bp.route("/profile")
@login_required
def profile_page():
    mode = request.args.get("mode", "view").strip().lower()
    edit_mode = mode == "edit"
    profile_data = _load_user_profile(session["user_id"])
    account_data = get_user_by_id(session["user_id"]) or {}
    two_factor_feature_enabled = bool(current_app.config.get("ENABLE_2FA", False))
    delegated_scope_set = {
        scope.strip()
        for scope in str(account_data.get("delegated_admin_scopes", "")).split(",")
        if scope.strip()
    }
    return render_template(
        "profile.html",
        profile_data=profile_data,
        edit_mode=edit_mode,
        two_factor_enabled=(
            two_factor_feature_enabled and (account_data.get("two_factor_enabled", "0") == "1")
        ),
        two_factor_feature_enabled=two_factor_feature_enabled,
        email_verified=(account_data.get("email_verified", "0") == "1"),
        delegated_scopes=sorted(delegated_scope_set),
        delegated_until=account_data.get("delegated_admin_until", ""),
        delegated_by=account_data.get("delegated_admin_by", ""),
        delegated_note=account_data.get("delegated_admin_note", ""),
        pending_manual_2fa_reviews=len(
            [
                row
                for row in _two_factor_reviews_for_user(session["user_id"], limit=40)
                if row.get("status") == "open"
            ]
        ),
        recent_manual_2fa_reviews=_two_factor_reviews_for_user(session["user_id"], limit=8),
    )


@main_bp.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    profile = {
        "full_name": sanitize_text(request.form.get("full_name", ""), max_length=120),
        "email_contact": sanitize_text(request.form.get("email_contact", ""), max_length=120),
        "phone": sanitize_text(request.form.get("phone", ""), max_length=40),
        "organization": sanitize_text(request.form.get("organization", ""), max_length=120),
        "designation": sanitize_text(request.form.get("designation", ""), max_length=100),
        "address": sanitize_text(request.form.get("address", ""), max_length=180),
        "gov_id": sanitize_text(request.form.get("gov_id", ""), max_length=80),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_user_profile(session["user_id"], profile)
    log_activity(session["user_id"], "profile_update", "success", "Profile details updated")
    flash("Profile updated and encrypted securely.", "success")
    return_to = request.form.get("return_to", "profile").strip().lower()
    if return_to == "dashboard":
        return redirect(url_for("main.user_dashboard", user_id=session["user_id"]))
    return redirect(url_for("main.profile_page", mode="view"))


@main_bp.route("/2fa/manual-review/request", methods=["POST"])
@login_required
def request_manual_2fa_review():
    if not bool(current_app.config.get("ENABLE_2FA", False)):
        flash("Manual 2FA workflow is disabled.", "error")
        return redirect(url_for("main.profile_page"))

    if session.get("role") == "admin":
        flash("Admin accounts do not need delegated access workflow.", "error")
        return redirect(url_for("main.profile_page"))

    user = get_user_by_id(session["user_id"])
    if not user:
        flash("User session not found.", "error")
        return redirect(url_for("auth.logout"))
    if user.get("email_verified") != "1":
        flash("Email must be verified before requesting delegated access.", "error")
        return redirect(url_for("main.profile_page"))

    two_factor_enabled = user.get("two_factor_enabled") == "1"
    otp_code = "".join(ch for ch in sanitize_text(request.form.get("otp_code", ""), max_length=16) if ch.isdigit())[:6]
    reason = sanitize_text(request.form.get("reason", ""), max_length=200)
    if two_factor_enabled and len(otp_code) != 6:
        flash("Enter a valid 2FA code to submit request.", "error")
        return redirect(url_for("main.profile_page"))
    if not two_factor_enabled and not reason:
        flash("Add a reason for manual review when 2FA is not enabled.", "error")
        return redirect(url_for("main.profile_page"))

    secret = user_2fa_secret(user)
    otp_validated = bool(len(otp_code) == 6 and secret and verify_totp_code(secret, otp_code))

    rows = _read_two_factor_reviews(Path(current_app.config["TWO_FACTOR_REVIEW_CSV"]))
    if any(row["user_id"] == session["user_id"] and row["status"] == "open" for row in rows):
        flash("An open manual 2FA review request already exists.", "error")
        return redirect(url_for("main.profile_page"))

    request_id = generate_verification_id()
    row = {
        "request_id": request_id,
        "user_id": session["user_id"],
        "username": session["username"],
        "otp_code": otp_code,
        "otp_validated": "1" if otp_validated else "0",
        "otp_validated_at": datetime.now(timezone.utc).isoformat() if otp_validated else "",
        "force_approved": "0",
        "force_approved_at": "",
        "force_approved_by": "",
        "status": "open",
        "reason": reason or "Manual delegated access request.",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "reviewed_at": "",
        "reviewed_by": "",
        "reviewed_by_username": "",
        "decision_note": "",
    }
    _append_two_factor_review(Path(current_app.config["TWO_FACTOR_REVIEW_CSV"]), row)
    push_alert_to_admins(
        severity="warning",
        category="auth",
        title="Manual 2FA Review Requested",
        message=(
            f"{session['username']} submitted code {otp_code or '-'} (REQ {request_id})"
            f" [auto-validated={ 'yes' if otp_validated else 'no' }]."
        ),
    )
    log_activity(
        session["user_id"],
        "manual_2fa_review_request",
        "success",
        f"REQ={request_id} auto_validated={1 if otp_validated else 0}",
    )
    if otp_validated:
        flash("Manual 2FA review request submitted to admin.", "success")
    elif two_factor_enabled:
        flash(
            "Manual request submitted without auto-validation. Admin can use Force Approve after manual confirmation.",
            "success",
        )
    else:
        flash(
            "Manual request submitted. Since 2FA is not enabled, admin must use Force Approve after manual identity checks.",
            "success",
        )
    return redirect(url_for("main.profile_page"))


@main_bp.route("/compare", methods=["GET", "POST"])
@main_bp.route("/admin/compare", methods=["GET", "POST"])
@admin_or_delegated_required("compare_lab")
def compare_records():
    first_id = ""
    second_id = ""
    if request.method == "POST":
        first_id = request.form.get("first_verification_id", "").strip().upper()
        second_id = request.form.get("second_verification_id", "").strip().upper()
    else:
        first_id = request.args.get("first_verification_id", "").strip().upper()
        second_id = request.args.get("second_verification_id", "").strip().upper()

    all_records = _read_records(Path(current_app.config["RECORDS_CSV"]))
    visible_records = sorted(
        _records_for_session(all_records),
        key=lambda row: row["uploaded_at"],
        reverse=True,
    )
    compare_result = None
    if first_id and second_id:
        compare_result = _compare_record_pair(first_id, second_id, visible_records)
        status = "success" if compare_result and compare_result.get("available") else "failed"
        log_activity(session["user_id"], "record_compare", status, f"{first_id} vs {second_id}")

    return render_template(
        "compare.html",
        records=visible_records[:300],
        compare_result=compare_result,
        first_id=first_id,
        second_id=second_id,
    )


@main_bp.route("/review-request/<verification_id>", methods=["POST"])
@login_required
def create_review_request(verification_id: str):
    verification_id = verification_id.upper()
    record = _record_by_verification_id(verification_id)
    if not record:
        flash("Record not found.", "error")
        return redirect(_dashboard_url_for_current_context())
    if session["role"] != "admin" and record["owner_id"] != session["user_id"]:
        flash("You can only request review for your own records.", "error")
        return redirect(_dashboard_url_for_current_context())
    if record.get("status") != "quarantined":
        flash("Review requests are only allowed for quarantined records.", "error")
        return redirect(url_for("main.record_detail", verification_id=verification_id))

    reason = sanitize_text(request.form.get("reason", ""), max_length=220)
    if not reason:
        reason = "Please review and release this record after manual validation."

    if _has_open_review_request(verification_id, session["user_id"]):
        flash("An open review request already exists for this record.", "error")
        return redirect(url_for("main.record_detail", verification_id=verification_id))

    request_id = generate_verification_id()
    row = {
        "request_id": request_id,
        "verification_id": verification_id,
        "requester_id": session["user_id"],
        "requester_username": session["username"],
        "record_owner_id": record["owner_id"],
        "status": "open",
        "reason": reason,
        "admin_id": "",
        "admin_username": "",
        "admin_note": "",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _append_review_request(Path(current_app.config["REVIEW_REQUESTS_CSV"]), row)
    push_alert_to_admins(
        severity="warning",
        category="review",
        title="Quarantine Review Requested",
        message=f"{session['username']} requested review for VID {verification_id}.",
        verification_id=verification_id,
    )
    log_activity(session["user_id"], "review_request_create", "success", f"{request_id} VID={verification_id}")
    flash(f"Review request submitted: {request_id}", "success")
    return redirect(url_for("main.record_detail", verification_id=verification_id))


@main_bp.route("/admin/review-request/<request_id>/resolve", methods=["POST"])
@role_required("admin")
def resolve_review_request(request_id: str):
    decision = request.form.get("decision", "").strip().lower()
    if decision not in {"approved", "rejected"}:
        flash("Invalid review decision.", "error")
        return redirect(url_for("main.admin_dashboard"))

    admin_note = sanitize_text(request.form.get("admin_note", ""), max_length=220)
    rows = _read_review_requests(Path(current_app.config["REVIEW_REQUESTS_CSV"]))
    target = next((row for row in rows if row["request_id"] == request_id), None)
    if not target:
        flash("Review request not found.", "error")
        return redirect(url_for("main.admin_dashboard"))
    if target["status"] != "open":
        flash("Review request is already resolved.", "error")
        return redirect(url_for("main.admin_dashboard"))

    target["status"] = decision
    target["admin_id"] = session["user_id"]
    target["admin_username"] = session["username"]
    target["admin_note"] = admin_note or ("Approved by admin." if decision == "approved" else "Rejected by admin.")
    target["updated_at"] = datetime.now(timezone.utc).isoformat()
    _write_review_requests(Path(current_app.config["REVIEW_REQUESTS_CSV"]), rows)

    verification_id = target["verification_id"].upper()
    requester_id = target["requester_id"]
    requester_name = target["requester_username"]
    record = _record_by_verification_id(verification_id)

    if decision == "approved":
        if record and record.get("status") == "quarantined":
            all_records = _read_records(Path(current_app.config["RECORDS_CSV"]))
            for row in all_records:
                if row["verification_id"].upper() == verification_id:
                    row["status"] = "active"
                    record = row
                    break
            _write_records(Path(current_app.config["RECORDS_CSV"]), all_records)

            if record:
                create_block(
                    chain_file=Path(current_app.config["BLOCKCHAIN_JSON"]),
                    file_hash=record["file_hash"],
                    owner_id=record["owner_id"],
                    verification_id=verification_id,
                    record_type="quarantine_release",
                )

        push_alert(
            requester_id,
            severity="info",
            category="review",
            title="Review Request Approved",
            message=f"Your request {request_id} for VID {verification_id} was approved.",
            verification_id=verification_id,
        )
    else:
        push_alert(
            requester_id,
            severity="warning",
            category="review",
            title="Review Request Rejected",
            message=f"Your request {request_id} for VID {verification_id} was rejected.",
            verification_id=verification_id,
        )

    log_activity(
        session["user_id"],
        "review_request_resolve",
        "success",
        f"{request_id} {decision} requester={requester_name} VID={verification_id}",
    )
    flash(f"Review request {request_id} marked as {decision}.", "success")
    return redirect(request.referrer or url_for("main.admin_dashboard"))


@main_bp.route("/record/<verification_id>/notes", methods=["POST"])
@login_required
def add_record_note(verification_id: str):
    verification_id = verification_id.upper()
    record = _record_by_verification_id(verification_id)
    if not record:
        flash("Record not found.", "error")
        return redirect(_dashboard_url_for_current_context())
    if session["role"] != "admin" and record["owner_id"] != session["user_id"]:
        flash("Access denied for note creation.", "error")
        return redirect(_dashboard_url_for_current_context())

    note_text = sanitize_text(request.form.get("note_text", ""), max_length=260)
    if not note_text:
        flash("Note cannot be empty.", "error")
        return redirect(url_for("main.record_detail", verification_id=verification_id))

    _append_note(
        Path(current_app.config["RECORD_NOTES_CSV"]),
        {
            "note_id": generate_verification_id(),
            "verification_id": verification_id,
            "author_id": session["user_id"],
            "author_username": session["username"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "note_text": note_text,
        },
    )
    log_activity(session["user_id"], "record_note_add", "success", f"VID={verification_id}")
    flash("Evidence note added.", "success")
    return redirect(url_for("main.record_detail", verification_id=verification_id))


@main_bp.route("/incident/create/<verification_id>", methods=["POST"])
@login_required
def create_incident(verification_id: str):
    verification_id = verification_id.upper()
    record = _record_by_verification_id(verification_id)
    if not record:
        flash("Record not found.", "error")
        return redirect(_dashboard_url_for_current_context())
    if session["role"] != "admin" and record["owner_id"] != session["user_id"]:
        flash("You cannot create incidents for this record.", "error")
        return redirect(_dashboard_url_for_current_context())

    severity = request.form.get("severity", "medium").strip().lower()
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "medium"
    title = sanitize_text(request.form.get("title", "Security Incident"), max_length=90)
    description = sanitize_text(request.form.get("description", ""), max_length=260)
    assignee = sanitize_text(request.form.get("assignee", "admin"), max_length=40)

    incident = {
        "incident_id": generate_verification_id(),
        "verification_id": verification_id,
        "created_by": session["user_id"],
        "created_by_username": session["username"],
        "assignee": assignee or "admin",
        "severity": severity,
        "status": "open",
        "title": title or "Security Incident",
        "description": description or "Incident created for manual investigation.",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "resolution_note": "",
    }
    _append_incident(Path(current_app.config["INCIDENTS_CSV"]), incident)

    push_alert_to_admins(
        severity="critical" if severity in {"high", "critical"} else "warning",
        category="incident",
        title=f"Incident {incident['incident_id']} Created",
        message=f"{title} for VID {verification_id}.",
        verification_id=verification_id,
    )
    log_activity(session["user_id"], "incident_create", "success", f"{incident['incident_id']} {verification_id}")
    flash(f"Incident created: {incident['incident_id']}", "success")
    return redirect(url_for("main.record_detail", verification_id=verification_id))


@main_bp.route("/incident/<incident_id>/status", methods=["POST"])
@role_required("admin")
def update_incident_status(incident_id: str):
    new_status = request.form.get("status", "open").strip().lower()
    if new_status not in {"open", "in_review", "resolved", "closed"}:
        flash("Invalid incident status.", "error")
        return redirect(url_for("main.admin_panel"))

    resolution_note = sanitize_text(request.form.get("resolution_note", ""), max_length=240)
    incidents = _read_incidents(Path(current_app.config["INCIDENTS_CSV"]))
    updated = False
    target_verification_id = ""
    for item in incidents:
        if item["incident_id"] == incident_id:
            item["status"] = new_status
            item["updated_at"] = datetime.now(timezone.utc).isoformat()
            if resolution_note:
                item["resolution_note"] = resolution_note
            target_verification_id = item["verification_id"]
            updated = True
            break
    if not updated:
        flash("Incident not found.", "error")
        return redirect(url_for("main.admin_panel"))

    _write_incidents(Path(current_app.config["INCIDENTS_CSV"]), incidents)
    log_activity(session["user_id"], "incident_status_update", "success", f"{incident_id} -> {new_status}")
    push_alert_to_admins(
        severity="info",
        category="incident",
        title=f"Incident {incident_id} Updated",
        message=f"Status changed to {new_status}.",
        verification_id=target_verification_id,
    )
    flash("Incident status updated.", "success")
    return redirect(url_for("main.admin_panel"))


@main_bp.route("/admin/integrity-center")
@role_required("admin")
def integrity_center():
    scans = _read_integrity_scans(Path(current_app.config["INTEGRITY_SCANS_CSV"]))
    scans = sorted(scans, key=lambda row: row["run_at"], reverse=True)
    incidents = _read_incidents(Path(current_app.config["INCIDENTS_CSV"]))
    incidents = sorted(incidents, key=lambda row: row["updated_at"], reverse=True)
    return render_template(
        "integrity_center.html",
        scans=scans[:80],
        incidents=incidents[:120],
    )


@main_bp.route("/admin/integrity-scan/run", methods=["POST"])
@role_required("admin")
def run_integrity_scan():
    job_id = enqueue_job(
        "integrity_scan",
        {
            "run_by": session["user_id"],
            "run_by_username": session["username"],
        },
        requested_by=session["user_id"],
    )
    if job_id:
        flash(f"Integrity scan queued ({job_id}). Check Background Job Queue for progress.", "success")
    else:
        flash("Job queue unavailable. Integrity scan could not be started.", "error")
    return redirect(url_for("main.integrity_center"))


@main_bp.route("/admin")
@role_required("admin")
def admin_panel():
    users = get_all_users()
    active_admin_count = len([u for u in users if u["role"] == "admin" and u["account_status"] == "active"])
    two_factor_queue = (
        _open_two_factor_reviews(limit=120) if bool(current_app.config.get("ENABLE_2FA", False)) else []
    )
    delegated_users = [
        user
        for user in users
        if user.get("role") != "admin"
        and user.get("delegated_admin_until")
        and (has_delegated_scope(user, "verify_batch") or has_delegated_scope(user, "compare_lab"))
    ]
    activities = _visible_activity_for_session(limit=200)
    transfers = sorted(
        _read_transfers(Path(current_app.config["TRANSFERS_CSV"])),
        key=lambda t: t["timestamp"],
        reverse=True,
    )
    incidents = sorted(
        _read_incidents(Path(current_app.config["INCIDENTS_CSV"])),
        key=lambda t: t["updated_at"],
        reverse=True,
    )
    return render_template(
        "admin.html",
        users=users,
        activities=activities,
        transfers=transfers[:80],
        policy=_policy(),
        api_keys=list_api_keys(limit=50),
        new_api_key_token=session.pop("new_api_key_token", None),
        incidents=incidents[:80],
        open_incidents=len([i for i in incidents if i["status"] not in {"resolved", "closed"}]),
        latest_scan=_latest_integrity_scan(),
        active_admin_count=active_admin_count,
        two_factor_queue=two_factor_queue[:50],
        open_two_factor_requests=len(two_factor_queue),
        delegated_users=delegated_users,
        unverified_users=len([u for u in users if u.get("email_verified") != "1"]),
    )


@main_bp.route("/admin/monitoring")
@role_required("admin")
def admin_monitoring():
    metrics = monitoring_metrics(window_hours=24)
    queue_obj = get_job_queue()
    queue_stats = queue_obj.stats() if queue_obj else {"queued": 0, "running": 0, "completed": 0, "failed": 0, "total": 0}
    recent_errors = [
        row
        for row in read_events(limit=120, since_hours=24)
        if row.get("severity") in {"error", "critical"}
    ][:60]
    recent_requests = read_events(limit=80, event_type="http_request", since_hours=6)
    return render_template(
        "monitoring.html",
        metrics=metrics,
        queue_stats=queue_stats,
        recent_errors=recent_errors,
        recent_requests=recent_requests,
    )


@main_bp.route("/admin/jobs")
@role_required("admin")
def admin_jobs():
    queue_obj = get_job_queue()
    if not queue_obj:
        return render_template("error.html", title="Unavailable", message="Job queue unavailable.", code=503), 503
    jobs = queue_obj.list(limit=240)
    return render_template("jobs.html", jobs=jobs, queue_stats=queue_obj.stats())


@main_bp.route("/admin/user/<user_id>/status", methods=["POST"])
@role_required("admin")
def admin_user_status(user_id: str):
    new_status = request.form.get("account_status", "").strip().lower()
    if new_status not in {"active", "locked"}:
        flash("Invalid status value.", "error")
        return redirect(url_for("main.admin_panel"))
    if set_user_status(user_id, new_status):
        push_alert(user_id, "warning" if new_status == "locked" else "info", "account", "Account Status Changed", f"Status changed to {new_status}.")
        flash("Account status updated.", "success")
    else:
        flash("User not found.", "error")
    return redirect(url_for("main.admin_panel"))


@main_bp.route("/admin/user/<user_id>/email-verify", methods=["POST"])
@role_required("admin")
def admin_user_email_verify(user_id: str):
    verified = request.form.get("email_verified", "1").strip() == "1"
    if set_user_email_verified(user_id, verified=verified):
        state = "verified" if verified else "unverified"
        push_alert(
            user_id,
            "info",
            "account",
            "Email Verification Status Updated",
            f"Admin updated your email state to {state}.",
        )
        log_activity(session["user_id"], "admin_email_verify_update", "success", f"{user_id} -> {state}")
        flash("Email verification status updated.", "success")
    else:
        flash("User not found.", "error")
    return redirect(url_for("main.admin_panel"))


@main_bp.route("/admin/user/<user_id>/delegate/revoke", methods=["POST"])
@role_required("admin")
def admin_revoke_delegation(user_id: str):
    if revoke_delegated_admin(user_id):
        push_alert(
            user_id,
            "warning",
            "account",
            "Delegated Admin Access Revoked",
            "Your temporary delegated admin scopes were revoked by admin.",
        )
        log_activity(session["user_id"], "admin_delegate_revoke", "success", f"user={user_id}")
        flash("Delegated admin access revoked.", "success")
    else:
        flash("Unable to revoke delegated access.", "error")
    return redirect(url_for("main.admin_dashboard"))


@main_bp.route("/admin/2fa-review/<request_id>/decision", methods=["POST"])
@role_required("admin")
def admin_two_factor_review_decision(request_id: str):
    if not bool(current_app.config.get("ENABLE_2FA", False)):
        flash("Manual 2FA workflow is disabled.", "error")
        return redirect(url_for("main.admin_dashboard"))

    decision = request.form.get("decision", "").strip().lower()
    if decision not in {"approved", "rejected", "force_approved"}:
        flash("Invalid review decision.", "error")
        return redirect(url_for("main.admin_dashboard"))
    force_approve = decision == "force_approved"
    if force_approve and not bool(current_app.config.get("ALLOW_FORCE_2FA_APPROVAL", True)):
        flash("Force approve is disabled by policy.", "error")
        return redirect(url_for("main.admin_dashboard"))

    rows = _read_two_factor_reviews(Path(current_app.config["TWO_FACTOR_REVIEW_CSV"]))
    target = next((row for row in rows if row["request_id"] == request_id), None)
    if not target:
        flash("Manual 2FA review request not found.", "error")
        return redirect(url_for("main.admin_dashboard"))
    if target["status"] != "open":
        flash("Review request is already processed.", "error")
        return redirect(url_for("main.admin_dashboard"))

    admin_note = sanitize_text(request.form.get("admin_note", ""), max_length=200)
    now_iso = datetime.now(timezone.utc).isoformat()
    if force_approve:
        force_ack = request.form.get("force_ack", "0").strip() == "1"
        if not force_ack:
            flash("Force approve requires explicit confirmation.", "error")
            return redirect(url_for("main.admin_dashboard"))
        if len(admin_note) < 12:
            flash("Force approve requires a detailed admin note (minimum 12 characters).", "error")
            return redirect(url_for("main.admin_dashboard"))

    target["status"] = "approved" if decision in {"approved", "force_approved"} else "rejected"
    target["reviewed_at"] = now_iso
    target["reviewed_by"] = session["user_id"]
    target["reviewed_by_username"] = session["username"]
    if force_approve:
        target["force_approved"] = "1"
        target["force_approved_at"] = now_iso
        target["force_approved_by"] = session["user_id"]
        target["decision_note"] = f"[FORCE APPROVED] {admin_note}"
    else:
        target["force_approved"] = "0"
        target["force_approved_at"] = ""
        target["force_approved_by"] = ""
        target["decision_note"] = admin_note

    if target["status"] == "approved":
        request_user = get_user_by_id(target.get("user_id", ""))
        if not request_user:
            target["status"] = "rejected"
            target["decision_note"] = "Auto-rejected: request user not found."
            flash("User for this request no longer exists.", "error")
            log_activity(
                session["user_id"],
                "admin_manual_2fa_review",
                "failed",
                f"{request_id} reject_reason=user_not_found",
            )
            _write_two_factor_reviews(Path(current_app.config["TWO_FACTOR_REVIEW_CSV"]), rows)
            return redirect(url_for("main.admin_dashboard"))
        if request_user.get("two_factor_enabled") != "1" and not force_approve:
            target["status"] = "rejected"
            target["decision_note"] = "Auto-rejected: user does not have 2FA enabled (use Force Approve if policy allows)."
            flash("User does not have 2FA enabled. Use Force Approve for manual exception handling.", "error")
            log_activity(
                session["user_id"],
                "admin_manual_2fa_review",
                "failed",
                f"{request_id} reject_reason=2fa_disabled",
            )
            _write_two_factor_reviews(Path(current_app.config["TWO_FACTOR_REVIEW_CSV"]), rows)
            return redirect(url_for("main.admin_dashboard"))

        if not force_approve and target.get("otp_validated") != "1":
            secret = user_2fa_secret(request_user)
            otp_code = "".join(ch for ch in str(target.get("otp_code", "")) if ch.isdigit())[:6]
            if secret and verify_totp_code(secret, otp_code):
                target["otp_validated"] = "1"
                target["otp_validated_at"] = datetime.now(timezone.utc).isoformat()
            else:
                target["status"] = "rejected"
                target["decision_note"] = "Auto-rejected: 2FA code not validated."
                push_alert(
                    target["user_id"],
                    "warning",
                    "auth",
                    "Manual 2FA Review Rejected",
                    "2FA code was not validated. Submit a fresh code and request again.",
                )
                flash("2FA code validation failed. Ask user to submit a fresh request.", "error")
                log_activity(
                    session["user_id"],
                    "admin_manual_2fa_review",
                    "failed",
                    f"{request_id} reject_reason=otp_not_validated",
                )
                _write_two_factor_reviews(Path(current_app.config["TWO_FACTOR_REVIEW_CSV"]), rows)
                return redirect(url_for("main.admin_dashboard"))

        raw_scopes = sanitize_text(request.form.get("delegated_scopes", "verify_batch,compare_lab"), max_length=120)
        scopes = [item.strip().lower() for item in raw_scopes.replace(";", ",").split(",") if item.strip()]
        try:
            hours = int(request.form.get("delegated_hours", "8"))
        except ValueError:
            hours = 8
        ok, message = grant_delegated_admin(
            target["user_id"],
            scopes=scopes,
            hours=hours,
            approved_by=session["username"],
            note=admin_note or "Manual 2FA review approved by admin.",
        )
        if ok:
            set_user_email_verified(target["user_id"], verified=True)
            if force_approve:
                push_alert_to_admins(
                    severity="critical",
                    category="auth",
                    title="Manual 2FA Force Approval",
                    message=f"{session['username']} force-approved request {request_id} for user {target['username']}.",
                )
            push_alert(
                target["user_id"],
                "info",
                "auth",
                "Manual 2FA Review Approved",
                f"Delegated scopes granted for {hours}h. Scopes: {', '.join(scopes) if scopes else 'verify_batch'}.",
            )
            if force_approve:
                flash(f"Force approval applied. {message}", "success")
            else:
                flash(f"Request approved. {message}", "success")
            log_activity(
                session["user_id"],
                "admin_manual_2fa_force_approve" if force_approve else "admin_manual_2fa_review",
                "success",
                f"{request_id} approved user={target['user_id']} scopes={','.join(scopes)} hours={hours}"
                f"{' force=1' if force_approve else ''}",
            )
        else:
            target["status"] = "rejected"
            target["decision_note"] = f"Auto-rejected: {message}"
            push_alert(
                target["user_id"],
                "warning",
                "auth",
                "Manual 2FA Review Rejected",
                message,
            )
            flash(message, "error")
            log_activity(
                session["user_id"],
                "admin_manual_2fa_force_approve" if force_approve else "admin_manual_2fa_review",
                "failed",
                f"{request_id} reject_reason={message}",
            )
    else:
        push_alert(
            target["user_id"],
            "warning",
            "auth",
            "Manual 2FA Review Rejected",
            admin_note or "Admin rejected this manual 2FA review request.",
        )
        log_activity(
            session["user_id"],
            "admin_manual_2fa_review",
            "success",
            f"{request_id} rejected",
        )
        flash("Request rejected.", "success")

    _write_two_factor_reviews(Path(current_app.config["TWO_FACTOR_REVIEW_CSV"]), rows)
    return redirect(url_for("main.admin_dashboard"))


@main_bp.route("/admin/user/<user_id>/role", methods=["POST"])
@role_required("admin")
def admin_user_role(user_id: str):
    role = request.form.get("role", "user").strip().lower()
    ok, message = set_user_role(user_id, role)
    if ok:
        push_alert(
            user_id,
            "info",
            "account",
            "Account Role Updated",
            f"Your platform role is now '{'admin' if role == 'admin' else 'user'}'.",
        )
        flash(message, "success")
        log_activity(session["user_id"], "admin_role_update", "success", f"{user_id} -> {role}")
    else:
        flash(message, "error")
        log_activity(session["user_id"], "admin_role_update", "failed", f"{user_id} -> {role}")
    return redirect(url_for("main.admin_panel"))


@main_bp.route("/admin/backup/export", methods=["POST"])
@role_required("admin")
def admin_export_backup():
    files = [
        current_app.config["USERS_CSV"],
        current_app.config["RECORDS_CSV"],
        current_app.config["TRANSFERS_CSV"],
        current_app.config["INCIDENTS_CSV"],
        current_app.config["RECORD_NOTES_CSV"],
        current_app.config["WATCHLIST_CSV"],
        current_app.config["USER_PREFERENCES_CSV"],
        current_app.config["REVIEW_REQUESTS_CSV"],
        current_app.config["TWO_FACTOR_REVIEW_CSV"],
        current_app.config["USER_DRIVE_CSV"],
        current_app.config["USER_PROFILES_JSON"],
        current_app.config["ACTIVITY_CSV"],
        current_app.config["NOTIFICATIONS_CSV"],
        current_app.config["INTEGRITY_SCANS_CSV"],
        current_app.config["API_KEYS_CSV"],
        current_app.config["POLICY_JSON"],
        current_app.config["BLOCKCHAIN_JSON"],
        current_app.config["ANALYSIS_JSON"],
        current_app.config["MAILBOX_LOG"],
        current_app.config["JOBS_JSON"],
        current_app.config["SIEM_LOG"],
        current_app.config["ERROR_LOG"],
    ]

    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        metadata = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "exported_by": session["user_id"],
            "username": session["username"],
            "file_count": len(files),
        }
        zf.writestr("metadata.json", json.dumps(metadata, indent=2))
        for file_path in files:
            path = Path(file_path)
            if not path.exists():
                continue
            archive_name = f"securechain_data/{path.name}"
            zf.write(path, arcname=archive_name)
        artifact_dir = Path(current_app.config["JOB_ARTIFACT_DIR"])
        if artifact_dir.exists():
            for artifact in artifact_dir.glob("*"):
                if artifact.is_file():
                    zf.write(artifact, arcname=f"securechain_data/job_artifacts/{artifact.name}")

    buffer.seek(0)
    log_activity(session["user_id"], "admin_backup_export", "success", "System backup ZIP downloaded")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return send_file(
        buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"securechain_backup_{timestamp}.zip",
    )


@main_bp.route("/admin/audit/export.ndjson")
@role_required("admin")
def admin_export_audit_ndjson():
    try:
        hours = int(request.args.get("hours", "168"))
    except ValueError:
        hours = 168
    hours = max(1, min(24 * 90, hours))
    payload = export_events_ndjson(since_hours=hours)
    log_activity(session["user_id"], "admin_audit_export", "success", f"hours={hours} bytes={len(payload)}")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return send_file(
        BytesIO(payload),
        mimetype="application/x-ndjson",
        as_attachment=True,
        download_name=f"securechain_audit_{timestamp}.ndjson",
    )


@main_bp.route("/admin/risk-board/export.csv")
@role_required("admin")
def export_admin_risk_board_csv():
    users = get_all_users()
    records = _read_records(Path(current_app.config["RECORDS_CSV"]))
    activities = _visible_activity_for_session(limit=5000)
    risk_rows = _build_user_risk_board(
        users=users,
        records=records,
        activities=activities,
        risk_alert_threshold=int(_policy()["risk_alert_threshold"]),
    )
    buffer_text = StringIO()
    writer = csv.DictWriter(
        buffer_text,
        fieldnames=[
            "username",
            "user_id",
            "role",
            "account_status",
            "record_count",
            "high_risk_count",
            "quarantined_count",
            "open_incidents",
            "failed_logins",
            "risk_score",
            "risk_level",
        ],
    )
    writer.writeheader()
    writer.writerows(risk_rows)
    payload = buffer_text.getvalue().encode("utf-8")
    log_activity(session["user_id"], "admin_risk_board_export", "success", f"rows={len(risk_rows)}")
    return send_file(
        BytesIO(payload),
        mimetype="text/csv",
        as_attachment=True,
        download_name="securechain_admin_risk_board.csv",
    )


@main_bp.route("/admin/policy", methods=["POST"])
@role_required("admin")
def admin_update_policy():
    updates = {
        "risk_alert_threshold": request.form.get("risk_alert_threshold", 55),
        "quarantine_threshold": request.form.get("quarantine_threshold", 78),
        "anomaly_alert_threshold": request.form.get("anomaly_alert_threshold", 70),
        "max_daily_uploads_per_user": request.form.get("max_daily_uploads_per_user", 120),
        "login_max_attempts": request.form.get("login_max_attempts", 5),
        "login_window_seconds": request.form.get("login_window_seconds", 600),
        "login_lock_seconds": request.form.get("login_lock_seconds", 900),
        "public_certificate_enabled": bool(request.form.get("public_certificate_enabled")),
    }
    policy = update_policy(Path(current_app.config["POLICY_JSON"]), updates)
    current_app.config["SECURITY_POLICY"] = policy
    current_app.config["LOGIN_LIMITER"] = LoginAttemptLimiter(
        max_attempts=int(policy["login_max_attempts"]),
        window_seconds=int(policy["login_window_seconds"]),
        lock_seconds=int(policy["login_lock_seconds"]),
    )
    flash("Security policy updated successfully.", "success")
    return redirect(url_for("main.admin_panel"))


@main_bp.route("/admin/api-keys/create", methods=["POST"])
@role_required("admin")
def admin_create_api_key():
    label = sanitize_text(request.form.get("label", "Integration Key"), max_length=60)
    scopes = sanitize_text(request.form.get("scopes", "verify:read"), max_length=120)
    token, _meta = create_api_key(label=label, created_by=session["user_id"], scopes=scopes)
    session["new_api_key_token"] = token
    flash("API key generated. Copy it now.", "success")
    return redirect(url_for("main.admin_panel"))


@main_bp.route("/admin/api-keys/<key_id>/revoke", methods=["POST"])
@role_required("admin")
def admin_revoke_api_key(key_id: str):
    if revoke_api_key(key_id):
        flash("API key revoked.", "success")
    else:
        flash("API key not found.", "error")
    return redirect(url_for("main.admin_panel"))


@main_bp.route("/api/stats")
@login_required
def api_stats():
    scoped_user_id = _scoped_user_id_from_request()
    if scoped_user_id:
        records = [
            row
            for row in _read_records(Path(current_app.config["RECORDS_CSV"]))
            if row["owner_id"] == scoped_user_id
        ]
        activities = _activities_for_user(scoped_user_id, limit=120)
        incidents = _incidents_for_user(scoped_user_id, limit=300)
    else:
        records = _records_for_session(_read_records(Path(current_app.config["RECORDS_CSV"])))
        activities = _visible_activity_for_session(limit=120)
        incidents = _visible_incidents_for_session(limit=300)
    analyses = {
        row["verification_id"]: get_analysis(Path(current_app.config["ANALYSIS_JSON"]), row["verification_id"])
        for row in records
    }
    snapshot = build_security_snapshot(records, analyses, activities, anomaly_alert_threshold=int(_policy()["anomaly_alert_threshold"]))
    return jsonify(
        {
            "analytics": _build_dashboard_analytics(records, activities, snapshot, incidents=incidents),
            "health": blockchain_health(Path(current_app.config["BLOCKCHAIN_JSON"])),
            "snapshot": snapshot,
        }
    )


@main_bp.route("/api/monitoring")
@role_required("admin")
def api_monitoring():
    queue_obj = get_job_queue()
    return jsonify(
        {
            "metrics": monitoring_metrics(window_hours=24),
            "queue": queue_obj.stats() if queue_obj else {"queued": 0, "running": 0, "completed": 0, "failed": 0, "total": 0},
            "recent_errors": [row for row in read_events(limit=30, since_hours=24) if row.get("severity") in {"error", "critical"}],
        }
    )


@main_bp.route("/api/activities")
@login_required
def api_activities():
    scoped_user_id = _scoped_user_id_from_request()
    if scoped_user_id:
        return jsonify({"activities": _activities_for_user(scoped_user_id, limit=20)})
    return jsonify({"activities": _visible_activity_for_session(limit=20)})


@main_bp.route("/api/notifications")
@login_required
def api_notifications():
    scoped_user_id = _scoped_user_id_from_request()
    user_id = scoped_user_id or session["user_id"]
    include_global = session.get("role") == "admin" and not scoped_user_id
    alerts = list_alerts(user_id=user_id, limit=20, include_global=include_global)
    return jsonify({"alerts": alerts, "unread_count": len([a for a in alerts if a["is_read"] == "0"])})


@main_bp.route("/api/incidents")
@login_required
def api_incidents():
    incidents = _visible_incidents_for_session(limit=30)
    return jsonify(
        {
            "incidents": incidents,
            "open_count": len([item for item in incidents if item["status"] not in {"resolved", "closed"}]),
        }
    )


@main_bp.route("/notifications/mark-read", methods=["POST"])
@login_required
def mark_notifications_read():
    payload = request.get_json(silent=True) or {}
    alert_ids = payload.get("alert_ids", [])
    if alert_ids and not isinstance(alert_ids, list):
        return jsonify({"status": "error", "message": "alert_ids must be a list"}), 400
    include_global = session.get("role") == "admin"
    changed = mark_alerts_read(
        session["user_id"],
        [str(a) for a in alert_ids] if alert_ids else None,
        include_global=include_global,
    )
    return jsonify({"status": "ok", "updated": changed})


@main_bp.route("/health")
def health() -> Response:
    queue_obj = get_job_queue()
    queue_stats = queue_obj.stats() if queue_obj else {"queued": 0, "running": 0, "completed": 0, "failed": 0, "total": 0}
    return jsonify(
        {
            "status": "ok",
            "time": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": uptime_seconds(),
            "blockchain": blockchain_health(Path(current_app.config["BLOCKCHAIN_JSON"])),
            "jobs": queue_stats,
        }
    )


def _render_user_dashboard(target_user: Dict[str, str] | None = None, admin_view: bool = False):
    if target_user is None:
        target_user = get_user_by_id(session["user_id"]) or {
            "user_id": session["user_id"],
            "username": session["username"],
            "role": session.get("role", "user"),
        }

    target_user_id = target_user["user_id"]
    target_username = target_user.get("username", target_user_id)

    all_records = _read_records(Path(current_app.config["RECORDS_CSV"]))
    records = [row for row in all_records if row["owner_id"] == target_user_id]
    records = sorted(records, key=lambda r: r["uploaded_at"], reverse=True)
    activities = _activities_for_user(target_user_id, limit=160)
    alerts = list_alerts(user_id=target_user_id, limit=20, include_global=False)
    incidents = _incidents_for_user(target_user_id, limit=25)
    health = blockchain_health(Path(current_app.config["BLOCKCHAIN_JSON"]))
    policy = _policy()

    analyses: Dict[str, Dict[str, str]] = {}
    for record in records:
        analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), record["verification_id"])
        analyses[record["verification_id"]] = analysis
        record["analysis"] = analysis

    snapshot = build_security_snapshot(
        records=records,
        analyses=analyses,
        activities=activities,
        anomaly_alert_threshold=int(policy["anomaly_alert_threshold"]),
    )
    analytics = _build_dashboard_analytics(records, activities, snapshot, incidents=incidents)
    watchlist = _user_watchlist_records(all_records, analyses, user_id=target_user_id)
    watchlist_ids = {item["verification_id"] for item in watchlist}
    user_preferences = _user_preferences(target_user_id)
    review_requests = _review_requests_for_user(target_user_id, limit=24)
    drive_items = _drive_items_for_user(target_user_id, limit=160)
    pending_drive_count = len([row for row in drive_items if row["status"] == "pending"])
    approved_drive_count = len([row for row in drive_items if row["status"] == "approved"])
    rejected_drive_count = len([row for row in drive_items if row["status"] == "rejected"])
    profile_data = _load_user_profile(target_user_id)
    if admin_view:
        profile_data = _masked_profile_for_admin(profile_data)
    delegated_scopes = [
        item.strip()
        for item in str(target_user.get("delegated_admin_scopes", "")).split(",")
        if item.strip()
    ]
    delegated_access_active = (
        has_delegated_scope(target_user, "verify_batch") or has_delegated_scope(target_user, "compare_lab")
    )

    return render_template(
        "user_dashboard.html",
        records=records,
        analytics=analytics,
        activities=activities[:15],
        alerts=alerts[:12],
        unread_alerts=len([a for a in alerts if a["is_read"] == "0"]),
        snapshot=snapshot,
        health=health,
        policy=policy,
        incidents=incidents[:10],
        open_incidents=len([item for item in incidents if item["status"] not in {"resolved", "closed"}]),
        latest_scan=_latest_integrity_scan(),
        watchlist=watchlist[:12],
        watchlist_ids=watchlist_ids,
        user_preferences=user_preferences,
        review_requests=review_requests,
        open_review_requests=len([item for item in review_requests if item["status"] == "open"]),
        dashboard_owner=target_user,
        is_self_dashboard=(target_user_id == session["user_id"]),
        admin_view=admin_view,
        dashboard_route=url_for("main.user_dashboard", user_id=target_user_id),
        dashboard_display_name=target_username,
        drive_items=drive_items[:80],
        pending_drive_count=pending_drive_count,
        approved_drive_count=approved_drive_count,
        rejected_drive_count=rejected_drive_count,
        profile_data=profile_data,
        delegated_access_active=delegated_access_active,
        delegated_scopes=delegated_scopes,
        delegated_until=target_user.get("delegated_admin_until", ""),
        delegated_by=target_user.get("delegated_admin_by", ""),
    )


def _render_admin_dashboard():
    records = sorted(
        _read_records(Path(current_app.config["RECORDS_CSV"])),
        key=lambda r: r["uploaded_at"],
        reverse=True,
    )
    activities = _visible_activity_for_session(limit=280)
    alerts = list_alerts(user_id=session["user_id"], limit=40, include_global=True)
    incidents = _visible_incidents_for_session(limit=120)
    users = get_all_users()
    health = blockchain_health(Path(current_app.config["BLOCKCHAIN_JSON"]))
    policy = _policy()
    monitor_stats = monitoring_metrics(window_hours=24)
    queue_obj = get_job_queue()
    queue_stats = queue_obj.stats() if queue_obj else {"queued": 0, "running": 0, "completed": 0, "failed": 0, "total": 0}

    analyses: Dict[str, Dict[str, str]] = {}
    high_risk_records: List[Dict[str, str]] = []
    quarantined_records: List[Dict[str, str]] = []
    pending_analyses = 0
    risk_alert_threshold = int(policy["risk_alert_threshold"])

    for record in records:
        analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), record["verification_id"])
        analyses[record["verification_id"]] = analysis
        record["analysis"] = analysis

        risk_value = int(record.get("quick_risk", "0") or 0)
        if analysis.get("status") == "complete":
            try:
                risk_value = int(analysis.get("risk_percentage", str(risk_value)))
            except (TypeError, ValueError):
                pass
        else:
            pending_analyses += 1

        record["effective_risk"] = str(risk_value)
        if risk_value >= risk_alert_threshold:
            high_risk_records.append(record)
        if record.get("status") == "quarantined":
            quarantined_records.append(record)

    snapshot = build_security_snapshot(
        records=records,
        analyses=analyses,
        activities=activities,
        anomaly_alert_threshold=int(policy["anomaly_alert_threshold"]),
    )
    analytics = _build_dashboard_analytics(records, activities, snapshot)

    owner_counts: Dict[str, int] = {}
    for row in records:
        owner = row.get("owner_username", "unknown")
        owner_counts[owner] = owner_counts.get(owner, 0) + 1
    top_owners = sorted(owner_counts.items(), key=lambda item: item[1], reverse=True)[:7]

    active_users = len([u for u in users if u["account_status"] == "active"])
    locked_users = len([u for u in users if u["account_status"] == "locked"])
    unverified_users = len([u for u in users if u.get("email_verified") != "1"])
    active_admins = len([u for u in users if u["role"] == "admin" and u["account_status"] == "active"])
    failed_logins_24h = len(
        [
            row
            for row in activities
            if row.get("action") == "login"
            and row.get("status") in {"failed", "blocked"}
            and _within_last_24h(row.get("timestamp", ""))
        ]
    )
    uploads_24h = len(
        [
            row
            for row in activities
            if row.get("action") == "upload"
            and row.get("status") == "success"
            and _within_last_24h(row.get("timestamp", ""))
        ]
    )
    critical_unread_alerts = len([a for a in alerts if a["severity"] == "critical" and a["is_read"] == "0"])
    review_queue = _open_review_requests(limit=120)
    two_factor_queue = (
        _open_two_factor_reviews(limit=120) if bool(current_app.config.get("ENABLE_2FA", False)) else []
    )
    drive_pending_queue = _pending_drive_items(limit=160)
    drive_recent_decisions = _recent_drive_decisions(limit=80)
    known_user_ids = {row["user_id"] for row in users}
    risk_board = _build_user_risk_board(
        users=users,
        records=records,
        activities=activities,
        risk_alert_threshold=risk_alert_threshold,
    )

    return render_template(
        "admin_dashboard.html",
        records=records[:30],
        total_records_count=len(records),
        activities=activities[:30],
        alerts=alerts[:20],
        incidents=incidents[:20],
        health=health,
        policy=policy,
        snapshot=snapshot,
        analytics=analytics,
        users=users,
        active_users=active_users,
        locked_users=locked_users,
        unverified_users=unverified_users,
        active_admins=active_admins,
        uploads_24h=uploads_24h,
        failed_logins_24h=failed_logins_24h,
        pending_analyses=pending_analyses,
        critical_unread_alerts=critical_unread_alerts,
        open_incidents=len([item for item in incidents if item["status"] not in {"resolved", "closed"}]),
        high_risk_records=sorted(high_risk_records, key=lambda r: int(r.get("effective_risk", "0")), reverse=True)[:15],
        quarantined_records=quarantined_records[:15],
        top_owners=top_owners,
        latest_scan=_latest_integrity_scan(),
        review_queue=review_queue[:30],
        open_review_requests=len(review_queue),
        risk_board=risk_board[:18],
        drive_pending_queue=drive_pending_queue[:30],
        drive_pending_count=len(drive_pending_queue),
        drive_recent_decisions=drive_recent_decisions[:20],
        known_user_ids=known_user_ids,
        monitor_stats=monitor_stats,
        queue_stats=queue_stats,
        two_factor_queue=two_factor_queue[:30],
        open_two_factor_requests=len(two_factor_queue),
        delegated_users=[
            user
            for user in users
            if user.get("role") != "admin"
            and user.get("delegated_admin_until")
            and (has_delegated_scope(user, "verify_batch") or has_delegated_scope(user, "compare_lab"))
        ][:30],
    )


def _ensure_json_storage(path: Path, default_obj: Dict[str, object]) -> None:
    if path.exists():
        return
    path.write_text(json.dumps(default_obj, indent=2), encoding="utf-8")


def _read_drive_items(path: Path) -> List[Dict[str, str]]:
    with _drive_lock:
        if not path.exists():
            return []
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            return list(csv.DictReader(csvfile))


def _write_drive_items(path: Path, rows: List[Dict[str, str]]) -> None:
    with _drive_lock:
        with path.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=DRIVE_FIELDS)
            writer.writeheader()
            writer.writerows(rows)


def _append_drive_item(path: Path, row: Dict[str, str]) -> None:
    with _drive_lock:
        with path.open("a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=DRIVE_FIELDS)
            writer.writerow(row)


def _drive_items_for_user(user_id: str, limit: int = 120) -> List[Dict[str, str]]:
    rows = _read_drive_items(Path(current_app.config["USER_DRIVE_CSV"]))
    rows = [row for row in rows if row["user_id"] == user_id]
    rows = sorted(rows, key=lambda row: row["uploaded_at"], reverse=True)
    return rows[:limit]


def _pending_drive_items(limit: int = 120) -> List[Dict[str, str]]:
    rows = _read_drive_items(Path(current_app.config["USER_DRIVE_CSV"]))
    rows = [row for row in rows if row["status"] == "pending"]
    rows = sorted(rows, key=lambda row: row["uploaded_at"], reverse=True)
    return rows[:limit]


def _recent_drive_decisions(limit: int = 80) -> List[Dict[str, str]]:
    rows = _read_drive_items(Path(current_app.config["USER_DRIVE_CSV"]))
    rows = [row for row in rows if row["status"] in {"approved", "rejected"}]
    rows = sorted(rows, key=lambda row: row["verified_at"], reverse=True)
    return rows[:limit]


def _normalize_drive_folder(folder: str) -> str:
    cleaned = sanitize_text(folder or "root", max_length=80).replace("\\", "/")
    chunks = []
    for part in cleaned.split("/"):
        safe = secure_filename(part.strip())
        if safe:
            chunks.append(safe)
        if len(chunks) >= 4:
            break
    return "/".join(chunks) if chunks else "root"


def _save_drive_encrypted_file(
    user_id: str,
    folder: str,
    original_filename: str,
    drive_id: str,
    content: bytes,
) -> str:
    safe_name = secure_filename(original_filename) or "document.bin"
    folder_path = Path(current_app.config["UPLOAD_DIR"]) / "drive" / user_id
    for part in folder.split("/"):
        folder_path = folder_path / part
    folder_path.mkdir(parents=True, exist_ok=True)
    stored_name = f"{drive_id}_{safe_name}.enc"
    destination = folder_path / stored_name
    destination.write_bytes(encrypt_bytes(content))
    rel_path = destination.relative_to(Path(current_app.config["UPLOAD_DIR"]))
    return str(rel_path).replace("\\", "/")


def _load_user_profile(user_id: str) -> Dict[str, str]:
    default = {
        "full_name": "",
        "email_contact": "",
        "phone": "",
        "organization": "",
        "designation": "",
        "address": "",
        "gov_id": "",
        "updated_at": "",
    }
    profiles_path = Path(current_app.config["USER_PROFILES_JSON"])
    _ensure_json_storage(profiles_path, default_obj={})
    with _profiles_lock:
        try:
            raw = json.loads(profiles_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            raw = {}
        token = raw.get(user_id, "")
    if not token:
        return default
    try:
        decrypted = decrypt_bytes(token.encode("utf-8"))
        loaded = json.loads(decrypted.decode("utf-8"))
        return {**default, **{k: str(v) for k, v in loaded.items() if k in default}}
    except Exception:
        return default


def _save_user_profile(user_id: str, profile: Dict[str, str]) -> None:
    clean = {
        "full_name": sanitize_text(profile.get("full_name", ""), max_length=120),
        "email_contact": sanitize_text(profile.get("email_contact", ""), max_length=120),
        "phone": sanitize_text(profile.get("phone", ""), max_length=40),
        "organization": sanitize_text(profile.get("organization", ""), max_length=120),
        "designation": sanitize_text(profile.get("designation", ""), max_length=100),
        "address": sanitize_text(profile.get("address", ""), max_length=180),
        "gov_id": sanitize_text(profile.get("gov_id", ""), max_length=80),
        "updated_at": profile.get("updated_at", datetime.now(timezone.utc).isoformat()),
    }
    token = encrypt_bytes(json.dumps(clean).encode("utf-8")).decode("utf-8")
    profiles_path = Path(current_app.config["USER_PROFILES_JSON"])
    _ensure_json_storage(profiles_path, default_obj={})
    with _profiles_lock:
        try:
            raw = json.loads(profiles_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            raw = {}
        raw[user_id] = token
        profiles_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")


def _masked_profile_for_admin(profile: Dict[str, str]) -> Dict[str, str]:
    gov_id = profile.get("gov_id", "")
    if len(gov_id) > 4:
        masked = "*" * (len(gov_id) - 4) + gov_id[-4:]
    else:
        masked = gov_id
    return {**profile, "gov_id": masked}


def _scoped_user_id_from_request() -> str:
    requested = request.args.get("user_id", "").strip()
    if not requested:
        return ""
    if session.get("role") == "admin":
        return requested
    if requested == session.get("user_id"):
        return requested
    return ""


def _read_review_requests(path: Path) -> List[Dict[str, str]]:
    with _review_requests_lock:
        if not path.exists():
            return []
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            return list(csv.DictReader(csvfile))


def _write_review_requests(path: Path, rows: List[Dict[str, str]]) -> None:
    with _review_requests_lock:
        with path.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=REVIEW_REQUEST_FIELDS)
            writer.writeheader()
            writer.writerows(rows)


def _append_review_request(path: Path, row: Dict[str, str]) -> None:
    with _review_requests_lock:
        with path.open("a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=REVIEW_REQUEST_FIELDS)
            writer.writerow(row)


def _review_requests_for_user(user_id: str, limit: int = 30) -> List[Dict[str, str]]:
    rows = _read_review_requests(Path(current_app.config["REVIEW_REQUESTS_CSV"]))
    rows = [row for row in rows if row["requester_id"] == user_id or row["record_owner_id"] == user_id]
    rows = sorted(rows, key=lambda row: row["updated_at"], reverse=True)
    return rows[:limit]


def _review_requests_for_record_for_session(verification_id: str) -> List[Dict[str, str]]:
    rows = _read_review_requests(Path(current_app.config["REVIEW_REQUESTS_CSV"]))
    rows = [row for row in rows if row["verification_id"].upper() == verification_id.upper()]
    if session.get("role") != "admin":
        user_id = session.get("user_id")
        rows = [row for row in rows if row["requester_id"] == user_id or row["record_owner_id"] == user_id]
    rows = sorted(rows, key=lambda row: row["updated_at"], reverse=True)
    return rows[:50]


def _has_open_review_request(verification_id: str, requester_id: str) -> bool:
    rows = _read_review_requests(Path(current_app.config["REVIEW_REQUESTS_CSV"]))
    return any(
        row["verification_id"].upper() == verification_id.upper()
        and row["requester_id"] == requester_id
        and row["status"] == "open"
        for row in rows
    )


def _open_review_requests(limit: int = 100) -> List[Dict[str, str]]:
    rows = _read_review_requests(Path(current_app.config["REVIEW_REQUESTS_CSV"]))
    rows = [row for row in rows if row["status"] == "open"]
    rows = sorted(rows, key=lambda row: row["created_at"], reverse=True)
    return rows[:limit]


def _read_two_factor_reviews(path: Path) -> List[Dict[str, str]]:
    with _two_factor_reviews_lock:
        if not path.exists():
            return []
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            return list(csv.DictReader(csvfile))


def _write_two_factor_reviews(path: Path, rows: List[Dict[str, str]]) -> None:
    with _two_factor_reviews_lock:
        with path.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=TWO_FACTOR_REVIEW_FIELDS)
            writer.writeheader()
            writer.writerows(rows)


def _append_two_factor_review(path: Path, row: Dict[str, str]) -> None:
    with _two_factor_reviews_lock:
        with path.open("a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=TWO_FACTOR_REVIEW_FIELDS)
            writer.writerow(row)


def _open_two_factor_reviews(limit: int = 100) -> List[Dict[str, str]]:
    rows = _read_two_factor_reviews(Path(current_app.config["TWO_FACTOR_REVIEW_CSV"]))
    rows = [row for row in rows if row.get("status") == "open"]
    rows = sorted(rows, key=lambda row: row.get("submitted_at", ""), reverse=True)
    return rows[:limit]


def _two_factor_reviews_for_user(user_id: str, limit: int = 40) -> List[Dict[str, str]]:
    rows = _read_two_factor_reviews(Path(current_app.config["TWO_FACTOR_REVIEW_CSV"]))
    rows = [row for row in rows if row.get("user_id") == user_id]
    rows = sorted(rows, key=lambda row: row.get("submitted_at", ""), reverse=True)
    return rows[:limit]


def _build_user_risk_board(
    users: List[Dict[str, str]],
    records: List[Dict[str, str]],
    activities: List[Dict[str, str]],
    risk_alert_threshold: int,
) -> List[Dict[str, str]]:
    by_owner: Dict[str, List[Dict[str, str]]] = {}
    for record in records:
        by_owner.setdefault(record["owner_id"], []).append(record)

    failed_logins_by_user: Dict[str, int] = {}
    for row in activities:
        if row.get("action") == "login" and row.get("status") in {"failed", "blocked"}:
            uid = row.get("user_id", "")
            if uid:
                failed_logins_by_user[uid] = failed_logins_by_user.get(uid, 0) + 1

    incidents = _read_incidents(Path(current_app.config["INCIDENTS_CSV"]))
    open_incident_by_owner: Dict[str, int] = {}
    for item in incidents:
        if item.get("status") in {"resolved", "closed"}:
            continue
        owner_id = _record_owner_id(item.get("verification_id", ""))
        if owner_id:
            open_incident_by_owner[owner_id] = open_incident_by_owner.get(owner_id, 0) + 1

    board: List[Dict[str, str]] = []
    for user in users:
        user_id = user["user_id"]
        user_records = by_owner.get(user_id, [])
        high_risk_count = 0
        quarantined_count = 0
        for record in user_records:
            if record.get("status") == "quarantined":
                quarantined_count += 1
            risk_value = int(record.get("quick_risk", "0") or 0)
            analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), record["verification_id"])
            if analysis.get("status") == "complete":
                try:
                    risk_value = int(analysis.get("risk_percentage", str(risk_value)))
                except (TypeError, ValueError):
                    pass
            if risk_value >= risk_alert_threshold:
                high_risk_count += 1

        failed_logins = failed_logins_by_user.get(user_id, 0)
        open_incidents = open_incident_by_owner.get(user_id, 0)
        score = min(
            99,
            high_risk_count * 14
            + quarantined_count * 18
            + open_incidents * 10
            + failed_logins * 8
            + max(0, len(user_records) - 20) // 2,
        )
        if score >= 75:
            risk_level = "critical"
        elif score >= 55:
            risk_level = "high"
        elif score >= 35:
            risk_level = "elevated"
        else:
            risk_level = "normal"

        board.append(
            {
                "username": user["username"],
                "user_id": user_id,
                "role": user["role"],
                "account_status": user["account_status"],
                "record_count": str(len(user_records)),
                "high_risk_count": str(high_risk_count),
                "quarantined_count": str(quarantined_count),
                "open_incidents": str(open_incidents),
                "failed_logins": str(failed_logins),
                "risk_score": str(score),
                "risk_level": risk_level,
            }
        )

    return sorted(
        board,
        key=lambda row: (
            int(row["risk_score"]),
            int(row["open_incidents"]),
            int(row["high_risk_count"]),
        ),
        reverse=True,
    )


def _policy() -> Dict[str, int | bool]:
    return dict(current_app.config.get("SECURITY_POLICY", {}))


def _next_verification_id() -> str:
    existing = {r["verification_id"] for r in _read_records(Path(current_app.config["RECORDS_CSV"]))}
    while True:
        candidate = generate_verification_id()
        if candidate not in existing:
            return candidate


def _parse_verification_ids(raw_value: str, limit: int = 50) -> List[str]:
    normalized = (
        raw_value.replace(",", " ")
        .replace(";", " ")
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("\t", " ")
    )
    output: List[str] = []
    seen = set()
    for token in normalized.split():
        cleaned = "".join(ch for ch in token.upper() if ch.isalnum())
        if len(cleaned) < 6 or len(cleaned) > 24:
            continue
        if cleaned in seen:
            continue
        output.append(cleaned)
        seen.add(cleaned)
        if len(output) >= limit:
            break
    return output


def _verification_payload(verification_id: str) -> Dict[str, object]:
    record = _record_by_verification_id(verification_id)
    if not record:
        return {"exists": False, "verification_id": verification_id}
    blocks = find_blocks_by_verification_id(Path(current_app.config["BLOCKCHAIN_JSON"]), verification_id)
    chain_valid, issues = validate_chain(Path(current_app.config["BLOCKCHAIN_JSON"]))
    latest_block = blocks[-1] if blocks else None
    integrity_match = bool(latest_block and latest_block["file_hash"] == record["file_hash"])
    analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), verification_id)
    return {
        "exists": True,
        "verification_id": verification_id,
        "record": record,
        "latest_block": latest_block,
        "chain_valid": chain_valid,
        "integrity_match": integrity_match,
        "tamper_detected": (not chain_valid) or (not integrity_match),
        "issues": issues,
        "analysis": analysis,
        "authenticity_score": analysis.get("authenticity_score", "Pending"),
        "risk_percentage": analysis.get("risk_percentage", record.get("quick_risk", "Pending")),
    }


def _records_for_session(records: List[Dict[str, str]]) -> List[Dict[str, str]]:
    if session.get("role") == "admin":
        return records
    user_id = session.get("user_id")
    return [record for record in records if record["owner_id"] == user_id]


def _record_by_verification_id(verification_id: str) -> Optional[Dict[str, str]]:
    records = _read_records(Path(current_app.config["RECORDS_CSV"]))
    return next((r for r in records if r["verification_id"].upper() == verification_id.upper()), None)


def _compute_next_version(records: List[Dict[str, str]], owner_id: str, filename: str) -> int:
    versions = [
        int(r["version"])
        for r in records
        if r["owner_id"] == owner_id and r["original_filename"].lower() == filename.lower()
    ]
    return max(versions) + 1 if versions else 1


def _generate_qr_code(verification_id: str, share_link: str) -> str:
    qr_file = Path(current_app.config["QR_DIR"]) / f"{verification_id}.svg"
    qr = segno.make(share_link)
    qr.save(str(qr_file), scale=4, border=1, kind="svg")
    return f"qrcodes/{verification_id}.svg"


def _build_dashboard_analytics(
    records: List[Dict[str, str]],
    activities: List[Dict[str, str]],
    snapshot: Dict[str, object],
    incidents: List[Dict[str, str]] | None = None,
) -> Dict[str, int]:
    suspicious_attempts = len(
        [a for a in activities if a["status"] in {"failed", "blocked"} and a["action"] in {"login", "upload"}]
    )
    active_users = len(
        {
            user["user_id"]
            for user in get_all_users()
            if user.get("last_login")
            and _within_last_24h(user["last_login"])
            and user["account_status"] == "active"
        }
    )
    incident_pool = incidents if incidents is not None else _visible_incidents_for_session(limit=300)

    return {
        "total_verified_files": len(records),
        "suspicious_attempts": suspicious_attempts,
        "active_users": active_users,
        "protection_score": _calculate_protection_score(records),
        "quarantined_files": len([r for r in records if r.get("status") == "quarantined"]),
        "anomaly_score": int(snapshot.get("anomaly_score", 0)),
        "security_posture": int(snapshot.get("posture_index", 0)),
        "open_incidents": len([item for item in incident_pool if item["status"] not in {"resolved", "closed"}]),
    }


def _calculate_protection_score(records: List[Dict[str, str]]) -> int:
    if not records:
        return 90
    scores = []
    for record in records:
        analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), record["verification_id"])
        if analysis.get("status") == "complete":
            try:
                scores.append(int(analysis.get("authenticity_score", "0")))
            except ValueError:
                continue
    return sum(scores) // len(scores) if scores else 86


def _within_last_24h(iso_time: str) -> bool:
    try:
        stamp = datetime.fromisoformat(iso_time).astimezone(timezone.utc)
        return (datetime.now(timezone.utc) - stamp).total_seconds() <= 86400
    except ValueError:
        return False


def _visible_activity_for_session(limit: int = 60) -> List[Dict[str, str]]:
    from .security import read_recent_activity

    activity = read_recent_activity(limit=limit)
    if session.get("role") == "admin":
        return activity
    user_id = session.get("user_id")
    return [item for item in activity if item["user_id"] in {user_id, "anonymous"}]


def _activities_for_user(user_id: str, limit: int = 160) -> List[Dict[str, str]]:
    from .security import read_recent_activity

    rows = read_recent_activity(limit=max(limit * 6, 600))
    rows = [row for row in rows if row.get("user_id") == user_id]
    return rows[:limit]


def _uploads_count_today(user_id: str) -> int:
    from .security import read_recent_activity

    today = datetime.now(timezone.utc).date()
    count = 0
    for row in read_recent_activity(limit=3000):
        if row["user_id"] != user_id or row["action"] != "upload" or row["status"] != "success":
            continue
        try:
            if datetime.fromisoformat(row["timestamp"]).astimezone(timezone.utc).date() == today:
                count += 1
        except ValueError:
            continue
    return count


def _ensure_csv_schema(path: Path, fieldnames: List[str]) -> None:
    if not path.exists():
        with path.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
        return
    with path.open("r", newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        current_fields = reader.fieldnames or []
        rows = list(reader)
    if current_fields == fieldnames:
        return
    migrated = [{field: row.get(field, "") for field in fieldnames} for row in rows]
    with path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(migrated)


def _read_records(path: Path) -> List[Dict[str, str]]:
    with _records_lock:
        if not path.exists():
            return []
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            return list(csv.DictReader(csvfile))


def _write_records(path: Path, rows: List[Dict[str, str]]) -> None:
    with _records_lock:
        with path.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=RECORD_FIELDS)
            writer.writeheader()
            writer.writerows(rows)


def _append_record(path: Path, row: Dict[str, str]) -> None:
    with _records_lock:
        with path.open("a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=RECORD_FIELDS)
            writer.writerow(row)


def _read_transfers(path: Path) -> List[Dict[str, str]]:
    with _transfers_lock:
        if not path.exists():
            return []
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            return list(csv.DictReader(csvfile))


def _append_transfer(path: Path, row: Dict[str, str]) -> None:
    with _transfers_lock:
        with path.open("a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=TRANSFER_FIELDS)
            writer.writerow(row)


def _visible_incidents_for_session(limit: int = 40) -> List[Dict[str, str]]:
    incidents = _read_incidents(Path(current_app.config["INCIDENTS_CSV"]))
    incidents = sorted(incidents, key=lambda row: row["updated_at"], reverse=True)
    if session.get("role") == "admin":
        return incidents[:limit]

    user_id = session.get("user_id")
    visible = [
        item
        for item in incidents
        if item["created_by"] == user_id
        or item["assignee"] == user_id
        or _record_owner_id(item["verification_id"]) == user_id
    ]
    return visible[:limit]


def _incidents_for_user(user_id: str, limit: int = 40) -> List[Dict[str, str]]:
    incidents = _read_incidents(Path(current_app.config["INCIDENTS_CSV"]))
    incidents = sorted(incidents, key=lambda row: row["updated_at"], reverse=True)
    visible = [
        item
        for item in incidents
        if item["created_by"] == user_id
        or item["assignee"] == user_id
        or _record_owner_id(item["verification_id"]) == user_id
    ]
    return visible[:limit]


def _record_owner_id(verification_id: str) -> str:
    record = _record_by_verification_id(verification_id)
    return record["owner_id"] if record else ""


def _incidents_for_verification(verification_id: str) -> List[Dict[str, str]]:
    incidents = _read_incidents(Path(current_app.config["INCIDENTS_CSV"]))
    rows = [row for row in incidents if row["verification_id"].upper() == verification_id.upper()]
    return sorted(rows, key=lambda row: row["updated_at"], reverse=True)


def _notes_for_verification(verification_id: str) -> List[Dict[str, str]]:
    notes = _read_notes(Path(current_app.config["RECORD_NOTES_CSV"]))
    rows = [row for row in notes if row["verification_id"].upper() == verification_id.upper()]
    return sorted(rows, key=lambda row: row["created_at"], reverse=True)


def _latest_integrity_scan() -> Dict[str, str] | None:
    scans = _read_integrity_scans(Path(current_app.config["INTEGRITY_SCANS_CSV"]))
    if not scans:
        return None
    scans = sorted(scans, key=lambda row: row["run_at"], reverse=True)
    return scans[0]


def _read_incidents(path: Path) -> List[Dict[str, str]]:
    with _incidents_lock:
        if not path.exists():
            return []
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            return list(csv.DictReader(csvfile))


def _write_incidents(path: Path, rows: List[Dict[str, str]]) -> None:
    with _incidents_lock:
        with path.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=INCIDENT_FIELDS)
            writer.writeheader()
            writer.writerows(rows)


def _append_incident(path: Path, row: Dict[str, str]) -> None:
    with _incidents_lock:
        with path.open("a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=INCIDENT_FIELDS)
            writer.writerow(row)


def _read_integrity_scans(path: Path) -> List[Dict[str, str]]:
    with _scans_lock:
        if not path.exists():
            return []
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            return list(csv.DictReader(csvfile))


def _read_notes(path: Path) -> List[Dict[str, str]]:
    with _notes_lock:
        if not path.exists():
            return []
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            return list(csv.DictReader(csvfile))


def _append_note(path: Path, row: Dict[str, str]) -> None:
    with _notes_lock:
        with path.open("a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=NOTE_FIELDS)
            writer.writerow(row)


def _read_watchlist(path: Path) -> List[Dict[str, str]]:
    with _watchlist_lock:
        if not path.exists():
            return []
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            return list(csv.DictReader(csvfile))


def _write_watchlist(path: Path, rows: List[Dict[str, str]]) -> None:
    with _watchlist_lock:
        with path.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=WATCHLIST_FIELDS)
            writer.writeheader()
            writer.writerows(rows)


def _append_watchlist(path: Path, row: Dict[str, str]) -> None:
    with _watchlist_lock:
        with path.open("a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=WATCHLIST_FIELDS)
            writer.writerow(row)


def _watchlist_item(user_id: str, verification_id: str) -> Optional[Dict[str, str]]:
    rows = _read_watchlist(Path(current_app.config["WATCHLIST_CSV"]))
    return next(
        (
            row
            for row in rows
            if row["user_id"] == user_id and row["verification_id"].upper() == verification_id.upper()
        ),
        None,
    )


def _user_watchlist_records(
    all_records: List[Dict[str, str]],
    analyses: Dict[str, Dict[str, str]] | None = None,
    user_id: str | None = None,
) -> List[Dict[str, str]]:
    analyses = analyses or {}
    target_user_id = user_id or session.get("user_id", "")
    by_id = {row["verification_id"].upper(): row for row in all_records}
    rows = _read_watchlist(Path(current_app.config["WATCHLIST_CSV"]))
    rows = [row for row in rows if row["user_id"] == target_user_id]
    rows = sorted(rows, key=lambda row: row["created_at"], reverse=True)
    output: List[Dict[str, str]] = []
    for item in rows:
        record = by_id.get(item["verification_id"].upper())
        if not record:
            continue
        if session.get("role") != "admin" and record["owner_id"] != target_user_id:
            continue
        analysis = analyses.get(record["verification_id"])
        if analysis is None:
            analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), record["verification_id"])
        output.append(
            {
                "watch_id": item["watch_id"],
                "verification_id": item["verification_id"],
                "note": item["note"],
                "created_at": item["created_at"],
                "original_filename": record["original_filename"],
                "status": record["status"],
                "risk_percentage": analysis.get("risk_percentage", record.get("quick_risk", "Pending")),
            }
        )
    return output


def _read_preferences(path: Path) -> List[Dict[str, str]]:
    with _preferences_lock:
        if not path.exists():
            return []
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            return list(csv.DictReader(csvfile))


def _write_preferences(path: Path, rows: List[Dict[str, str]]) -> None:
    with _preferences_lock:
        with path.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=PREFERENCE_FIELDS)
            writer.writeheader()
            writer.writerows(rows)


def _upsert_preferences(path: Path, row: Dict[str, str]) -> None:
    rows = _read_preferences(path)
    found = False
    for item in rows:
        if item["user_id"] == row["user_id"]:
            item.update(row)
            found = True
            break
    if not found:
        rows.append(row)
    _write_preferences(path, rows)


def _user_preferences(user_id: str) -> Dict[str, str]:
    default = {
        "user_id": user_id,
        "email_alerts": "1",
        "digest_hour_utc": "9",
        "risk_notify_min": "65",
        "chatbot_mode": "assistive",
        "updated_at": "",
    }
    rows = _read_preferences(Path(current_app.config["USER_PREFERENCES_CSV"]))
    found = next((item for item in rows if item["user_id"] == user_id), None)
    if not found:
        _upsert_preferences(Path(current_app.config["USER_PREFERENCES_CSV"]), default)
        return default
    return {
        "user_id": found.get("user_id", user_id),
        "email_alerts": found.get("email_alerts", "1"),
        "digest_hour_utc": found.get("digest_hour_utc", "9"),
        "risk_notify_min": found.get("risk_notify_min", "65"),
        "chatbot_mode": found.get("chatbot_mode", "assistive"),
        "updated_at": found.get("updated_at", ""),
    }


def _compare_record_pair(
    first_id: str,
    second_id: str,
    visible_records: List[Dict[str, str]],
) -> Dict[str, object]:
    by_id = {row["verification_id"].upper(): row for row in visible_records}
    first = by_id.get(first_id.upper())
    second = by_id.get(second_id.upper())
    if not first or not second:
        return {
            "available": False,
            "message": "One or both records are unavailable for your account scope.",
        }

    first_analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), first["verification_id"])
    second_analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), second["verification_id"])

    def _to_int(value: str, fallback: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return fallback

    first_risk = _to_int(str(first_analysis.get("risk_percentage", first.get("quick_risk", "0"))))
    second_risk = _to_int(str(second_analysis.get("risk_percentage", second.get("quick_risk", "0"))))

    return {
        "available": True,
        "first": first,
        "second": second,
        "first_risk": first_risk,
        "second_risk": second_risk,
        "risk_delta": second_risk - first_risk,
        "hash_match": first.get("file_hash") == second.get("file_hash"),
        "same_owner": first.get("owner_id") == second.get("owner_id"),
        "same_file_name": first.get("original_filename", "").lower() == second.get("original_filename", "").lower(),
        "same_status": first.get("status") == second.get("status"),
    }

