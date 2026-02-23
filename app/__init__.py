from __future__ import annotations

import os
import secrets
import time
from pathlib import Path

from flask import Flask, jsonify, render_template
from werkzeug.exceptions import RequestEntityTooLarge

from .alerts import init_alert_storage
from .api_access import init_api_key_storage
from .auth import auth_bp, init_auth_storage
from .blockchain import init_blockchain_storage
from .jobs import init_job_queue
from .monitoring import emit_event, init_monitoring_storage
from .policy import init_policy_storage
from .routes import init_route_storage, main_bp
from .security import initialize_security_state, setup_request_guards


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    data_dir = Path(app.root_path) / "data"
    upload_dir = Path(app.root_path) / "uploads"
    qr_dir = Path(app.root_path) / "static" / "qrcodes"

    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", secrets.token_hex(32)),
        SESSION_TIMEOUT_MINUTES=int(os.getenv("SESSION_TIMEOUT_MINUTES", "20")),
        MAX_CONTENT_LENGTH=int(os.getenv("MAX_UPLOAD_MB", "16")) * 1024 * 1024,
        ALLOWED_EXTENSIONS={
            "pdf",
            "png",
            "jpg",
            "jpeg",
            "txt",
            "csv",
            "doc",
            "docx",
        },
        ALLOWED_MIME_TYPES={
            "application/pdf",
            "image/png",
            "image/jpeg",
            "text/plain",
            "text/csv",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        },
        DATA_DIR=data_dir,
        UPLOAD_DIR=upload_dir,
        QR_DIR=qr_dir,
        USERS_CSV=Path(app.root_path) / "users.csv",
        RECORDS_CSV=data_dir / "records.csv",
        TRANSFERS_CSV=data_dir / "transfers.csv",
        ACTIVITY_CSV=data_dir / "activity_log.csv",
        BLOCKCHAIN_JSON=data_dir / "blockchain.json",
        ANALYSIS_JSON=data_dir / "analysis_results.json",
        NOTIFICATIONS_CSV=data_dir / "notifications.csv",
        POLICY_JSON=data_dir / "security_policy.json",
        API_KEYS_CSV=data_dir / "api_keys.csv",
        INTEGRITY_SCANS_CSV=data_dir / "integrity_scans.csv",
        INCIDENTS_CSV=data_dir / "incidents.csv",
        RECORD_NOTES_CSV=data_dir / "record_notes.csv",
        WATCHLIST_CSV=data_dir / "watchlist.csv",
        USER_PREFERENCES_CSV=data_dir / "user_preferences.csv",
        REVIEW_REQUESTS_CSV=data_dir / "review_requests.csv",
        TWO_FACTOR_REVIEW_CSV=data_dir / "two_factor_reviews.csv",
        USER_DRIVE_CSV=data_dir / "user_drive.csv",
        USER_PROFILES_JSON=data_dir / "user_profiles.json",
        ADMIN_SIGNUP_KEY=os.getenv("ADMIN_SIGNUP_KEY", "SECURECHAIN-ADMIN-KEY"),
        FERNET_KEY_FILE=data_dir / ".fernet.key",
        EMAIL_VERIFICATION_REQUIRED=_as_bool(os.getenv("EMAIL_VERIFICATION_REQUIRED", "1")),
        ENABLE_2FA=_as_bool(os.getenv("ENABLE_2FA", "0")),
        AUTH_SHOW_TOKEN_HINTS=_as_bool(os.getenv("AUTH_SHOW_TOKEN_HINTS", "0")),
        AUTH_TOKEN_TTL_HOURS=int(os.getenv("AUTH_TOKEN_TTL_HOURS", "24")),
        RESET_TOKEN_TTL_MINUTES=int(os.getenv("RESET_TOKEN_TTL_MINUTES", "30")),
        TWO_FA_LOGIN_WINDOW_SECONDS=int(os.getenv("TWO_FA_LOGIN_WINDOW_SECONDS", "300")),
        ALLOW_FORCE_2FA_APPROVAL=_as_bool(os.getenv("ALLOW_FORCE_2FA_APPROVAL", "1")),
        MAILBOX_LOG=data_dir / "mailbox.log",
        ENABLE_DEMO_USERS=_as_bool(os.getenv("ENABLE_DEMO_USERS", "1")),
        JOBS_JSON=data_dir / "jobs.json",
        JOB_ARTIFACT_DIR=data_dir / "job_artifacts",
        JOB_WORKERS=int(os.getenv("JOB_WORKERS", "2")),
        SIEM_LOG=data_dir / "siem.log",
        ERROR_LOG=data_dir / "error.log",
        APP_STARTED_AT=time.time(),
    )

    if test_config:
        app.config.update(test_config)

    path_keys = [
        "DATA_DIR",
        "UPLOAD_DIR",
        "QR_DIR",
        "USERS_CSV",
        "RECORDS_CSV",
        "TRANSFERS_CSV",
        "ACTIVITY_CSV",
        "BLOCKCHAIN_JSON",
        "ANALYSIS_JSON",
        "NOTIFICATIONS_CSV",
        "POLICY_JSON",
        "API_KEYS_CSV",
        "INTEGRITY_SCANS_CSV",
        "INCIDENTS_CSV",
        "RECORD_NOTES_CSV",
        "WATCHLIST_CSV",
        "USER_PREFERENCES_CSV",
        "REVIEW_REQUESTS_CSV",
        "TWO_FACTOR_REVIEW_CSV",
        "USER_DRIVE_CSV",
        "USER_PROFILES_JSON",
        "FERNET_KEY_FILE",
        "MAILBOX_LOG",
        "JOBS_JSON",
        "JOB_ARTIFACT_DIR",
        "SIEM_LOG",
        "ERROR_LOG",
    ]
    for key in path_keys:
        value = app.config.get(key)
        if value is None:
            continue
        app.config[key] = Path(value)
        if key.endswith("_DIR"):
            Path(app.config[key]).mkdir(parents=True, exist_ok=True)
        else:
            Path(app.config[key]).parent.mkdir(parents=True, exist_ok=True)

    Path(app.config["DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["QR_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["JOB_ARTIFACT_DIR"]).mkdir(parents=True, exist_ok=True)

    init_policy_storage(app)
    initialize_security_state(app)
    init_monitoring_storage(app)
    init_alert_storage(app)
    init_api_key_storage(app)
    init_auth_storage(app)
    init_route_storage(app)
    init_blockchain_storage(app)
    init_job_queue(app)
    setup_request_guards(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_upload(_err: RequestEntityTooLarge):
        return render_template(
            "error.html",
            title="Upload Too Large",
            message="The selected file exceeds the upload size limit.",
            code=413,
        ), 413

    @app.errorhandler(400)
    def handle_bad_request(_err):
        return render_template(
            "error.html",
            title="Bad Request",
            message="Security validation failed. Refresh the page and try again.",
            code=400,
        ), 400

    @app.errorhandler(404)
    def handle_not_found(_err):
        return render_template(
            "error.html",
            title="Not Found",
            message="The requested resource could not be found.",
            code=404,
        ), 404

    @app.errorhandler(500)
    def handle_server_error(_err):
        with app.app_context():
            emit_event(
                "server_error",
                severity="critical",
                message="Unhandled server exception",
                error=str(_err),
            )

        # Import lazily to avoid startup circulars.
        from .alerts import push_alert_to_admins

        try:
            push_alert_to_admins(
                severity="critical",
                category="system",
                title="Server Error Detected",
                message="An unhandled server error occurred. Review monitoring logs.",
            )
        except Exception:
            pass

        if _wants_json_response():
            return jsonify({"status": "error", "message": "Unexpected server failure"}), 500

        return (
            render_template(
                "error.html",
                title="Server Error",
                message="Unexpected server failure. The incident has been logged.",
                code=500,
            ),
            500,
        )

    return app


def _as_bool(raw: str) -> bool:
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _wants_json_response() -> bool:
    from flask import request

    best = request.accept_mimetypes.best
    return request.is_json or request.path.startswith("/api/") or best == "application/json"
