from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import os
import secrets
import struct
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import bcrypt
from cryptography.fernet import Fernet
from flask import abort, current_app, flash, g, has_request_context, redirect, request, session, url_for
from werkzeug.utils import secure_filename

from .monitoring import emit_event


_activity_lock = threading.Lock()


class LoginAttemptLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 600, lock_seconds: int = 900):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lock_seconds = lock_seconds
        self._state: Dict[str, Dict[str, float | List[float]]] = {}
        self._lock = threading.Lock()

    def is_blocked(self, key: str) -> Tuple[bool, int]:
        with self._lock:
            state = self._state.get(key, {})
            locked_until = float(state.get("locked_until", 0))
            now = time.time()
            if locked_until > now:
                return True, int(locked_until - now)
            return False, 0

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = time.time()
            state = self._state.setdefault(key, {"attempts": [], "locked_until": 0})
            attempts = [ts for ts in state["attempts"] if now - ts <= self.window_seconds]
            attempts.append(now)
            state["attempts"] = attempts
            if len(attempts) >= self.max_attempts:
                state["locked_until"] = now + self.lock_seconds
                state["attempts"] = []

    def record_success(self, key: str) -> None:
        with self._lock:
            if key in self._state:
                self._state.pop(key, None)


def initialize_security_state(app) -> None:
    key_file = Path(app.config["FERNET_KEY_FILE"])
    if not key_file.exists():
        key_file.write_bytes(Fernet.generate_key())

    activity_csv = Path(app.config["ACTIVITY_CSV"])
    if not activity_csv.exists():
        with activity_csv.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=["timestamp", "user_id", "action", "status", "details", "ip_address"],
            )
            writer.writeheader()

    app.config["LOGIN_LIMITER"] = LoginAttemptLimiter(
        max_attempts=int(app.config.get("LOGIN_MAX_ATTEMPTS", 5)),
        window_seconds=int(app.config.get("LOGIN_WINDOW_SECONDS", 600)),
        lock_seconds=int(app.config.get("LOGIN_LOCK_SECONDS", 900)),
    )


def setup_request_guards(app) -> None:
    @app.before_request
    def enforce_security_guards():
        g.request_started_at = time.time()
        g.request_id = secrets.token_hex(8)
        _enforce_session_timeout()
        result = _validate_csrf_token()
        if result is not None:
            return result

    @app.after_request
    def capture_request_telemetry(response):
        started_at = float(getattr(g, "request_started_at", time.time()))
        duration_ms = max(0, int((time.time() - started_at) * 1000))
        if request.endpoint != "static":
            try:
                emit_event(
                    "http_request",
                    severity="info" if response.status_code < 500 else "error",
                    message=f"{request.method} {request.path}",
                    request_id=getattr(g, "request_id", ""),
                    method=request.method,
                    path=request.path,
                    endpoint=request.endpoint or "",
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                    user_id=session.get("user_id", "anonymous"),
                    ip_address=request.headers.get("X-Forwarded-For", request.remote_addr or "unknown"),
                )
            except Exception:
                pass
        response.headers["X-Request-ID"] = str(getattr(g, "request_id", ""))
        # API and authenticated dashboard views should never be cached by the browser.
        # This keeps session-bound content fresh across tab switches and refreshes.
        if (request.endpoint and request.endpoint.startswith("api_")) or request.path.startswith("/dashboard"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    @app.context_processor
    def inject_security_helpers():
        return {"csrf_token": generate_csrf_token}


def _enforce_session_timeout() -> None:
    timeout_minutes = int(current_app.config["SESSION_TIMEOUT_MINUTES"])
    now_epoch = int(time.time())
    contexts = session.get("auth_contexts", {})
    if isinstance(contexts, dict) and contexts:
        changed = False
        for portal in list(contexts.keys()):
            ctx = contexts.get(portal, {})
            if not isinstance(ctx, dict):
                contexts.pop(portal, None)
                changed = True
                continue
            try:
                seen = int(ctx.get("last_seen", now_epoch))
            except (TypeError, ValueError):
                seen = now_epoch
            if now_epoch - seen > timeout_minutes * 60:
                contexts.pop(portal, None)
                changed = True

        if not contexts:
            session.clear()
            return

        active_portal = str(session.get("active_portal", ""))
        if active_portal not in contexts:
            active_portal = "admin" if "admin" in contexts else next(iter(contexts.keys()))
            changed = True

        active_ctx = contexts.get(active_portal, {})
        if isinstance(active_ctx, dict):
            active_ctx["last_seen"] = now_epoch
            contexts[active_portal] = active_ctx
            session["user_id"] = active_ctx.get("user_id", "")
            session["username"] = active_ctx.get("username", "")
            session["role"] = "admin" if active_ctx.get("role") == "admin" else "user"
            session["last_seen"] = now_epoch
            changed = True

        if changed:
            session["auth_contexts"] = contexts
            session["active_portal"] = active_portal
        return

    if "user_id" not in session:
        return

    last_seen = int(session.get("last_seen", now_epoch))
    if now_epoch - last_seen > timeout_minutes * 60:
        session.clear()
        return
    session["last_seen"] = now_epoch


def _validate_csrf_token():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return

    if request.endpoint in {"static"}:
        return

    token_in_session = session.get("_csrf_token")
    token_supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not token_in_session or token_supplied != token_in_session:
        # Keep strict CSRF behavior for API/AJAX calls.
        is_api_like = request.path.startswith("/api/") or request.is_json
        if is_api_like:
            abort(400)

        # For browser form submissions, regenerate token and redirect instead of hard 400.
        session["_csrf_token"] = secrets.token_urlsafe(32)
        flash("Security token expired. Please submit the form again.", "error")

        fallback = request.referrer
        if not fallback:
            if request.endpoint == "main.public_verify":
                fallback = url_for("main.public_verify")
            elif "user_id" in session:
                portal = request.args.get("portal", "").strip().lower()
                if portal not in {"admin", "user"}:
                    path = (request.path or "").lower()
                    if path.startswith("/dashboard/admin") or path.startswith("/admin"):
                        portal = "admin"
                    elif path.startswith("/dashboard/user"):
                        portal = "user"
                    else:
                        portal = "admin" if session.get("role") == "admin" else "user"
                fallback = url_for("main.dashboard", portal=portal)
            else:
                fallback = url_for("auth.login")
        return redirect(fallback)


def generate_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def calculate_sha256(content: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(content)
    return digest.hexdigest()


def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


def allowed_mime(mime_type: str) -> bool:
    return mime_type in current_app.config["ALLOWED_MIME_TYPES"]


def encrypt_bytes(content: bytes) -> bytes:
    return _get_fernet().encrypt(content)


def decrypt_bytes(content: bytes) -> bytes:
    return _get_fernet().decrypt(content)


def secure_stored_filename(original_filename: str, verification_id: str) -> str:
    safe = secure_filename(original_filename)
    return f"{verification_id}_{safe}.enc"


def save_encrypted_file(original_filename: str, verification_id: str, content: bytes) -> str:
    stored_name = secure_stored_filename(original_filename, verification_id)
    destination = Path(current_app.config["UPLOAD_DIR"]) / stored_name
    destination.write_bytes(encrypt_bytes(content))
    return stored_name


def read_encrypted_file(stored_filename: str) -> bytes:
    source = Path(current_app.config["UPLOAD_DIR"]) / stored_filename
    encrypted = source.read_bytes()
    return decrypt_bytes(encrypted)


def _get_fernet() -> Fernet:
    fernet = current_app.config.get("_FERNET")
    if fernet is not None:
        return fernet

    key_file = Path(current_app.config["FERNET_KEY_FILE"])
    key = key_file.read_bytes()
    fernet = Fernet(key)
    current_app.config["_FERNET"] = fernet
    return fernet


def log_activity(user_id: str, action: str, status: str, details: str = "") -> None:
    ip_address = "system"
    request_id = ""
    if has_request_context():
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
        request_id = str(getattr(g, "request_id", ""))

    row = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "action": action,
        "status": status,
        "details": details,
        "ip_address": ip_address,
    }
    activity_csv = Path(current_app.config["ACTIVITY_CSV"])

    with _activity_lock:
        with activity_csv.open("a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=["timestamp", "user_id", "action", "status", "details", "ip_address"],
            )
            writer.writerow(row)

    try:
        emit_event(
            "activity",
            severity="warning" if status in {"failed", "blocked"} else "info",
            message=f"{action}:{status}",
            user_id=user_id,
            action=action,
            status=status,
            details=details[:220],
            ip_address=ip_address,
            request_id=request_id,
        )
    except Exception:
        pass


def read_recent_activity(limit: int = 30) -> List[Dict[str, str]]:
    activity_csv = Path(current_app.config["ACTIVITY_CSV"])
    if not activity_csv.exists():
        return []
    with activity_csv.open("r", newline="", encoding="utf-8") as csvfile:
        rows = list(csv.DictReader(csvfile))
    return list(reversed(rows[-limit:]))


def generate_verification_id() -> str:
    return secrets.token_hex(6).upper()


def file_size_mb(size_in_bytes: int) -> float:
    return round(size_in_bytes / (1024 * 1024), 2)


def sanitize_text(value: str, max_length: int = 200) -> str:
    cleaned = value.replace("\n", " ").replace("\r", " ").strip()
    return cleaned[:max_length]


def getenv_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def generate_totp_secret(length: int = 20) -> str:
    # 160-bit default secret compatible with authenticator apps.
    random_bytes = secrets.token_bytes(max(10, int(length)))
    return base64.b32encode(random_bytes).decode("utf-8").rstrip("=")


def generate_totp_code(secret: str, for_time: int | None = None, interval: int = 30, digits: int = 6) -> str:
    stamp = int(for_time or time.time())
    normalized = _normalize_totp_secret(secret)
    counter = int(stamp // max(1, int(interval)))
    payload = struct.pack(">Q", counter)
    digest = hmac.new(normalized, payload, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    otp = binary % (10**digits)
    return f"{otp:0{digits}d}"


def verify_totp_code(secret: str, code: str, window: int = 1, interval: int = 30, digits: int = 6) -> bool:
    token = "".join(ch for ch in str(code) if ch.isdigit())
    if len(token) != digits:
        return False
    now = int(time.time())
    for offset in range(-max(0, int(window)), max(0, int(window)) + 1):
        sample = now + offset * max(1, int(interval))
        if generate_totp_code(secret, for_time=sample, interval=interval, digits=digits) == token:
            return True
    return False


def _normalize_totp_secret(secret: str) -> bytes:
    cleaned = "".join(ch for ch in str(secret).strip().upper() if ch.isalnum())
    if not cleaned:
        raise ValueError("Invalid TOTP secret.")
    padding = "=" * ((8 - len(cleaned) % 8) % 8)
    return base64.b32decode(cleaned + padding, casefold=True)
