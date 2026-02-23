from __future__ import annotations

import csv
import hashlib
import secrets
import threading
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote

import segno
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from .alerts import push_alert_to_admins
from .security import (
    decrypt_bytes,
    encrypt_bytes,
    generate_totp_secret,
    hash_password,
    log_activity,
    sanitize_text,
    verify_password,
    verify_totp_code,
)


auth_bp = Blueprint("auth", __name__)
_users_lock = threading.Lock()
USER_FIELDS = [
    "user_id",
    "username",
    "email",
    "password_hash",
    "role",
    "last_login",
    "account_status",
    "email_verified",
    "email_verification_token_hash",
    "email_verification_expires_at",
    "reset_token_hash",
    "reset_token_expires_at",
    "two_factor_enabled",
    "two_factor_secret",
    "delegated_admin_scopes",
    "delegated_admin_until",
    "delegated_admin_by",
    "delegated_admin_note",
    "delegated_admin_updated_at",
]


def init_auth_storage(app) -> None:
    users_csv = Path(app.config["USERS_CSV"])
    if not users_csv.exists():
        with users_csv.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=USER_FIELDS)
            writer.writeheader()

    users = [_normalize_user_row(row) for row in _read_users(users_csv)]
    for user in users:
        if user.get("username") in {"admin", "user"}:
            user["email_verified"] = "1"
    if app.config.get("ENABLE_DEMO_USERS", True):
        if not any(u["username"] == "admin" for u in users):
            users.append(
                {
                    "user_id": "admin001",
                    "username": "admin",
                    "email": "admin@securechain.local",
                    "password_hash": hash_password("Admin@12345"),
                    "role": "admin",
                    "last_login": "",
                    "account_status": "active",
                    "email_verified": "1",
                    "email_verification_token_hash": "",
                    "email_verification_expires_at": "",
                    "reset_token_hash": "",
                    "reset_token_expires_at": "",
                    "two_factor_enabled": "0",
                    "two_factor_secret": "",
                    "delegated_admin_scopes": "",
                    "delegated_admin_until": "",
                    "delegated_admin_by": "",
                    "delegated_admin_note": "",
                    "delegated_admin_updated_at": "",
                }
            )
        if not any(u["username"] == "user" for u in users):
            users.append(
                {
                    "user_id": "user001",
                    "username": "user",
                    "email": "user@securechain.local",
                    "password_hash": hash_password("User@12345"),
                    "role": "user",
                    "last_login": "",
                    "account_status": "active",
                    "email_verified": "1",
                    "email_verification_token_hash": "",
                    "email_verification_expires_at": "",
                    "reset_token_hash": "",
                    "reset_token_expires_at": "",
                    "two_factor_enabled": "0",
                    "two_factor_secret": "",
                    "delegated_admin_scopes": "",
                    "delegated_admin_until": "",
                    "delegated_admin_by": "",
                    "delegated_admin_note": "",
                    "delegated_admin_updated_at": "",
                }
            )
    _write_users(users_csv, users)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        _synchronize_auth_context()
        if "user_id" not in session:
            portal = _portal_from_request()
            if portal in {"admin", "user"}:
                return redirect(url_for("auth.login", portal=portal))
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped_view


def role_required(required_role: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            _synchronize_auth_context()
            if "user_id" not in session:
                portal = _portal_from_request()
                if portal in {"admin", "user"}:
                    return redirect(url_for("auth.login", portal=portal))
                return redirect(url_for("auth.login"))
            if session.get("role") != required_role:
                flash("You do not have permission for that action.", "error")
                safe_portal = "admin" if session.get("role") == "admin" else "user"
                return redirect(url_for("main.dashboard", portal=safe_portal))
            return view(*args, **kwargs)

        return wrapped

    return decorator


def sync_auth_context() -> None:
    _synchronize_auth_context()


def get_all_users() -> List[Dict[str, str]]:
    return [_normalize_user_row(row) for row in _read_users(Path(current_app.config["USERS_CSV"]))]


def get_user_by_id(user_id: str) -> Optional[Dict[str, str]]:
    users = get_all_users()
    return next((u for u in users if u["user_id"] == user_id), None)


def get_user_by_username(username: str) -> Optional[Dict[str, str]]:
    users = get_all_users()
    lookup = username.lower().strip()
    return next((u for u in users if u["username"].lower() == lookup), None)


def get_user_by_identity(identity: str) -> Optional[Dict[str, str]]:
    lookup = identity.lower().strip()
    if not lookup:
        return None
    users = get_all_users()
    return next(
        (u for u in users if u["username"].lower() == lookup or u["email"].lower() == lookup),
        None,
    )


def create_user(username: str, email: str, password: str, role: str = "user") -> tuple[bool, str, str]:
    username = sanitize_text(username, max_length=40)
    email = sanitize_text(email, max_length=120).lower()
    role = "admin" if role == "admin" else "user"

    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()
    if any(u["username"].lower() == username.lower() for u in users):
        return False, "Username already exists.", ""
    if any(u["email"].lower() == email for u in users):
        return False, "Email already exists.", ""

    email_required = bool(current_app.config.get("EMAIL_VERIFICATION_REQUIRED", True))
    user = {
        "user_id": f"u{secrets.token_hex(4)}",
        "username": username,
        "email": email,
        "password_hash": hash_password(password),
        "role": role,
        "last_login": "",
        "account_status": "active",
        "email_verified": "0" if email_required else "1",
        "email_verification_token_hash": "",
        "email_verification_expires_at": "",
        "reset_token_hash": "",
        "reset_token_expires_at": "",
        "two_factor_enabled": "0",
        "two_factor_secret": "",
        "delegated_admin_scopes": "",
        "delegated_admin_until": "",
        "delegated_admin_by": "",
        "delegated_admin_note": "",
        "delegated_admin_updated_at": "",
    }

    verification_token = ""
    if email_required:
        verification_token = _issue_email_verification_token_for_row(user)

    users.append(user)
    _write_users(users_csv, users)
    message = "Account created. Verify your email before first login." if email_required else "Account created."
    return True, message, verification_token


def update_user_last_login(user_id: str) -> None:
    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()
    for user in users:
        if user["user_id"] == user_id:
            user["last_login"] = datetime.now(timezone.utc).isoformat()
            break
    _write_users(users_csv, users)


def set_user_status(user_id: str, account_status: str) -> bool:
    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()
    changed = False
    for user in users:
        if user["user_id"] == user_id:
            user["account_status"] = account_status
            changed = True
            break
    if changed:
        _write_users(users_csv, users)
    return changed


def set_user_email_verified(user_id: str, verified: bool = True) -> bool:
    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()
    changed = False
    for user in users:
        if user["user_id"] != user_id:
            continue
        user["email_verified"] = "1" if verified else "0"
        if verified:
            user["email_verification_token_hash"] = ""
            user["email_verification_expires_at"] = ""
        changed = True
        break
    if changed:
        _write_users(users_csv, users)
    return changed


def grant_delegated_admin(
    user_id: str,
    scopes: List[str],
    hours: int,
    approved_by: str,
    note: str = "",
) -> tuple[bool, str]:
    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()
    target = next((user for user in users if user["user_id"] == user_id), None)
    if not target:
        return False, "User not found."
    if target.get("role") == "admin":
        return False, "User is already an admin."
    if target.get("account_status") != "active":
        return False, "User account must be active."

    cleaned_scopes = sorted(
        {
            sanitize_text(scope, max_length=40).strip().lower()
            for scope in scopes
            if sanitize_text(scope, max_length=40).strip()
        }
    )
    if not cleaned_scopes:
        cleaned_scopes = ["verify_batch"]

    hours = max(1, min(72, int(hours)))
    expires_at = datetime.now(timezone.utc) + timedelta(hours=hours)
    target["delegated_admin_scopes"] = ",".join(cleaned_scopes)
    target["delegated_admin_until"] = expires_at.isoformat()
    target["delegated_admin_by"] = sanitize_text(approved_by, max_length=80)
    target["delegated_admin_note"] = sanitize_text(note, max_length=200)
    target["delegated_admin_updated_at"] = datetime.now(timezone.utc).isoformat()
    _write_users(users_csv, users)
    return True, f"Delegated admin scopes granted for {hours} hour(s)."


def revoke_delegated_admin(user_id: str) -> bool:
    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()
    changed = False
    for user in users:
        if user["user_id"] != user_id:
            continue
        user["delegated_admin_scopes"] = ""
        user["delegated_admin_until"] = ""
        user["delegated_admin_by"] = ""
        user["delegated_admin_note"] = ""
        user["delegated_admin_updated_at"] = datetime.now(timezone.utc).isoformat()
        changed = True
        break
    if changed:
        _write_users(users_csv, users)
    return changed


def has_delegated_scope(user: Dict[str, str], scope: str) -> bool:
    if user.get("role") == "admin":
        return True

    expiry = _parse_iso(user.get("delegated_admin_until", ""))
    if not expiry or expiry < datetime.now(timezone.utc):
        return False

    raw_scopes = user.get("delegated_admin_scopes", "")
    scope_set = {item.strip().lower() for item in raw_scopes.split(",") if item.strip()}
    wanted = sanitize_text(scope, max_length=40).strip().lower()
    return "*" in scope_set or wanted in scope_set


def set_user_role(user_id: str, role: str) -> tuple[bool, str]:
    role = "admin" if role == "admin" else "user"
    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()

    target = next((user for user in users if user["user_id"] == user_id), None)
    if not target:
        return False, "User not found."

    if target["role"] == role:
        return True, f"Role already set to {role}."

    if target["username"] == "admin" and role != "admin":
        return False, "Primary admin account role cannot be changed."

    if target["role"] == "admin" and role == "user":
        active_admins = [
            user
            for user in users
            if user.get("role") == "admin" and user.get("account_status") == "active"
        ]
        if len(active_admins) <= 1:
            return False, "At least one active admin must remain."

    target["role"] = role
    _write_users(users_csv, users)
    return True, f"Role updated to {role}."


def reset_password_by_identity(identity: str) -> tuple[bool, str, str]:
    user = get_user_by_identity(identity)
    if not user:
        return False, "No matching account found.", ""
    token = issue_password_reset_token(user["user_id"])
    if not token:
        return False, "Unable to issue password reset token.", ""
    return True, "Password reset token issued.", token


def issue_password_reset_token(user_id: str) -> str:
    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()
    target = next((user for user in users if user["user_id"] == user_id), None)
    if not target:
        return ""

    raw_token = secrets.token_urlsafe(32)
    ttl = max(5, int(current_app.config.get("RESET_TOKEN_TTL_MINUTES", 30)))
    target["reset_token_hash"] = _hash_token(raw_token)
    target["reset_token_expires_at"] = (datetime.now(timezone.utc) + timedelta(minutes=ttl)).isoformat()
    _write_users(users_csv, users)
    return raw_token


def consume_password_reset_token(token: str, new_password: str) -> tuple[bool, str]:
    token_hash = _hash_token(token)
    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()
    now = datetime.now(timezone.utc)
    target = None
    for user in users:
        if user["reset_token_hash"] != token_hash:
            continue
        expiry = _parse_iso(user["reset_token_expires_at"])
        if not expiry or expiry < now:
            return False, "Reset token expired."
        target = user
        break

    if not target:
        return False, "Invalid password reset token."

    target["password_hash"] = hash_password(new_password)
    target["reset_token_hash"] = ""
    target["reset_token_expires_at"] = ""
    _write_users(users_csv, users)
    return True, "Password updated."


def issue_email_verification_token(user_id: str) -> str:
    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()
    target = next((user for user in users if user["user_id"] == user_id), None)
    if not target:
        return ""
    raw = _issue_email_verification_token_for_row(target)
    _write_users(users_csv, users)
    return raw


def consume_email_verification_token(token: str) -> tuple[bool, str, str]:
    token_hash = _hash_token(token)
    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()
    now = datetime.now(timezone.utc)
    for user in users:
        if user["email_verification_token_hash"] != token_hash:
            continue
        expiry = _parse_iso(user["email_verification_expires_at"])
        if not expiry or expiry < now:
            return False, "Verification link expired.", ""

        user["email_verified"] = "1"
        user["email_verification_token_hash"] = ""
        user["email_verification_expires_at"] = ""
        _write_users(users_csv, users)
        return True, "Email verification completed.", user["user_id"]

    return False, "Invalid verification link.", ""

def set_user_2fa_secret(user_id: str, secret: str) -> bool:
    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()
    target = next((user for user in users if user["user_id"] == user_id), None)
    if not target:
        return False
    token = encrypt_bytes(secret.encode("utf-8")).decode("utf-8")
    target["two_factor_enabled"] = "1"
    target["two_factor_secret"] = token
    _write_users(users_csv, users)
    return True


def disable_user_2fa(user_id: str) -> bool:
    users_csv = Path(current_app.config["USERS_CSV"])
    users = get_all_users()
    target = next((user for user in users if user["user_id"] == user_id), None)
    if not target:
        return False
    target["two_factor_enabled"] = "0"
    target["two_factor_secret"] = ""
    _write_users(users_csv, users)
    return True


def user_2fa_secret(user: Dict[str, str]) -> str:
    token = user.get("two_factor_secret", "")
    if not token:
        return ""
    try:
        return decrypt_bytes(token.encode("utf-8")).decode("utf-8")
    except Exception:
        return ""


@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role_portal = request.form.get("role_portal", "user").strip().lower()
        admin_access_key = request.form.get("admin_access_key", "").strip()

        if not username or not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for("auth.signup"))
        if "@" not in email:
            flash("Please provide a valid email address.", "error")
            return redirect(url_for("auth.signup"))
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("auth.signup"))

        password_error = _password_policy_error(password)
        if password_error:
            flash(password_error, "error")
            return redirect(url_for("auth.signup"))

        signup_role = "admin" if role_portal == "admin" else "user"
        if signup_role == "admin":
            expected_key = str(current_app.config.get("ADMIN_SIGNUP_KEY", "")).strip()
            if not expected_key or admin_access_key != expected_key:
                flash("Invalid admin access key.", "error")
                log_activity("anonymous", "signup", "failed", f"Admin key mismatch for {username}")
                return redirect(url_for("auth.signup"))

        ok, message, verification_token = create_user(username, email, password, role=signup_role)
        if not ok:
            flash(message, "error")
            log_activity("anonymous", "signup", "failed", message)
            return redirect(url_for("auth.signup"))

        verify_link = ""
        if verification_token:
            verify_link = url_for("auth.verify_email", token=verification_token, _external=True)
            _deliver_security_mail(
                to_email=email,
                subject="SecureChain email verification",
                message="Use this link to verify your account before first login.",
                action_link=verify_link,
            )

        log_activity("anonymous", "signup", "success", f"New {signup_role}: {username}")
        if signup_role == "admin":
            push_alert_to_admins(
                severity="warning",
                category="account",
                title="New Admin Account Created",
                message=f"Admin user '{username}' registered via signup panel.",
            )
        flash(message, "success")
        if verify_link and bool(current_app.config.get("AUTH_SHOW_TOKEN_HINTS", False)):
            flash(f"Demo verification link: {verify_link}", "success")
        return redirect(url_for("auth.login"))

    return render_template("signup.html")


@auth_bp.route("/verify-email/<token>")
def verify_email(token: str):
    ok, message, user_id = consume_email_verification_token(token)
    if ok:
        flash("Email verified successfully. You can now login.", "success")
        log_activity(user_id or "anonymous", "email_verify", "success", "Email verification complete")
    else:
        flash(message, "error")
        log_activity("anonymous", "email_verify", "failed", message)
    return redirect(url_for("auth.login"))


@auth_bp.route("/verify-email/resend", methods=["GET", "POST"])
def resend_verification():
    preview_link = ""
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        user = get_user_by_identity(identity)
        flash("If the account exists, a verification link has been issued.", "success")

        if user and user.get("email_verified") != "1":
            token = issue_email_verification_token(user["user_id"])
            if token:
                preview_link = url_for("auth.verify_email", token=token, _external=True)
                _deliver_security_mail(
                    to_email=user["email"],
                    subject="SecureChain email verification",
                    message="Use this link to verify your account.",
                    action_link=preview_link,
                )
                log_activity("anonymous", "email_verify_resend", "success", f"Identity={identity}")
            else:
                log_activity("anonymous", "email_verify_resend", "failed", f"Identity={identity}")
        else:
            log_activity("anonymous", "email_verify_resend", "success", "No-op or already verified")

    if preview_link and bool(current_app.config.get("AUTH_SHOW_TOKEN_HINTS", False)):
        flash(f"Demo verification link: {preview_link}", "success")
    return render_template("resend_verification.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identity = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role_portal = request.form.get("role_portal", "").strip().lower()
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
        limiter = current_app.config["LOGIN_LIMITER"]
        limit_key = f"{ip_address}:{identity.lower()}"

        blocked, wait_seconds = limiter.is_blocked(limit_key)
        if blocked:
            flash(f"Too many failed attempts. Try again in {wait_seconds} seconds.", "error")
            log_activity("anonymous", "login", "blocked", f"User {identity} blocked")
            push_alert_to_admins(
                severity="critical",
                category="auth",
                title="Login Throttling Triggered",
                message=f"Multiple failed login attempts for {identity} from {ip_address}.",
            )
            return redirect(url_for("auth.login"))

        user = get_user_by_identity(identity)
        if not user or not verify_password(password, user["password_hash"]):
            limiter.record_failure(limit_key)
            flash("Invalid username or password.", "error")
            log_activity("anonymous", "login", "failed", f"Bad credentials for {identity}")
            push_alert_to_admins(
                severity="warning",
                category="auth",
                title="Failed Login Attempt",
                message=f"Invalid credentials detected for {identity}.",
            )
            return redirect(url_for("auth.login"))

        if user["account_status"] != "active":
            flash("Account is not active. Contact administrator.", "error")
            log_activity(user["user_id"], "login", "failed", "Inactive account")
            return redirect(url_for("auth.login"))

        if role_portal in {"admin", "user"} and user["role"] != role_portal:
            limiter.record_failure(limit_key)
            flash("Use the correct login panel for this account type.", "error")
            log_activity(user["user_id"], "login", "failed", f"Panel-role mismatch: {role_portal}")
            return redirect(url_for("auth.login"))

        if bool(current_app.config.get("EMAIL_VERIFICATION_REQUIRED", True)) and user.get("email_verified") != "1":
            flash("Verify your email before login. Use resend verification if needed.", "error")
            log_activity(user["user_id"], "login", "failed", "Email not verified")
            return redirect(url_for("auth.login"))

        two_factor_enabled = (
            bool(current_app.config.get("ENABLE_2FA", False))
            and user.get("two_factor_enabled", "0") == "1"
            and bool(user.get("two_factor_secret"))
        )
        if two_factor_enabled:
            _clear_pending_2fa_session()
            session["pending_2fa_user_id"] = user["user_id"]
            session["pending_2fa_username"] = user["username"]
            session["pending_2fa_limit_key"] = limit_key
            session["pending_2fa_started_at"] = int(datetime.now(timezone.utc).timestamp())
            session["pending_2fa_portal"] = role_portal if role_portal in {"admin", "user"} else user["role"]
            session["last_seen"] = int(datetime.now(timezone.utc).timestamp())
            flash("Two-factor authentication required. Enter your verification code.", "success")
            log_activity(user["user_id"], "login", "success", "Password phase completed; waiting for 2FA")
            return redirect(url_for("auth.login_2fa"))

        limiter.record_success(limit_key)
        portal_hint = role_portal if role_portal in {"admin", "user"} else user["role"]
        _start_authenticated_session_for_portal(user, portal_hint=portal_hint)
        flash("Login successful.", "success")
        if portal_hint == "admin":
            return redirect(url_for("main.admin_dashboard", portal="admin"))
        return redirect(url_for("main.user_dashboard", user_id=user["user_id"], portal="user"))

    return render_template("login.html")


@auth_bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    if not bool(current_app.config.get("ENABLE_2FA", False)):
        _clear_pending_2fa_session()
        flash("Two-factor authentication is disabled.", "error")
        return redirect(url_for("auth.login"))

    user_id = session.get("pending_2fa_user_id", "")
    if not user_id:
        flash("2FA session expired. Login again.", "error")
        return redirect(url_for("auth.login"))

    started_at = int(session.get("pending_2fa_started_at", 0))
    max_window = max(60, int(current_app.config.get("TWO_FA_LOGIN_WINDOW_SECONDS", 300)))
    now_epoch = int(datetime.now(timezone.utc).timestamp())
    if not started_at or (now_epoch - started_at) > max_window:
        _clear_pending_2fa_session()
        flash("2FA session expired. Login again.", "error")
        return redirect(url_for("auth.login"))

    user = get_user_by_id(user_id)
    if not user or user.get("account_status") != "active":
        _clear_pending_2fa_session()
        flash("Account unavailable. Login again.", "error")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = sanitize_text(request.form.get("otp_code", ""), max_length=16)
        limiter = current_app.config["LOGIN_LIMITER"]
        limit_key = session.get("pending_2fa_limit_key", f"{request.remote_addr or 'unknown'}:{user['username'].lower()}")

        blocked, wait_seconds = limiter.is_blocked(limit_key)
        if blocked:
            flash(f"Too many failed attempts. Try again in {wait_seconds} seconds.", "error")
            log_activity(user["user_id"], "login_2fa", "blocked", f"User {user['username']} blocked")
            return redirect(url_for("auth.login_2fa"))

        secret = user_2fa_secret(user)
        if not secret or not verify_totp_code(secret, code):
            limiter.record_failure(limit_key)
            flash("Invalid 2FA code.", "error")
            log_activity(user["user_id"], "login_2fa", "failed", "Invalid OTP code")
            return redirect(url_for("auth.login_2fa"))

        limiter.record_success(limit_key)
        portal_hint = session.get("pending_2fa_portal", user.get("role", "user"))
        _clear_pending_2fa_session()
        _start_authenticated_session_for_portal(user, portal_hint=str(portal_hint))
        flash("Login successful.", "success")
        if str(portal_hint) == "admin":
            return redirect(url_for("main.admin_dashboard", portal="admin"))
        return redirect(url_for("main.user_dashboard", user_id=user["user_id"], portal="user"))

    return render_template("login_2fa.html", pending_username=session.get("pending_2fa_username", ""))

@auth_bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_two_factor():
    if not bool(current_app.config.get("ENABLE_2FA", False)):
        flash("Two-factor authentication is disabled by platform policy.", "error")
        return redirect(url_for("main.profile_page"))

    user = get_user_by_id(session["user_id"])
    if not user:
        flash("Session user not found.", "error")
        return redirect(url_for("auth.logout"))

    if bool(current_app.config.get("EMAIL_VERIFICATION_REQUIRED", True)) and user.get("email_verified") != "1":
        flash("Email verification required before enabling 2FA.", "error")
        return redirect(url_for("main.profile_page"))

    rotate = request.args.get("rotate", "0") == "1"
    pending_secret = session.get("pending_2fa_secret", "")
    if rotate or not pending_secret:
        pending_secret = generate_totp_secret()
        session["pending_2fa_secret"] = pending_secret

    provisioning_uri = _build_totp_uri(user["username"], pending_secret)
    qr_svg_data_uri = segno.make(provisioning_uri).svg_data_uri(scale=4)

    if request.method == "POST":
        code = sanitize_text(request.form.get("otp_code", ""), max_length=16)
        if not verify_totp_code(pending_secret, code):
            flash("Invalid verification code. Check authenticator clock and retry.", "error")
            return render_template(
                "two_factor_setup.html",
                pending_secret=pending_secret,
                provisioning_uri=provisioning_uri,
                qr_svg_data_uri=qr_svg_data_uri,
                already_enabled=(user.get("two_factor_enabled") == "1"),
            )

        if set_user_2fa_secret(user["user_id"], pending_secret):
            session.pop("pending_2fa_secret", None)
            flash("Two-factor authentication enabled.", "success")
            log_activity(user["user_id"], "2fa_enable", "success", "Authenticator app enrolled")
            return redirect(url_for("main.profile_page"))

        flash("Unable to enable 2FA right now.", "error")
        return redirect(url_for("main.profile_page"))

    return render_template(
        "two_factor_setup.html",
        pending_secret=pending_secret,
        provisioning_uri=provisioning_uri,
        qr_svg_data_uri=qr_svg_data_uri,
        already_enabled=(user.get("two_factor_enabled") == "1"),
    )


@auth_bp.route("/2fa/disable", methods=["POST"])
@login_required
def disable_two_factor():
    if not bool(current_app.config.get("ENABLE_2FA", False)):
        flash("Two-factor authentication is disabled by platform policy.", "error")
        return redirect(url_for("main.profile_page"))

    user = get_user_by_id(session["user_id"])
    if not user:
        flash("Session user not found.", "error")
        return redirect(url_for("auth.logout"))

    current_password = request.form.get("current_password", "")
    otp_code = sanitize_text(request.form.get("otp_code", ""), max_length=16)
    if not verify_password(current_password, user.get("password_hash", "")):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("main.profile_page"))

    secret = user_2fa_secret(user)
    if not secret or not verify_totp_code(secret, otp_code):
        flash("Invalid 2FA code.", "error")
        return redirect(url_for("main.profile_page"))

    if disable_user_2fa(user["user_id"]):
        flash("Two-factor authentication disabled.", "success")
        log_activity(user["user_id"], "2fa_disable", "success", "Authenticator app disabled")
    else:
        flash("Unable to disable 2FA.", "error")
    return redirect(url_for("main.profile_page"))


@auth_bp.route("/logout")
def logout():
    _synchronize_auth_context()
    requested_portal = request.args.get("portal", "").strip().lower()
    if requested_portal not in {"admin", "user"}:
        requested_portal = _portal_from_request() or str(session.get("active_portal", ""))

    user_id = session.get("user_id", "anonymous")
    contexts = session.get("auth_contexts", {})
    if isinstance(contexts, dict) and contexts:
        remove_portal = requested_portal if requested_portal in contexts else str(session.get("active_portal", ""))
        if remove_portal in contexts:
            removed = contexts.pop(remove_portal, {})
            if isinstance(removed, dict):
                user_id = str(removed.get("user_id") or user_id)
        if contexts:
            next_portal = "admin" if "admin" in contexts else next(iter(contexts.keys()))
            next_ctx = contexts[next_portal]
            session["auth_contexts"] = contexts
            session["active_portal"] = next_portal
            session["user_id"] = next_ctx.get("user_id", "")
            session["username"] = next_ctx.get("username", "")
            session["role"] = "admin" if next_ctx.get("role") == "admin" else "user"
            session["last_seen"] = int(datetime.now(timezone.utc).timestamp())
            _clear_pending_2fa_session()
            log_activity(user_id, "logout", "success", f"Portal {remove_portal or 'active'} session closed")
            if requested_portal in {"admin", "user"}:
                return redirect(url_for("auth.login", portal=requested_portal))
            return redirect(url_for("auth.login"))

    session.clear()
    log_activity(user_id, "logout", "success", "Session closed")
    if requested_portal in {"admin", "user"}:
        return redirect(url_for("auth.login", portal=requested_portal))
    return redirect(url_for("auth.login"))


@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    preview_link = ""
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        user = get_user_by_identity(identity)
        flash("If the account exists, a password reset link has been issued.", "success")

        if user:
            token = issue_password_reset_token(user["user_id"])
            if token:
                preview_link = url_for("auth.reset_password_confirm", token=token, _external=True)
                _deliver_security_mail(
                    to_email=user["email"],
                    subject="SecureChain password reset",
                    message="Use this secure link to reset your password.",
                    action_link=preview_link,
                )
                log_activity("anonymous", "password_reset_request", "success", f"Identity: {identity}")
            else:
                log_activity("anonymous", "password_reset_request", "failed", f"Identity: {identity}")
        else:
            log_activity("anonymous", "password_reset_request", "success", "Unknown identity")

    if preview_link and bool(current_app.config.get("AUTH_SHOW_TOKEN_HINTS", False)):
        flash(f"Demo reset link: {preview_link}", "success")
    return render_template("reset_password.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password_confirm(token: str):
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("auth.reset_password_confirm", token=token))

        password_error = _password_policy_error(password)
        if password_error:
            flash(password_error, "error")
            return redirect(url_for("auth.reset_password_confirm", token=token))

        ok, message = consume_password_reset_token(token, password)
        if ok:
            flash("Password reset successful. You can now login.", "success")
            log_activity("anonymous", "password_reset_confirm", "success", "Password reset complete")
            return redirect(url_for("auth.login"))
        flash(message, "error")
        log_activity("anonymous", "password_reset_confirm", "failed", message)
        return redirect(url_for("auth.reset_password"))

    return render_template("reset_password_confirm.html", token=token)

def _read_users(path: Path) -> List[Dict[str, str]]:
    with _users_lock:
        if not path.exists():
            return []
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            return list(csv.DictReader(csvfile))


def _write_users(path: Path, users: List[Dict[str, str]]) -> None:
    cleaned = [_normalize_user_row(user) for user in users]
    with _users_lock:
        with path.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=USER_FIELDS)
            writer.writeheader()
            writer.writerows(cleaned)


def _normalize_user_row(row: Dict[str, str]) -> Dict[str, str]:
    defaults = {
        "user_id": "",
        "username": "",
        "email": "",
        "password_hash": "",
        "role": "user",
        "last_login": "",
        "account_status": "active",
        "email_verified": "1",
        "email_verification_token_hash": "",
        "email_verification_expires_at": "",
        "reset_token_hash": "",
        "reset_token_expires_at": "",
        "two_factor_enabled": "0",
        "two_factor_secret": "",
        "delegated_admin_scopes": "",
        "delegated_admin_until": "",
        "delegated_admin_by": "",
        "delegated_admin_note": "",
        "delegated_admin_updated_at": "",
    }
    normalized = {key: str(row.get(key, defaults[key])) for key in USER_FIELDS}
    normalized["role"] = "admin" if normalized["role"] == "admin" else "user"
    normalized["account_status"] = "active" if normalized["account_status"] != "locked" else "locked"
    normalized["email_verified"] = "1" if normalized["email_verified"] == "1" else "0"
    normalized["two_factor_enabled"] = "1" if normalized["two_factor_enabled"] == "1" else "0"
    normalized["delegated_admin_scopes"] = sanitize_text(normalized.get("delegated_admin_scopes", ""), max_length=160)
    normalized["delegated_admin_until"] = sanitize_text(normalized.get("delegated_admin_until", ""), max_length=40)
    normalized["delegated_admin_by"] = sanitize_text(normalized.get("delegated_admin_by", ""), max_length=80)
    normalized["delegated_admin_note"] = sanitize_text(normalized.get("delegated_admin_note", ""), max_length=200)
    normalized["delegated_admin_updated_at"] = sanitize_text(
        normalized.get("delegated_admin_updated_at", ""), max_length=40
    )
    return normalized


def _start_authenticated_session(user: Dict[str, str]) -> None:
    _start_authenticated_session_for_portal(user, portal_hint=user.get("role", "user"))


def _start_authenticated_session_for_portal(user: Dict[str, str], portal_hint: str = "user") -> None:
    now_epoch = int(datetime.now(timezone.utc).timestamp())
    portal = "admin" if portal_hint == "admin" else "user"
    contexts = session.get("auth_contexts", {})
    if not isinstance(contexts, dict):
        contexts = {}
    contexts[portal] = {
        "user_id": user["user_id"],
        "username": user["username"],
        "role": "admin" if user.get("role") == "admin" else "user",
        "last_seen": now_epoch,
    }
    session["auth_contexts"] = contexts
    session["active_portal"] = portal
    session["user_id"] = user["user_id"]
    session["username"] = user["username"]
    session["role"] = "admin" if user.get("role") == "admin" else "user"
    session["last_seen"] = now_epoch
    
    # Only primary admin-role accounts can switch between admin/user dashboards.
    user_role = user.get("role", "user")
    if user_role == "admin":
        session["can_switch_dashboard"] = True
        session["switchable_role"] = "admin"
    else:
        session["can_switch_dashboard"] = False
        session.pop("switchable_role", None)
    
    _clear_pending_2fa_session()
    update_user_last_login(user["user_id"])
    log_activity(user["user_id"], "login", "success", "User authenticated")


def _clear_pending_2fa_session() -> None:
    for key in [
        "pending_2fa_user_id",
        "pending_2fa_username",
        "pending_2fa_limit_key",
        "pending_2fa_started_at",
        "pending_2fa_portal",
    ]:
        session.pop(key, None)


def _portal_from_request() -> str:
    candidate = request.args.get("portal", "").strip().lower()
    if candidate in {"admin", "user"}:
        return candidate
    path = (request.path or "").lower()
    if path.startswith("/dashboard/admin") or path.startswith("/admin"):
        return "admin"
    if path.startswith("/dashboard/user"):
        return "user"
    return ""


def _synchronize_auth_context() -> None:
    now_epoch = int(datetime.now(timezone.utc).timestamp())
    contexts = session.get("auth_contexts", {})
    if not isinstance(contexts, dict):
        contexts = {}

    # Backward compatibility with old single-context session payload.
    if not contexts and session.get("user_id"):
        role = "admin" if session.get("role") == "admin" else "user"
        contexts[role] = {
            "user_id": session.get("user_id", ""),
            "username": session.get("username", ""),
            "role": role,
            "last_seen": int(session.get("last_seen", now_epoch)),
        }

    if not contexts:
        return

    requested_portal = _portal_from_request()
    active_portal = session.get("active_portal", "")
    selected_portal = ""
    if requested_portal in contexts:
        selected_portal = requested_portal
    elif active_portal in contexts:
        selected_portal = str(active_portal)
    else:
        selected_portal = "admin" if "admin" in contexts else next(iter(contexts.keys()))

    context = contexts.get(selected_portal, {})
    if not isinstance(context, dict) or not context.get("user_id"):
        return

    context["last_seen"] = now_epoch
    contexts[selected_portal] = context
    session["auth_contexts"] = contexts
    session["active_portal"] = selected_portal
    session["user_id"] = context.get("user_id", "")
    session["username"] = context.get("username", "")
    session["role"] = "admin" if context.get("role") == "admin" else "user"
    session["last_seen"] = now_epoch


def _password_policy_error(password: str) -> str:
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if not any(ch.islower() for ch in password):
        return "Password must include at least one lowercase letter."
    if not any(ch.isupper() for ch in password):
        return "Password must include at least one uppercase letter."
    if not any(ch.isdigit() for ch in password):
        return "Password must include at least one number."
    if not any(not ch.isalnum() for ch in password):
        return "Password must include at least one special character."
    return ""


def _hash_token(token: str) -> str:
    pepper = str(current_app.config.get("SECRET_KEY", "securechain"))
    return hashlib.sha256(f"{pepper}:{token}".encode("utf-8")).hexdigest()


def _issue_email_verification_token_for_row(row: Dict[str, str]) -> str:
    raw_token = secrets.token_urlsafe(32)
    ttl_hours = max(1, int(current_app.config.get("AUTH_TOKEN_TTL_HOURS", 24)))
    row["email_verification_token_hash"] = _hash_token(raw_token)
    row["email_verification_expires_at"] = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
    row["email_verified"] = "0"
    return raw_token


def _parse_iso(raw: str) -> datetime | None:
    try:
        return datetime.fromisoformat(raw).astimezone(timezone.utc)
    except ValueError:
        return None


def _deliver_security_mail(to_email: str, subject: str, message: str, action_link: str = "") -> None:
    mail_path = Path(current_app.config["MAILBOX_LOG"])
    mail_path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "to": sanitize_text(to_email, max_length=120),
        "subject": sanitize_text(subject, max_length=120),
        "message": sanitize_text(message, max_length=260),
        "action_link": sanitize_text(action_link, max_length=260),
    }
    with mail_path.open("a", newline="", encoding="utf-8") as handle:
        handle.write(f"{row['timestamp']} | {row['to']} | {row['subject']} | {row['action_link']}\n")


def _build_totp_uri(username: str, secret: str) -> str:
    issuer = "SecureChain"
    label = quote(f"{issuer}:{username}")
    issuer_param = quote(issuer)
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer_param}&algorithm=SHA1&digits=6&period=30"
