from __future__ import annotations

import argparse
import csv
import io
import json
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.auth import create_user, get_user_by_username, set_user_email_verified


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


def _record(results: list[CheckResult], name: str, ok: bool, detail: str = "") -> None:
    results.append(CheckResult(name=name, ok=bool(ok), detail=detail))


def _csrf(client, path: str) -> str:
    client.get(path, follow_redirects=True)
    with client.session_transaction() as sess:
        return str(sess.get("_csrf_token", ""))


def _unique_suffix() -> str:
    return f"{int(time.time())}{int(time.perf_counter_ns()) % 100000:05d}"


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as csvfile:
        return list(csv.DictReader(csvfile))


def _count_jobs_by_type(path: Path, job_type: str) -> int:
    if not path.exists():
        return 0
    try:
        payload = json.loads(path.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError:
        return 0
    if not isinstance(payload, dict):
        return 0
    return len(
        [
            job
            for job in payload.values()
            if isinstance(job, dict) and str(job.get("job_type", "")) == job_type
        ]
    )


def _wait_for_integrity_job_increment(path: Path, baseline: int, timeout_s: float = 6.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _count_jobs_by_type(path, "integrity_scan") > baseline:
            return True
        time.sleep(0.05)
    return False


def _build_temp_app():
    base = Path(tempfile.mkdtemp(prefix="securechain-smoke-"))
    data_dir = base / "data"
    uploads_dir = base / "uploads"
    qr_dir = base / "qrcodes"
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "smoke-two-tabs-secret",
            "SERVER_NAME": "localhost",
            "DATA_DIR": data_dir,
            "UPLOAD_DIR": uploads_dir,
            "QR_DIR": qr_dir,
            "USERS_CSV": data_dir / "users.csv",
            "RECORDS_CSV": data_dir / "records.csv",
            "TRANSFERS_CSV": data_dir / "transfers.csv",
            "ACTIVITY_CSV": data_dir / "activity_log.csv",
            "BLOCKCHAIN_JSON": data_dir / "blockchain.json",
            "ANALYSIS_JSON": data_dir / "analysis_results.json",
            "NOTIFICATIONS_CSV": data_dir / "notifications.csv",
            "POLICY_JSON": data_dir / "security_policy.json",
            "API_KEYS_CSV": data_dir / "api_keys.csv",
            "INTEGRITY_SCANS_CSV": data_dir / "integrity_scans.csv",
            "INCIDENTS_CSV": data_dir / "incidents.csv",
            "RECORD_NOTES_CSV": data_dir / "record_notes.csv",
            "WATCHLIST_CSV": data_dir / "watchlist.csv",
            "USER_PREFERENCES_CSV": data_dir / "user_preferences.csv",
            "REVIEW_REQUESTS_CSV": data_dir / "review_requests.csv",
            "TWO_FACTOR_REVIEW_CSV": data_dir / "two_factor_reviews.csv",
            "USER_DRIVE_CSV": data_dir / "user_drive.csv",
            "USER_PROFILES_JSON": data_dir / "user_profiles.json",
            "ADMIN_SIGNUP_KEY": "TEST-ADMIN-KEY",
            "FERNET_KEY_FILE": data_dir / ".fernet.key",
            "MAILBOX_LOG": data_dir / "mailbox.log",
            "EMAIL_VERIFICATION_REQUIRED": True,
            "ENABLE_2FA": True,
            "AUTH_SHOW_TOKEN_HINTS": True,
            "ENABLE_DEMO_USERS": False,
            "JOBS_JSON": data_dir / "jobs.json",
            "JOB_ARTIFACT_DIR": data_dir / "job_artifacts",
            "JOB_WORKERS": 1,
            "SIEM_LOG": data_dir / "siem.log",
            "ERROR_LOG": data_dir / "error.log",
        }
    )
    return app, base


def _build_live_app():
    app = create_app({"TESTING": True, "SERVER_NAME": "localhost"})
    return app, None


def _setup_accounts(app, admin_username: str, admin_email: str, user_username: str, user_email: str, password: str) -> tuple[bool, str]:
    with app.app_context():
        ok, msg, _ = create_user(admin_username, admin_email, password, role="admin")
        if not ok:
            return False, f"admin create failed: {msg}"
        admin_user = get_user_by_username(admin_username)
        if not admin_user:
            return False, "admin lookup failed"
        set_user_email_verified(admin_user["user_id"], verified=True)

        ok, msg, _ = create_user(user_username, user_email, password, role="user")
        if not ok:
            return False, f"user create failed: {msg}"
        user = get_user_by_username(user_username)
        if not user:
            return False, "user lookup failed"
        set_user_email_verified(user["user_id"], verified=True)
    return True, ""


def _login(client, username: str, password: str, role_portal: str):
    token = _csrf(client, "/login")
    return client.post(
        "/login",
        data={
            "csrf_token": token,
            "role_portal": role_portal,
            "username": username,
            "password": password,
        },
        follow_redirects=True,
    )


def run_smoke(live_data: bool, password: str) -> tuple[list[CheckResult], str]:
    suffix = _unique_suffix()
    admin_username = f"smkadm{suffix[-6:]}"
    user_username = f"smkusr{suffix[-6:]}"
    admin_email = f"{admin_username}@example.local"
    user_email = f"{user_username}@example.local"

    app, temp_base = _build_live_app() if live_data else _build_temp_app()
    data_hint = str(Path(app.config["DATA_DIR"]))

    admin_client = app.test_client()
    user_client = app.test_client()
    anon_client = app.test_client()
    results: list[CheckResult] = []

    try:
        ok, msg = _setup_accounts(app, admin_username, admin_email, user_username, user_email, password)
        _record(results, "Create smoke accounts", ok, msg)
        if not ok:
            return results, data_hint

        admin_login = _login(admin_client, admin_username, password, "admin")
        _record(results, "Admin login", "Login successful" in admin_login.get_data(as_text=True))
        user_login = _login(user_client, user_username, password, "user")
        _record(results, "User login", "Login successful" in user_login.get_data(as_text=True))

        with admin_client.session_transaction() as sess:
            admin_id = str(sess.get("user_id", ""))
        with user_client.session_transaction() as sess:
            user_id = str(sess.get("user_id", ""))
        _record(results, "Session IDs available", bool(admin_id and user_id))

        user_dash = user_client.get(f"/dashboard/user/{user_id}?portal=user", follow_redirects=True)
        _record(results, "User dashboard", user_dash.status_code == 200 and "User Verification Workspace" in user_dash.get_data(as_text=True))
        user_profile = user_client.get("/profile?portal=user", follow_redirects=True)
        _record(results, "User profile", user_profile.status_code == 200)
        user_ai = user_client.get("/assistant?portal=user", follow_redirects=True)
        _record(results, "User AI page", user_ai.status_code == 200)
        user_chain = user_client.get("/blockchain?portal=user", follow_redirects=True)
        _record(results, "User blockchain page", user_chain.status_code == 200)

        user_upload_csrf = _csrf(user_client, f"/dashboard/user/{user_id}?portal=user")
        upload_resp = user_client.post(
            "/upload",
            data={
                "csrf_token": user_upload_csrf,
                "folder": "root",
                "document": (io.BytesIO(b"smoke-two-tabs-upload"), "smoke_two_tabs.txt"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        _record(results, "User upload", upload_resp.status_code == 200)

        drive_rows = _read_csv_rows(Path(app.config["USER_DRIVE_CSV"]))
        pending = [row for row in drive_rows if row.get("user_id") == user_id and row.get("status") == "pending"]
        drive_id = pending[-1]["drive_id"] if pending else ""
        _record(results, "Pending drive item", bool(drive_id), f"drive_id={drive_id}")

        admin_dash_csrf = _csrf(admin_client, "/dashboard/admin?portal=admin")
        approve_resp = admin_client.post(
            f"/admin/drive/{drive_id}/decision",
            data={
                "csrf_token": admin_dash_csrf,
                "decision": "approve",
                "admin_note": "smoke approval",
            },
            follow_redirects=True,
        )
        _record(results, "Admin approves upload", approve_resp.status_code == 200)

        record_rows = _read_csv_rows(Path(app.config["RECORDS_CSV"]))
        owned_records = [row for row in record_rows if row.get("owner_id") == user_id]
        verification_id = owned_records[-1]["verification_id"] if owned_records else ""
        _record(results, "Verification record created", bool(verification_id), f"vid={verification_id}")

        if verification_id:
            record_detail = user_client.get(f"/record/{verification_id}", follow_redirects=True)
            _record(results, "Record detail", record_detail.status_code == 200)
            public_verify = anon_client.get(f"/verify?verification_id={verification_id}", follow_redirects=True)
            _record(results, "Public verify", public_verify.status_code == 200)
            report_resp = user_client.get(f"/report/{verification_id}.pdf", follow_redirects=True)
            _record(results, "Report route", report_resp.status_code == 200)
            cert_resp = user_client.get(f"/certificate/{verification_id}.pdf", follow_redirects=True)
            _record(results, "Certificate route", cert_resp.status_code == 200)

        for name, path in [
            ("Admin dashboard", "/dashboard/admin?portal=admin"),
            ("Admin panel", "/admin?portal=admin"),
            ("Integrity center", "/admin/integrity-center?portal=admin"),
            ("Monitoring", "/admin/monitoring?portal=admin"),
            ("Jobs page", "/admin/jobs?portal=admin"),
            ("Compare lab", "/admin/compare?portal=admin"),
            ("Batch verify", "/verify/batch?portal=admin"),
        ]:
            resp = admin_client.get(path, follow_redirects=True)
            _record(results, name, resp.status_code == 200)

        jobs_path = Path(app.config["JOBS_JSON"])
        baseline_integrity_jobs = _count_jobs_by_type(jobs_path, "integrity_scan")
        scan_csrf = _csrf(admin_client, "/admin/integrity-center?portal=admin")
        scan_resp = admin_client.post(
            "/admin/integrity-scan/run",
            data={"csrf_token": scan_csrf},
            follow_redirects=True,
        )
        _record(results, "Enqueue integrity scan", scan_resp.status_code == 200 and "queued" in scan_resp.get_data(as_text=True).lower())
        _record(
            results,
            "Integrity job persisted",
            _wait_for_integrity_job_increment(jobs_path, baseline_integrity_jobs),
        )

        blocked_admin = user_client.get("/admin", follow_redirects=True)
        blocked_admin_body = blocked_admin.get_data(as_text=True)
        _record(
            results,
            "User blocked from /admin",
            blocked_admin.status_code == 200 and "You do not have permission for that action." in blocked_admin_body,
        )
        blocked_admin_dash = user_client.get("/dashboard/admin", follow_redirects=False)
        _record(
            results,
            "User blocked from /dashboard/admin",
            blocked_admin_dash.status_code in {301, 302} and "portal=user" in str(blocked_admin_dash.headers.get("Location", "")),
        )

        public_upload = anon_client.get("/upload/public", follow_redirects=True)
        _record(results, "Public upload page", public_upload.status_code == 200)
        public_verify_page = anon_client.get("/verify", follow_redirects=True)
        _record(results, "Public verify page", public_verify_page.status_code == 200)

        return results, data_hint
    finally:
        # Best-effort cleanup for temporary runs only.
        if temp_base is not None:
            shutil.rmtree(temp_base, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SecureChain two-tab smoke checks (admin + user).")
    parser.add_argument(
        "--live-data",
        action="store_true",
        help="Run against the app's live data directory instead of isolated temp data.",
    )
    parser.add_argument(
        "--password",
        default="StrongPass!123",
        help="Password used for generated smoke users.",
    )
    args = parser.parse_args()

    results, data_hint = run_smoke(live_data=args.live_data, password=args.password)
    passed = [item for item in results if item.ok]
    failed = [item for item in results if not item.ok]

    mode = "LIVE DATA" if args.live_data else "TEMP DATA"
    print(f"SMOKE TEST REPORT ({mode})")
    print(f"Data dir: {data_hint}")
    for item in results:
        prefix = "PASS" if item.ok else "FAIL"
        detail = f" | {item.detail}" if item.detail else ""
        print(f"[{prefix}] {item.name}{detail}")
    print(f"TOTAL={len(results)} PASS={len(passed)} FAIL={len(failed)}")

    if failed:
        print("FAILED ITEMS:")
        for item in failed:
            detail = f" | {item.detail}" if item.detail else ""
            print(f" - {item.name}{detail}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
