from __future__ import annotations

import csv
import json
import re
import tempfile
import time
import unittest
from pathlib import Path

from app import create_app
from app.auth import get_user_by_username
from app.jobs import get_job_queue
from app.monitoring import emit_event, monitoring_metrics, read_events
from app.security import generate_totp_code, generate_totp_secret, hash_password, verify_password, verify_totp_code


class BaseSecureChainTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        base = Path(self.temp_dir.name)
        data_dir = base / "data"
        uploads_dir = base / "uploads"
        qr_dir = base / "qrcodes"

        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key",
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
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _csrf(self, path: str) -> str:
        self.client.get(path, follow_redirects=True)
        with self.client.session_transaction() as sess:
            return str(sess.get("_csrf_token", ""))

    def _extract_token(self, response_text: str, route_prefix: str) -> str:
        pattern = rf"{re.escape(route_prefix)}/([A-Za-z0-9_\\-]+)"
        match = re.search(pattern, response_text)
        if not match:
            return ""
        return match.group(1)

    def _signup_user(self, username: str, email: str, password: str = "StrongPass!123") -> str:
        csrf = self._csrf("/signup")
        response = self.client.post(
            "/signup",
            data={
                "csrf_token": csrf,
                "role_portal": "user",
                "username": username,
                "email": email,
                "password": password,
                "confirm_password": password,
            },
            follow_redirects=True,
        )
        body = response.get_data(as_text=True)
        token = self._extract_token(body, "/verify-email")
        self.assertTrue(token, "Verification token link should be present in demo mode.")
        return token

    def _verify_email(self, token: str) -> None:
        response = self.client.get(f"/verify-email/{token}", follow_redirects=True)
        self.assertIn("Email verified successfully", response.get_data(as_text=True))

    def _login(self, identity: str, password: str, role: str = "user", follow_redirects: bool = True):
        csrf = self._csrf("/login")
        return self.client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "role_portal": role,
                "username": identity,
                "password": password,
            },
            follow_redirects=follow_redirects,
        )


class UnitSecurityTests(BaseSecureChainTest):
    def test_password_hash_roundtrip(self):
        hashed = hash_password("Abcd!12345")
        self.assertTrue(verify_password("Abcd!12345", hashed))
        self.assertFalse(verify_password("wrong", hashed))

    def test_totp_generation_and_verification(self):
        secret = generate_totp_secret()
        code = generate_totp_code(secret)
        self.assertTrue(verify_totp_code(secret, code))
        self.assertFalse(verify_totp_code(secret, "000000"))

    def test_monitoring_metrics_collects_events(self):
        with self.app.app_context():
            emit_event("http_request", severity="info", duration_ms=25, path="/health")
            emit_event("activity", severity="warning", action="login", status="failed")
            metrics = monitoring_metrics(window_hours=24)
            self.assertGreaterEqual(metrics["request_events"], 1)
            self.assertGreaterEqual(metrics["auth_failures"], 1)
            events = read_events(limit=5)
            self.assertGreaterEqual(len(events), 1)

    def test_background_queue_executes_job(self):
        with self.app.app_context():
            queue = get_job_queue()
            self.assertIsNotNone(queue)
            assert queue is not None

            queue.register_handler("unit_ping", lambda payload, _job: {"echo": payload.get("value", "")})
            job_id = queue.submit("unit_ping", {"value": "pong"}, requested_by="tester")

            for _ in range(40):
                job = queue.get(job_id)
                if job and job.get("status") in {"completed", "failed"}:
                    break
                time.sleep(0.05)

            job = queue.get(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job.get("status"), "completed")
            result = job.get("result", {})
            self.assertEqual(result.get("echo"), "pong")

    def test_integrity_scan_job_updates_scan_history(self):
        with self.app.app_context():
            queue = get_job_queue()
            self.assertIsNotNone(queue)
            assert queue is not None

            job_id = queue.submit(
                "integrity_scan",
                {"run_by": "tester001", "run_by_username": "Tester"},
                requested_by="tester001",
            )

            for _ in range(40):
                job = queue.get(job_id)
                if job and job.get("status") in {"completed", "failed"}:
                    break
                time.sleep(0.05)

            job = queue.get(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job.get("status"), "completed")
            result = job.get("result", {})
            self.assertTrue(result.get("scan_id"))

            with Path(self.app.config["INTEGRITY_SCANS_CSV"]).open("r", newline="", encoding="utf-8") as csvfile:
                rows = list(csv.DictReader(csvfile))
            self.assertGreaterEqual(len(rows), 1)
            self.assertEqual(rows[-1].get("scan_id", ""), str(result.get("scan_id", "")))


class IntegrationAuthTests(BaseSecureChainTest):
    def test_signup_verify_and_login_flow(self):
        token = self._signup_user("alice", "alice@example.com")

        blocked = self._login("alice", "StrongPass!123", role="user", follow_redirects=True)
        self.assertIn("Verify your email before login", blocked.get_data(as_text=True))

        self._verify_email(token)
        ok = self._login("alice", "StrongPass!123", role="user", follow_redirects=True)
        self.assertIn("Login successful", ok.get_data(as_text=True))

    def test_admin_user_portal_renders_user_navigation(self):
        csrf = self._csrf("/signup")
        signup = self.client.post(
            "/signup",
            data={
                "csrf_token": csrf,
                "role_portal": "admin",
                "username": "navadmin",
                "email": "navadmin@example.com",
                "password": "AdminPass!123",
                "confirm_password": "AdminPass!123",
                "admin_access_key": "TEST-ADMIN-KEY",
            },
            follow_redirects=True,
        )
        token = self._extract_token(signup.get_data(as_text=True), "/verify-email")
        self.assertTrue(token)
        self._verify_email(token)

        admin_login = self._login("navadmin", "AdminPass!123", role="admin", follow_redirects=True)
        self.assertIn("Login successful", admin_login.get_data(as_text=True))

        with self.client.session_transaction() as sess:
            user_id = str(sess.get("user_id", ""))
        self.assertTrue(user_id)

        response = self.client.get(f"/dashboard/user/{user_id}?portal=user", follow_redirects=True)
        body = response.get_data(as_text=True)
        self.assertIn("Switch to Admin", body)
        self.assertIn("Batch Upload", body)
        self.assertNotIn("SOC Dashboard", body)

    def test_user_cannot_access_admin_panel(self):
        token = self._signup_user("plainuser", "plainuser@example.com")
        self._verify_email(token)
        self._login("plainuser", "StrongPass!123", role="user", follow_redirects=True)

        admin_dash = self.client.get("/dashboard/admin", follow_redirects=False)
        self.assertEqual(admin_dash.status_code, 302)
        self.assertIn("/dashboard?portal=user", admin_dash.headers.get("Location", ""))

        admin_panel = self.client.get("/admin", follow_redirects=True)
        body = admin_panel.get_data(as_text=True)
        self.assertIn("You do not have permission for that action.", body)
        self.assertIn("User Verification Workspace", body)
        self.assertNotIn("Admin Control Panel", body)

    def test_dashboard_refresh_has_no_redirect_bounce_and_no_store_cache(self):
        token = self._signup_user("refreshuser", "refreshuser@example.com")
        self._verify_email(token)
        self._login("refreshuser", "StrongPass!123", role="user", follow_redirects=True)

        dashboard = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(dashboard.status_code, 302)
        self.assertIn("/dashboard/user/", dashboard.headers.get("Location", ""))

        canonical = self.client.get(dashboard.headers.get("Location", "/dashboard"), follow_redirects=False)
        self.assertEqual(canonical.status_code, 200)
        self.assertIn("no-store", canonical.headers.get("Cache-Control", ""))

        user_dash = self.client.get("/dashboard/user", follow_redirects=False)
        self.assertEqual(user_dash.status_code, 200)

    def test_password_reset_token_flow(self):
        token = self._signup_user("bob", "bob@example.com")
        self._verify_email(token)

        csrf = self._csrf("/reset-password")
        request_reset = self.client.post(
            "/reset-password",
            data={"csrf_token": csrf, "identity": "bob"},
            follow_redirects=True,
        )
        reset_token = self._extract_token(request_reset.get_data(as_text=True), "/reset-password")
        self.assertTrue(reset_token, "Reset token should be present in demo mode.")

        csrf_confirm = self._csrf(f"/reset-password/{reset_token}")
        confirm = self.client.post(
            f"/reset-password/{reset_token}",
            data={
                "csrf_token": csrf_confirm,
                "password": "ChangedPass!123",
                "confirm_password": "ChangedPass!123",
            },
            follow_redirects=True,
        )
        self.assertIn("Password reset successful", confirm.get_data(as_text=True))

        login = self._login("bob", "ChangedPass!123", role="user", follow_redirects=True)
        self.assertIn("Login successful", login.get_data(as_text=True))

    def test_optional_2fa_end_to_end(self):
        token = self._signup_user("carol", "carol@example.com")
        self._verify_email(token)
        self._login("carol", "StrongPass!123", role="user", follow_redirects=True)

        setup_page = self.client.get("/2fa/setup", follow_redirects=True)
        self.assertIn("Authenticator 2FA Setup", setup_page.get_data(as_text=True))
        with self.client.session_transaction() as sess:
            setup_secret = str(sess.get("pending_2fa_secret", ""))
            csrf = str(sess.get("_csrf_token", ""))
        self.assertTrue(setup_secret)
        otp_code = generate_totp_code(setup_secret)
        enable = self.client.post(
            "/2fa/setup",
            data={"csrf_token": csrf, "otp_code": otp_code},
            follow_redirects=True,
        )
        self.assertIn("Two-factor authentication enabled", enable.get_data(as_text=True))

        self.client.get("/logout", follow_redirects=True)
        phase_one = self._login("carol", "StrongPass!123", role="user", follow_redirects=False)
        self.assertEqual(phase_one.status_code, 302)
        self.assertIn("/login/2fa", phase_one.headers.get("Location", ""))

        self.client.get("/login/2fa", follow_redirects=True)
        with self.client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        phase_two = self.client.post(
            "/login/2fa",
            data={"csrf_token": csrf, "otp_code": generate_totp_code(setup_secret)},
            follow_redirects=True,
        )
        self.assertIn("Login successful", phase_two.get_data(as_text=True))

    def test_admin_manual_2fa_review_grants_delegated_access(self):
        user_client = self.app.test_client()
        admin_client = self.app.test_client()

        # Create and verify admin account.
        user_client.get("/signup", follow_redirects=True)
        with user_client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        admin_signup = user_client.post(
            "/signup",
            data={
                "csrf_token": csrf,
                "role_portal": "admin",
                "username": "boss",
                "email": "boss@example.com",
                "password": "BossPass!123",
                "confirm_password": "BossPass!123",
                "admin_access_key": "TEST-ADMIN-KEY",
            },
            follow_redirects=True,
        )
        admin_verify_token = self._extract_token(admin_signup.get_data(as_text=True), "/verify-email")
        self.assertTrue(admin_verify_token)
        user_client.get(f"/verify-email/{admin_verify_token}", follow_redirects=True)

        # Create and verify user account.
        token = self._signup_user("delegate_user", "delegate@example.com")
        self._verify_email(token)
        user_client.get("/login", follow_redirects=True)
        with user_client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        user_client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "role_portal": "user",
                "username": "delegate_user",
                "password": "StrongPass!123",
            },
            follow_redirects=True,
        )

        # Enable 2FA for user.
        setup_page = user_client.get("/2fa/setup", follow_redirects=True)
        self.assertIn("Authenticator 2FA Setup", setup_page.get_data(as_text=True))
        with user_client.session_transaction() as sess:
            setup_secret = str(sess.get("pending_2fa_secret", ""))
            csrf = str(sess.get("_csrf_token", ""))
        user_client.post(
            "/2fa/setup",
            data={"csrf_token": csrf, "otp_code": generate_totp_code(setup_secret)},
            follow_redirects=True,
        )

        # Submit manual review request with code.
        user_client.get("/profile", follow_redirects=True)
        with user_client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        user_client.post(
            "/2fa/manual-review/request",
            data={
                "csrf_token": csrf,
                "otp_code": generate_totp_code(setup_secret),
                "reason": "Need delegated verify task",
            },
            follow_redirects=True,
        )

        # Read request id from CSV.
        queue_file = Path(self.app.config["TWO_FACTOR_REVIEW_CSV"])
        with queue_file.open("r", newline="", encoding="utf-8") as csvfile:
            queue_rows = list(csv.DictReader(csvfile))
        self.assertGreaterEqual(len(queue_rows), 1)
        request_id = queue_rows[-1].get("request_id", "")
        self.assertEqual(queue_rows[-1].get("otp_validated"), "1")
        self.assertTrue(request_id)

        # Login admin and approve request.
        admin_client.get("/login", follow_redirects=True)
        with admin_client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        admin_client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "role_portal": "admin",
                "username": "boss",
                "password": "BossPass!123",
            },
            follow_redirects=True,
        )
        admin_client.get("/dashboard/admin", follow_redirects=True)
        with admin_client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        admin_client.post(
            f"/admin/2fa-review/{request_id}/decision",
            data={
                "csrf_token": csrf,
                "decision": "approved",
                "delegated_scopes": "verify_batch,compare_lab",
                "delegated_hours": "4",
                "admin_note": "Approved by manager",
            },
            follow_redirects=True,
        )

        # Delegated user can access batch verify.
        batch_page = user_client.get("/verify/batch", follow_redirects=True)
        self.assertEqual(batch_page.status_code, 200)
        self.assertIn("Batch", batch_page.get_data(as_text=True))

    def test_manual_2fa_request_allows_unvalidated_submission(self):
        token = self._signup_user("invalidotp", "invalidotp@example.com")
        self._verify_email(token)
        self._login("invalidotp", "StrongPass!123", role="user", follow_redirects=True)

        # Enable 2FA for user first.
        setup_page = self.client.get("/2fa/setup", follow_redirects=True)
        self.assertIn("Authenticator 2FA Setup", setup_page.get_data(as_text=True))
        with self.client.session_transaction() as sess:
            setup_secret = str(sess.get("pending_2fa_secret", ""))
            csrf = str(sess.get("_csrf_token", ""))
        self.client.post(
            "/2fa/setup",
            data={"csrf_token": csrf, "otp_code": generate_totp_code(setup_secret)},
            follow_redirects=True,
        )

        # Submit an invalid OTP for manual admin verification.
        self.client.get("/profile", follow_redirects=True)
        with self.client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        invalid_request = self.client.post(
            "/2fa/manual-review/request",
            data={"csrf_token": csrf, "otp_code": "000000", "reason": "test invalid otp"},
            follow_redirects=True,
        )
        self.assertIn("submitted without auto-validation", invalid_request.get_data(as_text=True))

        queue_file = Path(self.app.config["TWO_FACTOR_REVIEW_CSV"])
        with queue_file.open("r", newline="", encoding="utf-8") as csvfile:
            rows = list(csv.DictReader(csvfile))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("otp_validated"), "0")

    def test_manual_2fa_request_allowed_without_2fa_enabled(self):
        token = self._signup_user("manualno2fa", "manualno2fa@example.com")
        self._verify_email(token)
        self._login("manualno2fa", "StrongPass!123", role="user", follow_redirects=True)

        # User has no 2FA enabled but should still be able to submit a manual request.
        self.client.get("/profile", follow_redirects=True)
        with self.client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        response = self.client.post(
            "/2fa/manual-review/request",
            data={
                "csrf_token": csrf,
                "otp_code": "",
                "reason": "Need manager-reviewed manual access for urgent filing.",
            },
            follow_redirects=True,
        )
        body = response.get_data(as_text=True)
        self.assertIn("Manual request submitted", body)

        queue_file = Path(self.app.config["TWO_FACTOR_REVIEW_CSV"])
        with queue_file.open("r", newline="", encoding="utf-8") as csvfile:
            rows = list(csv.DictReader(csvfile))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("otp_validated"), "0")

    def test_force_approve_requires_ack_and_note_then_grants_access(self):
        user_client = self.app.test_client()
        admin_client = self.app.test_client()

        # Create and verify admin account.
        user_client.get("/signup", follow_redirects=True)
        with user_client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        admin_signup = user_client.post(
            "/signup",
            data={
                "csrf_token": csrf,
                "role_portal": "admin",
                "username": "forceboss",
                "email": "forceboss@example.com",
                "password": "BossPass!123",
                "confirm_password": "BossPass!123",
                "admin_access_key": "TEST-ADMIN-KEY",
            },
            follow_redirects=True,
        )
        admin_verify_token = self._extract_token(admin_signup.get_data(as_text=True), "/verify-email")
        self.assertTrue(admin_verify_token)
        user_client.get(f"/verify-email/{admin_verify_token}", follow_redirects=True)

        # Create and verify user account.
        token = self._signup_user("force_user", "force_user@example.com")
        self._verify_email(token)
        user_client.get("/login", follow_redirects=True)
        with user_client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        user_client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "role_portal": "user",
                "username": "force_user",
                "password": "StrongPass!123",
            },
            follow_redirects=True,
        )

        # Enable 2FA for user.
        setup_page = user_client.get("/2fa/setup", follow_redirects=True)
        self.assertIn("Authenticator 2FA Setup", setup_page.get_data(as_text=True))
        with user_client.session_transaction() as sess:
            setup_secret = str(sess.get("pending_2fa_secret", ""))
            csrf = str(sess.get("_csrf_token", ""))
        user_client.post(
            "/2fa/setup",
            data={"csrf_token": csrf, "otp_code": generate_totp_code(setup_secret)},
            follow_redirects=True,
        )

        # Submit manual review request.
        user_client.get("/profile", follow_redirects=True)
        with user_client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        user_client.post(
            "/2fa/manual-review/request",
            data={
                "csrf_token": csrf,
                "otp_code": generate_totp_code(setup_secret),
                "reason": "Need urgent access for operations",
            },
            follow_redirects=True,
        )

        # Mutate queue row to simulate unvalidated/stale OTP (legacy scenario).
        queue_file = Path(self.app.config["TWO_FACTOR_REVIEW_CSV"])
        with queue_file.open("r", newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            fieldnames = reader.fieldnames or []
            queue_rows = list(reader)
        self.assertGreaterEqual(len(queue_rows), 1)
        queue_rows[-1]["otp_validated"] = "0"
        queue_rows[-1]["otp_validated_at"] = ""
        queue_rows[-1]["otp_code"] = "000000"
        request_id = queue_rows[-1].get("request_id", "")
        with queue_file.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(queue_rows)
        self.assertTrue(request_id)

        # Login admin.
        admin_client.get("/login", follow_redirects=True)
        with admin_client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        admin_client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "role_portal": "admin",
                "username": "forceboss",
                "password": "BossPass!123",
            },
            follow_redirects=True,
        )

        # Force approval without explicit acknowledgment must fail.
        admin_client.get("/dashboard/admin", follow_redirects=True)
        with admin_client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        missing_ack = admin_client.post(
            f"/admin/2fa-review/{request_id}/decision",
            data={
                "csrf_token": csrf,
                "decision": "force_approved",
                "delegated_scopes": "verify_batch",
                "delegated_hours": "4",
                "admin_note": "Emergency override justification",
            },
            follow_redirects=True,
        )
        self.assertIn("Force approve requires explicit confirmation", missing_ack.get_data(as_text=True))

        # Force approval with short note must fail.
        admin_client.get("/dashboard/admin", follow_redirects=True)
        with admin_client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        weak_note = admin_client.post(
            f"/admin/2fa-review/{request_id}/decision",
            data={
                "csrf_token": csrf,
                "decision": "force_approved",
                "force_ack": "1",
                "delegated_scopes": "verify_batch",
                "delegated_hours": "4",
                "admin_note": "too short",
            },
            follow_redirects=True,
        )
        self.assertIn("minimum 12 characters", weak_note.get_data(as_text=True))

        # Proper force approval succeeds.
        admin_client.get("/dashboard/admin", follow_redirects=True)
        with admin_client.session_transaction() as sess:
            csrf = str(sess.get("_csrf_token", ""))
        approved = admin_client.post(
            f"/admin/2fa-review/{request_id}/decision",
            data={
                "csrf_token": csrf,
                "decision": "force_approved",
                "force_ack": "1",
                "delegated_scopes": "verify_batch",
                "delegated_hours": "4",
                "admin_note": "Emergency operations continuity override approved by manager.",
            },
            follow_redirects=True,
        )
        self.assertIn("Force approval applied", approved.get_data(as_text=True))

        # Queue row stores force-approve audit fields.
        with queue_file.open("r", newline="", encoding="utf-8") as csvfile:
            rows = list(csv.DictReader(csvfile))
        self.assertGreaterEqual(len(rows), 1)
        target = next((row for row in rows if row.get("request_id") == request_id), {})
        self.assertEqual(target.get("status"), "approved")
        self.assertEqual(target.get("force_approved"), "1")
        self.assertTrue(target.get("force_approved_at"))
        self.assertTrue(target.get("force_approved_by"))

        # Delegated user can access batch verify.
        batch_page = user_client.get("/verify/batch", follow_redirects=True)
        self.assertEqual(batch_page.status_code, 200)
        self.assertIn("Batch", batch_page.get_data(as_text=True))


class SecurityRegressionTests(BaseSecureChainTest):
    def test_csrf_missing_token_blocks_signup(self):
        response = self.client.post(
            "/signup",
            data={
                "role_portal": "user",
                "username": "mallory",
                "email": "mallory@example.com",
                "password": "StrongPass!123",
                "confirm_password": "StrongPass!123",
            },
            follow_redirects=True,
        )
        self.assertIn("Security token expired", response.get_data(as_text=True))
        with self.app.app_context():
            self.assertIsNone(get_user_by_username("mallory"))

    def test_login_attempt_lockout(self):
        token = self._signup_user("lockuser", "lock@example.com")
        self._verify_email(token)

        for _ in range(5):
            self._login("lockuser", "WrongPass!123", role="user", follow_redirects=True)
        blocked = self._login("lockuser", "StrongPass!123", role="user", follow_redirects=True)
        self.assertIn("Too many failed attempts", blocked.get_data(as_text=True))

    def test_siem_log_contains_activity_events(self):
        token = self._signup_user("siemuser", "siem@example.com")
        self._verify_email(token)
        self._login("siemuser", "StrongPass!123", role="user", follow_redirects=True)

        with self.app.app_context():
            siem_path = Path(self.app.config["SIEM_LOG"])
            lines = [line for line in siem_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertGreater(len(lines), 0)
            parsed = [json.loads(line) for line in lines]
            self.assertTrue(any(row.get("event_type") == "activity" for row in parsed))


if __name__ == "__main__":
    unittest.main()
