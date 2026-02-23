from __future__ import annotations

import csv
import json
import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

from flask import current_app

from .ai_engine import generate_certificate_pdf, generate_report_pdf, get_analysis, run_analysis_job
from .alerts import push_alert_to_admins
from .blockchain import find_blocks_by_verification_id, validate_chain
from .monitoring import emit_event
from .security import calculate_sha256, generate_verification_id, log_activity, read_encrypted_file


JobHandler = Callable[[Dict[str, object], Dict[str, object]], Dict[str, object] | None]
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
_integrity_scan_lock = threading.Lock()


class BackgroundJobQueue:
    def __init__(
        self,
        app,
        storage_file: Path,
        artifact_dir: Path,
        worker_count: int = 2,
    ) -> None:
        self._app = app
        self._storage_file = storage_file
        self._artifact_dir = artifact_dir
        self._worker_count = max(1, int(worker_count))
        self._handlers: Dict[str, JobHandler] = {}
        self._jobs: Dict[str, Dict[str, object]] = {}
        self._queue: queue.Queue[str] = queue.Queue()
        self._lock = threading.Lock()
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        self._storage_file.parent.mkdir(parents=True, exist_ok=True)
        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        self._load_jobs()
        self._started = True
        for idx in range(self._worker_count):
            worker = threading.Thread(
                target=self._run_worker,
                name=f"securechain-worker-{idx + 1}",
                daemon=True,
            )
            worker.start()

    def register_handler(self, job_type: str, handler: JobHandler) -> None:
        self._handlers[job_type] = handler

    def submit(
        self,
        job_type: str,
        payload: Dict[str, object],
        requested_by: str = "system",
    ) -> str:
        job_id = _generate_job_id()
        now = datetime.now(timezone.utc).isoformat()
        job = {
            "job_id": job_id,
            "job_type": str(job_type),
            "status": "queued",
            "requested_by": str(requested_by),
            "payload": payload,
            "result": {},
            "error": "",
            "created_at": now,
            "started_at": "",
            "finished_at": "",
        }
        with self._lock:
            self._jobs[job_id] = job
            self._persist_jobs()
        self._queue.put(job_id)
        with self._app.app_context():
            emit_event(
                "job_submit",
                severity="info",
                message=f"Background job queued: {job_type}",
                job_id=job_id,
                job_type=job_type,
                requested_by=requested_by,
            )
        return job_id

    def get(self, job_id: str) -> Optional[Dict[str, object]]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            return _clone_job(job)

    def list(
        self,
        limit: int = 120,
        job_type: str | None = None,
        status: str | None = None,
    ) -> List[Dict[str, object]]:
        with self._lock:
            rows = [_clone_job(job) for job in self._jobs.values()]
        if job_type:
            rows = [row for row in rows if row.get("job_type") == job_type]
        if status:
            rows = [row for row in rows if row.get("status") == status]
        rows = sorted(rows, key=lambda row: str(row.get("created_at", "")), reverse=True)
        return rows[:limit]

    def stats(self) -> Dict[str, int]:
        with self._lock:
            rows = list(self._jobs.values())
        return {
            "queued": len([row for row in rows if row.get("status") == "queued"]),
            "running": len([row for row in rows if row.get("status") == "running"]),
            "completed": len([row for row in rows if row.get("status") == "completed"]),
            "failed": len([row for row in rows if row.get("status") == "failed"]),
            "total": len(rows),
        }

    def latest_completed(
        self,
        job_type: str,
        verification_id: str,
    ) -> Optional[Dict[str, object]]:
        verification_id = verification_id.upper().strip()
        jobs = self.list(limit=600, job_type=job_type, status="completed")
        for row in jobs:
            payload = row.get("payload", {})
            if not isinstance(payload, dict):
                continue
            if str(payload.get("verification_id", "")).upper() == verification_id:
                return row
        return None

    def artifact_path(self, job_id: str) -> Optional[Path]:
        job = self.get(job_id)
        if not job:
            return None
        result = job.get("result", {})
        if not isinstance(result, dict):
            return None
        artifact_name = str(result.get("artifact_name", "")).strip()
        if not artifact_name:
            return None
        path = self._artifact_dir / artifact_name
        return path if path.exists() else None

    def _run_worker(self) -> None:
        while True:
            job_id = self._queue.get()
            try:
                self._execute(job_id)
            finally:
                self._queue.task_done()

    def _execute(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = "running"
            job["started_at"] = datetime.now(timezone.utc).isoformat()
            job["error"] = ""
            self._persist_jobs()
            snapshot = _clone_job(job)

        handler = self._handlers.get(str(snapshot.get("job_type", "")))
        if not handler:
            error = f"No handler registered for {snapshot.get('job_type', 'unknown')}."
            self._mark_failed(job_id, error)
            return

        try:
            with self._app.app_context():
                result = handler(dict(snapshot.get("payload", {})), snapshot) or {}
                emit_event(
                    "job_completed",
                    severity="info",
                    message=f"Background job completed: {snapshot.get('job_type')}",
                    job_id=job_id,
                    job_type=snapshot.get("job_type", ""),
                    requested_by=snapshot.get("requested_by", ""),
                )
            self._mark_completed(job_id, result)
        except Exception as err:  # pragma: no cover - defensive runtime guard
            with self._app.app_context():
                emit_event(
                    "job_failed",
                    severity="error",
                    message=f"Background job failed: {snapshot.get('job_type')}",
                    job_id=job_id,
                    job_type=snapshot.get("job_type", ""),
                    requested_by=snapshot.get("requested_by", ""),
                    error=str(err),
                )
            self._mark_failed(job_id, str(err))

    def _mark_completed(self, job_id: str, result: Dict[str, object]) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = "completed"
            job["finished_at"] = datetime.now(timezone.utc).isoformat()
            job["result"] = result
            job["error"] = ""
            self._persist_jobs()

    def _mark_failed(self, job_id: str, error: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = "failed"
            job["finished_at"] = datetime.now(timezone.utc).isoformat()
            job["error"] = str(error)[:260]
            self._persist_jobs()

    def _load_jobs(self) -> None:
        if not self._storage_file.exists():
            self._storage_file.write_text("{}", encoding="utf-8")
            self._jobs = {}
            return
        try:
            raw = self._storage_file.read_text(encoding="utf-8")
            loaded = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            loaded = {}

        self._jobs = {}
        for job_id, job in loaded.items():
            if not isinstance(job, dict):
                continue
            normalized = _clone_job(job)
            if normalized.get("status") == "running":
                normalized["status"] = "queued"
                normalized["started_at"] = ""
            self._jobs[str(job_id)] = normalized
            if normalized.get("status") == "queued":
                self._queue.put(str(job_id))
        self._persist_jobs()

    def _persist_jobs(self) -> None:
        payload = {job_id: job for job_id, job in self._jobs.items()}
        self._storage_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def init_job_queue(app) -> None:
    queue_obj = BackgroundJobQueue(
        app=app,
        storage_file=Path(app.config["JOBS_JSON"]),
        artifact_dir=Path(app.config["JOB_ARTIFACT_DIR"]),
        worker_count=int(app.config.get("JOB_WORKERS", 2)),
    )
    queue_obj.register_handler("ai_analysis", _handle_ai_analysis)
    queue_obj.register_handler("report_pdf", _handle_report_pdf)
    queue_obj.register_handler("certificate_pdf", _handle_certificate_pdf)
    queue_obj.register_handler("integrity_scan", _handle_integrity_scan)
    queue_obj.start()
    app.config["JOB_QUEUE"] = queue_obj


def get_job_queue() -> Optional[BackgroundJobQueue]:
    queue_obj = current_app.config.get("JOB_QUEUE")
    if isinstance(queue_obj, BackgroundJobQueue):
        return queue_obj
    return None


def enqueue_job(
    job_type: str,
    payload: Dict[str, object],
    requested_by: str = "system",
) -> str:
    queue_obj = get_job_queue()
    if not queue_obj:
        return ""
    return queue_obj.submit(job_type=job_type, payload=payload, requested_by=requested_by)


def _handle_ai_analysis(payload: Dict[str, object], _job: Dict[str, object]) -> Dict[str, object]:
    verification_id = str(payload.get("verification_id", "")).upper().strip()
    record_raw = payload.get("record", {})
    record = record_raw if isinstance(record_raw, dict) else {}
    chain_valid = bool(payload.get("chain_valid", True))
    if not verification_id:
        raise ValueError("Missing verification ID for AI analysis job.")
    run_analysis_job(
        analysis_file=Path(current_app.config["ANALYSIS_JSON"]),
        verification_id=verification_id,
        record={str(k): str(v) for k, v in record.items()},
        chain_valid=chain_valid,
    )
    return {"verification_id": verification_id}


def _handle_report_pdf(payload: Dict[str, object], job: Dict[str, object]) -> Dict[str, object]:
    verification_id = str(payload.get("verification_id", "")).upper().strip()
    if not verification_id:
        raise ValueError("Missing verification ID for report generation.")
    record = _record_by_verification_id(verification_id)
    if not record:
        raise ValueError("Verification record not found.")

    analysis = get_analysis(Path(current_app.config["ANALYSIS_JSON"]), verification_id)
    chain_valid, _ = validate_chain(Path(current_app.config["BLOCKCHAIN_JSON"]))
    if analysis.get("status") != "complete":
        analysis = {
            "risk_percentage": "Pending",
            "authenticity_score": "Pending",
            "fraud_indicator": "Pending",
            "security_summary": "AI analysis is still processing.",
            "explanation": "Retry after AI analysis queue is complete.",
        }

    buffer = generate_report_pdf(record, analysis, chain_valid)
    artifact_name = f"{job['job_id']}_security_report_{verification_id}.pdf"
    artifact_path = Path(current_app.config["JOB_ARTIFACT_DIR"]) / artifact_name
    artifact_path.write_bytes(buffer.getvalue())
    return {
        "artifact_name": artifact_name,
        "content_type": "application/pdf",
        "download_name": f"security_report_{verification_id}.pdf",
        "verification_id": verification_id,
    }


def _handle_certificate_pdf(payload: Dict[str, object], job: Dict[str, object]) -> Dict[str, object]:
    verification_id = str(payload.get("verification_id", "")).upper().strip()
    if not verification_id:
        raise ValueError("Missing verification ID for certificate generation.")
    record = _record_by_verification_id(verification_id)
    if not record:
        raise ValueError("Verification record not found.")
    blocks = find_blocks_by_verification_id(Path(current_app.config["BLOCKCHAIN_JSON"]), verification_id)
    if not blocks:
        raise ValueError("No blockchain block found for this verification ID.")

    chain_valid, _ = validate_chain(Path(current_app.config["BLOCKCHAIN_JSON"]))
    buffer = generate_certificate_pdf(record, blocks[-1], chain_valid)
    artifact_name = f"{job['job_id']}_certificate_{verification_id}.pdf"
    artifact_path = Path(current_app.config["JOB_ARTIFACT_DIR"]) / artifact_name
    artifact_path.write_bytes(buffer.getvalue())
    return {
        "artifact_name": artifact_name,
        "content_type": "application/pdf",
        "download_name": f"certificate_{verification_id}.pdf",
        "verification_id": verification_id,
    }


def _handle_integrity_scan(payload: Dict[str, object], _job: Dict[str, object]) -> Dict[str, object]:
    run_by = str(payload.get("run_by", "system")).strip() or "system"
    run_by_username = str(payload.get("run_by_username", "system")).strip() or "system"

    with _integrity_scan_lock:
        records = _read_records(Path(current_app.config["RECORDS_CSV"]))
        issues: List[Dict[str, object]] = []

        for row in records:
            verification_id = str(row.get("verification_id", "")).upper().strip()
            if not verification_id:
                continue

            stored_filename = str(row.get("stored_filename", "")).strip()
            original_filename = str(row.get("original_filename", "unknown")).strip() or "unknown"
            file_hash = str(row.get("file_hash", "")).strip()
            record_issues: List[str] = []

            stored_path = Path(current_app.config["UPLOAD_DIR"]) / stored_filename if stored_filename else Path("")
            if not stored_filename or not stored_path.exists():
                record_issues.append("encrypted_file_missing")
            else:
                try:
                    decrypted = read_encrypted_file(stored_filename)
                    current_hash = calculate_sha256(decrypted)
                    if current_hash != file_hash:
                        record_issues.append("encrypted_payload_hash_mismatch")
                except Exception:
                    record_issues.append("decrypt_or_read_failure")

            chain_blocks = find_blocks_by_verification_id(
                Path(current_app.config["BLOCKCHAIN_JSON"]),
                verification_id,
            )
            if not chain_blocks:
                record_issues.append("missing_blockchain_entry")
            else:
                latest = chain_blocks[-1]
                if str(latest.get("file_hash", "")) != file_hash:
                    record_issues.append("ledger_hash_mismatch")

            if record_issues:
                issues.append(
                    {
                        "verification_id": verification_id,
                        "file": original_filename,
                        "issues": record_issues,
                    }
                )

        total = len(records)
        failed = len(issues)
        passed = total - failed
        scan_id = generate_verification_id()
        scan_row = {
            "scan_id": scan_id,
            "run_at": datetime.now(timezone.utc).isoformat(),
            "run_by": run_by,
            "run_by_username": run_by_username,
            "total_records": str(total),
            "passed_records": str(passed),
            "failed_records": str(failed),
            "issue_summary_json": json.dumps(issues[:200]),
        }
        _append_integrity_scan(Path(current_app.config["INTEGRITY_SCANS_CSV"]), scan_row)

    log_activity(run_by, "integrity_scan_run", "success", f"total={total} failed={failed}")
    if failed > 0:
        push_alert_to_admins(
            severity="critical",
            category="integrity",
            title="Integrity Scan Detected Failures",
            message=f"{failed} of {total} records need investigation.",
        )
    else:
        push_alert_to_admins(
            severity="info",
            category="integrity",
            title="Integrity Scan Completed",
            message=f"All {total} records passed integrity checks.",
        )

    return {
        "scan_id": scan_id,
        "total_records": total,
        "passed_records": passed,
        "failed_records": failed,
    }


def _record_by_verification_id(verification_id: str) -> Dict[str, str] | None:
    records_path = Path(current_app.config["RECORDS_CSV"])
    if not records_path.exists():
        return None

    import csv  # local import to avoid module-level overhead

    with records_path.open("r", newline="", encoding="utf-8") as csvfile:
        rows = list(csv.DictReader(csvfile))
    return next((row for row in rows if row.get("verification_id", "").upper() == verification_id.upper()), None)


def _read_records(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as csvfile:
        return list(csv.DictReader(csvfile))


def _append_integrity_scan(path: Path, row: Dict[str, str]) -> None:
    with path.open("a", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=INTEGRITY_SCAN_FIELDS)
        writer.writerow(row)


def _clone_job(job: Dict[str, object]) -> Dict[str, object]:
    payload = job.get("payload", {})
    result = job.get("result", {})
    return {
        "job_id": str(job.get("job_id", "")),
        "job_type": str(job.get("job_type", "")),
        "status": str(job.get("status", "queued")),
        "requested_by": str(job.get("requested_by", "system")),
        "payload": dict(payload) if isinstance(payload, dict) else {},
        "result": dict(result) if isinstance(result, dict) else {},
        "error": str(job.get("error", "")),
        "created_at": str(job.get("created_at", "")),
        "started_at": str(job.get("started_at", "")),
        "finished_at": str(job.get("finished_at", "")),
    }


def _generate_job_id() -> str:
    return f"JOB{int(time.time() * 1000):X}{int(time.perf_counter_ns()) % 100000:05d}"
