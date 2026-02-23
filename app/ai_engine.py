from __future__ import annotations

import json
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Dict, List

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="analysis-worker")
_analysis_lock = threading.Lock()


def initialize_analysis_storage(path: Path) -> None:
    if not path.exists():
        path.write_text("{}", encoding="utf-8")


def submit_analysis_job(
    analysis_file: Path,
    verification_id: str,
    record: Dict[str, str],
    chain_valid: bool,
) -> None:
    initialize_analysis_storage(analysis_file)

    with _analysis_lock:
        data = _load_analyses(analysis_file)
        data[verification_id] = {
            "status": "pending",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_analyses(analysis_file, data)

    _executor.submit(_analyze_and_persist, analysis_file, verification_id, record, chain_valid)


def run_analysis_job(
    analysis_file: Path,
    verification_id: str,
    record: Dict[str, str],
    chain_valid: bool,
) -> None:
    initialize_analysis_storage(analysis_file)
    _analyze_and_persist(analysis_file, verification_id, record, chain_valid)


def get_analysis(analysis_file: Path, verification_id: str) -> Dict[str, str]:
    initialize_analysis_storage(analysis_file)
    with _analysis_lock:
        data = _load_analyses(analysis_file)
    return data.get(verification_id, {"status": "missing"})


def build_assistant_reply(
    question: str,
    context: Dict[str, str] | None = None,
    user_role: str = "user",
    mode: str = "assistive",
) -> Dict[str, object]:
    message = question.lower().strip()
    context = context or {}
    words = set(message.replace(",", " ").replace(".", " ").split())

    def asks_any(*keywords: str) -> bool:
        return any(k in message or k in words for k in keywords)

    verification_id = context.get("verification_id", "")
    risk_raw = context.get("risk_percentage", "")
    authenticity_raw = context.get("authenticity_score", "")
    fraud_indicator = context.get("fraud_indicator", "")
    record_status = context.get("record_status", "")

    try:
        risk_value = int(risk_raw)
    except (TypeError, ValueError):
        risk_value = -1

    try:
        auth_value = int(authenticity_raw)
    except (TypeError, ValueError):
        auth_value = -1

    chain_valid = context.get("chain_valid", "1") == "1"
    integrity_match = context.get("integrity_match", "1") == "1"
    tamper_detected = context.get("tamper_detected", "0") == "1"
    access_limited = context.get("access_limited", "0") == "1"

    intent = "general_guidance"
    confidence = 0.84

    if access_limited:
        intent = "access_control"
        confidence = 0.96
        reply = (
            "This record is outside your account scope. Ask an admin for delegated access or query a record you own. "
            "I can still explain the verification workflow and next actions."
        )
    elif asks_any("batch verify", "batch", "bulk verify", "multiple ids", "multi verify"):
        intent = "batch_verification"
        confidence = 0.93
        if user_role == "admin":
            reply = (
                "Use Admin Batch Verify to validate many verification IDs in one run. "
                "It classifies each ID as authentic, integrity alert, or missing and gives instant risk/authenticity visibility."
            )
        else:
            reply = (
                "Batch Verify is an admin workflow. Submit IDs to your security admin, or use Public Verify for single-ID checks."
            )
    elif asks_any("public upload", "guest upload", "external upload", "upload without login"):
        intent = "public_upload"
        confidence = 0.95
        reply = (
            "Public Upload accepts files without login and places them into admin verification queue. "
            "Files are encrypted at rest, hashed, and held as pending until admin approval."
        )
    elif asks_any("upload", "batch upload", "multi upload", "document upload", "drive"):
        intent = "upload_workflow"
        confidence = 0.9
        reply = (
            "User Batch Upload supports multiple files in one submission. "
            "Each file is policy-checked, encrypted, hash-indexed, and queued for admin verification."
        )
    elif asks_any("risk", "fraud", "suspicious", "anomaly"):
        intent = "risk_analysis"
        confidence = 0.92
        if risk_value >= 0:
            reply = (
                f"Current risk is {risk_value}% with fraud indicator '{fraud_indicator or 'unknown'}'. "
                "Prioritize manual review if risk is elevated, and enforce quarantine policy for high-risk files."
            )
        else:
            reply = (
                "Risk scoring combines extension profile, payload size pattern, version churn, behavior telemetry, "
                "and blockchain integrity signals."
            )
    elif asks_any("blockchain", "hash", "tamper", "integrity", "chain"):
        intent = "blockchain_integrity"
        confidence = 0.94
        status_text = "healthy" if chain_valid and integrity_match else "alert"
        reply = (
            "Verification trust requires both chain validity and hash integrity match. "
            f"Current chain posture for this context is {status_text}."
        )
    elif asks_any("verify", "authentic", "certificate", "qr"):
        intent = "verification"
        confidence = 0.9
        if verification_id:
            reply = (
                f"Verification ID {verification_id} can be validated through Public Verify. "
                "A valid record must exist, chain integrity must hold, and file hash must match the latest block."
            )
        else:
            reply = (
                "Use Public Verify with a verification ID or QR scan. "
                "The platform checks record existence, blockchain consistency, and hash integrity before marking it authentic."
            )
    elif asks_any("policy", "admin", "governance", "api key", "security settings"):
        intent = "governance"
        confidence = 0.88
        reply = (
            "Governance controls let admins tune risk thresholds, quarantine behavior, login throttling, and integration key lifecycle. "
            "Apply changes in Admin Panel and review SOC telemetry after each policy update."
        )
    elif asks_any("login", "password", "account", "reset", "access"):
        intent = "authentication"
        confidence = 0.89
        reply = (
            "Use the correct role login panel, then verify account status is active. "
            "If locked or throttled, wait lock window or request admin unlock, then rotate password."
        )
    elif asks_any("transfer", "ownership", "custody"):
        intent = "ownership"
        confidence = 0.9
        reply = (
            "Ownership transfer updates record owner metadata and appends blockchain transfer trace. "
            "Use this for legal chain-of-custody and audit defensibility."
        )
    else:
        reply = (
            "I can guide upload policy checks, blockchain verification, risk triage, incident workflow, "
            "ownership transfer, and admin governance controls."
        )

    tips = [
        "Use verification links or QR for external sharing instead of raw files.",
        "Run daily integrity scans and close unresolved incidents quickly.",
        "Keep policy thresholds aligned with real fraud volume and false-positive tolerance.",
    ]

    if user_role == "admin":
        tips.insert(0, "Admin action: use Batch Verify and SOC queue to triage high-risk submissions first.")
    else:
        tips.insert(0, "User action: upload in batches and monitor pending/approved/rejected queue status.")

    if verification_id:
        tips.insert(1, f"Active context: VID {verification_id}.")
    if risk_value >= 0:
        tips.insert(2, f"Context risk: {risk_value}% (status: {record_status or 'active'}).")
    if auth_value >= 0:
        tips.append(f"Authenticity score in context: {auth_value}%.")
    if tamper_detected or not chain_valid or not integrity_match:
        tips.insert(
            1,
            "Integrity alert present: quarantine record, open incident, and perform manual validation.",
        )

    if mode == "strict":
        reply = (
            "Compliance mode active: execute only policy-approved workflows with auditable actions. "
            + reply
        )
        tips.append("Document incident IDs, admin notes, and timestamped approvals for audit.")
    elif mode == "concise":
        reply = reply.split(".")[0] + "."
        tips = tips[:3]
    else:
        tips = tips[:5]

    return {
        "reply": reply,
        "tips": tips,
        "intent": intent,
        "confidence": confidence,
    }


def quick_risk_signal(filename: str, file_size: int, mime_type: str) -> Dict[str, int | str]:
    ext = filename.lower().rsplit(".", 1)[1] if "." in filename else ""
    risk = 6
    reason = "Standard document profile."
    high_risk_extensions = {"exe", "js", "bat", "vbs", "scr", "zip", "rar"}
    medium_risk_extensions = {"docm", "xlsm", "pptm", "html"}

    if ext in high_risk_extensions:
        risk += 55
        reason = "Executable or compressed payload type."
    elif ext in medium_risk_extensions:
        risk += 30
        reason = "Macro-capable document type."

    if file_size > 10 * 1024 * 1024:
        risk += 20
        reason = "Unusually large payload."
    elif file_size > 4 * 1024 * 1024:
        risk += 10

    if mime_type in {"application/octet-stream", "text/html"}:
        risk += 18
        reason = "Generic or script-like MIME type."

    risk = max(1, min(99, risk))
    if risk >= 70:
        severity = "critical"
    elif risk >= 50:
        severity = "warning"
    else:
        severity = "info"
    return {"quick_risk": risk, "severity": severity, "reason": reason}


def build_security_snapshot(
    records: List[Dict[str, str]],
    analyses: Dict[str, Dict[str, str]],
    activities: List[Dict[str, str]],
    anomaly_alert_threshold: int = 70,
) -> Dict[str, object]:
    complete = []
    for record in records:
        analysis = analyses.get(record["verification_id"], {})
        if analysis.get("status") == "complete":
            try:
                complete.append(
                    {
                        "verification_id": record["verification_id"],
                        "file_name": record["original_filename"],
                        "risk": int(analysis.get("risk_percentage", "0")),
                        "authenticity": int(analysis.get("authenticity_score", "0")),
                    }
                )
            except ValueError:
                continue

    avg_risk = int(sum(item["risk"] for item in complete) / len(complete)) if complete else 12
    high_risk_count = len([item for item in complete if item["risk"] >= 70])
    medium_risk_count = len([item for item in complete if 40 <= item["risk"] < 70])
    low_risk_count = len([item for item in complete if item["risk"] < 40])

    failed_events = [a for a in activities if a.get("status") in {"failed", "blocked"}]
    public_checks = len([a for a in activities if a.get("action") in {"public_verify", "api_verify"}])
    anomaly_score = min(99, high_risk_count * 18 + len(failed_events) * 6 + (avg_risk // 2))
    if anomaly_score < 20:
        anomaly_score = 20 if complete else 12

    if anomaly_score >= anomaly_alert_threshold:
        anomaly_label = "Elevated"
    elif anomaly_score >= 45:
        anomaly_label = "Moderate"
    else:
        anomaly_label = "Stable"

    posture_index = max(1, min(99, 100 - avg_risk - (len(failed_events) // 2)))
    if posture_index >= 82:
        posture_grade = "A"
    elif posture_index >= 70:
        posture_grade = "B"
    elif posture_index >= 55:
        posture_grade = "C"
    else:
        posture_grade = "D"

    top_risky = sorted(complete, key=lambda x: x["risk"], reverse=True)[:5]

    action_counts = Counter(a.get("action", "unknown") for a in activities)
    return {
        "avg_risk": avg_risk,
        "risk_distribution": {
            "high": high_risk_count,
            "medium": medium_risk_count,
            "low": low_risk_count,
        },
        "anomaly_score": anomaly_score,
        "anomaly_label": anomaly_label,
        "posture_index": posture_index,
        "posture_grade": posture_grade,
        "top_risky_records": top_risky,
        "failed_events": len(failed_events),
        "public_checks": public_checks,
        "activity_mix": dict(action_counts),
    }


def generate_report_pdf(record: Dict[str, str], analysis: Dict[str, str], chain_valid: bool) -> BytesIO:
    buffer = BytesIO()
    doc = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    doc.setTitle(f"Security Report - {record['verification_id']}")
    y = height - 60
    doc.setFont("Helvetica-Bold", 16)
    doc.drawString(50, y, "SecureChain AI Security Report")

    y -= 30
    doc.setFont("Helvetica", 11)
    lines = [
        f"Verification ID: {record['verification_id']}",
        f"File Name: {record['original_filename']}",
        f"Owner: {record['owner_username']}",
        f"Uploaded At: {record['uploaded_at']}",
        f"Blockchain Status: {'Valid' if chain_valid else 'Issue Detected'}",
        f"Risk Percentage: {analysis.get('risk_percentage', 'N/A')}%",
        f"Authenticity Score: {analysis.get('authenticity_score', 'N/A')}%",
        f"Fraud Indicator: {analysis.get('fraud_indicator', 'N/A')}",
        "",
        "Security Summary:",
        analysis.get("security_summary", "No analysis available."),
        "",
        "AI Explanation:",
        analysis.get("explanation", "No explanation available."),
    ]

    for line in lines:
        doc.drawString(50, y, line)
        y -= 18
        if y < 80:
            doc.showPage()
            y = height - 60
            doc.setFont("Helvetica", 11)

    doc.save()
    buffer.seek(0)
    return buffer


def generate_certificate_pdf(record: Dict[str, str], block: Dict[str, str], chain_valid: bool) -> BytesIO:
    buffer = BytesIO()
    doc = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    doc.setTitle(f"Digital Certificate - {record['verification_id']}")
    doc.setFont("Helvetica-Bold", 24)
    doc.drawCentredString(width / 2, height - 120, "Digital Authenticity Certificate")

    doc.setFont("Helvetica", 12)
    doc.drawCentredString(
        width / 2,
        height - 160,
        "This certifies that the referenced digital record is registered on blockchain.",
    )

    y = height - 230
    fields = [
        f"Verification ID: {record['verification_id']}",
        f"File: {record['original_filename']}",
        f"Owner: {record['owner_username']}",
        f"Owner ID: {record['owner_id']}",
        f"SHA256 Hash: {record['file_hash']}",
        f"Block #: {block['block_number']}",
        f"Block Hash: {block['block_hash']}",
        f"Status: {'Valid' if chain_valid else 'Integrity Alert'}",
        f"Issued At (UTC): {datetime.now(timezone.utc).isoformat()}",
    ]
    for field in fields:
        doc.drawString(70, y, field)
        y -= 22

    doc.setFont("Helvetica-Oblique", 10)
    doc.drawCentredString(width / 2, 80, "SecureChain Platform - Tamper-proof verification ledger")
    doc.save()
    buffer.seek(0)
    return buffer


def _analyze_and_persist(
    analysis_file: Path,
    verification_id: str,
    record: Dict[str, str],
    chain_valid: bool,
) -> None:
    result = _analyze_record(record, chain_valid)
    with _analysis_lock:
        data = _load_analyses(analysis_file)
        data[verification_id] = result
        _save_analyses(analysis_file, data)


def _analyze_record(record: Dict[str, str], chain_valid: bool) -> Dict[str, str]:
    risk = 8
    filename = record.get("original_filename", "").lower()
    ext = filename.rsplit(".", 1)[1] if "." in filename else ""
    file_size = int(record.get("file_size", "0"))
    version = int(record.get("version", "1"))

    high_risk_extensions = {"exe", "js", "bat", "vbs", "scr", "zip", "rar"}
    medium_risk_extensions = {"docm", "xlsm", "pptm"}

    if ext in high_risk_extensions:
        risk += 45
    elif ext in medium_risk_extensions:
        risk += 25

    if file_size > 8 * 1024 * 1024:
        risk += 15
    elif file_size > 2 * 1024 * 1024:
        risk += 8

    if version > 1:
        risk += min(version * 4, 20)

    if not chain_valid:
        risk += 30

    risk = max(1, min(99, risk))
    authenticity = max(1, 100 - risk + (5 if chain_valid else -10))
    authenticity = max(1, min(99, authenticity))

    if risk >= 70:
        fraud_indicator = "High"
    elif risk >= 40:
        fraud_indicator = "Medium"
    else:
        fraud_indicator = "Low"

    summary = (
        "Document appears trustworthy with low manipulation risk."
        if fraud_indicator == "Low"
        else "Document needs additional verification due to suspicious characteristics."
    )
    explanation = (
        "Score is derived from extension risk, file size pattern, version churn, and blockchain integrity."
    )

    recommendations: List[str] = [
        "Keep original source documents for legal backup.",
        "Share verification URL instead of raw files when possible.",
    ]
    if fraud_indicator != "Low":
        recommendations.insert(0, "Require secondary manual review before acceptance.")

    return {
        "status": "complete",
        "risk_percentage": str(risk),
        "authenticity_score": str(authenticity),
        "fraud_indicator": fraud_indicator,
        "security_summary": summary,
        "explanation": explanation,
        "recommendations": recommendations,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def _load_analyses(path: Path) -> Dict[str, Dict[str, str]]:
    try:
        raw = path.read_text(encoding="utf-8")
        return json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return {}


def _save_analyses(path: Path, data: Dict[str, Dict[str, str]]) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
