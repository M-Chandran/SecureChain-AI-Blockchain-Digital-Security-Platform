from __future__ import annotations

import csv
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from flask import current_app

from .security import generate_verification_id, sanitize_text


ALERT_FIELDS = [
    "alert_id",
    "timestamp",
    "user_id",
    "severity",
    "category",
    "title",
    "message",
    "verification_id",
    "is_read",
]

_alert_lock = threading.Lock()


def init_alert_storage(app) -> None:
    path = Path(app.config["NOTIFICATIONS_CSV"])
    if path.exists():
        return
    with path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=ALERT_FIELDS)
        writer.writeheader()


def push_alert(
    user_id: str,
    severity: str,
    category: str,
    title: str,
    message: str,
    verification_id: str = "",
) -> str:
    row = {
        "alert_id": generate_verification_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "severity": severity,
        "category": category,
        "title": sanitize_text(title, max_length=80),
        "message": sanitize_text(message, max_length=220),
        "verification_id": sanitize_text(verification_id, max_length=24).upper(),
        "is_read": "0",
    }
    path = Path(current_app.config["NOTIFICATIONS_CSV"])
    with _alert_lock:
        with path.open("a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=ALERT_FIELDS)
            writer.writerow(row)
    return row["alert_id"]


def push_alert_to_admins(
    severity: str,
    category: str,
    title: str,
    message: str,
    verification_id: str = "",
) -> List[str]:
    # Local import avoids circular dependency (`auth` imports this module).
    from .auth import get_all_users

    admin_ids = sorted(
        {
            row["user_id"]
            for row in get_all_users()
            if row.get("role") == "admin" and row.get("account_status", "active") == "active"
        }
    )
    if not admin_ids:
        admin_ids = ["all"]

    created: List[str] = []
    for admin_id in admin_ids:
        created.append(
            push_alert(
                admin_id,
                severity=severity,
                category=category,
                title=title,
                message=message,
                verification_id=verification_id,
            )
        )
    return created


def list_alerts(
    user_id: str | None = None,
    limit: int = 40,
    unread_only: bool = False,
    include_global: bool = False,
) -> List[Dict[str, str]]:
    path = Path(current_app.config["NOTIFICATIONS_CSV"])
    if not path.exists():
        return []
    with _alert_lock:
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            rows = list(csv.DictReader(csvfile))

    selected = []
    for row in rows:
        if user_id:
            targets = {user_id}
            if include_global:
                targets.add("all")
            if row["user_id"] not in targets:
                continue
        if unread_only and row["is_read"] == "1":
            continue
        selected.append(row)
    return list(reversed(selected[-limit:]))


def mark_alerts_read(user_id: str, alert_ids: List[str] | None = None, include_global: bool = False) -> int:
    path = Path(current_app.config["NOTIFICATIONS_CSV"])
    if not path.exists():
        return 0

    with _alert_lock:
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            rows = list(csv.DictReader(csvfile))

        changed = 0
        wanted = {i.upper() for i in (alert_ids or [])}
        for row in rows:
            targets = {user_id}
            if include_global:
                targets.add("all")
            if row["user_id"] not in targets:
                continue
            if wanted and row["alert_id"].upper() not in wanted:
                continue
            if row["is_read"] != "1":
                row["is_read"] = "1"
                changed += 1

        with path.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=ALERT_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    return changed
