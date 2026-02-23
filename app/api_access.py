from __future__ import annotations

import csv
import hashlib
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from flask import current_app

from .security import generate_verification_id, sanitize_text


API_KEY_FIELDS = [
    "key_id",
    "label",
    "key_hash",
    "created_by",
    "created_at",
    "last_used",
    "status",
    "scopes",
]

_api_lock = threading.Lock()


def init_api_key_storage(app) -> None:
    path = Path(app.config["API_KEYS_CSV"])
    if path.exists():
        return
    with path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=API_KEY_FIELDS)
        writer.writeheader()


def create_api_key(label: str, created_by: str, scopes: str = "verify:read") -> tuple[str, Dict[str, str]]:
    token = f"sc_{secrets.token_urlsafe(30)}"
    row = {
        "key_id": generate_verification_id(),
        "label": sanitize_text(label or "Integration Key", max_length=60),
        "key_hash": _hash_token(token),
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_used": "",
        "status": "active",
        "scopes": sanitize_text(scopes, max_length=120),
    }
    path = Path(current_app.config["API_KEYS_CSV"])
    with _api_lock:
        with path.open("a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=API_KEY_FIELDS)
            writer.writerow(row)
    return token, row


def list_api_keys(limit: int = 80) -> List[Dict[str, str]]:
    path = Path(current_app.config["API_KEYS_CSV"])
    if not path.exists():
        return []
    with _api_lock:
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            rows = list(csv.DictReader(csvfile))
    return list(reversed(rows[-limit:]))


def validate_api_key(token: str, required_scope: str = "verify:read") -> Optional[Dict[str, str]]:
    if not token:
        return None
    token_hash = _hash_token(token)
    path = Path(current_app.config["API_KEYS_CSV"])
    if not path.exists():
        return None

    with _api_lock:
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            rows = list(csv.DictReader(csvfile))

        matched = None
        for row in rows:
            if row["status"] != "active":
                continue
            if row["key_hash"] != token_hash:
                continue
            scopes = {s.strip() for s in row["scopes"].split(",") if s.strip()}
            if required_scope not in scopes:
                continue
            row["last_used"] = datetime.now(timezone.utc).isoformat()
            matched = row
            break

        if matched:
            with path.open("w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=API_KEY_FIELDS)
                writer.writeheader()
                writer.writerows(rows)
    return matched


def revoke_api_key(key_id: str) -> bool:
    path = Path(current_app.config["API_KEYS_CSV"])
    if not path.exists():
        return False
    changed = False
    with _api_lock:
        with path.open("r", newline="", encoding="utf-8") as csvfile:
            rows = list(csv.DictReader(csvfile))
        for row in rows:
            if row["key_id"] == key_id:
                row["status"] = "revoked"
                changed = True
                break
        if changed:
            with path.open("w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=API_KEY_FIELDS)
                writer.writeheader()
                writer.writerows(rows)
    return changed


def _hash_token(token: str) -> str:
    pepper = str(current_app.config.get("SECRET_KEY", "securechain"))
    return hashlib.sha256(f"{pepper}:{token}".encode("utf-8")).hexdigest()
