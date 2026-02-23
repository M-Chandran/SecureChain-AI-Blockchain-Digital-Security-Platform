from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Dict


_policy_lock = threading.Lock()

DEFAULT_POLICY = {
    "risk_alert_threshold": 55,
    "quarantine_threshold": 78,
    "anomaly_alert_threshold": 70,
    "max_daily_uploads_per_user": 120,
    "login_max_attempts": 5,
    "login_window_seconds": 600,
    "login_lock_seconds": 900,
    "public_certificate_enabled": True,
}


def init_policy_storage(app) -> None:
    path = Path(app.config["POLICY_JSON"])
    if not path.exists():
        path.write_text(json.dumps(DEFAULT_POLICY, indent=2), encoding="utf-8")

    policy = load_policy(path)
    app.config["SECURITY_POLICY"] = policy
    app.config["LOGIN_MAX_ATTEMPTS"] = int(policy["login_max_attempts"])
    app.config["LOGIN_WINDOW_SECONDS"] = int(policy["login_window_seconds"])
    app.config["LOGIN_LOCK_SECONDS"] = int(policy["login_lock_seconds"])


def load_policy(path: Path) -> Dict[str, int | bool]:
    with _policy_lock:
        try:
            raw = path.read_text(encoding="utf-8")
            loaded = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            loaded = {}

        merged = {**DEFAULT_POLICY}
        for key, default in DEFAULT_POLICY.items():
            if key not in loaded:
                continue
            value = loaded[key]
            if isinstance(default, bool):
                merged[key] = bool(value)
            else:
                try:
                    merged[key] = int(value)
                except (TypeError, ValueError):
                    merged[key] = default
        return merged


def save_policy(path: Path, policy: Dict[str, int | bool]) -> Dict[str, int | bool]:
    cleaned = _sanitize_policy(policy)
    with _policy_lock:
        path.write_text(json.dumps(cleaned, indent=2), encoding="utf-8")
    return cleaned


def update_policy(path: Path, updates: Dict[str, object]) -> Dict[str, int | bool]:
    current = load_policy(path)
    for key, value in updates.items():
        if key not in DEFAULT_POLICY:
            continue
        current[key] = value
    return save_policy(path, current)


def _sanitize_policy(policy: Dict[str, object]) -> Dict[str, int | bool]:
    cleaned: Dict[str, int | bool] = {}
    for key, default in DEFAULT_POLICY.items():
        raw = policy.get(key, default)
        if isinstance(default, bool):
            cleaned[key] = bool(raw)
            continue
        try:
            ivalue = int(raw)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            ivalue = int(default)
        if key.endswith("_threshold"):
            ivalue = max(1, min(99, ivalue))
        elif key == "max_daily_uploads_per_user":
            ivalue = max(1, min(10000, ivalue))
        elif key == "login_max_attempts":
            ivalue = max(2, min(15, ivalue))
        elif key.endswith("_seconds"):
            ivalue = max(30, min(86400, ivalue))
        cleaned[key] = ivalue
    return cleaned
