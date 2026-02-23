from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import quantiles
from typing import Dict, List

from flask import current_app


_monitor_lock = threading.Lock()


def init_monitoring_storage(app) -> None:
    app.config.setdefault("APP_STARTED_AT", time.time())

    siem_path = Path(app.config["SIEM_LOG"])
    error_path = Path(app.config["ERROR_LOG"])
    siem_path.parent.mkdir(parents=True, exist_ok=True)
    error_path.parent.mkdir(parents=True, exist_ok=True)

    if not siem_path.exists():
        siem_path.write_text("", encoding="utf-8")
    if not error_path.exists():
        error_path.write_text("", encoding="utf-8")


def emit_event(
    event_type: str,
    severity: str = "info",
    message: str = "",
    **fields,
) -> None:
    row = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": str(event_type),
        "severity": str(severity).lower(),
        "message": str(message)[:240],
    }
    for key, value in fields.items():
        if value is None:
            continue
        if isinstance(value, (dict, list, int, float, bool)):
            row[key] = value
        else:
            row[key] = str(value)

    siem_path = Path(current_app.config["SIEM_LOG"])
    with _monitor_lock:
        with siem_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")

        if row["severity"] in {"error", "critical"}:
            error_path = Path(current_app.config["ERROR_LOG"])
            with error_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, separators=(",", ":")) + "\n")


def read_events(
    limit: int = 200,
    event_type: str | None = None,
    severity: str | None = None,
    since_hours: int | None = None,
) -> List[Dict[str, object]]:
    path = Path(current_app.config["SIEM_LOG"])
    if not path.exists():
        return []

    cutoff = None
    if since_hours is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=max(1, int(since_hours)))

    output: List[Dict[str, object]] = []
    with _monitor_lock:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event_type and row.get("event_type") != event_type:
                continue
            if severity and row.get("severity") != severity:
                continue

            if cutoff is not None:
                stamp_raw = row.get("timestamp", "")
                try:
                    stamp = datetime.fromisoformat(str(stamp_raw)).astimezone(timezone.utc)
                except ValueError:
                    continue
                if stamp < cutoff:
                    continue

            output.append(row)

    output = sorted(output, key=lambda item: str(item.get("timestamp", "")), reverse=True)
    return output[:limit]


def export_events_ndjson(since_hours: int | None = None) -> bytes:
    events = read_events(limit=50000, since_hours=since_hours)
    lines = [json.dumps(item, separators=(",", ":")) for item in reversed(events)]
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


def uptime_seconds() -> int:
    started = float(current_app.config.get("APP_STARTED_AT", time.time()))
    return max(0, int(time.time() - started))


def monitoring_metrics(window_hours: int = 24) -> Dict[str, int]:
    events = read_events(limit=50000, since_hours=window_hours)
    request_events = [event for event in events if event.get("event_type") == "http_request"]
    auth_failures = [
        event
        for event in events
        if event.get("event_type") == "activity"
        and event.get("action") == "login"
        and event.get("status") in {"failed", "blocked"}
    ]
    durations = [
        int(event.get("duration_ms", 0))
        for event in request_events
        if isinstance(event.get("duration_ms"), (int, float, str))
    ]
    valid_durations = []
    for raw in durations:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        if value >= 0:
            valid_durations.append(value)

    if len(valid_durations) >= 2:
        p95_latency = int(quantiles(valid_durations, n=20)[18])
    elif len(valid_durations) == 1:
        p95_latency = valid_durations[0]
    else:
        p95_latency = 0

    return {
        "uptime_seconds": uptime_seconds(),
        "window_hours": max(1, int(window_hours)),
        "total_events": len(events),
        "request_events": len(request_events),
        "error_events": len([event for event in events if event.get("severity") == "error"]),
        "critical_events": len([event for event in events if event.get("severity") == "critical"]),
        "auth_failures": len(auth_failures),
        "p95_latency_ms": p95_latency,
    }
