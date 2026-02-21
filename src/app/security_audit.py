from __future__ import annotations

import logging
from datetime import datetime, timedelta
from threading import Lock
from typing import Any

from fastapi import Request

from .db import SessionLocal
from .models import PaymentLog
from .utils import dumps_json, utcnow


logger = logging.getLogger(__name__)

_recent_events_lock = Lock()
_recent_events: dict[str, datetime] = {}


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _trim_recent_events(now: datetime) -> None:
    if len(_recent_events) < 4000:
        return
    cutoff = now - timedelta(hours=2)
    stale_keys = [key for key, seen_at in _recent_events.items() if seen_at < cutoff]
    for key in stale_keys:
        _recent_events.pop(key, None)
    if len(_recent_events) > 4500:
        # Keep map bounded even under heavy probing.
        for key in list(_recent_events.keys())[:1200]:
            _recent_events.pop(key, None)


def request_security_context(request: Request) -> dict[str, str]:
    query_keys = sorted({str(key).strip().lower() for key in request.query_params.keys() if str(key).strip()})
    user_agent = request.headers.get("user-agent", "").strip()
    referer = request.headers.get("referer", "").strip()
    return {
        "ip": client_ip(request),
        "http_method": request.method,
        "request_path": request.url.path,
        "query_keys": ",".join(query_keys[:18]),
        "user_agent": user_agent[:240],
        "referer": referer[:240],
    }


def log_security_event(
    *,
    event_code: str,
    message: str,
    level: str = "warning",
    context: dict[str, Any] | None = None,
    dedupe_key: str | None = None,
    dedupe_window_seconds: int = 90,
) -> bool:
    now = utcnow()
    payload = dict(context or {})
    payload["event_code"] = event_code

    key_parts = [
        event_code,
        str(payload.get("ip") or ""),
        str(payload.get("request_path") or ""),
        str(payload.get("http_method") or ""),
    ]
    fingerprint = dedupe_key or "|".join(key_parts)

    window_seconds = max(0, dedupe_window_seconds)
    with _recent_events_lock:
        prev = _recent_events.get(fingerprint)
        if prev is not None and window_seconds > 0 and (now - prev).total_seconds() < window_seconds:
            return False
        _recent_events[fingerprint] = now
        _trim_recent_events(now)

    db = SessionLocal()
    try:
        db.add(
            PaymentLog(
                payment_id=None,
                level=level,
                message=message,
                context_json=dumps_json(payload),
                created_at=now,
            )
        )
        db.commit()
        return True
    except Exception:
        logger.exception("Failed to persist security audit event %s", event_code)
        db.rollback()
        return False
    finally:
        db.close()
