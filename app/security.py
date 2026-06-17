from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from collections import defaultdict, deque

from app.config import Settings


def utcnow() -> datetime:
    return datetime.now(UTC)


def generate_one_time_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_verification_code(secret: str, email: str, code: str) -> str:
    payload = f"{email.lower()}:{code}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def mask_email(email: str) -> str:
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def create_session_token(settings: Settings, user_id: int, email: str) -> str:
    now = utcnow()
    payload = {
        "uid": user_id,
        "email": email.lower(),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=settings.session_ttl_hours)).timestamp()),
    }
    encoded = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(
        settings.app_secret.encode("utf-8"), encoded.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{encoded}.{signature}"


def verify_session_token(settings: Settings, token: str) -> dict | None:
    try:
        encoded, signature = token.split(".", 1)
    except ValueError:
        return None

    expected = hmac.new(
        settings.app_secret.encode("utf-8"), encoded.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None

    try:
        payload = json.loads(_b64url_decode(encoded).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None

    if int(payload.get("exp", 0)) < int(utcnow().timestamp()):
        return None

    return payload


def create_csrf_token(settings: Settings) -> str:
    nonce = secrets.token_urlsafe(24)
    signature = hmac.new(
        settings.app_secret.encode("utf-8"), nonce.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{nonce}.{signature}"


def verify_csrf_token(settings: Settings, token: str | None) -> bool:
    if not token:
        return False
    try:
        nonce, signature = token.split(".", 1)
    except ValueError:
        return False
    expected = hmac.new(
        settings.app_secret.encode("utf-8"), nonce.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, *, limit: int, window_seconds: int) -> bool:
        now = utcnow().timestamp()
        threshold = now - window_seconds
        events = self._events[key]
        while events and events[0] < threshold:
            events.popleft()
        if len(events) >= limit:
            return False
        events.append(now)
        return True
