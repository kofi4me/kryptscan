from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from sqlite3 import Connection, Row
from typing import Any


CREDIT_CATALOG = {
    "free_basic_va": {
        "name": "Free Basic Vulnerability Assessment",
        "credits": 0,
        "scan_tier": "free_preview",
        "report_access": "web_only",
    },
    "standard_va": {
        "name": "Standard Vulnerability Assessment",
        "credits": 1,
        "scan_tier": "full_scan",
        "report_access": "pdf_json",
    },
    "deep_va": {
        "name": "Deep Vulnerability Assessment",
        "credits": 3,
        "scan_tier": "full_scan",
        "report_access": "pdf_json",
    },
    "ethical_pentest": {
        "name": "Ethical Penetration Test",
        "credits": 8,
        "scan_tier": "full_scan",
        "report_access": "pdf_json",
    },
    "remediation_retest": {
        "name": "Remediation Retest",
        "credits": 1,
        "scan_tier": "full_scan",
        "report_access": "pdf_json",
    },
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat()


def target_fingerprint(target: str) -> str:
    return hashlib.sha256(target.strip().lower().encode("utf-8")).hexdigest()


def coupon_hash(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()


def ensure_wallet(connection: Connection, user: Row) -> None:
    connection.execute(
        """
        INSERT INTO credit_wallets (user_id, organization_id, purchased_credits, promotional_credits, updated_at)
        VALUES (?, ?, 0, 0, ?)
        ON CONFLICT(user_id) DO NOTHING
        """,
        (user["id"], user["organization_id"], _iso(_now())),
    )


def wallet_snapshot(connection: Connection, user: Row) -> dict[str, int]:
    ensure_wallet(connection, user)
    wallet = connection.execute(
        "SELECT purchased_credits, promotional_credits FROM credit_wallets WHERE user_id = ? AND organization_id = ?",
        (user["id"], user["organization_id"]),
    ).fetchone()
    purchased = int(wallet["purchased_credits"] or 0)
    promotional = int(wallet["promotional_credits"] or 0)
    return {"purchased": purchased, "promotional": promotional, "total": purchased + promotional}


def free_trial_available(connection: Connection, user: Row, *, exclude_scan_id: int | None = None) -> bool:
    claim = connection.execute(
        "SELECT status FROM free_trial_claims WHERE user_id = ? AND organization_id = ?",
        (user["id"], user["organization_id"]),
    ).fetchone()
    if claim is not None:
        return claim["status"] == "refunded"
    if exclude_scan_id is None:
        prior_scan = connection.execute(
            "SELECT 1 FROM scans WHERE organization_id = ? AND requested_by = ? LIMIT 1",
            (user["organization_id"], user["id"]),
        ).fetchone()
    else:
        prior_scan = connection.execute(
            "SELECT 1 FROM scans WHERE organization_id = ? AND requested_by = ? AND id != ? LIMIT 1",
            (user["organization_id"], user["id"], exclude_scan_id),
        ).fetchone()
    prior_audit = connection.execute(
        "SELECT 1 FROM audit_events WHERE organization_id = ? AND actor_id = ? AND action = 'scan.launch_requested' LIMIT 1",
        (user["organization_id"], user["id"]),
    ).fetchone()
    return prior_scan is None and prior_audit is None


def service_for_quote(connection: Connection, user: Row, assessment_mode: str, service_level: str) -> tuple[str, dict[str, Any]]:
    if assessment_mode == "ethical_pentesting":
        key = "ethical_pentest"
    elif service_level == "deep":
        key = "deep_va"
    elif free_trial_available(connection, user):
        key = "free_basic_va"
    else:
        key = "standard_va"
    return key, {"id": key, **CREDIT_CATALOG[key]}


def create_quote(
    connection: Connection,
    user: Row,
    *,
    target: str,
    assessment_mode: str,
    service_level: str,
) -> dict[str, Any]:
    connection.execute(
        "DELETE FROM scan_quotes WHERE redeemed_at IS NULL AND expires_at <= ?",
        (_iso(_now()),),
    )
    service_id, service = service_for_quote(connection, user, assessment_mode, service_level)
    wallet = wallet_snapshot(connection, user)
    cost = int(service["credits"])
    token = secrets.token_urlsafe(32)
    now = _now()
    expires_at = now + timedelta(minutes=15)
    connection.execute(
        """
        INSERT INTO scan_quotes (
            quote_token, user_id, organization_id, target_fingerprint, assessment_mode,
            service_level, scan_tier, credit_cost, balance_after, expires_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            token,
            user["id"],
            user["organization_id"],
            target_fingerprint(target),
            assessment_mode,
            service_level,
            service["scan_tier"],
            cost,
            wallet["total"] - cost,
            _iso(expires_at),
            _iso(now),
        ),
    )
    return {
        "quote_token": token,
        "expires_at": _iso(expires_at),
        "service": service,
        "credit_balance": wallet,
        "balance_after": wallet["total"] - cost,
        "sufficient_credits": cost == 0 or wallet["total"] >= cost,
        "free_trial": service_id == "free_basic_va",
    }


def load_valid_quote(
    connection: Connection,
    user: Row,
    *,
    quote_token: str,
    target: str,
    assessment_mode: str,
    service_level: str,
) -> Row | None:
    return connection.execute(
        """
        SELECT * FROM scan_quotes
        WHERE quote_token = ? AND user_id = ? AND organization_id = ?
          AND target_fingerprint = ? AND assessment_mode = ? AND service_level = ?
          AND redeemed_at IS NULL AND expires_at > ?
        """,
        (
            quote_token,
            user["id"],
            user["organization_id"],
            target_fingerprint(target),
            assessment_mode,
            service_level,
            _iso(_now()),
        ),
    ).fetchone()


def reserve_scan_credits(connection: Connection, user: Row, quote: Row, scan_id: int) -> None:
    cost = int(quote["credit_cost"] or 0)
    now = _iso(_now())
    claimed = connection.execute(
        """
        UPDATE scan_quotes SET redeemed_at = ?
        WHERE id = ? AND user_id = ? AND organization_id = ?
          AND redeemed_at IS NULL AND expires_at > ?
        """,
        (now, quote["id"], user["id"], user["organization_id"], now),
    )
    if claimed.rowcount != 1:
        raise ValueError("This scan-cost estimate has expired or was already used.")
    if quote["scan_tier"] == "free_preview":
        if not free_trial_available(connection, user, exclude_scan_id=scan_id):
            raise ValueError("The free basic assessment has already been used.")
        connection.execute(
            """
            INSERT INTO free_trial_claims (user_id, organization_id, scan_id, status, claimed_at, updated_at)
            VALUES (?, ?, ?, 'reserved', ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET scan_id = excluded.scan_id, status = 'reserved', updated_at = excluded.updated_at
            """,
            (user["id"], user["organization_id"], scan_id, now, now),
        )
    elif cost > 0:
        wallet = wallet_snapshot(connection, user)
        if wallet["total"] < cost:
            raise ValueError(f"This scan requires {cost} credits, but only {wallet['total']} are available.")
        promo_used = min(wallet["promotional"], cost)
        purchased_used = cost - promo_used
        connection.execute(
            """
            UPDATE credit_wallets
            SET promotional_credits = promotional_credits - ?, purchased_credits = purchased_credits - ?, updated_at = ?
            WHERE user_id = ? AND organization_id = ?
            """,
            (promo_used, purchased_used, now, user["id"], user["organization_id"]),
        )
        connection.execute(
            """
            INSERT INTO credit_transactions (
                user_id, organization_id, scan_id, transaction_type, purchased_delta,
                promotional_delta, source, details_json, created_at
            ) VALUES (?, ?, ?, 'reservation', ?, ?, 'scan', ?, ?)
            """,
            (
                user["id"], user["organization_id"], scan_id,
                -purchased_used, -promo_used,
                json.dumps({"quote_id": quote["id"], "credit_cost": cost}), now,
            ),
        )
    connection.execute(
        "UPDATE scans SET credit_cost = ?, credit_status = 'reserved', quote_id = ? WHERE id = ?",
        (cost, quote["id"], scan_id),
    )


def finalize_scan_credits(connection: Connection, user: Row, scan_id: int) -> None:
    scan = connection.execute(
        "SELECT credit_status, scan_tier FROM scans WHERE id = ? AND organization_id = ? AND requested_by = ?",
        (scan_id, user["organization_id"], user["id"]),
    ).fetchone()
    if scan is None or scan["credit_status"] != "reserved":
        return
    now = _iso(_now())
    connection.execute("UPDATE scans SET credit_status = 'consumed' WHERE id = ?", (scan_id,))
    if scan["scan_tier"] == "free_preview":
        connection.execute(
            "UPDATE free_trial_claims SET status = 'consumed', updated_at = ? WHERE user_id = ? AND scan_id = ?",
            (now, user["id"], scan_id),
        )
    connection.execute(
        """
        INSERT INTO credit_transactions (
            user_id, organization_id, scan_id, transaction_type, source, details_json, created_at
        ) VALUES (?, ?, ?, 'finalized', 'scan', '{}', ?)
        """,
        (user["id"], user["organization_id"], scan_id, now),
    )


def refund_scan_credits(connection: Connection, user: Row, scan_id: int, reason: str) -> None:
    scan = connection.execute(
        "SELECT credit_status, scan_tier FROM scans WHERE id = ? AND organization_id = ? AND requested_by = ?",
        (scan_id, user["organization_id"], user["id"]),
    ).fetchone()
    if scan is None or scan["credit_status"] != "reserved":
        return
    now = _iso(_now())
    reservation = connection.execute(
        """
        SELECT purchased_delta, promotional_delta FROM credit_transactions
        WHERE scan_id = ? AND user_id = ? AND transaction_type = 'reservation'
        ORDER BY id DESC LIMIT 1
        """,
        (scan_id, user["id"]),
    ).fetchone()
    purchased_refund = -int(reservation["purchased_delta"] or 0) if reservation else 0
    promotional_refund = -int(reservation["promotional_delta"] or 0) if reservation else 0
    if purchased_refund or promotional_refund:
        ensure_wallet(connection, user)
        connection.execute(
            """
            UPDATE credit_wallets SET purchased_credits = purchased_credits + ?,
                promotional_credits = promotional_credits + ?, updated_at = ?
            WHERE user_id = ? AND organization_id = ?
            """,
            (purchased_refund, promotional_refund, now, user["id"], user["organization_id"]),
        )
    if scan["scan_tier"] == "free_preview":
        connection.execute(
            "UPDATE free_trial_claims SET status = 'refunded', updated_at = ? WHERE user_id = ? AND scan_id = ?",
            (now, user["id"], scan_id),
        )
    connection.execute("UPDATE scans SET credit_status = 'refunded' WHERE id = ?", (scan_id,))
    connection.execute(
        """
        INSERT INTO credit_transactions (
            user_id, organization_id, scan_id, transaction_type, purchased_delta,
            promotional_delta, source, details_json, created_at
        ) VALUES (?, ?, ?, 'refund', ?, ?, 'platform_failure', ?, ?)
        """,
        (user["id"], user["organization_id"], scan_id, purchased_refund, promotional_refund, json.dumps({"reason": reason}), now),
    )


def redeem_coupon(connection: Connection, user: Row, code: str) -> dict[str, Any]:
    now = _iso(_now())
    coupon = connection.execute(
        """
        SELECT * FROM coupons WHERE code_hash = ? AND active = 1
          AND redemption_count < max_redemptions AND (expires_at IS NULL OR expires_at > ?)
        """,
        (coupon_hash(code), now),
    ).fetchone()
    if coupon is None:
        raise ValueError("This coupon is invalid, expired, or fully redeemed.")
    prior = connection.execute(
        "SELECT 1 FROM coupon_redemptions WHERE coupon_id = ? AND user_id = ?",
        (coupon["id"], user["id"]),
    ).fetchone()
    if prior:
        raise ValueError("This coupon has already been redeemed by your account.")
    credits = int(coupon["credit_amount"])
    ensure_wallet(connection, user)
    connection.execute(
        "UPDATE credit_wallets SET promotional_credits = promotional_credits + ?, updated_at = ? WHERE user_id = ?",
        (credits, now, user["id"]),
    )
    connection.execute(
        "INSERT INTO coupon_redemptions (coupon_id, user_id, organization_id, credits_granted, redeemed_at) VALUES (?, ?, ?, ?, ?)",
        (coupon["id"], user["id"], user["organization_id"], credits, now),
    )
    connection.execute("UPDATE coupons SET redemption_count = redemption_count + 1 WHERE id = ?", (coupon["id"],))
    connection.execute(
        """
        INSERT INTO credit_transactions (
            user_id, organization_id, transaction_type, promotional_delta, source, details_json, created_at
        ) VALUES (?, ?, 'coupon_credit', ?, 'coupon', ?, ?)
        """,
        (user["id"], user["organization_id"], credits, json.dumps({"coupon_id": coupon["id"], "label": coupon["label"]}), now),
    )
    return {"credits_granted": credits, "label": coupon["label"], "credit_balance": wallet_snapshot(connection, user)}
