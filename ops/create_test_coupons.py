from __future__ import annotations

import argparse
import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from sqlite3 import Connection, Row

from app.db import get_connection, init_db
from app.services.credits import coupon_hash


TEST_PACKS = (
    {"plan": "professional", "prefix": "PRO", "price_usd": 29, "credits": 20},
    {"plan": "business", "prefix": "BUS", "price_usd": 59, "credits": 45},
    {"plan": "msp", "prefix": "MSP", "price_usd": 99, "credits": 90},
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def find_coupon_admin(connection: Connection, email: str | None = None) -> Row:
    parameters: tuple[str, ...] = ()
    email_filter = ""
    if email:
        email_filter = "AND lower(email) = lower(?)"
        parameters = (email.strip(),)
    admin = connection.execute(
        f"""
        SELECT id, email, role
        FROM users
        WHERE role IN ('admin', 'super_admin') AND is_verified = 1
          {email_filter}
        ORDER BY CASE role WHEN 'super_admin' THEN 0 ELSE 1 END, id
        LIMIT 1
        """,
        parameters,
    ).fetchone()
    if admin is None:
        qualifier = f" for {email.strip()}" if email else ""
        raise ValueError(f"No verified KryptScan administrator was found{qualifier}.")
    return admin


def provision_test_coupons(
    connection: Connection,
    *,
    created_by: int,
    expires_at: datetime,
    max_redemptions: int = 1,
) -> list[dict[str, object]]:
    if max_redemptions < 1:
        raise ValueError("Maximum redemptions must be at least one.")
    if expires_at.tzinfo is None:
        raise ValueError("Coupon expiry must include a timezone.")
    if expires_at <= _utcnow():
        raise ValueError("Coupon expiry must be in the future.")

    created_at = _utcnow().isoformat()
    expiry = expires_at.astimezone(timezone.utc).isoformat()
    batch = f"{_utcnow().strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3).upper()}"
    created: list[dict[str, object]] = []
    creator = connection.execute(
        "SELECT organization_id FROM users WHERE id = ?",
        (created_by,),
    ).fetchone()
    if creator is None:
        raise ValueError("Coupon creator does not exist.")

    for pack in TEST_PACKS:
        label = f"Quick test {pack['plan']} pack ({batch})"
        for _ in range(5):
            code = f"KS-{pack['prefix']}-{pack['credits']}-{secrets.token_hex(6).upper()}"
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO coupons (
                        code_hash, label, credit_amount, max_redemptions,
                        redemption_count, expires_at, active, created_by, created_at
                    ) VALUES (?, ?, ?, ?, 0, ?, 1, ?, ?)
                    """,
                    (
                        coupon_hash(code),
                        label,
                        pack["credits"],
                        max_redemptions,
                        expiry,
                        created_by,
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError:
                continue
            connection.execute(
                """
                INSERT INTO audit_events (
                    organization_id, actor_id, action, details_json, created_at
                ) VALUES (?, ?, 'admin.test_coupon_created', ?, ?)
                """,
                (
                    creator["organization_id"],
                    created_by,
                    json.dumps(
                        {
                            "coupon_id": cursor.lastrowid,
                            "plan": pack["plan"],
                            "credit_amount": pack["credits"],
                            "max_redemptions": max_redemptions,
                            "batch": batch,
                        },
                        separators=(",", ":"),
                    ),
                    created_at,
                ),
            )
            created.append(
                {
                    "id": cursor.lastrowid,
                    "plan": pack["plan"],
                    "price_usd": pack["price_usd"],
                    "credits": pack["credits"],
                    "code": code,
                    "expires_at": expiry,
                    "max_redemptions": max_redemptions,
                }
            )
            break
        else:
            raise RuntimeError(f"Unable to generate a unique {pack['plan']} coupon code.")

    return created


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create short-lived KryptScan test coupons for all three credit packs."
    )
    parser.add_argument(
        "--admin-email",
        help="Verified admin account recorded as the coupon creator. The first verified admin is used when omitted.",
    )
    parser.add_argument("--expires-days", type=int, default=7)
    parser.add_argument("--max-redemptions", type=int, default=1)
    args = parser.parse_args()

    if not 1 <= args.expires_days <= 30:
        parser.error("--expires-days must be between 1 and 30.")
    if not 1 <= args.max_redemptions <= 100:
        parser.error("--max-redemptions must be between 1 and 100.")

    init_db()
    try:
        with get_connection() as connection:
            admin = find_coupon_admin(connection, args.admin_email)
            coupons = provision_test_coupons(
                connection,
                created_by=int(admin["id"]),
                expires_at=_utcnow() + timedelta(days=args.expires_days),
                max_redemptions=args.max_redemptions,
            )
    except (RuntimeError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Created by {admin['email']}. Coupon codes are shown only once:")
    for coupon in coupons:
        print(
            f"{coupon['plan']}: ${coupon['price_usd']} / {coupon['credits']} credits -> "
            f"{coupon['code']}"
        )
    print(f"Expires: {coupons[0]['expires_at']}")
    print(f"Maximum redemptions per code: {args.max_redemptions}")


if __name__ == "__main__":
    main()
