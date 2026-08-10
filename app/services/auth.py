from __future__ import annotations

from sqlite3 import Row

from app.db import get_connection
from app.emailer import BaseEmailSender
from app.security import (
    generate_one_time_code,
    hash_verification_code,
    mask_email,
    utcnow,
)


class AuthService:
    def __init__(self, settings, email_sender: BaseEmailSender) -> None:
        self.settings = settings
        self.email_sender = email_sender

    def request_code(self, email: str) -> dict:
        normalized = email.strip().lower()
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("Valid organizational email required.")
        domain = normalized.split("@", 1)[1]
        if "." not in domain:
            raise ValueError("A business email domain is required.")
        code = generate_one_time_code()
        code_hash = hash_verification_code(self.settings.app_secret, normalized, code)
        created_at = utcnow()
        expires_at = created_at.replace(microsecond=0)
        expires_at = expires_at.timestamp() + 10 * 60

        with get_connection() as connection:
            organization = connection.execute(
                "SELECT * FROM organizations WHERE email_domain = ?",
                (domain,),
            ).fetchone()

            if organization is None:
                connection.execute(
                    """
                    INSERT INTO organizations (name, email_domain, account_type, created_at)
                    VALUES (?, ?, 'msp', ?)
                    """,
                    (domain.replace(".", " ").title(), domain, created_at.isoformat()),
                )
                organization = connection.execute(
                    "SELECT * FROM organizations WHERE email_domain = ?",
                    (domain,),
                ).fetchone()

            user = connection.execute(
                "SELECT * FROM users WHERE email = ?",
                (normalized,),
            ).fetchone()

            if user is None:
                connection.execute(
                    """
                    INSERT INTO users (organization_id, email, role, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (organization["id"], normalized, "owner", created_at.isoformat()),
                )

            connection.execute(
                """
                INSERT INTO email_verifications (email, code_hash, expires_at, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (normalized, code_hash, str(int(expires_at)), created_at.isoformat()),
            )

        self.email_sender.send_verification_code(normalized, code, domain)
        return {
            "message": "Verification code sent.",
            "email": mask_email(normalized),
            "domain": domain,
            "delivery": self.settings.email_delivery,
            "expires_in_seconds": 10 * 60,
        }

    def verify_code(self, email: str, code: str) -> Row:
        normalized = email.strip().lower()
        if "@" not in normalized:
            raise ValueError("Valid organizational email required.")
        expected_hash = hash_verification_code(self.settings.app_secret, normalized, code)
        now = utcnow()

        with get_connection() as connection:
            record = connection.execute(
                """
                SELECT *
                FROM email_verifications
                WHERE email = ? AND consumed_at IS NULL
                ORDER BY id DESC
                LIMIT 1
                """,
                (normalized,),
            ).fetchone()

            if record is None:
                raise ValueError("No active verification code was found for that email.")

            if int(record["expires_at"]) < int(now.timestamp()):
                raise ValueError("That verification code has expired.")

            if expected_hash != record["code_hash"]:
                raise ValueError("The verification code is invalid.")

            connection.execute(
                "UPDATE email_verifications SET consumed_at = ? WHERE id = ?",
                (now.isoformat(), record["id"]),
            )
            connection.execute(
                """
                UPDATE users
                SET is_verified = 1,
                    verified_at = COALESCE(verified_at, ?),
                    last_login_at = ?
                WHERE email = ?
                """,
                (now.isoformat(), now.isoformat(), normalized),
            )

            user = connection.execute(
                """
                SELECT users.*, organizations.name AS organization_name, organizations.email_domain
                FROM users
                JOIN organizations ON organizations.id = users.organization_id
                WHERE users.email = ?
                """,
                (normalized,),
            ).fetchone()

        if user is None:
            raise ValueError("Unable to load user after verification.")
        return user

    def get_user_by_id(self, user_id: int) -> Row | None:
        with get_connection() as connection:
            return connection.execute(
                """
                SELECT users.*, organizations.name AS organization_name, organizations.email_domain
                FROM users
                JOIN organizations ON organizations.id = users.organization_id
                WHERE users.id = ?
                """,
                (user_id,),
            ).fetchone()
