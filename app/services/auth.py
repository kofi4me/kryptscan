from __future__ import annotations

from sqlite3 import Row

from app.db import get_connection
from app.emailer import BaseEmailSender
from app.security import (
    generate_one_time_code,
    hash_password,
    hash_verification_code,
    mask_email,
    utcnow,
    verify_password,
)


PUBLIC_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
}


def _email_parts(email: str) -> tuple[str, str]:
    normalized = email.strip().lower()
    if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
        raise ValueError("Valid email required.")
    domain = normalized.split("@", 1)[1]
    if "." not in domain:
        raise ValueError("A valid email domain is required.")
    return normalized, domain


def _organization_identity(email: str) -> tuple[str, str]:
    normalized, domain = _email_parts(email)
    if domain in PUBLIC_EMAIL_DOMAINS:
        return normalized, normalized
    return domain, domain.replace(".", " ").title()


def _ensure_organization(connection, email: str, company_name: str | None = None) -> Row:
    organization_key, fallback_name = _organization_identity(email)
    organization = connection.execute(
        "SELECT * FROM organizations WHERE email_domain = ?",
        (organization_key,),
    ).fetchone()
    if organization is None:
        connection.execute(
            """
            INSERT INTO organizations (name, email_domain, account_type, created_at)
            VALUES (?, ?, 'msp', ?)
            """,
            ((company_name or fallback_name).strip(), organization_key, utcnow().isoformat()),
        )
        organization = connection.execute(
            "SELECT * FROM organizations WHERE email_domain = ?",
            (organization_key,),
        ).fetchone()
    return organization


class AuthService:
    def __init__(self, settings, email_sender: BaseEmailSender) -> None:
        self.settings = settings
        self.email_sender = email_sender

    def request_code(self, email: str) -> dict:
        normalized, domain = _email_parts(email)
        code = generate_one_time_code()
        code_hash = hash_verification_code(self.settings.app_secret, normalized, code)
        created_at = utcnow()
        expires_at = created_at.replace(microsecond=0)
        expires_at = expires_at.timestamp() + 10 * 60

        with get_connection() as connection:
            organization = _ensure_organization(connection, normalized)

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
            elif user["organization_id"] != organization["id"]:
                connection.execute(
                    "UPDATE users SET organization_id = ? WHERE id = ?",
                    (organization["id"], user["id"]),
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

    def register_account(self, payload) -> dict:
        normalized, domain = _email_parts(payload.email)
        if not payload.data_protection_accepted:
            raise ValueError("Data protection agreement acceptance is required.")
        if not payload.safe_use_accepted:
            raise ValueError("Safe-use acceptance is required.")
        if not _strong_password(payload.password):
            raise ValueError("Password must be at least 12 characters and include uppercase, lowercase, number, and symbol.")
        now = utcnow()
        with get_connection() as connection:
            organization = _ensure_organization(connection, normalized, payload.company_name.strip())

            existing = connection.execute("SELECT * FROM users WHERE email = ?", (normalized,)).fetchone()
            if existing and existing["password_hash"]:
                raise ValueError("An account already exists for that email. Use Login or Password Reset.")

            if existing:
                connection.execute(
                    """
                    UPDATE users
                    SET organization_id = ?,
                        full_name = ?,
                        job_title = ?,
                        professional_role = ?,
                        company_name = ?,
                        company_address = ?,
                        phone_number = ?,
                        date_of_birth = ?,
                        testing_reason = ?,
                        data_protection_accepted = 1,
                        data_protection_accepted_at = ?,
                        safe_use_accepted = 1,
                        profile_completed_at = ?,
                        password_hash = ?,
                        password_changed_at = ?
                    WHERE id = ?
                    """,
                    (
                        organization["id"],
                        payload.full_name.strip(),
                        payload.job_title.strip(),
                        payload.professional_role.strip(),
                        payload.company_name.strip(),
                        payload.company_address.strip(),
                        payload.phone_number.strip(),
                        (payload.date_of_birth or "").strip(),
                        payload.testing_reason.strip(),
                        now.isoformat(),
                        now.isoformat(),
                        hash_password(payload.password),
                        now.isoformat(),
                        existing["id"],
                    ),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO users (
                        organization_id,
                        email,
                        full_name,
                        job_title,
                        professional_role,
                        company_name,
                        company_address,
                        phone_number,
                        date_of_birth,
                        testing_reason,
                        data_protection_accepted,
                        data_protection_accepted_at,
                        safe_use_accepted,
                        profile_completed_at,
                        password_hash,
                        password_changed_at,
                        role,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 1, ?, ?, ?, 'owner', ?)
                    """,
                    (
                        organization["id"],
                        normalized,
                        payload.full_name.strip(),
                        payload.job_title.strip(),
                        payload.professional_role.strip(),
                        payload.company_name.strip(),
                        payload.company_address.strip(),
                        payload.phone_number.strip(),
                        (payload.date_of_birth or "").strip(),
                        payload.testing_reason.strip(),
                        now.isoformat(),
                        now.isoformat(),
                        hash_password(payload.password),
                        now.isoformat(),
                        now.isoformat(),
                    ),
                )
            connection.execute("UPDATE organizations SET name = ? WHERE id = ?", (payload.company_name.strip(), organization["id"]))

        return self.request_code(normalized)

    def login(self, email: str, password: str) -> Row:
        normalized = email.strip().lower()
        now = utcnow()
        with get_connection() as connection:
            user = connection.execute(
                """
                SELECT users.*, organizations.name AS organization_name, organizations.email_domain
                FROM users
                JOIN organizations ON organizations.id = users.organization_id
                WHERE users.email = ?
                """,
                (normalized,),
            ).fetchone()
            if user is None or not verify_password(password, user["password_hash"]):
                if user is not None:
                    failed = int(user["failed_login_count"] or 0) + 1
                    locked_until = None
                    if failed >= 5:
                        locked_until = (now.timestamp() + 15 * 60)
                    connection.execute(
                        "UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?",
                        (failed, str(int(locked_until)) if locked_until else None, user["id"]),
                    )
                raise ValueError("Invalid email or password.")
            if user["locked_until"] and int(user["locked_until"]) > int(now.timestamp()):
                raise ValueError("Account is temporarily locked after multiple failed login attempts. Try again later.")
            if not bool(user["is_verified"]):
                self.request_code(normalized)
                raise PermissionError("Email verification required. A new verification code has been sent.")
            organization = _ensure_organization(connection, normalized, user["company_name"] or user["organization_name"])
            if user["organization_id"] != organization["id"]:
                connection.execute(
                    "UPDATE users SET organization_id = ? WHERE id = ?",
                    (organization["id"], user["id"]),
                )
            connection.execute(
                "UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
                (now.isoformat(), user["id"]),
            )
            refreshed = connection.execute(
                """
                SELECT users.*, organizations.name AS organization_name, organizations.email_domain
                FROM users
                JOIN organizations ON organizations.id = users.organization_id
                WHERE users.id = ?
                """,
                (user["id"],),
            ).fetchone()
        return refreshed

    def request_password_reset(self, email: str) -> dict:
        normalized = email.strip().lower()
        code = generate_one_time_code()
        code_hash = hash_verification_code(self.settings.app_secret, normalized, code)
        now = utcnow()
        expires_at = int(now.timestamp() + 10 * 60)
        with get_connection() as connection:
            user = connection.execute("SELECT * FROM users WHERE email = ?", (normalized,)).fetchone()
            if user is not None:
                connection.execute(
                    """
                    INSERT INTO password_resets (email, code_hash, expires_at, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (normalized, code_hash, str(expires_at), now.isoformat()),
                )
                self.email_sender.send_password_reset_code(normalized, code)
        return {
            "message": "If the account exists, a password reset code has been sent.",
            "email": mask_email(normalized) if "@" in normalized else normalized,
            "expires_in_seconds": 10 * 60,
            "delivery": self.settings.email_delivery,
        }

    def reset_password(self, email: str, code: str, new_password: str) -> Row:
        normalized = email.strip().lower()
        if not _strong_password(new_password):
            raise ValueError("Password must be at least 12 characters and include uppercase, lowercase, number, and symbol.")
        expected_hash = hash_verification_code(self.settings.app_secret, normalized, code)
        now = utcnow()
        with get_connection() as connection:
            record = connection.execute(
                """
                SELECT *
                FROM password_resets
                WHERE email = ? AND consumed_at IS NULL
                ORDER BY id DESC
                LIMIT 1
                """,
                (normalized,),
            ).fetchone()
            if record is None:
                raise ValueError("No active password reset code was found.")
            if int(record["expires_at"]) < int(now.timestamp()):
                raise ValueError("That password reset code has expired.")
            if expected_hash != record["code_hash"]:
                raise ValueError("The password reset code is invalid.")
            connection.execute(
                "UPDATE password_resets SET consumed_at = ? WHERE id = ?",
                (now.isoformat(), record["id"]),
            )
            connection.execute(
                """
                UPDATE users
                SET password_hash = ?,
                    password_changed_at = ?,
                    failed_login_count = 0,
                    locked_until = NULL
                WHERE email = ?
                """,
                (hash_password(new_password), now.isoformat(), normalized),
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
            raise ValueError("Unable to reset password for that account.")
        return user

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
                    last_login_at = ?,
                    organization_id = ?
                WHERE email = ?
                """,
                (now.isoformat(), now.isoformat(), _ensure_organization(connection, normalized)["id"], normalized),
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


def _strong_password(password: str) -> bool:
    return (
        len(password) >= 12
        and any(char.islower() for char in password)
        and any(char.isupper() for char in password)
        and any(char.isdigit() for char in password)
        and any(not char.isalnum() for char in password)
    )
