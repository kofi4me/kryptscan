from __future__ import annotations

import sqlite3
from contextlib import contextmanager

from app.config import get_settings


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email_domain TEXT NOT NULL UNIQUE,
    account_type TEXT NOT NULL DEFAULT 'msp',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    email TEXT NOT NULL UNIQUE,
    full_name TEXT,
    job_title TEXT,
    professional_role TEXT,
    company_name TEXT,
    company_address TEXT,
    phone_number TEXT,
    testing_reason TEXT,
    safe_use_accepted INTEGER NOT NULL DEFAULT 0,
    profile_completed_at TEXT,
    role TEXT NOT NULL DEFAULT 'owner',
    is_verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    verified_at TEXT,
    last_login_at TEXT,
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE IF NOT EXISTS entitlements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    plan TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    plan TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    currency TEXT NOT NULL,
    payment_method TEXT NOT NULL,
    status TEXT NOT NULL,
    provider_reference TEXT NOT NULL,
    payer_name TEXT NOT NULL,
    payer_email TEXT NOT NULL,
    safe_details_json TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS email_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    target TEXT NOT NULL,
    normalized_target TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    ownership_domain TEXT NOT NULL,
    authorization_method TEXT NOT NULL,
    verification_note TEXT,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (organization_id, normalized_target, asset_type),
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    client_name TEXT NOT NULL,
    authorization_reference TEXT NOT NULL,
    scope_notes TEXT NOT NULL,
    testing_window TEXT NOT NULL,
    allowed_categories_json TEXT NOT NULL,
    emergency_contact TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending_approval',
    approved_by INTEGER,
    approved_at TEXT,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    actor_id INTEGER,
    action TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (actor_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    requested_by INTEGER NOT NULL,
    engagement_id INTEGER,
    scanner_backend TEXT NOT NULL,
    assessment_mode TEXT NOT NULL DEFAULT 'vulnerability_assessment',
    scan_tier TEXT NOT NULL DEFAULT 'full_scan',
    status TEXT NOT NULL,
    external_task_id TEXT,
    external_report_id TEXT,
    report_json TEXT,
    metrics_json TEXT,
    scan_profile_json TEXT,
    report_pdf_path TEXT,
    report_email_sent_at TEXT,
    report_email_error TEXT,
    progress_percent INTEGER NOT NULL DEFAULT 0,
    progress_message TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    refreshed_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id),
    FOREIGN KEY (target_id) REFERENCES targets(id),
    FOREIGN KEY (requested_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS manual_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    evidence TEXT NOT NULL,
    remediation TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);
"""


def init_db() -> None:
    settings = get_settings()
    with sqlite3.connect(settings.database_path) as connection:
        connection.executescript(SCHEMA)
        _ensure_user_columns(connection)
        _ensure_engagement_columns(connection)
        _ensure_scan_columns(connection)
        _ensure_table(connection, "entitlements")
        _ensure_table(connection, "payments")
        _ensure_table(connection, "engagements")
        _ensure_table(connection, "manual_findings")
        _ensure_table(connection, "audit_events")


def _ensure_user_columns(connection: sqlite3.Connection) -> None:
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(users)").fetchall()
    }
    if "role" not in columns:
        connection.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'owner'")
    required_columns = {
        "job_title": "TEXT",
        "professional_role": "TEXT",
        "company_name": "TEXT",
        "company_address": "TEXT",
        "phone_number": "TEXT",
        "testing_reason": "TEXT",
        "safe_use_accepted": "INTEGER NOT NULL DEFAULT 0",
        "profile_completed_at": "TEXT",
    }
    for column_name, column_type in required_columns.items():
        if column_name not in columns:
            connection.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}")


def _ensure_engagement_columns(connection: sqlite3.Connection) -> None:
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(engagements)").fetchall()
    }
    required_columns = {
        "approved_by": "INTEGER",
        "approved_at": "TEXT",
    }
    for column_name, column_type in required_columns.items():
        if column_name not in columns:
            connection.execute(f"ALTER TABLE engagements ADD COLUMN {column_name} {column_type}")


def _ensure_scan_columns(connection: sqlite3.Connection) -> None:
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(scans)").fetchall()
    }
    required_columns = {
        "engagement_id": "INTEGER",
        "assessment_mode": "TEXT NOT NULL DEFAULT 'vulnerability_assessment'",
        "scan_tier": "TEXT NOT NULL DEFAULT 'full_scan'",
        "scan_profile_json": "TEXT",
        "report_pdf_path": "TEXT",
        "report_email_sent_at": "TEXT",
        "report_email_error": "TEXT",
        "progress_percent": "INTEGER NOT NULL DEFAULT 0",
        "progress_message": "TEXT",
    }
    for column_name, column_type in required_columns.items():
        if column_name not in columns:
            connection.execute(
                f"ALTER TABLE scans ADD COLUMN {column_name} {column_type}"
            )


def _ensure_table(connection: sqlite3.Connection, table_name: str) -> None:
    exists = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    if exists:
        return
    connection.executescript(SCHEMA)


@contextmanager
def get_connection():
    settings = get_settings()
    connection = sqlite3.connect(settings.database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON;")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()
