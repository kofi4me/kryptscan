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
    is_verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    verified_at TEXT,
    last_login_at TEXT,
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
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

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    requested_by INTEGER NOT NULL,
    scanner_backend TEXT NOT NULL,
    status TEXT NOT NULL,
    external_task_id TEXT,
    external_report_id TEXT,
    report_json TEXT,
    metrics_json TEXT,
    scan_profile_json TEXT,
    report_pdf_path TEXT,
    report_email_sent_at TEXT,
    report_email_error TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    refreshed_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (target_id) REFERENCES targets(id),
    FOREIGN KEY (requested_by) REFERENCES users(id)
);
"""


def init_db() -> None:
    settings = get_settings()
    with sqlite3.connect(settings.database_path) as connection:
        connection.executescript(SCHEMA)
        _ensure_scan_columns(connection)


def _ensure_scan_columns(connection: sqlite3.Connection) -> None:
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(scans)").fetchall()
    }
    required_columns = {
        "scan_profile_json": "TEXT",
        "report_pdf_path": "TEXT",
        "report_email_sent_at": "TEXT",
        "report_email_error": "TEXT",
    }
    for column_name, column_type in required_columns.items():
        if column_name not in columns:
            connection.execute(
                f"ALTER TABLE scans ADD COLUMN {column_name} {column_type}"
            )


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
