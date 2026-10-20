from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.db import init_db


class DatabaseMigrationTests(unittest.TestCase):
    def test_init_db_upgrades_credit_transactions_before_creating_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "legacy.db"
            with closing(sqlite3.connect(database_path)) as connection:
                with connection:
                    connection.executescript(
                        """
                        CREATE TABLE credit_transactions (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            organization_id INTEGER NOT NULL,
                            scan_id INTEGER,
                            transaction_type TEXT NOT NULL,
                            purchased_delta INTEGER NOT NULL DEFAULT 0,
                            promotional_delta INTEGER NOT NULL DEFAULT 0,
                            source TEXT NOT NULL,
                            details_json TEXT NOT NULL,
                            created_at TEXT NOT NULL
                        );
                        """
                    )

            with patch(
                "app.db.get_settings",
                return_value=SimpleNamespace(database_path=database_path),
            ):
                init_db()

            with closing(sqlite3.connect(database_path)) as connection:
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(credit_transactions)"
                    ).fetchall()
                }
                indexes = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA index_list(credit_transactions)"
                    ).fetchall()
                }

            self.assertIn("payment_id", columns)
            self.assertIn("ux_credit_transactions_payment_credit", indexes)


if __name__ == "__main__":
    unittest.main()
