from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from ops import kryptscan_maintenance


class MaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=kryptscan_maintenance.APP_ROOT)
        self.root = Path(self.temp.name)
        self.database = self.root / "kryptscan.db"
        connection = sqlite3.connect(self.database)
        connection.execute(
            """
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY,
                report_pdf_path TEXT,
                report_json_path TEXT,
                report_json TEXT,
                completed_at TEXT,
                status TEXT
            )
            """
        )
        connection.commit()
        connection.close()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_database_backup_is_readable(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute(
            "INSERT INTO scans (id, completed_at, status) VALUES (1, ?, 'completed')",
            (datetime.now(timezone.utc).isoformat(),),
        )
        connection.commit()
        connection.close()
        with patch.object(kryptscan_maintenance, "_database_path", return_value=self.database):
            output = kryptscan_maintenance.backup_database(self.root / "backups", keep_days=14)
        backup = sqlite3.connect(output)
        try:
            self.assertEqual(backup.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 1)
        finally:
            backup.close()

    def test_cleanup_removes_only_expired_report_artifacts(self) -> None:
        old_pdf = self.root / "old.pdf"
        old_json = self.root / "old.json"
        recent_pdf = self.root / "recent.pdf"
        old_pdf.write_text("pdf", encoding="utf-8")
        old_json.write_text("{}", encoding="utf-8")
        recent_pdf.write_text("pdf", encoding="utf-8")
        old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        recent = datetime.now(timezone.utc).isoformat()
        connection = sqlite3.connect(self.database)
        connection.executemany(
            """
            INSERT INTO scans (
                id, report_pdf_path, report_json_path, report_json, completed_at, status
            ) VALUES (?, ?, ?, '{}', ?, 'completed')
            """,
            [
                (1, str(old_pdf), str(old_json), old),
                (2, str(recent_pdf), None, recent),
            ],
        )
        connection.commit()
        connection.close()

        with (
            patch.object(kryptscan_maintenance, "APP_ROOT", self.root),
            patch.object(kryptscan_maintenance, "_database_path", return_value=self.database),
        ):
            scans, files = kryptscan_maintenance.clean_reports(30, dry_run=False)

        self.assertEqual((scans, files), (1, 2))
        self.assertFalse(old_pdf.exists())
        self.assertFalse(old_json.exists())
        self.assertTrue(recent_pdf.exists())
        connection = sqlite3.connect(self.database)
        try:
            row = connection.execute(
                "SELECT report_pdf_path, report_json_path, report_json FROM scans WHERE id = 1"
            ).fetchone()
            self.assertEqual(row, (None, None, None))
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
