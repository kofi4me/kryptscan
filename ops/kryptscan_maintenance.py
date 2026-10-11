from __future__ import annotations

import argparse
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.config import get_settings


APP_ROOT = Path(__file__).resolve().parents[1]


def _database_path() -> Path:
    path = Path(get_settings().database_path)
    return path if path.is_absolute() else (APP_ROOT / path).resolve()


def backup_database(destination: Path, keep_days: int) -> Path:
    database = _database_path()
    if not database.exists():
        raise FileNotFoundError(f"Database not found: {database}")
    destination.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = destination / f"kryptscan-{stamp}.sqlite3"
    source_connection = sqlite3.connect(database)
    backup_connection = sqlite3.connect(output)
    try:
        source_connection.backup(backup_connection)
    finally:
        backup_connection.close()
        source_connection.close()
    os.chmod(output, 0o600)
    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
    for candidate in destination.glob("kryptscan-*.sqlite3"):
        modified = datetime.fromtimestamp(candidate.stat().st_mtime, timezone.utc)
        if modified < cutoff:
            candidate.unlink(missing_ok=True)
    return output


def _safe_report_path(raw_path: str | None) -> Path | None:
    if not raw_path:
        return None
    path = Path(raw_path)
    if not path.is_absolute():
        path = APP_ROOT / path
    resolved = path.resolve()
    try:
        resolved.relative_to(APP_ROOT.resolve())
    except ValueError:
        return None
    return resolved


def clean_reports(retention_days: int, dry_run: bool) -> tuple[int, int]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    connection = sqlite3.connect(_database_path())
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        """
        SELECT id, report_pdf_path, report_json_path
        FROM scans
        WHERE completed_at IS NOT NULL AND completed_at < ?
          AND status IN ('completed', 'failed')
        """,
        (cutoff.isoformat(),),
    ).fetchall()
    deleted_files = 0
    cleaned_scans = 0
    try:
        for row in rows:
            for field in ("report_pdf_path", "report_json_path"):
                path = _safe_report_path(row[field])
                if path and path.is_file():
                    if not dry_run:
                        path.unlink()
                    deleted_files += 1
            if not dry_run:
                connection.execute(
                    """
                    UPDATE scans
                    SET report_pdf_path = NULL, report_json_path = NULL, report_json = NULL
                    WHERE id = ?
                    """,
                    (row["id"],),
                )
            cleaned_scans += 1
        if not dry_run:
            connection.commit()
    finally:
        connection.close()
    return cleaned_scans, deleted_files


def main() -> None:
    parser = argparse.ArgumentParser(description="Back up KryptScan and enforce report retention.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    backup = subparsers.add_parser("backup")
    backup.add_argument("--destination", type=Path, default=APP_ROOT / "backups")
    backup.add_argument("--keep-days", type=int, default=14)
    cleanup = subparsers.add_parser("cleanup")
    cleanup.add_argument("--retention-days", type=int, default=30)
    cleanup.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.command == "backup":
        print(backup_database(args.destination, max(1, args.keep_days)))
    else:
        scans, files = clean_reports(max(1, args.retention_days), args.dry_run)
        print(f"scans={scans} files={files} dry_run={args.dry_run}")


if __name__ == "__main__":
    main()
