from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


@dataclass(frozen=True)
class Settings:
    app_name: str
    app_secret: str
    app_host: str
    app_port: int
    base_dir: Path
    database_path: Path
    reports_dir: Path
    templates_dir: Path
    static_dir: Path
    session_cookie_name: str
    session_ttl_hours: int
    email_delivery: str
    email_from: str
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    smtp_use_tls: bool
    scanner_backend: str
    nuclei_path: str
    nuclei_severity: str
    nuclei_rate_limit: int
    nuclei_concurrency: int
    nuclei_bulk_size: int
    nuclei_timeout_minutes: int
    nuclei_headless: bool
    nuclei_template_paths: str
    greenbone_connection: str
    greenbone_host: str
    greenbone_port: int
    greenbone_username: str
    greenbone_password: str
    greenbone_scan_config_id: str
    greenbone_scanner_id: str
    greenbone_socket_path: str


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    _load_env_file(BASE_DIR / ".env")

    database_path = BASE_DIR / _env("DATABASE_PATH", "data/vuln_app.db")
    database_path.parent.mkdir(parents=True, exist_ok=True)
    reports_dir = BASE_DIR / _env("REPORTS_DIR", "data/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        app_name=_env("APP_NAME", "Sentinel Scope"),
        app_secret=_env("APP_SECRET", "development-secret"),
        app_host=_env("APP_HOST", "127.0.0.1"),
        app_port=_env_int("APP_PORT", 8000),
        base_dir=BASE_DIR,
        database_path=database_path,
        reports_dir=reports_dir,
        templates_dir=BASE_DIR / "app" / "templates",
        static_dir=BASE_DIR / "app" / "static",
        session_cookie_name=_env("SESSION_COOKIE_NAME", "sentinel_scope_session"),
        session_ttl_hours=_env_int("SESSION_TTL_HOURS", 24),
        email_delivery=_env("EMAIL_DELIVERY", "console").strip().lower(),
        email_from=_env("EMAIL_FROM", "security@example.com"),
        smtp_host=_env("SMTP_HOST", ""),
        smtp_port=_env_int("SMTP_PORT", 587),
        smtp_username=_env("SMTP_USERNAME", ""),
        smtp_password=_env("SMTP_PASSWORD", ""),
        smtp_use_tls=_env_bool("SMTP_USE_TLS", True),
        scanner_backend=_env("SCANNER_BACKEND", "mock").strip().lower(),
        nuclei_path=_env("NUCLEI_PATH", "nuclei"),
        nuclei_severity=_env("NUCLEI_SEVERITY", "critical,high,medium,low"),
        nuclei_rate_limit=_env_int("NUCLEI_RATE_LIMIT", 150),
        nuclei_concurrency=_env_int("NUCLEI_CONCURRENCY", 25),
        nuclei_bulk_size=_env_int("NUCLEI_BULK_SIZE", 25),
        nuclei_timeout_minutes=_env_int("NUCLEI_TIMEOUT_MINUTES", 15),
        nuclei_headless=_env_bool("NUCLEI_HEADLESS", False),
        nuclei_template_paths=_env("NUCLEI_TEMPLATE_PATHS", ""),
        greenbone_connection=_env("GREENBONE_CONNECTION", "tls").strip().lower(),
        greenbone_host=_env("GREENBONE_HOST", "127.0.0.1"),
        greenbone_port=_env_int("GREENBONE_PORT", 9390),
        greenbone_username=_env("GREENBONE_USERNAME", "admin"),
        greenbone_password=_env("GREENBONE_PASSWORD", "admin"),
        greenbone_scan_config_id=_env(
            "GREENBONE_SCAN_CONFIG_ID", "daba56c8-73ec-11df-a475-002264764cea"
        ),
        greenbone_scanner_id=_env(
            "GREENBONE_SCANNER_ID", "08b69003-5fc2-4037-a479-93b440211c73"
        ),
        greenbone_socket_path=_env("GREENBONE_SOCKET_PATH", "/run/gvmd/gvmd.sock"),
    )
