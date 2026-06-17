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
    app_env: str
    app_secret: str
    app_host: str
    app_port: int
    base_dir: Path
    database_path: Path
    reports_dir: Path
    templates_dir: Path
    static_dir: Path
    session_cookie_name: str
    csrf_cookie_name: str
    session_ttl_hours: int
    session_cookie_secure: bool
    trusted_hosts: list[str]
    rate_limit_enabled: bool
    max_request_body_bytes: int
    allow_private_network_targets: bool
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
    nmap_path: str
    sslyze_path: str
    testssl_path: str
    zap_baseline_path: str
    nikto_path: str
    amass_path: str
    subfinder_path: str
    trivy_path: str
    httpx_path: str
    naabu_path: str
    dnsx_path: str
    katana_path: str
    wafw00f_path: str
    whatweb_path: str
    semgrep_path: str
    gitleaks_path: str
    grype_path: str
    checkov_path: str
    prowler_path: str
    scoutsuite_path: str
    cloud_checks_enabled: bool
    kryptnet_payment_api_url: str
    kryptnet_payment_webhook_secret: str
    payment_demo_mode: bool
    openai_api_key: str
    openai_base_url: str
    openai_model: str
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
    _load_env_file(BASE_DIR / ".env.scanner")

    database_path = BASE_DIR / _env("DATABASE_PATH", "data/vuln_app.db")
    database_path.parent.mkdir(parents=True, exist_ok=True)
    reports_dir = BASE_DIR / _env("REPORTS_DIR", "data/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        app_name=_env("APP_NAME", "Sentinel Scope"),
        app_env=_env("APP_ENV", "development").strip().lower(),
        app_secret=_env("APP_SECRET", "development-secret"),
        app_host=_env("APP_HOST", "127.0.0.1"),
        app_port=_env_int("APP_PORT", 8000),
        base_dir=BASE_DIR,
        database_path=database_path,
        reports_dir=reports_dir,
        templates_dir=BASE_DIR / "app" / "templates",
        static_dir=BASE_DIR / "app" / "static",
        session_cookie_name=_env("SESSION_COOKIE_NAME", "sentinel_scope_session"),
        csrf_cookie_name=_env("CSRF_COOKIE_NAME", "kryptnet_csrf"),
        session_ttl_hours=_env_int("SESSION_TTL_HOURS", 24),
        session_cookie_secure=_env_bool("SESSION_COOKIE_SECURE", False),
        trusted_hosts=[
            host.strip()
            for host in _env("TRUSTED_HOSTS", "127.0.0.1,localhost").split(",")
            if host.strip()
        ],
        rate_limit_enabled=_env_bool("RATE_LIMIT_ENABLED", True),
        max_request_body_bytes=_env_int("MAX_REQUEST_BODY_BYTES", 1_048_576),
        allow_private_network_targets=_env_bool("ALLOW_PRIVATE_NETWORK_TARGETS", False),
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
        nmap_path=_env("NMAP_PATH", "nmap"),
        sslyze_path=_env("SSLYZE_PATH", "sslyze"),
        testssl_path=_env("TESTSSL_PATH", "testssl.sh"),
        zap_baseline_path=_env("ZAP_BASELINE_PATH", "zap-baseline.py"),
        nikto_path=_env("NIKTO_PATH", "nikto"),
        amass_path=_env("AMASS_PATH", "amass"),
        subfinder_path=_env("SUBFINDER_PATH", "subfinder"),
        trivy_path=_env("TRIVY_PATH", "trivy"),
        httpx_path=_env("HTTPX_PATH", "httpx"),
        naabu_path=_env("NAABU_PATH", "naabu"),
        dnsx_path=_env("DNSX_PATH", "dnsx"),
        katana_path=_env("KATANA_PATH", "katana"),
        wafw00f_path=_env("WAFW00F_PATH", "wafw00f"),
        whatweb_path=_env("WHATWEB_PATH", "whatweb"),
        semgrep_path=_env("SEMGREP_PATH", "semgrep"),
        gitleaks_path=_env("GITLEAKS_PATH", "gitleaks"),
        grype_path=_env("GRYPE_PATH", "grype"),
        checkov_path=_env("CHECKOV_PATH", "checkov"),
        prowler_path=_env("PROWLER_PATH", "prowler"),
        scoutsuite_path=_env("SCOUTSUITE_PATH", "ScoutSuite"),
        cloud_checks_enabled=_env_bool("CLOUD_CHECKS_ENABLED", False),
        kryptnet_payment_api_url=_env("KRYPTNET_PAYMENT_API_URL", "https://payments.kryptnet.com/api"),
        kryptnet_payment_webhook_secret=_env("KRYPTNET_PAYMENT_WEBHOOK_SECRET", ""),
        payment_demo_mode=_env_bool("PAYMENT_DEMO_MODE", False),
        openai_api_key=_env("OPENAI_API_KEY", ""),
        openai_base_url=_env("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        openai_model=_env("OPENAI_MODEL", "gpt-5-mini"),
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
