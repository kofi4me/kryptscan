from __future__ import annotations

import json
import ipaddress
import re
import secrets
import shutil
import urllib.error
import urllib.request
from datetime import timedelta
from pathlib import Path
from sqlite3 import Row
from urllib.parse import urlparse

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import get_settings
from app.db import get_connection, init_db
from app.emailer import get_email_sender
from app.models import (
    AssessmentReport,
    AuthRequest,
    AuthVerifyRequest,
    AuditEventSummary,
    ClientPortalResponse,
    DashboardResponse,
    EngagementCreateRequest,
    EngagementSummary,
    Finding,
    ManualFindingCreateRequest,
    ManualFindingSummary,
    MemberCreateRequest,
    MemberSummary,
    PaymentCheckoutRequest,
    PaymentIntentRequest,
    LoginRequest,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    PaymentSummary,
    PaymentWebhookRequest,
    RegistrationRequest,
    RegistrationProfileRequest,
    ScanCreateRequest,
    ScanSummary,
    SeverityCounts,
)
from app.security import (
    InMemoryRateLimiter,
    create_csrf_token,
    create_session_token,
    utcnow,
    verify_csrf_token,
    verify_session_token,
)
from app.services.auth import AuthService
from app.services.ownership import (
    authorize_target,
    build_scan_protocols,
    infer_asset_type,
    normalize_assessment_mode,
)
from app.services.pdf_report import write_pdf_report
from app.services.reporting import build_assessment_report
from app.services.scanners import get_scanner_provider, greenbone_is_available, resolve_backend_name
from app.services.toolchain import get_assessment_profiles, get_ethical_pentest_toolchain


settings = get_settings()
templates = Jinja2Templates(directory=str(settings.templates_dir))
app = FastAPI(title=settings.app_name)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
app.mount("/static", StaticFiles(directory=settings.static_dir), name="static")

email_sender = get_email_sender(settings)
auth_service = AuthService(settings, email_sender)
rate_limiter = InMemoryRateLimiter()


@app.on_event("startup")
def startup_event() -> None:
    _assert_secure_config()
    init_db()


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if int(request.headers.get("content-length") or 0) > settings.max_request_body_bytes:
        return JSONResponse(
            {"detail": "Request body is too large."},
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )
    webhook_path = request.url.path == "/api/payments/webhook/kryptnet"
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not webhook_path:
        blocked = _verify_same_origin_request(request) or _verify_csrf_request(request)
        if blocked is not None:
            return blocked
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        ),
    )
    if settings.session_cookie_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if not request.cookies.get(settings.csrf_cookie_name):
        response.set_cookie(
            settings.csrf_cookie_name,
            create_csrf_token(settings),
            httponly=False,
            secure=settings.session_cookie_secure,
            samesite="lax",
            max_age=int(timedelta(hours=settings.session_ttl_hours).total_seconds()),
        )
    return response


def _assert_secure_config() -> None:
    if settings.app_env in {"production", "prod"} and settings.app_secret == "development-secret":
        raise RuntimeError("Set APP_SECRET to a strong unique value before running in production.")
    if settings.app_env in {"production", "prod"} and settings.payment_demo_mode:
        raise RuntimeError("PAYMENT_DEMO_MODE must be false in production.")
    if settings.app_env in {"production", "prod"} and not settings.kryptnet_payment_webhook_secret:
        raise RuntimeError("Set KRYPTNET_PAYMENT_WEBHOOK_SECRET before running in production.")


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def _rate_limit(request: Request, bucket: str, *, limit: int, window_seconds: int) -> None:
    if not settings.rate_limit_enabled:
        return
    key = f"{bucket}:{_client_ip(request)}"
    if not rate_limiter.allow(key, limit=limit, window_seconds=window_seconds):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests from this network. Wait briefly or try again after a few minutes.",
        )


def _verify_same_origin_request(request: Request) -> JSONResponse | None:
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    source = origin or referer
    if not source:
        return
    source_host = urlparse(source).netloc
    if source_host and source_host != request.headers.get("host"):
        return JSONResponse(
            {"detail": "Cross-origin request blocked."},
            status_code=status.HTTP_403_FORBIDDEN,
        )
    return None


def _verify_csrf_request(request: Request) -> JSONResponse | None:
    cookie_token = request.cookies.get(settings.csrf_cookie_name)
    header_token = request.headers.get("x-csrf-token")
    if cookie_token != header_token or not verify_csrf_token(settings, header_token):
        response = JSONResponse(
            {"detail": "CSRF token validation failed."},
            status_code=status.HTTP_403_FORBIDDEN,
        )
        response.set_cookie(
            settings.csrf_cookie_name,
            create_csrf_token(settings),
            httponly=False,
            secure=settings.session_cookie_secure,
            samesite="lax",
            max_age=int(timedelta(hours=settings.session_ttl_hours).total_seconds()),
        )
        return response
    return None


def _require_target_network_policy(normalized_target: str, target_kind: str) -> None:
    if settings.allow_private_network_targets:
        return
    if target_kind not in {"ip", "cidr"}:
        return
    try:
        network = ipaddress.ip_network(normalized_target, strict=False)
    except ValueError:
        return
    if any(
        (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )
        for address in (network.network_address, network.broadcast_address)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Private, loopback, reserved, or link-local network targets are disabled "
                "for this deployment. Set ALLOW_PRIVATE_NETWORK_TARGETS=true only on an isolated MSP scanner."
            ),
        )


def _serialize_user(user: Row) -> dict:
    profile_complete = (
        bool(user["profile_completed_at"])
        and bool(user["safe_use_accepted"])
        and bool(user["data_protection_accepted"])
        and bool(user["password_hash"])
    )
    return {
        "id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "full_name": user["full_name"],
        "job_title": user["job_title"],
        "professional_role": user["professional_role"],
        "company_name": user["company_name"],
        "company_address": user["company_address"],
        "phone_number": user["phone_number"],
        "date_of_birth": user["date_of_birth"],
        "testing_reason": user["testing_reason"],
        "data_protection_accepted": bool(user["data_protection_accepted"]),
        "safe_use_accepted": bool(user["safe_use_accepted"]),
        "profile_complete": profile_complete,
        "organization_id": user["organization_id"],
        "organization_name": user["organization_name"],
        "email_domain": user["email_domain"],
    }


def _get_report_for_scan(scan: Row) -> AssessmentReport | None:
    if not scan["report_json"]:
        return None
    payload = json.loads(scan["report_json"])
    return AssessmentReport.model_validate(payload)


def _serialize_engagement(engagement: Row) -> EngagementSummary:
    return EngagementSummary(
        id=engagement["id"],
        client_name=engagement["client_name"],
        company_address=engagement["company_address"],
        contact_name=engagement["contact_name"],
        contact_email=engagement["contact_email"],
        contact_phone=engagement["contact_phone"],
        authorization_reference=engagement["authorization_reference"],
        scope_notes=engagement["scope_notes"],
        testing_window=engagement["testing_window"],
        allowed_categories=json.loads(engagement["allowed_categories_json"] or "[]"),
        emergency_contact=engagement["emergency_contact"],
        status=engagement["status"],
        approved_at=engagement["approved_at"],
        created_at=engagement["created_at"],
    )


def _serialize_manual_finding(row: Row) -> ManualFindingSummary:
    return ManualFindingSummary(
        id=row["id"],
        scan_id=row["scan_id"],
        title=row["title"],
        severity=row["severity"],
        category=row["category"],
        evidence=row["evidence"],
        remediation=row["remediation"],
        created_at=row["created_at"],
    )


def _serialize_member(row: Row) -> MemberSummary:
    return MemberSummary(
        id=row["id"],
        email=row["email"],
        role=row["role"],
        full_name=row["full_name"],
        is_verified=bool(row["is_verified"]),
        created_at=row["created_at"],
    )


def _serialize_payment(row: Row) -> PaymentSummary:
    return PaymentSummary(
        id=row["id"],
        provider=row["provider"],
        plan=row["plan"],
        amount_cents=row["amount_cents"],
        currency=row["currency"],
        payment_method=row["payment_method"],
        status=row["status"],
        provider_reference=row["provider_reference"],
        payer_email=row["payer_email"],
        safe_details=json.loads(row["safe_details_json"] or "{}"),
        created_at=row["created_at"],
    )


def _serialize_audit_event(row: Row) -> AuditEventSummary:
    return AuditEventSummary(
        id=row["id"],
        actor_id=row["actor_id"],
        action=row["action"],
        details=json.loads(row["details_json"] or "{}"),
        created_at=row["created_at"],
    )


def _audit(connection, user: Row, action: str, details: dict | None = None) -> None:
    connection.execute(
        """
        INSERT INTO audit_events (organization_id, actor_id, action, details_json, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            user["organization_id"],
            user["id"],
            action,
            json.dumps(details or {}),
            utcnow().isoformat(),
        ),
    )


def _clean_optional(value: str | None) -> str:
    return value.strip() if value else ""


def _active_entitlement(connection, organization_id: int) -> Row | None:
    return connection.execute(
        """
        SELECT *
        FROM entitlements
        WHERE organization_id = ?
          AND status = 'active'
          AND expires_at > ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (organization_id, utcnow().isoformat()),
    ).fetchone()


def _serialize_entitlement(entitlement: Row | None) -> dict:
    if entitlement is None:
        return {"status": "inactive", "plan": None, "expires_at": None}
    return {
        "status": entitlement["status"],
        "plan": entitlement["plan"],
        "expires_at": entitlement["expires_at"],
    }


PLAN_CATALOG = {
    "starter": {
        "name": "Starter",
        "amount_cents": 9900,
        "currency": "USD",
        "access_days": 365,
        "payment_path": "/checkout/starter",
        "description": "One-time payment for a small business vulnerability assessment package.",
    },
    "professional": {
        "name": "Professional",
        "amount_cents": 29900,
        "currency": "USD",
        "access_days": 365,
        "payment_path": "/checkout/professional",
        "description": "One-time payment for professional vulnerability assessment and ethical testing work.",
    },
    "msp_scale": {
        "name": "MSP Scale",
        "amount_cents": 79900,
        "currency": "USD",
        "access_days": 365,
        "payment_path": "/checkout/msp-scale",
        "description": "One-time payment for larger MSP delivery and multi-client testing work.",
    },
}


def _plan_details(plan: str) -> dict:
    normalized = (plan or "professional").strip().lower()
    if normalized not in PLAN_CATALOG:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported plan.")
    plan = {"id": normalized, **PLAN_CATALOG[normalized]}
    plan["payment_url"] = f"{settings.kryptnet_payment_api_url.rstrip('/')}{plan['payment_path']}"
    return plan


def _require_owner_or_analyst(user: Row) -> None:
    if user["role"] not in {"owner", "analyst"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner or analyst role required.")


def _require_owner(user: Row) -> None:
    if user["role"] != "owner":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner role required.")


def _require_completed_registration(user: Row) -> None:
    if not user["profile_completed_at"] or not bool(user["safe_use_accepted"]) or not bool(user["data_protection_accepted"]) or not user["password_hash"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Complete registration, password setup, data protection agreement, and safe-use acceptance before using services.",
        )


def _is_client_viewer(user: Row) -> bool:
    return user["role"] == "client_viewer"


def _require_entitlement(connection, user: Row) -> None:
    if settings.payment_demo_mode:
        return
    if _active_entitlement(connection, user["organization_id"]) is None:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail="Completed one-time payment required.")


def _summary_from_row(scan: Row) -> ScanSummary:
    report = _get_report_for_scan(scan)
    counts = report.severity_counts if report else None
    risk_score = report.risk_score if report else None
    return ScanSummary(
        id=scan["id"],
        target=scan["normalized_target"],
        asset_type=scan["asset_type"],
        scanner_backend=scan["scanner_backend"],
        assessment_mode=normalize_assessment_mode(scan["assessment_mode"]),
        scan_tier=scan["scan_tier"] or "full_scan",
        engagement_id=scan["engagement_id"],
        manual_finding_count=scan["manual_finding_count"] or 0,
        status=scan["status"],
        created_at=scan["created_at"],
        completed_at=scan["completed_at"],
        error_message=scan["error_message"],
        risk_score=risk_score,
        severity_counts=counts,
        report_pdf_available=bool(scan["report_pdf_path"]),
        report_email_sent_at=scan["report_email_sent_at"],
        report_email_error=scan["report_email_error"],
        progress_percent=int(scan["progress_percent"] or 0),
        progress_message=scan["progress_message"],
    )


def _load_scan(connection, scan_id: int, organization_id: int) -> Row | None:
    return connection.execute(
        """
        SELECT scans.*,
               targets.normalized_target,
               targets.asset_type,
               targets.target,
               targets.ownership_domain,
               targets.authorization_method,
               targets.verification_note,
               COUNT(manual_findings.id) AS manual_finding_count
        FROM scans
        JOIN targets ON targets.id = scans.target_id
        LEFT JOIN manual_findings ON manual_findings.scan_id = scans.id
        WHERE scans.id = ? AND scans.organization_id = ?
        GROUP BY scans.id
        """,
        (scan_id, organization_id),
    ).fetchone()


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
    return slug.strip("-") or "target"


def _report_path_for_scan(scan_id: int, target: str):
    filename = f"scan-{scan_id}-{_slugify(target)}.pdf"
    return settings.reports_dir / filename


def _safe_report_file_path(path_value: str) -> str:
    reports_root = settings.reports_dir.resolve()
    candidate = Path(path_value).resolve()
    if candidate != reports_root and reports_root not in candidate.parents:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Report file path is outside the allowed reports directory.",
        )
    if candidate.suffix.lower() != ".pdf":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only PDF report downloads are allowed.",
        )
    return str(candidate)


def _update_scan_progress(scan_id: int, organization_id: int, percent: int, message: str) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE scans
            SET progress_percent = ?,
                progress_message = ?,
                refreshed_at = ?
            WHERE id = ? AND organization_id = ?
            """,
            (max(0, min(100, percent)), message, utcnow().isoformat(), scan_id, organization_id),
        )


def _report_msp_details(user: Row) -> dict[str, str]:
    return {
        "MSP organization": user["organization_name"],
        "Verified MSP domain": user["email_domain"],
        "Report prepared by": user["email"],
        "User role": user["role"],
    }


def _report_owner_details(scan: Row, engagement: Row | None) -> dict[str, str]:
    if engagement:
        return {
            "Owner / client name": engagement["client_name"],
            "Owner / client address": engagement["company_address"] or "",
            "Primary contact": engagement["contact_name"] or "",
            "Contact email": engagement["contact_email"] or "",
            "Contact phone": engagement["contact_phone"] or "",
            "Authorized target": scan["normalized_target"],
            "Asset type": scan["asset_type"],
            "Authorization reference": engagement["authorization_reference"],
            "Testing window": engagement["testing_window"],
            "Emergency contact": engagement["emergency_contact"],
            "Scope notes": engagement["scope_notes"],
        }
    return {
        "Owner organization domain": scan["ownership_domain"],
        "Authorized target": scan["normalized_target"],
        "Original target request": scan["target"],
        "Asset type": scan["asset_type"],
        "Authorization method": scan["authorization_method"],
        "Verification note": scan["verification_note"] or "",
    }


def _enrich_report_for_scan(
    scan_id: int,
    user: Row,
    scan: Row,
    report: AssessmentReport,
) -> AssessmentReport:
    mode = normalize_assessment_mode(scan["assessment_mode"])
    engagement = None
    with get_connection() as connection:
        if scan["engagement_id"]:
            engagement = connection.execute(
                "SELECT * FROM engagements WHERE id = ? AND organization_id = ?",
                (scan["engagement_id"], user["organization_id"]),
            ).fetchone()
        manual_findings = connection.execute(
            "SELECT * FROM manual_findings WHERE scan_id = ? AND organization_id = ? ORDER BY id",
            (scan_id, user["organization_id"]),
        ).fetchall()
    report = _merge_manual_findings(report, scan["normalized_target"], manual_findings)
    scope_summary = (
        f"Client: {engagement['client_name']}. Scope: {engagement['scope_notes']}. "
        f"Testing window: {engagement['testing_window']}. Authorization: {engagement['authorization_reference']}."
        if engagement
        else report.scope_summary
    )
    methodology = list(report.methodology)
    if mode == "ethical_pentesting":
        methodology = [
            "Engagement intake and rules-of-engagement confirmation",
            "Full-stack web, API, network, identity, and cloud-oriented review planning",
            *methodology,
            "Manual tester evidence review and client-ready remediation mapping",
        ]
    limitations = list(report.limitations)
    if engagement:
        limitations.append(f"Emergency contact on record: {engagement['emergency_contact']}.")
    return report.model_copy(
        update={
            "scope_summary": scope_summary,
            "methodology": methodology,
            "limitations": limitations,
            "scan_protocols": json.loads(scan["scan_profile_json"] or "[]"),
        }
    )


def _deliver_completed_report(
    scan_id: int,
    user: Row,
    scan: Row,
    report: AssessmentReport,
    *,
    notify_user: bool,
) -> tuple[str, str | None, str | None]:
    pdf_path = _report_path_for_scan(scan_id, scan["normalized_target"])
    mode = normalize_assessment_mode(scan["assessment_mode"])
    engagement = None
    with get_connection() as connection:
        if scan["engagement_id"]:
            engagement = connection.execute(
                "SELECT * FROM engagements WHERE id = ? AND organization_id = ?",
                (scan["engagement_id"], user["organization_id"]),
            ).fetchone()
    report = _enrich_report_for_scan(scan_id, user, scan, report)
    pdf_bytes = write_pdf_report(
        output_path=pdf_path,
        target=scan["normalized_target"],
        asset_type=scan["asset_type"],
        scanner_backend=scan["scanner_backend"],
        assessment_mode=mode,
        recipient_email=user["email"],
        report=report,
        msp_details=_report_msp_details(user),
        owner_details=_report_owner_details(scan, engagement),
    )

    emailed_at = None
    email_error = None
    if notify_user:
        try:
            email_sender.send_assessment_report(
                email=user["email"],
                target=scan["normalized_target"],
                pdf_filename=pdf_path.name,
                pdf_bytes=pdf_bytes,
                summary=report.executive_summary,
            )
            emailed_at = utcnow().isoformat()
        except Exception as exc:  # pragma: no cover - delivery depends on environment
            email_error = str(exc)

    return str(pdf_path), emailed_at, email_error


def _merge_manual_findings(report: AssessmentReport, target: str, rows: list[Row]) -> AssessmentReport:
    if not rows:
        return report
    base_findings = [
        finding
        for finding in report.findings
        if finding.service != "manual-review" and finding.evidence != "Manual tester evidence"
    ]
    manual = [
        Finding(
            title=row["title"],
            severity=row["severity"],
            cvss=_cvss_for_severity(row["severity"]),
            category=row["category"],
            host=target,
            service="manual-review",
            description=row["evidence"],
            remediation=row["remediation"],
            evidence="Manual tester evidence",
        )
        for row in rows
    ]
    merged = build_assessment_report(target, [*base_findings, *manual])
    return merged.model_copy(
        update={
            "scan_protocols": report.scan_protocols,
            "scope_summary": report.scope_summary,
            "methodology": report.methodology,
            "limitations": report.limitations,
        }
    )


def _cvss_for_severity(severity: str) -> float:
    return {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 2.5,
        "info": 0.0,
    }.get(severity.lower(), 5.5)


def _store_completed_scan(
    scan_id: int,
    user: Row,
    report: AssessmentReport,
    *,
    notify_user: bool,
    create_pdf: bool = True,
    backend_name: str | None = None,
) -> Row:
    with get_connection() as connection:
        scan = _load_scan(connection, scan_id, user["organization_id"])
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
        if backend_name and scan["scanner_backend"] != backend_name:
            connection.execute(
                "UPDATE scans SET scanner_backend = ? WHERE id = ?",
                (backend_name, scan_id),
            )
            scan = _load_scan(connection, scan_id, user["organization_id"])

        delivered_path = None
        emailed_at = None
        email_error = None
        if create_pdf:
            delivered_path, emailed_at, email_error = _deliver_completed_report(
                scan_id=scan_id,
                user=user,
                scan=scan,
                report=report,
                notify_user=notify_user,
            )
        persisted_report = _enrich_report_for_scan(scan_id, user, scan, report)
        completed_at = utcnow().isoformat()
        connection.execute(
            """
            UPDATE scans
            SET status = 'completed',
                report_json = ?,
                metrics_json = ?,
                report_pdf_path = COALESCE(?, report_pdf_path),
                report_email_sent_at = COALESCE(?, report_email_sent_at),
                report_email_error = ?,
                progress_percent = 100,
                progress_message = 'Scan complete successfully. Report is ready.',
                refreshed_at = ?,
                completed_at = ?
            WHERE id = ?
            """,
            (
                persisted_report.model_dump_json(),
                json.dumps({"risk_score": persisted_report.risk_score}),
                delivered_path,
                emailed_at,
                email_error,
                completed_at,
                completed_at,
                scan_id,
            ),
        )
        return _load_scan(connection, scan_id, user["organization_id"])


def _run_scan_job(scan_id: int, user_id: int) -> None:
    user = auth_service.get_user_by_id(user_id)
    if user is None:
        return

    with get_connection() as connection:
        scan = _load_scan(connection, scan_id, user["organization_id"])
        if scan is None:
            return
        connection.execute(
            """
            UPDATE scans
            SET status = 'running',
                started_at = COALESCE(started_at, ?),
                progress_percent = 10,
                progress_message = 'Scan started. Preparing approved toolchain.',
                refreshed_at = ?
            WHERE id = ? AND organization_id = ?
            """,
            (utcnow().isoformat(), utcnow().isoformat(), scan_id, user["organization_id"]),
        )
        _audit(connection, user, "scan.started", {"scan_id": scan_id, "backend": scan["scanner_backend"]})
        scan = _load_scan(connection, scan_id, user["organization_id"])

    _update_scan_progress(scan_id, user["organization_id"], 20, "Validating scope, scan profile, and scanner backend.")
    provider = get_scanner_provider(settings, scan["scanner_backend"])
    try:
        scan_protocols = json.loads(scan["scan_profile_json"] or "[]")
        _update_scan_progress(scan_id, user["organization_id"], 35, "Running scanner stages. This can take several minutes for full assessments.")
        try:
            scheduled = provider.schedule(
                scan["normalized_target"],
                scan["asset_type"],
                assessment_mode=scan["assessment_mode"],
                scan_tier=scan["scan_tier"],
                scan_protocols=scan_protocols,
            )
        except TypeError:
            scheduled = provider.schedule(scan["normalized_target"], scan["asset_type"])
    except Exception as exc:
        with get_connection() as connection:
            connection.execute(
                """
                UPDATE scans
                SET status = 'failed',
                    error_message = ?,
                    progress_message = ?,
                    refreshed_at = ?
                WHERE id = ? AND organization_id = ?
                """,
                (str(exc), f"Scan failed: {str(exc)}", utcnow().isoformat(), scan_id, user["organization_id"]),
            )
            _audit(connection, user, "scan.failed", {"scan_id": scan_id, "error": str(exc)})
        return

    if scheduled.report is not None:
        _update_scan_progress(scan_id, user["organization_id"], 90, "Scanner results received. Building professional report.")
        create_pdf = (scan["scan_tier"] or "full_scan") == "full_scan"
        _store_completed_scan(
            scan_id=scan_id,
            user=user,
            report=scheduled.report,
            notify_user=False,
            create_pdf=create_pdf,
            backend_name=scheduled.backend,
        )
        with get_connection() as connection:
            _audit(connection, user, "scan.completed", {"scan_id": scan_id, "backend": scheduled.backend})
        return

    with get_connection() as connection:
        connection.execute(
            """
            UPDATE scans
            SET status = ?,
                scanner_backend = ?,
                external_task_id = ?,
                external_report_id = ?,
                progress_percent = 45,
                progress_message = ?,
                refreshed_at = ?
            WHERE id = ? AND organization_id = ?
            """,
            (
                scheduled.status,
                scheduled.backend,
                scheduled.external_task_id,
                scheduled.external_report_id,
                scheduled.message,
                utcnow().isoformat(),
                scan_id,
                user["organization_id"],
            ),
        )
        _audit(
            connection,
            user,
            "scan.external_task_started",
            {"scan_id": scan_id, "backend": scheduled.backend, "task_id": scheduled.external_task_id},
        )


def get_current_user(request: Request) -> Row:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    payload = verify_session_token(settings, token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session.")

    user = auth_service.get_user_by_id(int(payload["uid"]))
    if user is None or not user["is_verified"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User session is no longer valid.")
    return user


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "app_name": settings.app_name,
            "scanner_backend": settings.scanner_backend,
            "email_delivery": settings.email_delivery,
        },
    )


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "app": settings.app_name,
        "scanner_backend": settings.scanner_backend,
    }


def _tool_health(name: str, path_value: str, category: str) -> dict:
    resolved_path = shutil.which(path_value)
    return {
        "name": name,
        "category": category,
        "configured_path": path_value,
        "available": bool(resolved_path),
        "resolved_path": resolved_path,
    }


def _worker_available_tools() -> dict[str, bool]:
    if settings.scanner_backend != "worker" or not settings.scanner_worker_url:
        return {}
    request = urllib.request.Request(
        f"{settings.scanner_worker_url.rstrip('/')}/health",
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError):
        return {}
    available_tools = payload.get("available_tools")
    if not isinstance(available_tools, dict):
        return {}
    return {str(name).lower(): bool(available) for name, available in available_tools.items()}


def _merge_worker_tool_health(tools: list[dict]) -> tuple[list[dict], bool]:
    worker_tools = _worker_available_tools()
    if not worker_tools:
        return tools, False
    aliases = {
        "Nuclei": "nuclei",
        "Nmap": "nmap",
        "Naabu": "naabu",
        "OWASP ZAP baseline": "zap",
        "Nikto": "nikto",
        "ProjectDiscovery httpx": "httpx",
        "Katana": "katana",
        "WhatWeb": "whatweb",
        "wafw00f": "wafw00f",
        "SSLyze": "sslyze",
        "testssl.sh": "testssl.sh",
        "Amass": "amass",
        "Subfinder": "subfinder",
        "dnsx": "dnsx",
        "Trivy": "trivy",
        "Semgrep": "semgrep",
        "Gitleaks": "gitleaks",
        "Grype": "grype",
        "Checkov": "checkov",
        "Prowler": "prowler",
        "ScoutSuite": "scoutsuite",
    }
    merged = []
    for tool in tools:
        worker_key = aliases.get(tool["name"])
        if worker_key and worker_key in worker_tools:
            tool = {
                **tool,
                "available": worker_tools[worker_key],
                "resolved_path": "scanner worker" if worker_tools[worker_key] else tool.get("resolved_path"),
                "source": "worker",
            }
        merged.append(tool)
    return merged, True


@app.get("/api/scanner-health")
def scanner_health(user: Row = Depends(get_current_user)) -> dict:
    _require_owner_or_analyst(user)
    tools = [
        _tool_health("Nuclei", settings.nuclei_path, "Vulnerability Assessment"),
        {
            "name": "Greenbone/OpenVAS Python client",
            "category": "Vulnerability Assessment",
            "configured_path": "python-gvm",
            "available": greenbone_is_available(),
            "resolved_path": "installed" if greenbone_is_available() else None,
        },
        _tool_health("Nmap", settings.nmap_path, "Network and Services"),
        _tool_health("Naabu", settings.naabu_path, "Network and Services"),
        _tool_health("OWASP ZAP baseline", settings.zap_baseline_path, "Web and API"),
        _tool_health("Nikto", settings.nikto_path, "Web and API"),
        _tool_health("ProjectDiscovery httpx", settings.httpx_path, "Web and API"),
        _tool_health("Katana", settings.katana_path, "Web and API"),
        _tool_health("WhatWeb", settings.whatweb_path, "Web and API"),
        _tool_health("wafw00f", settings.wafw00f_path, "Web Protection"),
        _tool_health("SSLyze", settings.sslyze_path, "TLS"),
        _tool_health("testssl.sh", settings.testssl_path, "TLS"),
        _tool_health("Amass", settings.amass_path, "Authorized Reconnaissance"),
        _tool_health("Subfinder", settings.subfinder_path, "Authorized Reconnaissance"),
        _tool_health("dnsx", settings.dnsx_path, "Authorized Reconnaissance"),
        _tool_health("Trivy", settings.trivy_path, "Code, Cloud, and IaC"),
        _tool_health("Semgrep", settings.semgrep_path, "Code and Supply Chain"),
        _tool_health("Gitleaks", settings.gitleaks_path, "Code and Supply Chain"),
        _tool_health("Grype", settings.grype_path, "Code and Supply Chain"),
        _tool_health("Checkov", settings.checkov_path, "Cloud and IaC"),
        _tool_health("Prowler", settings.prowler_path, "Cloud Posture"),
        _tool_health("ScoutSuite", settings.scoutsuite_path, "Cloud Posture"),
    ]
    tools.append(
        {
            "name": "OpenAI AI triage",
            "category": "AI Reporting",
            "configured_path": "OPENAI_API_KEY",
            "available": bool(settings.openai_api_key),
            "resolved_path": "configured" if settings.openai_api_key else None,
        }
    )
    tools.append(
        {
            "name": "Cloud credential checks",
            "category": "Cloud Posture",
            "configured_path": "CLOUD_CHECKS_ENABLED",
            "available": settings.cloud_checks_enabled,
            "resolved_path": "enabled" if settings.cloud_checks_enabled else None,
        }
    )
    tools, worker_connected = _merge_worker_tool_health(tools)
    available = sum(1 for tool in tools if tool["available"])
    return {
        "available": available,
        "missing": len(tools) - available,
        "tools": tools,
        "backend": settings.scanner_backend,
        "worker_connected": worker_connected,
    }


@app.post("/api/auth/request-code")
def request_code(request: Request, payload: AuthRequest) -> dict:
    _rate_limit(request, "auth.request_code", limit=20, window_seconds=15 * 60)
    try:
        return auth_service.request_code(payload.email)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Verification email could not be sent. Check SMTP settings and try Resend code.",
        ) from exc


@app.post("/api/auth/register")
def register(request: Request, payload: RegistrationRequest) -> dict:
    _rate_limit(request, "auth.register", limit=20, window_seconds=15 * 60)
    try:
        result = auth_service.register_account(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Registration was saved, but the verification email could not be sent. Use Resend code or check SMTP settings.",
        ) from exc
    return result


@app.post("/api/auth/login")
def login(request: Request, payload: LoginRequest) -> Response:
    _rate_limit(request, "auth.login", limit=30, window_seconds=15 * 60)
    try:
        user = auth_service.login(payload.email, payload.password)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    token = create_session_token(settings, int(user["id"]), user["email"])
    response = JSONResponse({"message": "Login successful.", "user": _serialize_user(user)})
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=int(timedelta(hours=settings.session_ttl_hours).total_seconds()),
    )
    return response


@app.post("/api/auth/password-reset/request")
def request_password_reset(request: Request, payload: PasswordResetRequest) -> dict:
    _rate_limit(request, "auth.password_reset_request", limit=15, window_seconds=15 * 60)
    return auth_service.request_password_reset(payload.email)


@app.post("/api/auth/password-reset/confirm")
def confirm_password_reset(request: Request, payload: PasswordResetConfirmRequest) -> Response:
    _rate_limit(request, "auth.password_reset_confirm", limit=20, window_seconds=15 * 60)
    try:
        user = auth_service.reset_password(payload.email, payload.code, payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    token = create_session_token(settings, int(user["id"]), user["email"])
    response = JSONResponse({"message": "Password reset successful.", "user": _serialize_user(user)})
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=int(timedelta(hours=settings.session_ttl_hours).total_seconds()),
    )
    return response


@app.post("/api/auth/verify")
def verify_code(request: Request, payload: AuthVerifyRequest) -> Response:
    _rate_limit(request, "auth.verify_code", limit=30, window_seconds=15 * 60)
    try:
        user = auth_service.verify_code(payload.email, payload.code)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    token = create_session_token(settings, int(user["id"]), user["email"])
    response = JSONResponse({"message": "Authentication successful.", "user": _serialize_user(user)})
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=int(timedelta(hours=settings.session_ttl_hours).total_seconds()),
    )
    return response


@app.post("/api/auth/logout")
def logout() -> Response:
    response = JSONResponse({"message": "Logged out."})
    response.delete_cookie(settings.session_cookie_name)
    return response


@app.post("/api/auth/complete-registration")
def complete_registration(
    request: Request,
    payload: RegistrationProfileRequest,
    user: Row = Depends(get_current_user),
) -> dict:
    _rate_limit(request, "auth.complete_registration", limit=20, window_seconds=60)
    if not payload.safe_use_accepted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Safe-use acceptance is required.",
        )
    if not payload.data_protection_accepted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data protection agreement acceptance is required.",
        )
    now = utcnow().isoformat()
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE users
            SET full_name = ?,
                job_title = ?,
                professional_role = ?,
                company_name = ?,
                company_address = ?,
                phone_number = ?,
                date_of_birth = ?,
                testing_reason = ?,
                data_protection_accepted = 1,
                data_protection_accepted_at = COALESCE(data_protection_accepted_at, ?),
                safe_use_accepted = 1,
                profile_completed_at = ?
            WHERE id = ? AND organization_id = ?
            """,
            (
                payload.full_name.strip(),
                payload.job_title.strip(),
                payload.professional_role.strip(),
                payload.company_name.strip(),
                payload.company_address.strip(),
                payload.phone_number.strip(),
                (payload.date_of_birth or "").strip(),
                payload.testing_reason.strip(),
                now,
                now,
                user["id"],
                user["organization_id"],
            ),
        )
        connection.execute(
            "UPDATE organizations SET name = ? WHERE id = ?",
            (payload.company_name.strip(), user["organization_id"]),
        )
        refreshed = auth_service.get_user_by_id(int(user["id"]))
        _audit(connection, user, "auth.registration_completed", {"user_id": user["id"]})
    return {"message": "Registration completed.", "user": _serialize_user(refreshed)}


@app.get("/api/dashboard", response_model=DashboardResponse)
def dashboard(user: Row = Depends(get_current_user)) -> DashboardResponse:
    with get_connection() as connection:
        if _is_client_viewer(user):
            scans = connection.execute(
                """
                SELECT scans.*,
                       targets.normalized_target,
                       targets.asset_type,
                       targets.target,
                       COUNT(manual_findings.id) AS manual_finding_count
                FROM scans
                JOIN targets ON targets.id = scans.target_id
                LEFT JOIN manual_findings ON manual_findings.scan_id = scans.id
                WHERE scans.organization_id = ? AND scans.status = 'completed'
                GROUP BY scans.id
                ORDER BY scans.id DESC
                LIMIT 15
                """,
                (user["organization_id"],),
            ).fetchall()
            entitlement = _active_entitlement(connection, user["organization_id"])
            scan_summaries = [_summary_from_row(scan) for scan in scans]
            return DashboardResponse(
                user=_serialize_user(user),
                organization={
                    "id": user["organization_id"],
                    "name": user["organization_name"],
                    "domain": user["email_domain"],
                },
                entitlement=_serialize_entitlement(entitlement),
                stats={
                    "authorized_assets": 0,
                    "total_scans": len(scan_summaries),
                    "active_scans": 0,
                    "latest_risk_score": scan_summaries[0].risk_score if scan_summaries else None,
                    "latest_severity_counts": scan_summaries[0].severity_counts if scan_summaries and scan_summaries[0].severity_counts else SeverityCounts(),
                },
                scans=scan_summaries,
            )

        scans = connection.execute(
            """
            SELECT scans.*,
                   targets.normalized_target,
                   targets.asset_type,
                   targets.target,
                   COUNT(manual_findings.id) AS manual_finding_count
            FROM scans
            JOIN targets ON targets.id = scans.target_id
            LEFT JOIN manual_findings ON manual_findings.scan_id = scans.id
            WHERE scans.organization_id = ?
            GROUP BY scans.id
            ORDER BY scans.id DESC
            LIMIT 15
            """,
            (user["organization_id"],),
        ).fetchall()

        engagements = connection.execute(
            """
            SELECT *
            FROM engagements
            WHERE organization_id = ?
            ORDER BY id DESC
            LIMIT 20
            """,
            (user["organization_id"],),
        ).fetchall()

        manual_findings = connection.execute(
            """
            SELECT manual_findings.*
            FROM manual_findings
            JOIN scans ON scans.id = manual_findings.scan_id
            WHERE manual_findings.organization_id = ?
            ORDER BY manual_findings.id DESC
            LIMIT 30
            """,
            (user["organization_id"],),
        ).fetchall()

        audit_events = connection.execute(
            """
            SELECT *
            FROM audit_events
            WHERE organization_id = ?
            ORDER BY id DESC
            LIMIT 20
            """,
            (user["organization_id"],),
        ).fetchall()

        members = connection.execute(
            """
            SELECT *
            FROM users
            WHERE organization_id = ?
            ORDER BY id
            """,
            (user["organization_id"],),
        ).fetchall()

        payments = connection.execute(
            """
            SELECT *
            FROM payments
            WHERE organization_id = ?
            ORDER BY id DESC
            LIMIT 10
            """,
            (user["organization_id"],),
        ).fetchall()

        target_count = connection.execute(
            "SELECT COUNT(*) AS count FROM targets WHERE organization_id = ?",
            (user["organization_id"],),
        ).fetchone()["count"]
        entitlement = _active_entitlement(connection, user["organization_id"])

    scan_summaries = [_summary_from_row(scan) for scan in scans]
    latest_completed = next((scan for scan in scan_summaries if scan.risk_score is not None), None)
    stats = {
        "authorized_assets": target_count,
        "total_scans": len(scan_summaries),
        "active_scans": sum(1 for scan in scan_summaries if scan.status in {"queued", "running"}),
        "latest_risk_score": latest_completed.risk_score if latest_completed else None,
        "latest_severity_counts": (
            latest_completed.severity_counts
            if latest_completed
            else SeverityCounts()
        ),
    }

    return DashboardResponse(
        user=_serialize_user(user),
        organization={
            "id": user["organization_id"],
            "name": user["organization_name"],
            "domain": user["email_domain"],
        },
        entitlement=_serialize_entitlement(entitlement),
        stats=stats,
        toolchain=get_ethical_pentest_toolchain(),
        profiles=get_assessment_profiles(),
        engagements=[_serialize_engagement(row) for row in engagements],
        members=[_serialize_member(row) for row in members],
        payments=[_serialize_payment(row) for row in payments],
        manual_findings=[_serialize_manual_finding(row) for row in manual_findings],
        audit_events=[_serialize_audit_event(row) for row in audit_events],
        scans=scan_summaries,
    )


@app.post("/api/payments/intent")
def create_payment_intent(
    request: Request,
    payload: PaymentIntentRequest,
    user: Row = Depends(get_current_user),
) -> dict:
    _rate_limit(request, "payments.intent", limit=20, window_seconds=60)
    _require_owner(user)
    _require_completed_registration(user)
    plan = _plan_details(payload.plan)
    return {
        "provider": "kryptnet_payment_api",
        "plan": plan,
        "accepted_methods": ["debit_card", "credit_card"],
        "client_reference": f"intent_{secrets.token_hex(10)}",
        "checkout_url": plan["payment_url"],
        "note": "KryptNet Payment API checkout accepts debit and credit card payments.",
    }


@app.post("/api/payments/checkout")
def create_payment_checkout(
    request: Request,
    payload: PaymentCheckoutRequest,
    user: Row = Depends(get_current_user),
) -> dict:
    _rate_limit(request, "payments.checkout", limit=10, window_seconds=60)
    _require_owner(user)
    _require_completed_registration(user)
    plan = _plan_details(payload.plan)
    provider_reference = f"kryptnet_{secrets.token_hex(12)}"
    now = utcnow().isoformat()
    expires_at = (utcnow() + timedelta(days=plan["access_days"])).isoformat()
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO payments (
                organization_id,
                provider,
                plan,
                amount_cents,
                currency,
                payment_method,
                status,
                provider_reference,
                payer_name,
                payer_email,
                safe_details_json,
                created_by,
                created_at
            )
            VALUES (?, 'kryptnet_payment_api', ?, ?, ?, 'debit_credit_checkout', 'checkout_created', ?, ?, ?, ?, ?, ?)
            """,
            (
                user["organization_id"],
                plan["id"],
                plan["amount_cents"],
                plan["currency"],
                provider_reference,
                user["organization_name"],
                user["email"],
                json.dumps(
                    {
                        "checkout_url": plan["payment_url"],
                        "payment_type": "one_time",
                        "accepted_methods": ["debit_card", "credit_card"],
                    }
                ),
                user["id"],
                now,
            ),
        )
        if settings.payment_demo_mode:
            connection.execute(
                "UPDATE entitlements SET status = 'expired' WHERE organization_id = ?",
                (user["organization_id"],),
            )
            connection.execute(
                """
                INSERT INTO entitlements (organization_id, plan, status, expires_at, created_at)
                VALUES (?, ?, 'active', ?, ?)
                """,
                (user["organization_id"], plan["id"], expires_at, now),
            )
        _audit(
            connection,
            user,
            "payment.checkout_created",
            {
                "payment_id": cursor.lastrowid,
                "plan": plan["id"],
                "amount_cents": plan["amount_cents"],
                "provider_reference": provider_reference,
                "checkout_url": plan["payment_url"],
                "payment_type": "one_time",
            },
        )
    return {
        "provider": "kryptnet_payment_api",
        "plan": plan,
        "status": "checkout_created",
        "payment_access_status": "active" if settings.payment_demo_mode else "pending_payment",
        "checkout_url": plan["payment_url"],
        "provider_reference": provider_reference,
        "message": (
            "KryptNet debit/credit checkout link prepared. Demo mode activated paid access locally."
            if settings.payment_demo_mode
            else "KryptNet debit/credit checkout link prepared. Paid access activates after payment confirmation."
        ),
    }


@app.post("/api/payments/webhook/kryptnet")
def kryptnet_payment_webhook(request: Request, payload: PaymentWebhookRequest) -> dict:
    _rate_limit(request, "payments.webhook", limit=120, window_seconds=60)
    if not settings.kryptnet_payment_webhook_secret:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Payment webhook is not configured.")
    supplied_secret = request.headers.get("x-kryptnet-webhook-secret", "")
    if not secrets.compare_digest(supplied_secret, settings.kryptnet_payment_webhook_secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid payment webhook secret.")

    normalized_status = payload.status.strip().lower()
    paid_statuses = {"paid", "completed", "complete", "succeeded", "success"}
    failed_statuses = {"failed", "canceled", "cancelled", "expired", "declined"}
    if normalized_status not in paid_statuses | failed_statuses | {"pending", "processing"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported payment status.")

    now = utcnow().isoformat()
    with get_connection() as connection:
        payment = connection.execute(
            "SELECT * FROM payments WHERE provider_reference = ?",
            (payload.provider_reference.strip(),),
        ).fetchone()
        if payment is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payment reference not found.")
        plan = _plan_details(payment["plan"])
        if payload.plan and payload.plan.strip().lower() != plan["id"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payment plan mismatch.")
        if payload.amount_cents is not None and int(payload.amount_cents) != int(payment["amount_cents"]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payment amount mismatch.")
        if payload.currency and payload.currency.upper() != payment["currency"].upper():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payment currency mismatch.")

        stored_details = json.loads(payment["safe_details_json"] or "{}")
        stored_details.update(
            {
                "webhook_status": normalized_status,
                "webhook_received_at": now,
                "webhook_payer_email": payload.payer_email,
            }
        )
        connection.execute(
            "UPDATE payments SET status = ?, safe_details_json = ? WHERE id = ?",
            (normalized_status, json.dumps(stored_details), payment["id"]),
        )

        access_status = "unchanged"
        if normalized_status in paid_statuses:
            expires_at = (utcnow() + timedelta(days=plan["access_days"])).isoformat()
            connection.execute(
                "UPDATE entitlements SET status = 'expired' WHERE organization_id = ?",
                (payment["organization_id"],),
            )
            connection.execute(
                """
                INSERT INTO entitlements (organization_id, plan, status, expires_at, created_at)
                VALUES (?, ?, 'active', ?, ?)
                """,
                (payment["organization_id"], plan["id"], expires_at, now),
            )
            access_status = "active"
        elif normalized_status in failed_statuses:
            connection.execute(
                "UPDATE entitlements SET status = 'expired' WHERE organization_id = ? AND plan = ?",
                (payment["organization_id"], plan["id"]),
            )
            access_status = "inactive"

        connection.execute(
            """
            INSERT INTO audit_events (organization_id, actor_id, action, details_json, created_at)
            VALUES (?, NULL, 'payment.webhook_received', ?, ?)
            """,
            (
                payment["organization_id"],
                json.dumps(
                    {
                        "payment_id": payment["id"],
                        "provider_reference": payload.provider_reference,
                        "status": normalized_status,
                        "access_status": access_status,
                    }
                ),
                now,
            ),
        )

    return {"status": "accepted", "payment_status": normalized_status, "payment_access_status": access_status}


@app.post("/api/payments/submit")
def submit_payment(
    request: Request,
    user: Row = Depends(get_current_user),
) -> dict:
    _rate_limit(request, "payments.submit", limit=10, window_seconds=60)
    _require_owner(user)
    _require_completed_registration(user)
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Direct payment submission is disabled. Use KryptNet debit/credit checkout only.",
    )


@app.post("/api/members", response_model=MemberSummary)
def create_member(
    request: Request,
    payload: MemberCreateRequest,
    user: Row = Depends(get_current_user),
) -> MemberSummary:
    _rate_limit(request, "members.create", limit=20, window_seconds=60)
    _require_owner(user)
    role = payload.role.strip().lower()
    if role not in {"owner", "analyst", "client_viewer"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported role.")
    email = payload.email.strip().lower()
    if "@" not in email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Valid email required.")
    now = utcnow().isoformat()
    with get_connection() as connection:
        existing = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if existing and existing["organization_id"] != user["organization_id"]:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User belongs to another organization.")
        if existing:
            connection.execute(
                """
                UPDATE users
                SET role = ?,
                    full_name = COALESCE(?, full_name)
                WHERE id = ?
                """,
                (role, payload.full_name, existing["id"]),
            )
            member_id = existing["id"]
        else:
            connection.execute(
                """
                INSERT INTO users (organization_id, email, full_name, role, is_verified, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
                """,
                (user["organization_id"], email, payload.full_name, role, now),
            )
            member_id = connection.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        member = connection.execute(
            "SELECT * FROM users WHERE id = ? AND organization_id = ?",
            (member_id, user["organization_id"]),
        ).fetchone()
        _audit(connection, user, "member.upserted", {"member_id": member["id"], "email": member["email"], "role": member["role"]})
    return _serialize_member(member)


@app.get("/api/client-portal", response_model=ClientPortalResponse)
def client_portal(user: Row = Depends(get_current_user)) -> ClientPortalResponse:
    if user["role"] not in {"owner", "analyst", "client_viewer"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Portal access denied.")
    with get_connection() as connection:
        scans = connection.execute(
            """
            SELECT scans.*, targets.normalized_target, targets.asset_type, targets.target
            FROM scans
            JOIN targets ON targets.id = scans.target_id
            WHERE scans.organization_id = ? AND scans.status = 'completed'
            ORDER BY scans.completed_at DESC
            LIMIT 20
            """,
            (user["organization_id"],),
        ).fetchall()

    reports = []
    remediation_queue = []
    for scan in scans:
        report = _get_report_for_scan(scan)
        if report is None:
            continue
        reports.append(
            {
                "scan_id": scan["id"],
                "target": scan["normalized_target"],
                "assessment_mode": normalize_assessment_mode(scan["assessment_mode"]),
                "risk_score": report.risk_score,
                "risk_band": report.risk_band,
                "completed_at": scan["completed_at"],
                "pdf_available": bool(scan["report_pdf_path"]),
            }
        )
        for item in report.remediation_plan[:5]:
            remediation_queue.append(
                {
                    "scan_id": scan["id"],
                    "target": scan["normalized_target"],
                    "title": item.title,
                    "priority": item.priority,
                    "action": item.action,
                    "owner": item.owner,
                }
            )
    return ClientPortalResponse(
        user=_serialize_user(user),
        organization={
            "id": user["organization_id"],
            "name": user["organization_name"],
            "domain": user["email_domain"],
        },
        reports=reports,
        remediation_queue=remediation_queue,
    )


@app.post("/api/billing/mock-activate")
def activate_mock_billing(request: Request, user: Row = Depends(get_current_user)) -> dict:
    _rate_limit(request, "billing.mock_activate", limit=5, window_seconds=60)
    _require_owner(user)
    expires_at = (utcnow() + timedelta(days=30)).isoformat()
    with get_connection() as connection:
        connection.execute(
            "UPDATE entitlements SET status = 'expired' WHERE organization_id = ?",
            (user["organization_id"],),
        )
        connection.execute(
            """
            INSERT INTO entitlements (organization_id, plan, status, expires_at, created_at)
            VALUES (?, 'professional', 'active', ?, ?)
            """,
            (user["organization_id"], expires_at, utcnow().isoformat()),
        )
        _audit(connection, user, "billing.mock_activated", {"plan": "professional", "expires_at": expires_at})
    return {"status": "active", "plan": "professional", "expires_at": expires_at}


@app.post("/api/engagements", response_model=EngagementSummary)
def create_engagement(
    request: Request,
    payload: EngagementCreateRequest,
    user: Row = Depends(get_current_user),
) -> EngagementSummary:
    _rate_limit(request, "engagements.create", limit=20, window_seconds=60)
    _require_owner_or_analyst(user)
    allowed_categories = payload.allowed_categories or [
        "web",
        "api",
        "network",
        "identity",
        "cloud",
        "reporting",
    ]
    now = utcnow().isoformat()
    with get_connection() as connection:
        _require_entitlement(connection, user)
        cursor = connection.execute(
            """
            INSERT INTO engagements (
                organization_id,
                client_name,
                company_address,
                contact_name,
                contact_email,
                contact_phone,
                authorization_reference,
                scope_notes,
                testing_window,
                allowed_categories_json,
                emergency_contact,
                status,
                created_by,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_approval', ?, ?)
            """,
            (
                user["organization_id"],
                payload.client_name.strip(),
                _clean_optional(payload.company_address),
                _clean_optional(payload.contact_name),
                _clean_optional(payload.contact_email),
                _clean_optional(payload.contact_phone),
                payload.authorization_reference.strip(),
                payload.scope_notes.strip(),
                payload.testing_window.strip(),
                json.dumps(allowed_categories),
                payload.emergency_contact.strip(),
                user["id"],
                now,
            ),
        )
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id = ? AND organization_id = ?",
            (cursor.lastrowid, user["organization_id"]),
        ).fetchone()
        _audit(connection, user, "engagement.created", {"engagement_id": engagement["id"], "client_name": engagement["client_name"]})
    return _serialize_engagement(engagement)


@app.post("/api/engagements/{engagement_id}/approve", response_model=EngagementSummary)
def approve_engagement(
    request: Request,
    engagement_id: int,
    user: Row = Depends(get_current_user),
) -> EngagementSummary:
    _rate_limit(request, "engagements.approve", limit=20, window_seconds=60)
    _require_owner(user)
    with get_connection() as connection:
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id = ? AND organization_id = ?",
            (engagement_id, user["organization_id"]),
        ).fetchone()
        if engagement is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Engagement not found.")
        approved_at = utcnow().isoformat()
        connection.execute(
            """
            UPDATE engagements
            SET status = 'approved',
                approved_by = ?,
                approved_at = ?
            WHERE id = ? AND organization_id = ?
            """,
            (user["id"], approved_at, engagement_id, user["organization_id"]),
        )
        _audit(connection, user, "engagement.approved", {"engagement_id": engagement_id})
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id = ? AND organization_id = ?",
            (engagement_id, user["organization_id"]),
        ).fetchone()
    return _serialize_engagement(engagement)


@app.post("/api/scans", response_model=ScanSummary)
def create_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: ScanCreateRequest,
    user: Row = Depends(get_current_user),
) -> ScanSummary:
    _rate_limit(request, "scans.create", limit=6, window_seconds=60)
    _require_owner_or_analyst(user)
    _require_completed_registration(user)
    asset_type = payload.asset_type or infer_asset_type(payload.target)
    if asset_type not in {"website", "network"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported target type.")
    try:
        assessment_mode = normalize_assessment_mode(payload.assessment_mode)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    scan_tier = payload.scan_tier.strip().lower()
    if scan_tier != "full_scan":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Free vulnerability testing has been removed. Select Vulnerability Assessment or Ethical Pen-Testing.",
        )
    selected_backend = resolve_backend_name(settings, asset_type, assessment_mode)

    try:
        authorization = authorize_target(user["email_domain"], payload.target, asset_type)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    _require_target_network_policy(
        authorization["normalized_target"],
        authorization["target_kind"],
    )

    now = utcnow().isoformat()
    scan_protocols = build_scan_protocols(asset_type, authorization["target_kind"], assessment_mode)
    scan_protocols.append("Full scan: deeper testing with PDF report delivery to verified email")
    if assessment_mode == "ethical_pentesting":
        depth = payload.pentest_depth.strip().lower()
        if depth not in {"standard", "deep"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Testing depth must be standard or deep.")
        validation_mode = payload.validation_mode.strip().lower()
        if validation_mode not in {"safe_validation", "evidence_only"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Validation mode must be safe_validation or evidence_only.")
        focus = [item.strip().lower() for item in payload.vulnerability_focus if item.strip()]
        if not focus:
            focus = ["web", "api", "network", "tls", "identity", "cloud", "code", "secrets"]
        allowed_focus = {"web", "api", "network", "tls", "identity", "cloud", "code", "secrets"}
        unsupported_focus = sorted(set(focus) - allowed_focus)
        if unsupported_focus:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported vulnerability focus: {', '.join(unsupported_focus)}.",
            )
        scan_protocols.extend(
            [
                f"Ethical testing depth: {depth}",
                f"Validation mode: {validation_mode.replace('_', ' ')}",
                f"Vulnerability focus: {', '.join(focus)}",
            ]
        )
        if payload.known_vulnerabilities:
            scan_protocols.append(f"Known vulnerabilities to validate: {payload.known_vulnerabilities.strip()}")

    report_company_name = _clean_optional(payload.report_company_name)
    report_company_address = _clean_optional(payload.report_company_address)
    report_contact_name = _clean_optional(payload.report_contact_name)
    report_contact_email = _clean_optional(payload.report_contact_email)
    report_contact_phone = _clean_optional(payload.report_contact_phone)
    report_authorization_reference = _clean_optional(payload.report_authorization_reference)
    report_scope_notes = _clean_optional(payload.report_scope_notes)
    report_testing_window = _clean_optional(payload.report_testing_window)
    report_emergency_contact = _clean_optional(payload.report_emergency_contact)
    report_values = [
        report_company_name,
        report_company_address,
        report_contact_name,
        report_contact_email,
        report_contact_phone,
        report_authorization_reference,
        report_scope_notes,
        report_testing_window,
        report_emergency_contact,
    ]
    report_intake_requested = any(report_values)
    if report_intake_requested and not payload.engagement_id:
        missing_report_fields = [
            label
            for label, value in [
                ("company name", report_company_name),
                ("company address", report_company_address),
                ("contact name", report_contact_name),
                ("contact email", report_contact_email),
                ("contact phone", report_contact_phone),
                ("authorization reference", report_authorization_reference),
                ("scope notes", report_scope_notes),
                ("testing window", report_testing_window),
                ("emergency contact", report_emergency_contact),
            ]
            if not value
        ]
        if missing_report_fields:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Complete all optional report details or hide the report section before launching this service: {', '.join(missing_report_fields)}.",
            )

    with get_connection() as connection:
        if scan_tier == "full_scan":
            _require_entitlement(connection, user)
        connection.execute(
            """
            INSERT INTO targets (
                organization_id,
                target,
                normalized_target,
                asset_type,
                ownership_domain,
                authorization_method,
                verification_note,
                created_by,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(organization_id, normalized_target, asset_type) DO UPDATE SET
                target = excluded.target,
                verification_note = excluded.verification_note
            """,
            (
                user["organization_id"],
                payload.target.strip(),
                authorization["normalized_target"],
                asset_type,
                user["email_domain"],
                authorization["authorization_method"],
                authorization["verification_note"],
                user["id"],
                now,
            ),
        )

        target_row = connection.execute(
            """
            SELECT *
            FROM targets
            WHERE organization_id = ? AND normalized_target = ? AND asset_type = ?
            """,
            (
                user["organization_id"],
                authorization["normalized_target"],
                asset_type,
            ),
        ).fetchone()

        engagement_id = payload.engagement_id
        if engagement_id is not None:
            engagement = connection.execute(
                "SELECT * FROM engagements WHERE id = ? AND organization_id = ?",
                (engagement_id, user["organization_id"]),
            ).fetchone()
            if engagement is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Engagement not found.")
        elif report_intake_requested:
            cursor = connection.execute(
                """
                INSERT INTO engagements (
                    organization_id,
                    client_name,
                    company_address,
                    contact_name,
                    contact_email,
                    contact_phone,
                    authorization_reference,
                    scope_notes,
                    testing_window,
                    allowed_categories_json,
                    emergency_contact,
                    status,
                    approved_by,
                    approved_at,
                    created_by,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?, ?)
                """,
                (
                    user["organization_id"],
                    report_company_name,
                    report_company_address,
                    report_contact_name,
                    report_contact_email,
                    report_contact_phone,
                    report_authorization_reference,
                    report_scope_notes,
                    report_testing_window,
                    json.dumps(["web", "api", "network", "identity", "cloud", "reporting"]),
                    report_emergency_contact,
                    user["id"],
                    now,
                    user["id"],
                    now,
                ),
            )
            engagement_id = cursor.lastrowid

        cursor = connection.execute(
            """
            INSERT INTO scans (
                organization_id,
                target_id,
                requested_by,
                engagement_id,
                scanner_backend,
                assessment_mode,
                scan_tier,
                status,
                scan_profile_json,
                progress_percent,
                progress_message,
                created_at,
                started_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?)
            """,
            (
                user["organization_id"],
                target_row["id"],
                user["id"],
                engagement_id,
                selected_backend,
                assessment_mode,
                scan_tier,
                json.dumps(scan_protocols),
                5,
                "Scan queued. Waiting for scanner worker.",
                now,
                None,
            ),
        )
        scan_id = cursor.lastrowid

        scan = _load_scan(connection, scan_id, user["organization_id"])
        _audit(
            connection,
            user,
            "scan.created",
            {
                "scan_id": scan_id,
                "target": authorization["normalized_target"],
                "mode": assessment_mode,
                "tier": scan_tier,
                "engagement_id": engagement_id,
            },
        )

    background_tasks.add_task(_run_scan_job, scan_id, int(user["id"]))
    return _summary_from_row(scan)


@app.post("/api/scans/{scan_id}/manual-findings", response_model=ManualFindingSummary)
def add_manual_finding(
    request: Request,
    scan_id: int,
    payload: ManualFindingCreateRequest,
    user: Row = Depends(get_current_user),
) -> ManualFindingSummary:
    _rate_limit(request, "manual_findings.create", limit=30, window_seconds=60)
    _require_owner_or_analyst(user)
    severity = payload.severity.strip().lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported severity.")

    now = utcnow().isoformat()
    with get_connection() as connection:
        scan = _load_scan(connection, scan_id, user["organization_id"])
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
        cursor = connection.execute(
            """
            INSERT INTO manual_findings (
                organization_id,
                scan_id,
                title,
                severity,
                category,
                evidence,
                remediation,
                created_by,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["organization_id"],
                scan_id,
                payload.title.strip(),
                severity,
                payload.category.strip(),
                payload.evidence.strip(),
                payload.remediation.strip(),
                user["id"],
                now,
            ),
        )
        finding = connection.execute(
            "SELECT * FROM manual_findings WHERE id = ? AND organization_id = ?",
            (cursor.lastrowid, user["organization_id"]),
        ).fetchone()
        _audit(connection, user, "manual_finding.created", {"scan_id": scan_id, "manual_finding_id": finding["id"]})

    _regenerate_completed_report(scan_id, user, notify_user=False)
    return _serialize_manual_finding(finding)


@app.post("/api/scans/{scan_id}/regenerate-report", response_model=ScanSummary)
def regenerate_report(
    request: Request,
    scan_id: int,
    user: Row = Depends(get_current_user),
) -> ScanSummary:
    _rate_limit(request, "reports.regenerate", limit=10, window_seconds=60)
    _require_owner_or_analyst(user)
    scan = _regenerate_completed_report(scan_id, user, notify_user=False)
    return _summary_from_row(scan)


def _regenerate_completed_report(scan_id: int, user: Row, *, notify_user: bool) -> Row:
    with get_connection() as connection:
        scan = _load_scan(connection, scan_id, user["organization_id"])
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
        report = _get_report_for_scan(scan)
        if report is None:
            return scan

    return _store_completed_scan(
        scan_id=scan_id,
        user=user,
        report=report,
        notify_user=notify_user,
        create_pdf=(scan["scan_tier"] or "full_scan") == "full_scan",
        backend_name=scan["scanner_backend"],
    )


@app.post("/api/scans/{scan_id}/refresh", response_model=ScanSummary)
def refresh_scan(
    request: Request,
    scan_id: int,
    user: Row = Depends(get_current_user),
) -> ScanSummary:
    _rate_limit(request, "scans.refresh", limit=20, window_seconds=60)
    _require_owner_or_analyst(user)
    with get_connection() as connection:
        scan = _load_scan(connection, scan_id, user["organization_id"])
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    if scan["scanner_backend"] in {"mock", "nuclei", "ethical_toolkit", "free_preview"}:
        provider = get_scanner_provider(settings, scan["scanner_backend"])
        refreshed = provider.refresh(scan["normalized_target"], scan["asset_type"])
    elif scan["scanner_backend"] == "worker":
        provider = get_scanner_provider(settings, scan["scanner_backend"])
        try:
            refreshed = provider.refresh(
                scan["normalized_target"],
                scan["asset_type"],
                scan["external_task_id"],
                scan["external_report_id"],
            )
        except Exception as exc:
            with get_connection() as connection:
                connection.execute(
                    "UPDATE scans SET status = 'failed', error_message = ?, progress_message = ?, refreshed_at = ? WHERE id = ?",
                    (str(exc), f"Worker refresh failed: {str(exc)}", utcnow().isoformat(), scan_id),
                )
                scan = _load_scan(connection, scan_id, user["organization_id"])
            return _summary_from_row(scan)
    else:
        provider = get_scanner_provider(settings, scan["scanner_backend"])
        try:
            refreshed = provider.refresh(
                scan["normalized_target"],
                scan["asset_type"],
                scan["external_task_id"],
                scan["external_report_id"],
            )
        except Exception as exc:
            with get_connection() as connection:
                connection.execute(
                    "UPDATE scans SET status = 'failed', error_message = ?, refreshed_at = ? WHERE id = ?",
                    (str(exc), utcnow().isoformat(), scan_id),
                )
                scan = _load_scan(connection, scan_id, user["organization_id"])
            return _summary_from_row(scan)

    if refreshed.report is not None:
        scan = _store_completed_scan(
            scan_id=scan_id,
            user=user,
            report=refreshed.report,
            notify_user=False,
            create_pdf=(scan["scan_tier"] or "full_scan") == "full_scan",
            backend_name=scan["scanner_backend"],
        )
    else:
        with get_connection() as connection:
            connection.execute(
                "UPDATE scans SET status = ?, progress_message = ?, refreshed_at = ? WHERE id = ?",
                (refreshed.status, refreshed.message, utcnow().isoformat(), scan_id),
            )
            scan = _load_scan(connection, scan_id, user["organization_id"])

    return _summary_from_row(scan)


@app.get("/api/reports/{scan_id}")
def get_report(scan_id: int, user: Row = Depends(get_current_user)) -> dict:
    with get_connection() as connection:
        scan = _load_scan(connection, scan_id, user["organization_id"])
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    report = _get_report_for_scan(scan)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Report is not ready yet. Refresh the scan status and try again.",
        )
    if not report.scan_protocols and scan["scan_profile_json"]:
        report = report.model_copy(
            update={"scan_protocols": json.loads(scan["scan_profile_json"])}
        )
    return report.model_dump()


@app.get("/api/reports/{scan_id}/pdf")
def download_report_pdf(scan_id: int, user: Row = Depends(get_current_user)) -> FileResponse:
    with get_connection() as connection:
        scan = _load_scan(connection, scan_id, user["organization_id"])
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    if not scan["report_pdf_path"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="PDF report is not ready yet.",
        )

    with get_connection() as connection:
        _audit(connection, user, "report.pdf_downloaded", {"scan_id": scan_id})

    return FileResponse(
        path=_safe_report_file_path(scan["report_pdf_path"]),
        media_type="application/pdf",
        filename=_report_path_for_scan(scan_id, scan["normalized_target"]).name,
        headers={"Cache-Control": "private, no-store, max-age=0"},
    )


@app.post("/api/reports/{scan_id}/email", response_model=ScanSummary)
def email_report_pdf(
    request: Request,
    scan_id: int,
    user: Row = Depends(get_current_user),
) -> ScanSummary:
    _rate_limit(request, "reports.email", limit=6, window_seconds=60)
    _require_owner_or_analyst(user)
    with get_connection() as connection:
        scan = _load_scan(connection, scan_id, user["organization_id"])
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
        if (scan["scan_tier"] or "full_scan") == "free_preview":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Free vulnerability preview reports are web-only and are not emailed as PDF.",
            )
        report = _get_report_for_scan(scan)
        if report is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Report is not ready yet.")

    updated_scan = _store_completed_scan(
        scan_id=scan_id,
        user=user,
        report=report,
        notify_user=True,
        create_pdf=True,
        backend_name=scan["scanner_backend"],
    )
    with get_connection() as connection:
        _audit(connection, user, "report.pdf_emailed", {"scan_id": scan_id, "email": user["email"]})
    return _summary_from_row(updated_scan)
