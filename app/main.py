from __future__ import annotations

import json
import re
from datetime import timedelta
from sqlite3 import Row

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.db import get_connection, init_db
from app.emailer import get_email_sender
from app.models import (
    AssessmentReport,
    AuthRequest,
    AuthVerifyRequest,
    DashboardResponse,
    ScanCreateRequest,
    ScanSummary,
    SeverityCounts,
)
from app.security import create_session_token, utcnow, verify_session_token
from app.services.auth import AuthService
from app.services.ownership import authorize_target, build_scan_protocols, infer_asset_type
from app.services.pdf_report import write_pdf_report
from app.services.scanners import get_scanner_provider, resolve_backend_name


settings = get_settings()
templates = Jinja2Templates(directory=str(settings.templates_dir))
app = FastAPI(title=settings.app_name)
app.mount("/static", StaticFiles(directory=settings.static_dir), name="static")

email_sender = get_email_sender(settings)
auth_service = AuthService(settings, email_sender)


@app.on_event("startup")
def startup_event() -> None:
    init_db()


def _serialize_user(user: Row) -> dict:
    return {
        "id": user["id"],
        "email": user["email"],
        "organization_id": user["organization_id"],
        "organization_name": user["organization_name"],
        "email_domain": user["email_domain"],
    }


def _get_report_for_scan(scan: Row) -> AssessmentReport | None:
    if not scan["report_json"]:
        return None
    payload = json.loads(scan["report_json"])
    return AssessmentReport.model_validate(payload)


def _summary_from_row(scan: Row) -> ScanSummary:
    report = _get_report_for_scan(scan)
    counts = report.severity_counts if report else None
    risk_score = report.risk_score if report else None
    return ScanSummary(
        id=scan["id"],
        target=scan["normalized_target"],
        asset_type=scan["asset_type"],
        scanner_backend=scan["scanner_backend"],
        status=scan["status"],
        created_at=scan["created_at"],
        completed_at=scan["completed_at"],
        error_message=scan["error_message"],
        risk_score=risk_score,
        severity_counts=counts,
        report_pdf_available=bool(scan["report_pdf_path"]),
        report_email_sent_at=scan["report_email_sent_at"],
        report_email_error=scan["report_email_error"],
    )


def _load_scan(connection, scan_id: int, organization_id: int) -> Row | None:
    return connection.execute(
        """
        SELECT scans.*, targets.normalized_target, targets.asset_type, targets.target
        FROM scans
        JOIN targets ON targets.id = scans.target_id
        WHERE scans.id = ? AND scans.organization_id = ?
        """,
        (scan_id, organization_id),
    ).fetchone()


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
    return slug.strip("-") or "target"


def _report_path_for_scan(scan_id: int, target: str):
    filename = f"scan-{scan_id}-{_slugify(target)}.pdf"
    return settings.reports_dir / filename


def _deliver_completed_report(
    scan_id: int,
    user: Row,
    scan: Row,
    report: AssessmentReport,
    *,
    notify_user: bool,
) -> tuple[str, str | None, str | None]:
    pdf_path = _report_path_for_scan(scan_id, scan["normalized_target"])
    report = report.model_copy(
        update={
            "scan_protocols": json.loads(scan["scan_profile_json"] or "[]"),
        }
    )
    pdf_bytes = write_pdf_report(
        output_path=pdf_path,
        target=scan["normalized_target"],
        asset_type=scan["asset_type"],
        scanner_backend=scan["scanner_backend"],
        recipient_email=user["email"],
        report=report,
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


def _store_completed_scan(
    scan_id: int,
    user: Row,
    report: AssessmentReport,
    *,
    notify_user: bool,
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

        delivered_path, emailed_at, email_error = _deliver_completed_report(
            scan_id=scan_id,
            user=user,
            scan=scan,
            report=report,
            notify_user=notify_user,
        )
        persisted_report = report.model_copy(
            update={"scan_protocols": json.loads(scan["scan_profile_json"] or "[]")}
        )
        completed_at = utcnow().isoformat()
        connection.execute(
            """
            UPDATE scans
            SET status = 'completed',
                report_json = ?,
                metrics_json = ?,
                report_pdf_path = ?,
                report_email_sent_at = COALESCE(?, report_email_sent_at),
                report_email_error = ?,
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


@app.post("/api/auth/request-code")
def request_code(payload: AuthRequest) -> dict:
    return auth_service.request_code(payload.email)


@app.post("/api/auth/verify")
def verify_code(payload: AuthVerifyRequest) -> Response:
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
        samesite="lax",
        max_age=int(timedelta(hours=settings.session_ttl_hours).total_seconds()),
    )
    return response


@app.post("/api/auth/logout")
def logout() -> Response:
    response = JSONResponse({"message": "Logged out."})
    response.delete_cookie(settings.session_cookie_name)
    return response


@app.get("/api/dashboard", response_model=DashboardResponse)
def dashboard(user: Row = Depends(get_current_user)) -> DashboardResponse:
    with get_connection() as connection:
        scans = connection.execute(
            """
            SELECT scans.*, targets.normalized_target, targets.asset_type, targets.target
            FROM scans
            JOIN targets ON targets.id = scans.target_id
            WHERE scans.organization_id = ?
            ORDER BY scans.id DESC
            LIMIT 15
            """,
            (user["organization_id"],),
        ).fetchall()

        target_count = connection.execute(
            "SELECT COUNT(*) AS count FROM targets WHERE organization_id = ?",
            (user["organization_id"],),
        ).fetchone()["count"]

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
        stats=stats,
        scans=scan_summaries,
    )


@app.post("/api/scans", response_model=ScanSummary)
def create_scan(payload: ScanCreateRequest, user: Row = Depends(get_current_user)) -> ScanSummary:
    asset_type = payload.asset_type or infer_asset_type(payload.target)
    if asset_type not in {"website", "network"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported target type.")
    selected_backend = resolve_backend_name(settings, asset_type)

    try:
        authorization = authorize_target(user["email_domain"], payload.target, asset_type)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    now = utcnow().isoformat()
    scan_protocols = build_scan_protocols(asset_type, authorization["target_kind"])

    with get_connection() as connection:
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

        cursor = connection.execute(
            """
            INSERT INTO scans (
                organization_id,
                target_id,
                requested_by,
                scanner_backend,
                status,
                scan_profile_json,
                created_at,
                started_at
            )
            VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)
            """,
            (
                user["organization_id"],
                target_row["id"],
                user["id"],
                selected_backend,
                json.dumps(scan_protocols),
                now,
                now,
            ),
        )
        scan_id = cursor.lastrowid

        scan = _load_scan(connection, scan_id, user["organization_id"])

    provider = get_scanner_provider(settings, selected_backend)
    try:
        scheduled = provider.schedule(
            authorization["normalized_target"],
            asset_type,
        )
    except Exception as exc:
        with get_connection() as connection:
            connection.execute(
                "UPDATE scans SET status = 'failed', error_message = ?, refreshed_at = ? WHERE id = ?",
                (str(exc), utcnow().isoformat(), scan_id),
            )
            scan = _load_scan(connection, scan_id, user["organization_id"])
        return _summary_from_row(scan)

    if scheduled.report is not None:
        scan = _store_completed_scan(
            scan_id=scan_id,
            user=user,
            report=scheduled.report,
            notify_user=True,
            backend_name=scheduled.backend,
        )
    else:
        with get_connection() as connection:
            connection.execute(
                """
                UPDATE scans
                SET status = ?,
                    scanner_backend = ?,
                    external_task_id = ?,
                    external_report_id = ?,
                    refreshed_at = ?
                WHERE id = ?
                """,
                (
                    scheduled.status,
                    scheduled.backend,
                    scheduled.external_task_id,
                    scheduled.external_report_id,
                    utcnow().isoformat(),
                    scan_id,
                ),
            )
            scan = _load_scan(connection, scan_id, user["organization_id"])

    return _summary_from_row(scan)


@app.post("/api/scans/{scan_id}/refresh", response_model=ScanSummary)
def refresh_scan(scan_id: int, user: Row = Depends(get_current_user)) -> ScanSummary:
    with get_connection() as connection:
        scan = _load_scan(connection, scan_id, user["organization_id"])
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    if scan["scanner_backend"] in {"mock", "nuclei"}:
        provider = get_scanner_provider(settings, scan["scanner_backend"])
        refreshed = provider.refresh(scan["normalized_target"], scan["asset_type"])
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
            notify_user=not bool(scan["report_email_sent_at"]),
            backend_name=scan["scanner_backend"],
        )
    else:
        with get_connection() as connection:
            connection.execute(
                "UPDATE scans SET status = ?, refreshed_at = ? WHERE id = ?",
                (refreshed.status, utcnow().isoformat(), scan_id),
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

    return FileResponse(
        path=scan["report_pdf_path"],
        media_type="application/pdf",
        filename=_report_path_for_scan(scan_id, scan["normalized_target"]).name,
    )
