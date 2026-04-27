from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AuthRequest(BaseModel):
    email: str


class AuthVerifyRequest(BaseModel):
    email: str
    code: str = Field(min_length=6, max_length=6)


class ScanCreateRequest(BaseModel):
    target: str = Field(min_length=3, max_length=255)
    asset_type: str | None = None


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ChartDatum(BaseModel):
    label: str
    value: float


class TrendPoint(BaseModel):
    label: str
    value: float


class Finding(BaseModel):
    title: str
    severity: str
    cvss: float = 0.0
    category: str
    host: str
    port: str | None = None
    service: str | None = None
    cve: str | None = None
    description: str
    remediation: str
    evidence: str | None = None


class ComplianceCheck(BaseModel):
    name: str
    status: str
    detail: str


class RemediationItem(BaseModel):
    title: str
    priority: str
    action: str
    owner: str


class AssessmentReport(BaseModel):
    executive_summary: str
    risk_score: int
    risk_band: str
    severity_counts: SeverityCounts
    scan_protocols: list[str] = Field(default_factory=list)
    findings: list[Finding]
    compliance_checks: list[ComplianceCheck]
    remediation_plan: list[RemediationItem]
    top_services: list[ChartDatum]
    top_categories: list[ChartDatum]
    trend: list[TrendPoint]
    generated_at: str


class ScanSummary(BaseModel):
    id: int
    target: str
    asset_type: str
    scanner_backend: str
    status: str
    created_at: str
    completed_at: str | None = None
    error_message: str | None = None
    risk_score: int | None = None
    severity_counts: SeverityCounts | None = None
    report_pdf_available: bool = False
    report_email_sent_at: str | None = None
    report_email_error: str | None = None


class DashboardResponse(BaseModel):
    user: dict[str, Any]
    organization: dict[str, Any]
    stats: dict[str, Any]
    scans: list[ScanSummary]
