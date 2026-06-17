from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AuthRequest(BaseModel):
    email: str


class AuthVerifyRequest(BaseModel):
    email: str
    code: str = Field(min_length=6, max_length=6)


class RegistrationProfileRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=160)
    job_title: str = Field(min_length=2, max_length=120)
    professional_role: str = Field(min_length=2, max_length=120)
    company_name: str = Field(min_length=2, max_length=180)
    company_address: str = Field(min_length=5, max_length=300)
    phone_number: str = Field(min_length=7, max_length=40)
    testing_reason: str = Field(min_length=10, max_length=1000)
    safe_use_accepted: bool


class ScanCreateRequest(BaseModel):
    target: str = Field(min_length=3, max_length=255)
    asset_type: str | None = None
    assessment_mode: str = "vulnerability_assessment"
    scan_tier: str = "full_scan"
    engagement_id: int | None = None
    pentest_depth: str = Field(default="standard")
    vulnerability_focus: list[str] = Field(default_factory=list)
    known_vulnerabilities: str | None = Field(default=None, max_length=1000)
    validation_mode: str = Field(default="safe_validation")


class EngagementCreateRequest(BaseModel):
    client_name: str = Field(min_length=2, max_length=160)
    authorization_reference: str = Field(min_length=3, max_length=200)
    scope_notes: str = Field(min_length=5, max_length=1200)
    testing_window: str = Field(min_length=3, max_length=160)
    allowed_categories: list[str] = Field(default_factory=list)
    emergency_contact: str = Field(min_length=3, max_length=160)


class EngagementSummary(BaseModel):
    id: int
    client_name: str
    authorization_reference: str
    scope_notes: str
    testing_window: str
    allowed_categories: list[str]
    emergency_contact: str
    status: str
    approved_at: str | None = None
    created_at: str


class ManualFindingCreateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=180)
    severity: str = Field(default="medium")
    category: str = Field(min_length=3, max_length=120)
    evidence: str = Field(min_length=3, max_length=2000)
    remediation: str = Field(min_length=3, max_length=2000)


class ManualFindingSummary(BaseModel):
    id: int
    scan_id: int
    title: str
    severity: str
    category: str
    evidence: str
    remediation: str
    created_at: str


class MemberCreateRequest(BaseModel):
    email: str
    role: str = Field(default="analyst")
    full_name: str | None = None


class MemberSummary(BaseModel):
    id: int
    email: str
    role: str
    full_name: str | None = None
    is_verified: bool
    created_at: str


class PaymentIntentRequest(BaseModel):
    plan: str = Field(default="professional")


class PaymentCheckoutRequest(BaseModel):
    plan: str = Field(default="professional")


class PaymentWebhookRequest(BaseModel):
    provider_reference: str = Field(min_length=8, max_length=120)
    status: str = Field(min_length=2, max_length=40)
    plan: str | None = None
    amount_cents: int | None = None
    currency: str | None = None
    payer_email: str | None = None


class PaymentSummary(BaseModel):
    id: int
    provider: str
    plan: str
    amount_cents: int
    currency: str
    payment_method: str
    status: str
    provider_reference: str
    payer_email: str
    safe_details: dict[str, Any]
    created_at: str


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
    scope_summary: str = ""
    methodology: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
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
    assessment_mode: str = "vulnerability_assessment"
    scan_tier: str = "full_scan"
    engagement_id: int | None = None
    manual_finding_count: int = 0
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


class AuditEventSummary(BaseModel):
    id: int
    actor_id: int | None = None
    action: str
    details: dict[str, Any]
    created_at: str


class DashboardResponse(BaseModel):
    user: dict[str, Any]
    organization: dict[str, Any]
    entitlement: dict[str, Any]
    stats: dict[str, Any]
    toolchain: list[dict[str, Any]] = Field(default_factory=list)
    profiles: list[dict[str, Any]] = Field(default_factory=list)
    engagements: list[EngagementSummary] = Field(default_factory=list)
    members: list[MemberSummary] = Field(default_factory=list)
    payments: list[PaymentSummary] = Field(default_factory=list)
    manual_findings: list[ManualFindingSummary] = Field(default_factory=list)
    audit_events: list[AuditEventSummary] = Field(default_factory=list)
    scans: list[ScanSummary]


class ClientPortalResponse(BaseModel):
    user: dict[str, Any]
    organization: dict[str, Any]
    reports: list[dict[str, Any]] = Field(default_factory=list)
    remediation_queue: list[dict[str, Any]] = Field(default_factory=list)
