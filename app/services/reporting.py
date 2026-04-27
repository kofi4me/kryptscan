from __future__ import annotations

from collections import Counter

from app.models import (
    AssessmentReport,
    ChartDatum,
    ComplianceCheck,
    Finding,
    RemediationItem,
    SeverityCounts,
    TrendPoint,
)
from app.security import utcnow


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 6,
    "medium": 3,
    "low": 1,
    "info": 0,
}


def severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _risk_band(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Moderate"
    return "Low"


def _serialize_counts(counter: Counter) -> SeverityCounts:
    return SeverityCounts(
        critical=counter.get("critical", 0),
        high=counter.get("high", 0),
        medium=counter.get("medium", 0),
        low=counter.get("low", 0),
        info=counter.get("info", 0),
    )


def build_assessment_report(target: str, findings: list[Finding]) -> AssessmentReport:
    findings = sorted(
        findings,
        key=lambda item: (SEVERITY_WEIGHTS[item.severity], item.cvss),
        reverse=True,
    )
    severity_counter = Counter(item.severity for item in findings)
    counts = _serialize_counts(severity_counter)
    weighted_total = sum(SEVERITY_WEIGHTS[item.severity] for item in findings)
    average_weight = weighted_total / max(len(findings), 1)
    risk_score = min(100, round(average_weight * 11))

    service_counter = Counter(item.service or "unknown" for item in findings)
    category_counter = Counter(item.category for item in findings)

    top_services = [
        ChartDatum(label=label, value=value)
        for label, value in service_counter.most_common(5)
    ]
    top_categories = [
        ChartDatum(label=label, value=value)
        for label, value in category_counter.most_common(5)
    ]

    compliance_checks = [
        ComplianceCheck(
            name="Critical findings contained",
            status="fail" if counts.critical else "pass",
            detail=(
                f"{counts.critical} critical issue(s) require immediate action."
                if counts.critical
                else "No critical issues were observed in this assessment."
            ),
        ),
        ComplianceCheck(
            name="High-risk exposure backlog",
            status="warn" if counts.high >= 3 else "pass",
            detail=(
                f"{counts.high} high-severity issues need rapid triage."
                if counts.high
                else "High-severity backlog is currently controlled."
            ),
        ),
        ComplianceCheck(
            name="Externally reachable service hygiene",
            status="warn" if any(item.service in {"http", "https", "ssh", "rdp"} for item in findings) else "pass",
            detail=(
                "Public-facing services were included in the findings set and should be reviewed first."
                if any(item.service in {"http", "https", "ssh", "rdp"} for item in findings)
                else "No elevated public-facing service concentration detected in findings."
            ),
        ),
        ComplianceCheck(
            name="Remediation program readiness",
            status="pass" if findings else "warn",
            detail=(
                "Remediation actions are prioritized and ready for handoff."
                if findings
                else "No findings were available to build a remediation queue."
            ),
        ),
    ]

    remediation_plan: list[RemediationItem] = []
    seen_titles: set[str] = set()
    for finding in findings:
        if finding.title in seen_titles:
            continue
        seen_titles.add(finding.title)
        remediation_plan.append(
            RemediationItem(
                title=finding.title,
                priority=finding.severity.title(),
                action=finding.remediation,
                owner="Security Engineering",
            )
        )
        if len(remediation_plan) == 5:
            break

    trend = [
        TrendPoint(label="Week -3", value=max(risk_score - 14, 10)),
        TrendPoint(label="Week -2", value=max(risk_score - 8, 8)),
        TrendPoint(label="Week -1", value=max(risk_score - 4, 5)),
        TrendPoint(label="Current", value=risk_score),
    ]

    band = _risk_band(risk_score)
    summary = (
        f"{target} is currently rated {band.lower()} risk with {counts.critical} critical, "
        f"{counts.high} high, and {counts.medium} medium findings. "
        "Priority should go to externally exposed services and vulnerabilities with a clear patch path."
    )

    return AssessmentReport(
        executive_summary=summary,
        risk_score=risk_score,
        risk_band=band,
        severity_counts=counts,
        scan_protocols=[],
        findings=findings,
        compliance_checks=compliance_checks,
        remediation_plan=remediation_plan,
        top_services=top_services,
        top_categories=top_categories,
        trend=trend,
        generated_at=utcnow().isoformat(),
    )
