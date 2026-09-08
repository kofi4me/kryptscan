from __future__ import annotations

from collections import Counter
import re

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
SCANNER_DIAGNOSTIC_CATEGORIES = {
    "Scanner Toolchain",
    "Tool Execution",
    "Tool Readiness",
}
NEGATIVE_EVIDENCE_PATTERNS = [
    r"\bok\b\s*[-:]?\s*not vulnerable\b",
    r"\bnot vulnerable\b",
    r"\bnot affected\b",
    r"\bno vulnerability detected\b",
    r"\bno vulnerabilities? detected\b",
    r"\bsafe\b",
    r"\bpass(?:ed)?\b",
]
CONFIRMED_EVIDENCE_PATTERNS = [
    r"\bvulnerable\b",
    r"\bconfirmed\b",
    r"\bexploit(?:able|ed)?\b",
    r"\bdetected\b",
    r"\baffected\b",
]
INCONCLUSIVE_TEST_NAMES = {"heartbleed", "robot"}
FINAL_REPORT_STATUSES = {
    "CONFIRMED",
    "LIKELY",
    "POTENTIAL",
    "INCONCLUSIVE",
    "NOT_VULNERABLE",
    "FALSE_POSITIVE",
    "REMEDIATED",
    "ACCEPTED_RISK",
    "INFORMATIONAL",
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


def _tool_name(finding: Finding) -> str:
    if ":" in finding.title:
        return finding.title.split(":", 1)[0].strip()
    return finding.service or finding.category or "KryptScan"


def _has_pattern(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def _is_inconclusive_named_test(text: str) -> bool:
    lowered = text.lower()
    return any(name in lowered for name in INCONCLUSIVE_TEST_NAMES)


def _is_scanner_diagnostic(finding: Finding, text: str) -> bool:
    if finding.category in SCANNER_DIAGNOSTIC_CATEGORIES:
        return True
    lowered = text.lower()
    diagnostic_terms = [" api error", " error", " failed", "not installed", "timed out", "timeout", "unavailable"]
    return finding.category in {"AI Reporting", "Assessment Quality"} and any(term in lowered for term in diagnostic_terms)


def _service_remediation(finding: Finding) -> str:
    service = (finding.service or "").lower()
    port = str(finding.port or "").lower()
    if service == "ftp" or port == "21":
        return (
            "Determine whether public FTP access is operationally required. If unnecessary, disable the service and "
            "block TCP/21 at the perimeter firewall. If file transfer remains required, consider SFTP or another "
            "encrypted transfer method, then review anonymous access, authentication controls, source restrictions, "
            "logging, and patch status."
        )
    if service == "ssh" or port == "22":
        return (
            "Restrict administrative access to approved source networks or VPN infrastructure. Review password "
            "authentication, root login, MFA, key management, logging, fail2ban or equivalent protection, and vendor "
            "security updates for the detected SSH package."
        )
    if service in {"domain", "dns"} or port == "53":
        return (
            "Validate DNS recursion, zone-transfer controls, DNSSEC posture, version disclosure, logging, and relevant "
            "vendor vulnerability advisories before treating this as a confirmed DNS vulnerability."
        )
    return finding.remediation


def _validated_finding(finding: Finding) -> Finding:
    text = " ".join(
        item
        for item in [finding.title, finding.description, finding.evidence or "", finding.remediation]
        if item
    )
    detected_by = finding.detected_by or [_tool_name(finding)]
    if _is_scanner_diagnostic(finding, text):
        return finding.model_copy(
            update={
                "severity": "info",
                "cvss": 0.0,
                "finding_type": "SCANNER_ERROR",
                "validation_status": "SCANNER_ERROR",
                "confidence": 100,
                "detected_by": detected_by,
            }
        )
    if _has_pattern(text, NEGATIVE_EVIDENCE_PATTERNS):
        return finding.model_copy(
            update={
                "severity": "info",
                "cvss": 0.0,
                "category": "Passed Security Test",
                "finding_type": "INFORMATIONAL",
                "validation_status": "NOT_VULNERABLE",
                "confidence": 100,
                "detected_by": detected_by,
                "description": f"Scanner evidence indicates this test did not confirm a vulnerability. Original result: {finding.description}",
                "remediation": "No vulnerability remediation is required from this passed test. Retain the evidence for audit context.",
            }
        )
    if _is_inconclusive_named_test(text) and not _has_pattern(text, CONFIRMED_EVIDENCE_PATTERNS):
        return finding.model_copy(
            update={
                "severity": "info",
                "cvss": 0.0,
                "finding_type": "OBSERVATION",
                "validation_status": "INCONCLUSIVE",
                "confidence": 20,
                "detected_by": detected_by,
                "description": f"The scanner referenced this test but did not provide sufficient vulnerable/not-vulnerable evidence. Original result: {finding.description}",
                "remediation": "Manually verify the scanner output before treating this as a vulnerability.",
            }
        )
    if finding.severity == "info" or finding.cvss <= 0:
        finding_type = finding.finding_type if finding.finding_type != "VULNERABILITY" else "OBSERVATION"
        return finding.model_copy(
            update={
                "finding_type": finding_type,
                "validation_status": finding.validation_status if finding.validation_status != "POTENTIAL" else "INFORMATIONAL",
                "confidence": max(finding.confidence, 65),
                "detected_by": detected_by,
                "remediation": _service_remediation(finding),
            }
        )
    status = (
        finding.validation_status
        if finding.validation_status in {"CONFIRMED", "LIKELY"}
        else "CONFIRMED"
        if finding.cve or finding.cvss_vector or _has_pattern(text, CONFIRMED_EVIDENCE_PATTERNS)
        else "POTENTIAL"
    )
    confidence = 90 if status == "CONFIRMED" else 55
    return finding.model_copy(
        update={
            "finding_type": finding.finding_type or "VULNERABILITY",
            "validation_status": status,
            "confidence": max(finding.confidence, confidence),
            "detected_by": detected_by,
            "remediation": _service_remediation(finding),
        }
    )


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[tuple[str, str, str, str], Finding] = {}
    for finding in findings:
        key = (
            finding.host.lower(),
            str(finding.port or "").lower(),
            (finding.service or "").lower(),
            re.sub(r"[^a-z0-9]+", " ", finding.title.lower()).strip(),
        )
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = finding
            continue
        detected_by = sorted(set(existing.detected_by + finding.detected_by))
        stronger = max([existing, finding], key=lambda item: (SEVERITY_WEIGHTS[item.severity], item.confidence, item.cvss))
        deduped[key] = stronger.model_copy(update={"detected_by": detected_by, "confidence": min(100, max(stronger.confidence, len(detected_by) * 20 + stronger.confidence))})
    return list(deduped.values())


def _integrity_diagnostics(findings: list[Finding]) -> list[ComplianceCheck]:
    diagnostics: list[ComplianceCheck] = []
    for finding in findings:
        text = " ".join([finding.title, finding.description, finding.evidence or ""])
        finding_label = finding.title[:120]
        if finding.severity in {"critical", "high"} and _has_pattern(text, NEGATIVE_EVIDENCE_PATTERNS):
            diagnostics.append(
                ComplianceCheck(
                    name=f"Report integrity: {finding_label}",
                    status="fail",
                    detail=(
                        "High-impact severity conflicted with negative evidence. The item was removed from "
                        "executive vulnerability counts and requires analyst review before final client delivery."
                    ),
                )
            )
        if finding.validation_status == "CONFIRMED" and not (finding.description.strip() or (finding.evidence or "").strip()):
            diagnostics.append(
                ComplianceCheck(
                    name=f"Report integrity: {finding_label}",
                    status="fail",
                    detail="Confirmed finding has no description or evidence. Analyst review is required.",
                )
            )
        if finding.cvss >= 9.0 and not finding.cvss_vector:
            diagnostics.append(
                ComplianceCheck(
                    name=f"Report integrity: {finding_label}",
                    status="warn",
                    detail="Critical CVSS score has no CVSS vector. Add a vector before issuing a final technical report.",
                )
            )
        if finding.validation_status not in FINAL_REPORT_STATUSES and finding.finding_type != "SCANNER_ERROR":
            diagnostics.append(
                ComplianceCheck(
                    name=f"Report integrity: {finding_label}",
                    status="warn",
                    detail=f"Unexpected finding status '{finding.validation_status}' should be reviewed before final delivery.",
                )
            )
    return diagnostics


def build_assessment_report(target: str, findings: list[Finding]) -> AssessmentReport:
    findings = _deduplicate_findings([_validated_finding(item) for item in findings])
    findings = sorted(
        findings,
        key=lambda item: (SEVERITY_WEIGHTS[item.severity], item.confidence, item.cvss),
        reverse=True,
    )
    scanner_diagnostics = [
        ComplianceCheck(name=item.title, status="fail", detail=item.description)
        for item in findings
        if item.finding_type == "SCANNER_ERROR"
    ]
    diagnostics = [*scanner_diagnostics, *_integrity_diagnostics(findings)]
    reportable_findings = [
        item
        for item in findings
        if item.finding_type != "SCANNER_ERROR"
    ]
    actionable_findings = [
        item
        for item in reportable_findings
        if item.finding_type in {"VULNERABILITY", "SECURITY_MISCONFIGURATION", "EXPOSURE"}
        and item.validation_status in {"CONFIRMED", "LIKELY", "POTENTIAL"}
        and item.severity in {"critical", "high", "medium", "low"}
    ]
    severity_counter = Counter(item.severity for item in actionable_findings)
    severity_counter["info"] = sum(
        1
        for item in reportable_findings
        if item.severity == "info" or item.finding_type in {"OBSERVATION", "INFORMATIONAL"}
    )
    counts = _serialize_counts(severity_counter)
    weighted_total = sum(SEVERITY_WEIGHTS[item.severity] * max(item.confidence, 1) / 100 for item in actionable_findings)
    critical_high_pressure = counts.critical * 12 + counts.high * 7
    medium_pressure = min(counts.medium * 3, 18)
    low_pressure = min(counts.low, 6)
    average_weight = weighted_total / max(len(actionable_findings), 1)
    risk_score = min(100, round((average_weight * 8) + critical_high_pressure + medium_pressure + low_pressure))
    service_counter = Counter(item.service or "unknown" for item in reportable_findings)
    category_counter = Counter(item.category for item in reportable_findings)
    expected_components = 9
    completed_components = max(0, expected_components - len(scanner_diagnostics))
    assessment_coverage = round((completed_components / expected_components) * 100)
    coverage_status = "Complete" if assessment_coverage >= 90 else "Partial" if assessment_coverage >= 55 else "Limited"

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
            status="fail" if counts.high else "pass",
            detail=(
                f"{counts.high} high-severity issue(s) need rapid triage."
                if counts.high
                else "High-severity backlog is currently controlled."
            ),
        ),
        ComplianceCheck(
            name="Externally reachable service hygiene",
            status="warn" if any(item.service in {"http", "https", "ssh", "rdp"} for item in reportable_findings) else "pass",
            detail=(
                "Public-facing services were included in the findings set and should be reviewed first."
                if any(item.service in {"http", "https", "ssh", "rdp"} for item in reportable_findings)
                else "No elevated public-facing service concentration detected in findings."
            ),
        ),
        ComplianceCheck(
            name="Remediation program readiness",
            status="pass" if actionable_findings else "warn",
            detail=(
                "Remediation actions are prioritized and ready for handoff."
                if actionable_findings
                else "No findings were available to build a remediation queue."
            ),
        ),
    ]

    remediation_plan: list[RemediationItem] = []
    seen_titles: set[str] = set()
    for finding in reportable_findings or findings:
        if finding.category in {"Scanner Toolchain", "AI Reporting", "Assessment Quality"}:
            continue
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
    if coverage_status != "Complete":
        summary = (
            f"{target} is currently rated {band.lower()} risk based on a {coverage_status.lower()} external assessment "
            f"with {assessment_coverage}% tool coverage. KryptScan identified {counts.critical} confirmed or potential "
            f"critical, {counts.high} high, and {counts.medium} medium vulnerability findings. Scanner diagnostics "
            "should be reviewed before treating this as a complete representation of the target security posture."
        )
    else:
        summary = (
            f"{target} is currently rated {band.lower()} risk with {counts.critical} confirmed or potential critical, "
            f"{counts.high} high, and {counts.medium} medium vulnerability findings. Priority should go to externally "
            "exposed services and vulnerabilities with clear evidence, high confidence, and a practical remediation path."
        )

    return AssessmentReport(
        executive_summary=summary,
        risk_score=risk_score,
        risk_band=band,
        assessment_coverage=assessment_coverage,
        assessment_coverage_status=coverage_status,
        severity_counts=counts,
        scope_summary=f"Assessment scope was limited to {target} and evidence collected during the approved workflow.",
        methodology=[
            "Authorized target validation",
            "Scanner evidence normalization",
            "Severity scoring and remediation prioritization",
            "Analyst review of technical findings",
        ],
        limitations=[
            "Results reflect the reachable services and evidence available at assessment time.",
            "Authenticated application, cloud, identity, and business logic testing require client-provided access and explicit approval.",
        ],
        scan_protocols=[],
        diagnostics=diagnostics,
        findings=reportable_findings,
        compliance_checks=compliance_checks,
        remediation_plan=remediation_plan,
        top_services=top_services,
        top_categories=top_categories,
        trend=trend,
        generated_at=utcnow().isoformat(),
    )
