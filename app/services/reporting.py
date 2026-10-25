from __future__ import annotations

from collections import Counter
import re

from app.models import (
    AssessmentCheckResult,
    AssessmentReport,
    ChartDatum,
    ComplianceCheck,
    CoverageCategory,
    CoverageSummary,
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
RISK_MODEL_VERSION = "KS-RISK-2.0"
EVALUATED_SECURITY_RESULTS = {"VULNERABLE", "NOT_VULNERABLE", "POTENTIAL"}
FAILED_EXECUTION_STATUSES = {"FAILED", "TIMED_OUT"}
INTERNAL_SERVICE_NAMES = {
    "amass",
    "checkov",
    "dnsx",
    "feroxbuster",
    "ffuf",
    "gitleaks",
    "gobuster",
    "grype",
    "httpx",
    "katana",
    "kryptscan-orchestrator",
    "kryptscan-roe",
    "naabu",
    "nikto",
    "nmap",
    "nuclei",
    "openai",
    "scanner-worker",
    "semgrep",
    "sslyze",
    "subfinder",
    "testssl.sh",
    "trivy",
    "wafw00f",
    "whatweb",
    "zap",
    "zap-baseline.py",
}
ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


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


def _risk_band(score: int | None) -> str:
    if score is None:
        return "Undetermined"
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


def _clean_text(value: str | None) -> str:
    if not value:
        return ""
    return ANSI_ESCAPE_RE.sub("", value).replace("\x00", "").strip()


def is_customer_facing_service(finding: Finding) -> bool:
    service = (finding.service or "").strip().lower()
    if not service or service in INTERNAL_SERVICE_NAMES:
        return False
    if finding.category in SCANNER_DIAGNOSTIC_CATEGORIES | {"AI Reporting", "Assessment Planning", "Rules of Engagement"}:
        return False
    return bool(finding.port) or service in {
        "dns",
        "domain",
        "ftp",
        "http",
        "https",
        "imap",
        "ldap",
        "mssql",
        "mysql",
        "pop3",
        "postgresql",
        "rdp",
        "smb",
        "smtp",
        "ssh",
        "telnet",
        "tls",
    }


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
    finding = finding.model_copy(
        update={
            "title": _clean_text(finding.title),
            "description": _clean_text(finding.description),
            "evidence": _clean_text(finding.evidence) or None,
            "remediation": _clean_text(finding.remediation),
        }
    )
    text = " ".join(
        item
        for item in [finding.title, finding.description, finding.evidence or ""]
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


def _coverage_from_checks(
    check_results: list[AssessmentCheckResult],
    *,
    has_usable_evidence: bool,
) -> tuple[CoverageSummary, list[CoverageCategory], int, str, str]:
    if not check_results:
        summary = CoverageSummary(
            planned=1,
            applicable=1,
            executed=1 if has_usable_evidence else 0,
            successfully_evaluated=1 if has_usable_evidence else 0,
            inconclusive=0 if has_usable_evidence else 1,
        )
        coverage = 100 if has_usable_evidence else 0
        status = "Complete" if has_usable_evidence else "Limited"
        outcome = "COMPLETED" if has_usable_evidence else "INCONCLUSIVE"
        return summary, [], coverage, status, outcome

    applicable = [item for item in check_results if item.applicable]
    executed = [item for item in applicable if item.execution_status in {"COMPLETED", "FAILED", "TIMED_OUT"}]
    evaluated = [
        item
        for item in applicable
        if item.execution_status == "COMPLETED" and item.security_result in EVALUATED_SECURITY_RESULTS
    ]
    failed = [item for item in applicable if item.execution_status == "FAILED"]
    timed_out = [item for item in applicable if item.execution_status == "TIMED_OUT"]
    skipped = [item for item in applicable if item.execution_status == "SKIPPED"]
    inconclusive = [
        item
        for item in applicable
        if item.security_result == "INCONCLUSIVE" or (
            item.execution_status == "COMPLETED" and item.security_result not in EVALUATED_SECURITY_RESULTS
        )
    ]
    summary = CoverageSummary(
        planned=len(check_results),
        applicable=len(applicable),
        executed=len(executed),
        successfully_evaluated=len(evaluated),
        failed=len(failed),
        timed_out=len(timed_out),
        skipped=len(skipped),
        not_applicable=len(check_results) - len(applicable),
        inconclusive=len(inconclusive),
    )
    coverage = round((len(evaluated) / len(applicable)) * 100) if applicable else 0
    if applicable and len(evaluated) == len(applicable) and not failed and not timed_out and not inconclusive:
        status = "Complete"
        outcome = "COMPLETED"
    elif not applicable:
        status = "Limited"
        outcome = "INCONCLUSIVE"
    elif not evaluated:
        status = "Limited"
        outcome = (
            "FAILED"
            if all(item.execution_status in FAILED_EXECUTION_STATUSES for item in applicable)
            else "CANCELLED"
            if all(item.execution_status == "CANCELLED" for item in applicable)
            else "INCONCLUSIVE"
        )
    elif coverage >= 80:
        status = "Substantial"
        outcome = "COMPLETED_WITH_LIMITATIONS"
    else:
        status = "Partial" if coverage >= 50 else "Limited"
        outcome = "PARTIAL"

    grouped: dict[str, list[AssessmentCheckResult]] = {}
    for item in check_results:
        grouped.setdefault(item.category, []).append(item)
    categories: list[CoverageCategory] = []
    for category, items in grouped.items():
        category_applicable = [item for item in items if item.applicable]
        category_evaluated = [
            item
            for item in category_applicable
            if item.execution_status == "COMPLETED" and item.security_result in EVALUATED_SECURITY_RESULTS
        ]
        if not category_applicable:
            category_status = "NOT_APPLICABLE"
        elif len(category_evaluated) == len(category_applicable):
            category_status = "COMPLETED"
        elif category_evaluated:
            category_status = "PARTIAL"
        elif all(item.execution_status in FAILED_EXECUTION_STATUSES for item in category_applicable):
            category_status = "FAILED"
        else:
            category_status = "INCONCLUSIVE"
        unresolved = [
            f"{item.name}: {item.execution_status}/{item.security_result}"
            for item in category_applicable
            if item not in category_evaluated
        ]
        reason = "; ".join(unresolved[:4]) or f"{len(category_evaluated)} applicable check(s) produced usable evidence."
        categories.append(CoverageCategory(name=category, status=category_status, reason=reason))
    return summary, categories, coverage, status, outcome


def _risk_score(
    actionable_findings: list[Finding],
    counts: SeverityCounts,
    coverage: CoverageSummary,
    assessment_coverage: int,
) -> int | None:
    confirmed = [item for item in actionable_findings if item.validation_status in {"CONFIRMED", "LIKELY"}]
    evidence_sufficient = (
        coverage.applicable > 0
        and assessment_coverage >= 85
        and coverage.failed == 0
        and coverage.timed_out == 0
        and coverage.inconclusive <= max(1, round(coverage.applicable * 0.1))
    )
    if not actionable_findings:
        return 5 if evidence_sufficient else None
    if not confirmed and not evidence_sufficient:
        return None

    weighted_total = sum(
        SEVERITY_WEIGHTS[item.severity] * max(item.confidence, 1) / 100
        for item in actionable_findings
    )
    critical_high_pressure = counts.critical * 12 + counts.high * 7
    medium_pressure = min(counts.medium * 3, 18)
    low_pressure = min(counts.low, 6)
    average_weight = weighted_total / max(len(actionable_findings), 1)
    score = round((average_weight * 8) + critical_high_pressure + medium_pressure + low_pressure)
    severity_floor = (
        80
        if counts.critical
        else 60
        if counts.high
        else 35
        if counts.medium
        else 15
        if counts.low
        else 5
    )
    return min(100, max(severity_floor, score))


def build_assessment_report(
    target: str,
    findings: list[Finding],
    check_results: list[AssessmentCheckResult] | None = None,
) -> AssessmentReport:
    check_results = check_results or []
    findings = _deduplicate_findings([_validated_finding(item) for item in findings])
    findings = sorted(
        findings,
        key=lambda item: (SEVERITY_WEIGHTS[item.severity], item.confidence, item.cvss),
        reverse=True,
    )
    finding_diagnostics = [
        ComplianceCheck(name=item.title, status="fail", detail=item.description)
        for item in findings
        if item.finding_type == "SCANNER_ERROR"
    ]
    check_diagnostics = [
        ComplianceCheck(
            name=item.name,
            status="fail" if item.execution_status in FAILED_EXECUTION_STATUSES else "warn",
            detail=(
                f"Execution: {item.execution_status}. Security result: {item.security_result}. "
                f"{_clean_text(item.detail) or 'No additional diagnostic detail was returned.'}"
            ),
        )
        for item in check_results
        if item.applicable
        and (
            item.execution_status in FAILED_EXECUTION_STATUSES
            or item.security_result in {"INCONCLUSIVE", "NOT_TESTED"}
        )
    ]
    diagnostics = [*check_diagnostics, *finding_diagnostics, *_integrity_diagnostics(findings)]
    reportable_findings = [
        item
        for item in findings
        if item.finding_type not in {"SCANNER_ERROR", "ASSESSMENT_NOTE", "CHECK_RESULT"}
        and item.category not in {"Assessment Planning", "Rules of Engagement", "AI Reporting"}
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
    coverage_summary, coverage_categories, assessment_coverage, coverage_status, assessment_outcome = _coverage_from_checks(
        check_results,
        has_usable_evidence=bool(reportable_findings),
    )
    risk_score = _risk_score(actionable_findings, counts, coverage_summary, assessment_coverage)
    service_counter = Counter(
        item.service
        for item in reportable_findings
        if item.service and is_customer_facing_service(item)
    )
    category_counter = Counter(
        item.category
        for item in reportable_findings
        if item.category not in {"Passed Security Test", "Assessment Limitation"}
    )

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
            name="Critical finding status",
            status="fail" if counts.critical else "pass" if risk_score is not None else "warn",
            detail=(
                f"{counts.critical} critical issue(s) require immediate action."
                if counts.critical
                else "No critical issue was confirmed in the usable evidence."
                if risk_score is not None
                else "No critical issue was confirmed, but assessment evidence is insufficient to claim absence."
            ),
        ),
        ComplianceCheck(
            name="High-severity finding status",
            status="fail" if counts.high else "pass" if risk_score is not None else "warn",
            detail=(
                f"{counts.high} high-severity issue(s) need rapid triage."
                if counts.high
                else "No high-severity issue was confirmed in the usable evidence."
                if risk_score is not None
                else "No high-severity issue was confirmed, but incomplete coverage prevents a clean assurance statement."
            ),
        ),
        ComplianceCheck(
            name="Externally reachable service hygiene",
            status=(
                "warn"
                if any(item.service in {"http", "https", "ssh", "rdp"} for item in reportable_findings)
                or risk_score is None
                else "pass"
            ),
            detail=(
                "Public-facing services were included in the findings set and should be reviewed first."
                if any(item.service in {"http", "https", "ssh", "rdp"} for item in reportable_findings)
                else "Service exposure could not be established with sufficient confidence."
                if risk_score is None
                else "No elevated public-facing service concentration was observed in the completed checks."
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
    for finding in actionable_findings:
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

    trend = [TrendPoint(label="Current", value=risk_score)] if risk_score is not None else []

    band = _risk_band(risk_score)
    if risk_score is None:
        summary = (
            f"Overall security risk for {target} is undetermined because the assessment produced insufficient usable "
            f"evidence. Outcome: {assessment_outcome}. Successfully evaluated coverage was {assessment_coverage}% "
            f"({coverage_summary.successfully_evaluated} of {coverage_summary.applicable} applicable checks). "
            f"The available evidence contains {counts.critical} critical, {counts.high} high, and {counts.medium} "
            "medium confirmed or potential findings, but incomplete or inconclusive checks prevent a defensible "
            "overall security rating."
        )
    elif coverage_status != "Complete":
        summary = (
            f"Observed risk for {target} is {band.lower()} ({risk_score}/100) based on the usable evidence collected. "
            f"Outcome: {assessment_outcome}; successfully evaluated coverage was {assessment_coverage}%. "
            f"KryptScan identified {counts.critical} critical, {counts.high} high, and {counts.medium} medium confirmed "
            "or potential findings. This provisional rating is not proof of the target's complete security posture."
        )
    else:
        summary = (
            f"{target} has an observed {band.lower()} risk rating ({risk_score}/100) with {counts.critical} confirmed or potential critical, "
            f"{counts.high} high, and {counts.medium} medium vulnerability findings. Priority should go to externally "
            "exposed services and findings with clear evidence, high confidence, and a practical remediation path. "
            "A low observed finding count does not guarantee the absence of vulnerabilities."
        )

    limitations = [
        "Results reflect only the reachable services and evidence available during the assessment window.",
        "Authenticated application, cloud, identity, and business-logic testing require client-provided access and explicit approval.",
    ]
    if assessment_outcome != "COMPLETED":
        limitations.append(
            f"The assessment outcome was {assessment_outcome}; failed, timed-out, filtered, or inconclusive checks reduce assurance."
        )

    return AssessmentReport(
        executive_summary=summary,
        risk_score=risk_score,
        risk_band=band,
        risk_model_version=RISK_MODEL_VERSION,
        assessment_outcome=assessment_outcome,
        assessment_coverage=assessment_coverage,
        assessment_coverage_status=coverage_status,
        coverage_summary=coverage_summary,
        coverage_categories=coverage_categories,
        check_results=check_results,
        severity_counts=counts,
        scope_summary=f"Assessment scope was limited to {target} and evidence collected during the approved workflow.",
        methodology=[
            "Authorized target validation",
            "Scanner evidence normalization",
            "Severity scoring and remediation prioritization",
            "Automated evidence-quality and consistency checks",
        ],
        limitations=limitations,
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
