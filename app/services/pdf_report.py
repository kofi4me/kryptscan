from __future__ import annotations

from pathlib import Path
import re
from typing import Iterable

from app.models import AssessmentReport, Finding
from app.services.reporting import is_customer_facing_service


PAGE_WIDTH = 612
PAGE_HEIGHT = 792
LEFT_MARGIN = 48
RIGHT_MARGIN = 48
TOP_MARGIN = 724
BOTTOM_MARGIN = 54
CONTENT_WIDTH = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN


def _escape_pdf_text(value: str) -> str:
    sanitized = value.encode("latin-1", "replace").decode("latin-1")
    return (
        sanitized.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _wrap_text(text: str, max_chars: int) -> list[str]:
    words = text.split()
    if not words:
        return [""]

    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if len(candidate) <= max_chars:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


class _Canvas:
    def __init__(self, brand_name: str = "KryptScan") -> None:
        self.pages: list[list[str]] = []
        self.page_commands: list[str] = []
        self.brand_name = brand_name
        self.y = TOP_MARGIN
        self._new_page()

    def _new_page(self) -> None:
        self.page_commands = []
        self.pages.append(self.page_commands)
        self.y = TOP_MARGIN
        page_number = len(self.pages)
        brand = _escape_pdf_text(self.brand_name[:70])
        self.page_commands.extend(
            [
                f"0.025 0.055 0.120 rg 0 756 {PAGE_WIDTH} 36 re f",
                f"0.110 0.330 0.820 rg 0 752 420 4 re f",
                f"0.820 0.110 0.150 rg 420 752 {PAGE_WIDTH - 420} 4 re f",
                f"BT /F2 10 Tf 1 1 1 rg 1 0 0 1 {LEFT_MARGIN} 770 Tm ({brand}) Tj ET",
                f"0.020 0.025 0.035 rg 0 0 {PAGE_WIDTH} 32 re f",
                f"BT /F1 8 Tf 0.88 0.90 0.94 rg 1 0 0 1 {LEFT_MARGIN} 12 Tm (CONFIDENTIAL - SECURITY ASSESSMENT) Tj ET",
                f"BT /F1 8 Tf 0.88 0.90 0.94 rg 1 0 0 1 {PAGE_WIDTH - RIGHT_MARGIN - 45} 12 Tm (Page {page_number}) Tj ET",
            ]
        )

    def _ensure_space(self, height: float) -> None:
        if self.y - height < BOTTOM_MARGIN:
            self._new_page()

    def spacer(self, height: float) -> None:
        self.y -= height

    def text(
        self,
        text: str,
        *,
        size: int = 10,
        bold: bool = False,
        color: tuple[float, float, float] = (0.12, 0.17, 0.22),
        indent: float = 0,
        extra_gap: float = 3,
    ) -> None:
        font = "F2" if bold else "F1"
        x = LEFT_MARGIN + indent
        max_chars = max(24, int((CONTENT_WIDTH - indent) / max(size * 0.5, 5)))
        lines = _wrap_text(text, max_chars=max_chars)
        line_height = size + extra_gap
        for line in lines:
            self._ensure_space(line_height)
            safe_line = _escape_pdf_text(line)
            self.page_commands.append(
                (
                    "BT "
                    f"/{font} {size} Tf "
                    f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg "
                    f"1 0 0 1 {x:.2f} {self.y:.2f} Tm "
                    f"({safe_line}) Tj ET"
                )
            )
            self.y -= line_height

    def divider(self) -> None:
        self._ensure_space(14)
        line_y = self.y
        self.page_commands.append(
            f"0.790 0.835 0.875 RG 0.8 w {LEFT_MARGIN} {line_y:.2f} m {PAGE_WIDTH - RIGHT_MARGIN} {line_y:.2f} l S"
        )
        self.y -= 14

    def page_break(self) -> None:
        self._new_page()

    def bar_chart(
        self,
        title: str,
        items: Iterable[tuple[str, float, tuple[float, float, float]]],
    ) -> None:
        item_list = list(items)
        if not item_list:
            return

        self.text(title, size=13, bold=True)
        max_value = max(value for _, value, _ in item_list) or 1
        for label, value, color in item_list:
            self._ensure_space(28)
            label_y = self.y
            self.text(f"{label}: {value}", size=10)
            bar_y = label_y - 14
            track_width = 240
            self.page_commands.append(
                f"0.910 0.929 0.949 rg 290 {bar_y:.2f} {track_width} 9 re f"
            )
            fill_width = max(8, (value / max_value) * track_width)
            self.page_commands.append(
                f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg 290 {bar_y:.2f} {fill_width:.2f} 9 re f"
            )
            self.y -= 10
        self.spacer(8)

    def metric_grid(self, items: Iterable[tuple[str, str]]) -> None:
        item_list = list(items)
        if not item_list:
            return
        card_width = (CONTENT_WIDTH - 12) / 2
        card_height = 50
        colors = [
            ((0.94, 0.97, 1.0), (0.10, 0.33, 0.82)),
            ((1.0, 0.95, 0.95), (0.78, 0.12, 0.16)),
            ((0.94, 0.99, 0.98), (0.04, 0.52, 0.43)),
            ((0.98, 0.96, 1.0), (0.42, 0.18, 0.72)),
        ]
        for row_start in range(0, len(item_list), 2):
            self._ensure_space(card_height + 6)
            row_top = self.y
            for column, (label, value) in enumerate(item_list[row_start:row_start + 2]):
                x = LEFT_MARGIN + column * (card_width + 12)
                y = row_top - card_height
                fill, accent = colors[(row_start + column) % len(colors)]
                self.page_commands.append(
                    f"{fill[0]:.3f} {fill[1]:.3f} {fill[2]:.3f} rg {x:.2f} {y:.2f} {card_width:.2f} {card_height:.2f} re f"
                )
                self.page_commands.append(
                    f"{accent[0]:.3f} {accent[1]:.3f} {accent[2]:.3f} rg {x:.2f} {y:.2f} 5 {card_height:.2f} re f"
                )
                safe_label = _escape_pdf_text(label.upper()[:42])
                safe_value = _escape_pdf_text(value.replace("_", " ")[:46])
                self.page_commands.append(
                    f"BT /F1 8 Tf 0.30 0.38 0.49 rg 1 0 0 1 {x + 14:.2f} {row_top - 16:.2f} Tm ({safe_label}) Tj ET"
                )
                self.page_commands.append(
                    f"BT /F2 12 Tf 0.07 0.13 0.24 rg 1 0 0 1 {x + 14:.2f} {row_top - 35:.2f} Tm ({safe_value}) Tj ET"
                )
            self.y -= card_height + 6
        self.spacer(4)


def _safe(value: str | None, fallback: str = "Not provided") -> str:
    if value is None:
        return fallback
    return value.strip() or fallback


def _risk_score_label(report: AssessmentReport) -> str:
    return f"{report.risk_score}/100" if report.risk_score is not None else "Undetermined"


def _redact_sensitive(value: str | None) -> str:
    text = _safe(value, "")
    text = re.sub(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)\S+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*\S+", r"\1=[REDACTED]", text)
    text = re.sub(r"(?i)(bearer|basic)\s+[a-z0-9._~+/=-]+", r"\1 [REDACTED]", text)
    text = re.sub(r"(?i)(session|cookie)[=:]\s*[^;\s]+", r"\1=[REDACTED]", text)
    return text


def _is_pentest_mode(assessment_mode: str) -> bool:
    return assessment_mode in {"ethical_pentesting", "authorized_pentest"}


def _finding_id(prefix: str, index: int) -> str:
    return f"{prefix}-{index:03d}"


def _actionable_findings(report: AssessmentReport) -> list[Finding]:
    return [
        finding
        for finding in report.findings
        if finding.finding_type in {"VULNERABILITY", "SECURITY_MISCONFIGURATION"}
        and finding.validation_status not in {"NOT_VULNERABLE", "FALSE_POSITIVE", "SCANNER_ERROR"}
    ]


def _exposure_findings(report: AssessmentReport) -> list[Finding]:
    return [
        finding
        for finding in report.findings
        if finding.finding_type in {"EXPOSURE", "OBSERVATION", "INFORMATIONAL"}
        or finding.validation_status in {"INCONCLUSIVE", "NOT_VULNERABLE", "INFORMATIONAL"}
    ]


def _top_risks(report: AssessmentReport) -> list[Finding]:
    weights = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return sorted(
        _actionable_findings(report),
        key=lambda item: (weights.get(item.severity, 0), item.confidence, item.cvss),
        reverse=True,
    )[:5]


def _remediation_window(finding: Finding) -> str:
    if finding.severity == "critical":
        return "Immediate - 0-7 Days"
    if finding.severity == "high":
        return "High Priority - 7-30 Days"
    if finding.severity == "medium":
        return "Medium Priority - 30-60 Days"
    return "Security Hardening - 60-90 Days"


def _technical_impact(finding: Finding) -> str:
    category = finding.category.lower()
    service = (finding.service or "").lower()
    if "tls" in category or service in {"ssl", "tls", "https"}:
        return "Successful abuse could weaken transport security, increase interception risk, or reduce assurance in encrypted communications."
    if "web" in category or service in {"http", "https"}:
        return "Successful abuse could affect application confidentiality, integrity, session handling, or exposed web functionality depending on the affected component."
    if service in {"ssh", "ftp", "rdp"}:
        return "Successful abuse could increase the risk of unauthorized administrative access, credential attack paths, or service misuse."
    if "cloud" in category:
        return "Successful abuse could expose cloud resources, permissions, configuration weaknesses, or data paths within the approved scope."
    return "Successful abuse could reduce the security posture of the affected asset and should be assessed against business exposure and compensating controls."


def _business_impact(finding: Finding) -> str:
    if finding.severity in {"critical", "high"}:
        return "Potential business impact includes unauthorized access, data exposure, service disruption, compliance concern, or increased incident-response cost where exploitation is feasible."
    if finding.finding_type == "EXPOSURE":
        return "The exposure increases attack surface and may raise operational risk if the service is unnecessary, weakly protected, or not monitored."
    return "Business impact is currently limited or context-dependent, but remediation or validation will reduce uncertainty and improve resilience."


def _verification_guidance(finding: Finding) -> str:
    if finding.cve:
        return f"Apply the vendor fix or compensating control, then retest {finding.cve} with the same scanner and analyst review."
    if finding.service:
        return f"Retest the affected {finding.service} service after remediation and confirm the evidence no longer reproduces."
    return "Retest the affected asset after remediation and retain before/after evidence for closure."


def _positive_observations(report: AssessmentReport) -> list[str]:
    positives = []
    if report.risk_score is not None and report.severity_counts.critical == 0:
        positives.append("No critical vulnerability was confirmed from the available evidence.")
    if report.risk_score is not None and report.severity_counts.high == 0:
        positives.append("No high-severity vulnerability was confirmed from the available evidence.")
    passed = [finding.title for finding in report.findings if finding.validation_status == "NOT_VULNERABLE"]
    positives.extend(f"{title} did not validate as vulnerable." for title in passed[:3])
    if report.assessment_coverage_status == "Complete":
        positives.append("Assessment coverage completed without material scanner diagnostics.")
    return positives[:5]


def _write_cover_page(
    canvas: _Canvas,
    *,
    target: str,
    asset_type: str,
    assessment_mode: str,
    recipient_email: str,
    report: AssessmentReport,
    msp_details: dict[str, str] | None,
    owner_details: dict[str, str] | None,
    scan_metadata: dict[str, str | None] | None = None,
) -> None:
    issuer = _safe((msp_details or {}).get("Company name"), "Authorized Security Provider")
    client = _safe(
        (owner_details or {}).get("Assessed organization") or (owner_details or {}).get("Company name"),
        "Authorized Target Owner",
    )
    canvas.text(issuer, size=24, bold=True, color=(0.07, 0.25, 0.65))
    canvas.spacer(8)
    canvas.text("PENETRATION TESTING REPORT", size=20, bold=True, color=(0.70, 0.10, 0.12))
    canvas.spacer(18)
    canvas.text("CONFIDENTIAL - SECURITY ASSESSMENT REPORT", size=13, bold=True)
    canvas.divider()
    for label, value in [
        ("Client", client),
        ("Target", target),
        ("Assessment Type", "External Web & Network Penetration Test"),
        ("Pentest Profile", assessment_mode.replace("_", " ").title()),
        ("Target Type", asset_type),
        ("Report Generated", report.generated_at),
        ("Prepared By", _safe((msp_details or {}).get("Company name"), "KryptNet LLC / Authorized MSP")),
        ("Report Recipient", recipient_email),
        ("Scan ID", _safe((scan_metadata or {}).get("scan_id"))),
        ("Report ID", _safe((scan_metadata or {}).get("report_id"))),
        ("Scan Status", _safe((scan_metadata or {}).get("status"))),
        ("Scan Started", _safe((scan_metadata or {}).get("started_at"))),
        ("Scan Completed", _safe((scan_metadata or {}).get("completed_at"))),
        ("Assessment Outcome", report.assessment_outcome),
        ("Assessment Platform", "KryptScan"),
    ]:
        canvas.text(f"{label}: {value}", size=12)
    canvas.spacer(20)
    canvas.text("Assessment evidence processed by the KryptScan platform", size=10, color=(0.35, 0.40, 0.45))
    canvas.page_break()


def _write_confidentiality_notice(canvas: _Canvas) -> None:
    canvas.text("Confidentiality Notice", size=18, bold=True)
    canvas.text(
        "This report contains security-sensitive information concerning the assessed systems and is intended solely for the authorized organization and designated recipients. Unauthorized disclosure may expose information about system configurations, vulnerabilities, security weaknesses, and remediation activities.",
        size=11,
        extra_gap=4,
    )
    canvas.spacer(8)
    canvas.text(
        "Do not share this report outside the approved remediation, management, legal, or security operations audience without authorization.",
        size=11,
    )
    canvas.page_break()


def _write_executive_dashboard(canvas: _Canvas, report: AssessmentReport) -> None:
    confirmed = sum(1 for item in report.findings if item.validation_status in {"CONFIRMED", "LIKELY"})
    needs_validation = sum(1 for item in report.findings if item.validation_status in {"POTENTIAL", "INCONCLUSIVE"})
    assets_tested = len({item.host for item in report.findings if item.host})
    services = len(
        {
            item.service
            for item in report.findings
            if item.service and is_customer_facing_service(item)
        }
    )
    metrics = [
        ("Assessment Outcome", report.assessment_outcome),
        ("Overall Security Risk", report.risk_band),
        ("Risk Score", _risk_score_label(report)),
        ("Assessment Coverage", f"{report.assessment_coverage}%"),
        ("Analyst Review", report.analyst_review_status),
        ("Critical Vulnerabilities", str(report.severity_counts.critical)),
        ("High Vulnerabilities", str(report.severity_counts.high)),
        ("Medium Vulnerabilities", str(report.severity_counts.medium)),
        ("Low Vulnerabilities", str(report.severity_counts.low)),
        ("Security Observations", str(report.severity_counts.info)),
        ("Confirmed Findings", str(confirmed)),
        ("Findings Requiring Validation", str(needs_validation)),
        ("Assets Tested", str(max(assets_tested, 1))),
        ("Services Assessed", str(services)),
    ]
    canvas.text("Executive Summary", size=18, bold=True)
    canvas.metric_grid(metrics)
    canvas.divider()
    canvas.text("Executive Interpretation", size=14, bold=True)
    canvas.text(report.executive_summary, size=11, extra_gap=4)
    canvas.divider()


def _write_pentest_finding(canvas: _Canvas, finding: Finding, finding_code: str) -> None:
    canvas.text(f"{finding_code} - {finding.title}", size=13, bold=True)
    for label, value in [
        ("Severity", finding.severity.upper()),
        ("Status", finding.validation_status),
        ("Confidence", f"{finding.confidence}%"),
        ("Affected Asset", finding.host),
        ("Port", finding.port or "n/a"),
        ("Service", finding.service or "n/a"),
        ("Finding Type", finding.finding_type),
        ("CVSS Score", f"{finding.cvss}" if finding.cvss else "Not assigned"),
        ("CVSS Vector", finding.cvss_vector or "Not assigned"),
        ("CVE", finding.cve or "Not applicable"),
        ("CWE", finding.cwe or "Not applicable"),
        ("Detected By", ", ".join(finding.detected_by) if finding.detected_by else "KryptScan"),
    ]:
        canvas.text(f"{label}: {value}", size=9, indent=8)
    canvas.text("Description", size=10, bold=True, indent=8)
    canvas.text(_redact_sensitive(finding.description), size=9, indent=16)
    canvas.text("Technical Evidence", size=10, bold=True, indent=8)
    canvas.text(_redact_sensitive(finding.evidence or finding.description), size=9, indent=16, color=(0.30, 0.37, 0.44))
    canvas.text("Validation Performed", size=10, bold=True, indent=8)
    canvas.text("KryptScan used permitted non-destructive evidence collection and correlation. Exploitation was not attempted unless explicitly documented in manual tester evidence.", size=9, indent=16)
    canvas.text("Validation Result", size=10, bold=True, indent=8)
    canvas.text(finding.validation_status, size=9, indent=16)
    canvas.text("Technical Impact", size=10, bold=True, indent=8)
    canvas.text(_technical_impact(finding), size=9, indent=16)
    canvas.text("Business Impact", size=10, bold=True, indent=8)
    canvas.text(_business_impact(finding), size=9, indent=16)
    canvas.text("Remediation", size=10, bold=True, indent=8)
    canvas.text(_redact_sensitive(finding.remediation), size=9, indent=16)
    canvas.text(f"Remediation Priority: {_remediation_window(finding)}", size=9, bold=True, indent=8)
    canvas.text("Verification", size=10, bold=True, indent=8)
    canvas.text(_verification_guidance(finding), size=9, indent=16)
    canvas.spacer(6)


def _build_pentest_pdf_bytes(
    target: str,
    asset_type: str,
    scanner_backend: str,
    assessment_mode: str,
    recipient_email: str,
    report: AssessmentReport,
    msp_details: dict[str, str] | None = None,
    owner_details: dict[str, str] | None = None,
    scan_metadata: dict[str, str | None] | None = None,
) -> bytes:
    issuer = _safe((msp_details or {}).get("Company name"), "Authorized Security Provider")
    canvas = _Canvas(brand_name=issuer)
    _write_cover_page(
        canvas,
        target=target,
        asset_type=asset_type,
        assessment_mode=assessment_mode,
        recipient_email=recipient_email,
        report=report,
        msp_details=msp_details,
        owner_details=owner_details,
        scan_metadata=scan_metadata,
    )
    _write_confidentiality_notice(canvas)
    _write_executive_dashboard(canvas, report)

    top_risks = _top_risks(report)
    canvas.text("Top Security Risks", size=14, bold=True)
    if top_risks:
        for index, finding in enumerate(top_risks, start=1):
            canvas.text(
                f"{index}. {_finding_id('KS-PT', index)} - {finding.title} | {finding.severity.upper()} | {finding.confidence}% | {finding.validation_status}",
                size=10,
            )
    else:
        canvas.text("No confirmed or potential vulnerability finding was available in the usable evidence. This does not establish that vulnerabilities are absent.", size=10, indent=8)
    canvas.divider()

    canvas.text("Scope & Authorization", size=14, bold=True)
    canvas.text(report.scope_summary, size=10, indent=8)
    for label, value in [
        ("Primary Target", target),
        ("Target Type", asset_type),
        ("Scanner Backend", scanner_backend),
        ("Authenticated Testing", "Only when explicitly approved in the rules of engagement"),
        ("Prohibited Activities", "Destructive exploitation, brute force, persistence, denial-of-service, and data exfiltration"),
    ]:
        canvas.text(f"{label}: {value}", size=10, indent=8)
    if owner_details:
        for label, value in owner_details.items():
            if value:
                canvas.text(f"{label}: {value}", size=10, indent=8)
    canvas.divider()

    canvas.text("Rules of Engagement", size=14, bold=True)
    for protocol in report.scan_protocols or ["Verified account and authorized target validation"]:
        canvas.text(f"- {protocol}", size=10, indent=8)
    canvas.text("Detected: YES where evidence exists. Exploitation: NOT ATTEMPTED unless documented. Destructive test: NOT PERMITTED.", size=10, indent=8)
    canvas.divider()

    canvas.text("Assessment Methodology", size=14, bold=True)
    phases = [
        ("Phase 1 - Reconnaissance", "DNS analysis, approved asset discovery, host discovery, technology identification, and external attack-surface identification."),
        ("Phase 2 - Enumeration", "Ports, services, versions, TLS posture, web technologies, and exposed interfaces."),
        ("Phase 3 - Vulnerability Discovery", "Known vulnerability checks, web security checks, TLS/security configuration review, service configuration review, and application weakness discovery."),
        ("Phase 4 - Automated Validation", "Candidate evidence was evaluated using permitted, non-destructive automated checks. Manual exploitation is not implied."),
        ("Phase 5 - Correlation", "Scanner results were normalized, deduplicated, and checked for evidence consistency."),
        ("Phase 6 - Risk Analysis", "Confirmed and likely findings were evaluated using severity, exploitability, exposure, confidence, and business relevance."),
        ("Phase 7 - Reporting", "Findings were translated into technical and management recommendations."),
    ]
    for phase, detail in phases:
        canvas.text(phase, size=10, bold=True, indent=8)
        canvas.text(detail, size=9, indent=16)
    for item in report.methodology:
        canvas.text(f"- {item}", size=9, indent=8)
    canvas.divider()

    canvas.text("Assessment Coverage", size=14, bold=True)
    canvas.text(f"Assessment Outcome: {report.assessment_outcome}", size=11, bold=True)
    canvas.text(f"Assessment Coverage: {report.assessment_coverage}% - {report.assessment_coverage_status}", size=11, bold=True)
    if report.coverage_categories:
        for item in report.coverage_categories:
            canvas.text(f"{item.name}: {item.status}", size=10, bold=True, indent=8)
            if item.reason:
                canvas.text(_redact_sensitive(item.reason), size=9, indent=16, color=(0.35, 0.40, 0.45))
    else:
        canvas.text("Category-level coverage data was not recorded for this assessment.", size=10, indent=8)
    canvas.divider()

    canvas.text("Scanner / Engine Health", size=14, bold=True)
    if report.diagnostics:
        for diagnostic in report.diagnostics:
            canvas.text(f"{diagnostic.name} [{diagnostic.status.upper()}]", size=10, bold=True, indent=8)
            canvas.text(_redact_sensitive(diagnostic.detail), size=9, indent=16)
        canvas.text("Failed or partial tool output is listed as diagnostics and excluded from confirmed vulnerabilities.", size=9, indent=8)
    else:
        canvas.text("No scanner diagnostics affected this report.", size=10, indent=8)
    canvas.divider()

    canvas.text("Attack Surface Summary", size=14, bold=True)
    if report.top_services:
        for item in report.top_services:
            canvas.text(f"Service: {item.label} | Observations: {int(item.value)} | Exposure: Review", size=10, indent=8)
    else:
        canvas.text("No service-level attack surface observations were available.", size=10, indent=8)
    canvas.divider()

    if any(
        [
            report.severity_counts.critical,
            report.severity_counts.high,
            report.severity_counts.medium,
            report.severity_counts.low,
            report.severity_counts.info,
        ]
    ):
        canvas.bar_chart(
            "Severity Distribution",
            [
                ("Critical", report.severity_counts.critical, (1.0, 0.16, 0.22)),
                ("High", report.severity_counts.high, (1.0, 0.36, 0.22)),
                ("Medium", report.severity_counts.medium, (0.95, 0.65, 0.18)),
                ("Low", report.severity_counts.low, (0.19, 0.70, 0.42)),
                ("Info", report.severity_counts.info, (0.25, 0.58, 0.95)),
            ],
        )
    else:
        canvas.text("Severity Distribution", size=13, bold=True)
        canvas.text("No reportable vulnerability severity was established from the usable evidence.", size=10, indent=8)
        canvas.divider()

    all_vulnerabilities = _actionable_findings(report)
    canvas.text("Findings Summary", size=14, bold=True)
    if all_vulnerabilities:
        for index, finding in enumerate(all_vulnerabilities, start=1):
            cvss = f"{finding.cvss}" if finding.cvss else "Not assigned"
            canvas.text(
                f"{_finding_id('KS-PT', index)} | {finding.title} | {finding.severity.upper()} | CVSS {cvss} | {finding.confidence}% | {finding.validation_status}",
                size=9,
            )
    else:
        canvas.text("No vulnerability finding was included in the findings register; review coverage and limitations before drawing assurance conclusions.", size=10, indent=8)
    canvas.divider()

    for severity in ["critical", "high", "medium", "low"]:
        severity_findings = [finding for finding in all_vulnerabilities if finding.severity == severity]
        canvas.text(f"{severity.title()} Findings", size=14, bold=True)
        if not severity_findings:
            canvas.text(f"No {severity} findings recorded.", size=10, indent=8)
            canvas.divider()
            continue
        for finding in severity_findings:
            _write_pentest_finding(canvas, finding, _finding_id("KS-PT", all_vulnerabilities.index(finding) + 1))
        canvas.divider()

    exposures = _exposure_findings(report)
    canvas.text("Security Exposures & Observations", size=14, bold=True)
    if exposures:
        for index, finding in enumerate(exposures, start=1):
            canvas.text(f"{index}. {finding.title} [{finding.finding_type} | {finding.validation_status}]", size=10, bold=True)
            canvas.text(f"Asset: {finding.host}  Port: {finding.port or 'n/a'}  Service: {finding.service or 'n/a'}", size=9, indent=8)
            canvas.text(f"Why it matters: {_redact_sensitive(finding.description)}", size=9, indent=8)
            canvas.text(f"Recommendation: {_redact_sensitive(finding.remediation)}", size=9, indent=8)
    else:
        canvas.text("No exposure or informational observations were recorded.", size=10, indent=8)
    canvas.divider()

    positives = _positive_observations(report)
    canvas.text("Positive Security Observations", size=14, bold=True)
    if positives:
        for item in positives:
            canvas.text(f"- {item}", size=10, indent=8)
    else:
        canvas.text("No positive security observations were available from the final evidence set.", size=10, indent=8)
    canvas.divider()

    canvas.text("Remediation Roadmap", size=14, bold=True)
    if all_vulnerabilities:
        for finding in all_vulnerabilities[:10]:
            canvas.text(f"{finding.title} | Owner: Security Engineering | Priority: {_remediation_window(finding)} | Status: Open", size=9, indent=8)
    else:
        canvas.text("No remediation roadmap items were generated from confirmed or potential vulnerabilities.", size=10, indent=8)
    canvas.divider()

    canvas.text("Assessment Limitations", size=14, bold=True)
    for item in report.limitations:
        canvas.text(f"- {item}", size=10, indent=8)
    canvas.text("- This report represents externally observable security posture during the authorized testing period. Internal network security, social engineering, physical security, denial-of-service testing, and authenticated business logic testing were outside scope unless expressly authorized.", size=10, indent=8)
    canvas.divider()

    canvas.text("Technical Appendix", size=14, bold=True)
    canvas.text("Raw scanner evidence is summarized here with sensitive tokens, passwords, cookies, and authorization values redacted.", size=10, indent=8)
    for index, finding in enumerate(report.findings, start=1):
        if finding.evidence:
            canvas.text(f"Appendix {index}: {finding.title}", size=9, bold=True, indent=8)
            canvas.text(_redact_sensitive(finding.evidence), size=8, indent=16, color=(0.30, 0.37, 0.44))

    return _serialize_pdf(canvas.pages)


def _build_pdf_bytes(
    target: str,
    asset_type: str,
    scanner_backend: str,
    assessment_mode: str,
    recipient_email: str,
    report: AssessmentReport,
    msp_details: dict[str, str] | None = None,
    owner_details: dict[str, str] | None = None,
    scan_metadata: dict[str, str | None] | None = None,
) -> bytes:
    if _is_pentest_mode(assessment_mode):
        return _build_pentest_pdf_bytes(
            target=target,
            asset_type=asset_type,
            scanner_backend=scanner_backend,
            assessment_mode=assessment_mode,
            recipient_email=recipient_email,
            report=report,
            msp_details=msp_details,
            owner_details=owner_details,
            scan_metadata=scan_metadata,
        )

    issuer = _safe((msp_details or {}).get("Company name"), "Authorized Security Provider")
    canvas = _Canvas(brand_name=issuer)
    title = "PENETRATION TESTING REPORT" if assessment_mode in {"ethical_pentesting", "authorized_pentest"} else "VULNERABILITY ASSESSMENT REPORT"
    canvas.text(issuer, size=18, bold=True, color=(0.07, 0.25, 0.65))
    canvas.text(title, size=20, bold=True)
    canvas.text(target, size=15, bold=True, color=(0.18, 0.45, 0.62))
    canvas.spacer(4)
    canvas.text(f"Target type: {asset_type}")
    canvas.text(f"Assessment mode: {assessment_mode.replace('_', ' ').title()}")
    canvas.text(f"Scanner backend: {scanner_backend}")
    canvas.text(f"Report recipient: {recipient_email}")
    canvas.text(f"Scan ID: {_safe((scan_metadata or {}).get('scan_id'))}")
    canvas.text(f"Report ID: {_safe((scan_metadata or {}).get('report_id'))}")
    canvas.text(f"Scan status: {_safe((scan_metadata or {}).get('status'))}")
    canvas.text(f"Scan started: {_safe((scan_metadata or {}).get('started_at'))}")
    canvas.text(f"Scan completed: {_safe((scan_metadata or {}).get('completed_at'))}")
    canvas.text(f"Generated at: {report.generated_at}")
    canvas.text("Assessment platform: KryptScan")
    canvas.divider()

    if msp_details:
        canvas.text("MSP / Testing Provider", size=14, bold=True)
        for label, value in msp_details.items():
            if value:
                canvas.text(f"{label}: {value}", size=10, indent=8)
        canvas.divider()

    if owner_details:
        canvas.text("Assessed Organization / Target", size=14, bold=True)
        for label, value in owner_details.items():
            if value:
                canvas.text(f"{label}: {value}", size=10, indent=8)
        canvas.divider()

    canvas.text("Executive Summary", size=14, bold=True)
    canvas.text(report.executive_summary, size=11, extra_gap=4)
    if report.scope_summary:
        canvas.spacer(4)
        canvas.text("Scope", size=12, bold=True)
        canvas.text(report.scope_summary, size=10, indent=8)
    canvas.spacer(4)
    canvas.metric_grid(
        [
            ("Assessment Outcome", report.assessment_outcome),
            ("Overall Security Risk", report.risk_band),
            ("Risk Score", _risk_score_label(report)),
            ("Assessment Coverage", f"{report.assessment_coverage}% - {report.assessment_coverage_status}"),
            ("Critical + High", str(report.severity_counts.critical + report.severity_counts.high)),
            ("Analyst Review", report.analyst_review_status),
        ]
    )
    canvas.text(
        f"Assessment coverage: {report.assessment_coverage}% - {report.assessment_coverage_status}",
        size=12,
        bold=True,
        color=(0.70, 0.16, 0.16) if report.assessment_coverage_status != "Complete" else (0.10, 0.48, 0.34),
    )
    canvas.divider()

    if report.coverage_categories:
        canvas.text("Coverage by Category", size=14, bold=True)
        for item in report.coverage_categories:
            canvas.text(f"{item.name}: {item.status}", size=10, bold=True, indent=8)
            canvas.text(_redact_sensitive(item.reason), size=9, indent=16, color=(0.35, 0.40, 0.45))
        canvas.divider()

    if report.diagnostics:
        canvas.text("Assessment Coverage & Tool Health", size=14, bold=True)
        canvas.text(
            "The following scanner diagnostics affected assessment coverage. These are KryptScan operational diagnostics, not customer vulnerabilities.",
            size=10,
            indent=8,
        )
        for diagnostic in report.diagnostics:
            canvas.text(f"{diagnostic.name} [{diagnostic.status.upper()}]", size=10, bold=True, indent=8)
            canvas.text(diagnostic.detail, size=9, indent=16, color=(0.35, 0.40, 0.45))
        canvas.divider()

    if assessment_mode in {"ethical_pentesting", "authorized_pentest"}:
        canvas.text("Rules of Engagement & Validation Approach", size=14, bold=True)
        canvas.text(
            "This ethical pen-testing report separates verified vulnerabilities, exposure observations, inconclusive tests, and KryptScan scanner diagnostics. Testing is documented as non-destructive unless the approved scope states otherwise.",
            size=10,
            indent=8,
        )
        canvas.text(
            "Use confirmed and high-confidence findings for immediate remediation. Use potential or inconclusive findings for analyst validation before declaring client impact.",
            size=10,
            indent=8,
        )
        canvas.text(
            "After remediation, rerun targeted retesting for the affected services, application paths, controls, or CVEs and retain the retest result as closure evidence.",
            size=10,
            indent=8,
        )
        canvas.divider()

    if report.methodology:
        canvas.text("Methodology", size=14, bold=True)
        for item in report.methodology:
            canvas.text(f"- {item}", size=10, indent=8)
        canvas.divider()

    if report.limitations:
        canvas.text("Limitations", size=14, bold=True)
        for item in report.limitations:
            canvas.text(f"- {item}", size=10, indent=8)
        canvas.divider()

    if any(
        [
            report.severity_counts.critical,
            report.severity_counts.high,
            report.severity_counts.medium,
            report.severity_counts.low,
            report.severity_counts.info,
        ]
    ):
        canvas.bar_chart(
            "Severity Distribution",
            [
                ("Critical", report.severity_counts.critical, (1.0, 0.36, 0.45)),
                ("High", report.severity_counts.high, (1.0, 0.48, 0.35)),
                ("Medium", report.severity_counts.medium, (0.965, 0.678, 0.333)),
                ("Low", report.severity_counts.low, (0.545, 0.878, 0.545)),
                ("Info", report.severity_counts.info, (0.357, 0.753, 0.922)),
            ],
        )
    else:
        canvas.text("Severity Distribution", size=13, bold=True)
        canvas.text("No reportable vulnerability severity was established from the usable evidence.", size=10, indent=8)
        canvas.divider()

    if report.scan_protocols:
        canvas.text("Applied Scan Protocols", size=14, bold=True)
        for protocol in report.scan_protocols:
            canvas.text(f"- {protocol}", size=11, indent=8)
        canvas.divider()

    canvas.text("Risk Severity Checks", size=14, bold=True)
    for check in report.compliance_checks:
        canvas.text(f"{check.name} [{check.status.upper()}]", size=11, bold=True)
        canvas.text(check.detail, size=10, indent=8)
        canvas.spacer(2)
    canvas.divider()

    if report.remediation_plan:
        canvas.text("Remediation Priorities", size=14, bold=True)
        for item in report.remediation_plan:
            canvas.text(f"{item.priority}: {item.title}", size=11, bold=True)
            canvas.text(item.action, size=10, indent=8)
            canvas.text(f"Owner: {item.owner}", size=10, indent=8, color=(0.35, 0.40, 0.45))
            canvas.spacer(2)
        canvas.divider()

    if report.top_services:
        canvas.bar_chart(
            "Top Affected Services",
            [(item.label, item.value, (0.31, 0.82, 0.77)) for item in report.top_services],
        )

    if report.top_categories:
        canvas.bar_chart(
            "Top Finding Categories",
            [(item.label, item.value, (0.35, 0.75, 0.92)) for item in report.top_categories],
        )

    vulnerability_findings = [
        finding
        for finding in report.findings
        if finding.finding_type in {"VULNERABILITY", "SECURITY_MISCONFIGURATION"}
        and finding.validation_status not in {"NOT_VULNERABLE", "SCANNER_ERROR"}
    ]
    exposure_findings = [
        finding
        for finding in report.findings
        if finding not in vulnerability_findings
    ]

    canvas.text("Confirmed and Potential Vulnerabilities", size=14, bold=True)
    if not vulnerability_findings:
        canvas.text("No confirmed or potential vulnerability finding was available in the usable scanner evidence. This does not establish that vulnerabilities are absent.", size=10, indent=8)
        canvas.spacer(4)
    for index, finding in enumerate(vulnerability_findings, start=1):
        canvas.text(
            f"{index}. {finding.title} [{finding.severity.upper()} | CVSS {finding.cvss}]",
            size=11,
            bold=True,
        )
        canvas.text(
            f"Type: {finding.finding_type}  Status: {finding.validation_status}  Confidence: {finding.confidence}%",
            size=10,
            indent=8,
            color=(0.35, 0.40, 0.45),
        )
        canvas.text(
            f"Host: {finding.host}  Port: {finding.port or 'n/a'}  Service: {finding.service or 'n/a'}",
            size=10,
            indent=8,
            color=(0.35, 0.40, 0.45),
        )
        if finding.cve:
            canvas.text(f"CVE: {finding.cve}", size=10, indent=8, color=(0.35, 0.40, 0.45))
        if finding.cwe:
            canvas.text(f"CWE: {finding.cwe}", size=10, indent=8, color=(0.35, 0.40, 0.45))
        if finding.cvss_vector:
            canvas.text(f"CVSS vector: {finding.cvss_vector}", size=10, indent=8, color=(0.35, 0.40, 0.45))
        if finding.detected_by:
            canvas.text(f"Detected by: {', '.join(finding.detected_by)}", size=10, indent=8, color=(0.35, 0.40, 0.45))
        canvas.text(f"Description: {_redact_sensitive(finding.description)}", size=10, indent=8)
        canvas.text(f"Remediation: {_redact_sensitive(finding.remediation)}", size=10, indent=8)
        if finding.evidence:
            canvas.text(f"Evidence: {_redact_sensitive(finding.evidence)}", size=10, indent=8, color=(0.30, 0.37, 0.44))
        canvas.spacer(5)
    canvas.divider()

    canvas.text("Exposures and Security Observations", size=14, bold=True)
    if not exposure_findings:
        canvas.text("No additional exposure or informational observations were recorded.", size=10, indent=8)
    for index, finding in enumerate(exposure_findings, start=1):
        canvas.text(
            f"{index}. {finding.title} [{finding.validation_status} | {finding.finding_type}]",
            size=11,
            bold=True,
        )
        canvas.text(
            f"Host: {finding.host}  Port: {finding.port or 'n/a'}  Service: {finding.service or 'n/a'}  Confidence: {finding.confidence}%",
            size=10,
            indent=8,
            color=(0.35, 0.40, 0.45),
        )
        canvas.text(f"Description: {_redact_sensitive(finding.description)}", size=10, indent=8)
        canvas.text(f"Recommended review: {_redact_sensitive(finding.remediation)}", size=10, indent=8)
        if finding.evidence:
            canvas.text(f"Evidence: {_redact_sensitive(finding.evidence)}", size=9, indent=8, color=(0.30, 0.37, 0.44))
        canvas.spacer(5)

    return _serialize_pdf(canvas.pages)


def _serialize_pdf(pages: list[list[str]]) -> bytes:
    objects: list[bytes] = []

    def add_object(payload: bytes) -> int:
        objects.append(payload)
        return len(objects)

    catalog_id = add_object(b"<< /Type /Catalog /Pages 2 0 R >>")
    pages_id = add_object(b"<< /Type /Pages /Kids [] /Count 0 >>")
    font_regular_id = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    font_bold_id = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

    page_ids: list[int] = []
    for commands in pages:
        stream_data = "\n".join(commands).encode("latin-1", "replace")
        contents_id = add_object(
            b"<< /Length " + str(len(stream_data)).encode("ascii") + b" >>\nstream\n" + stream_data + b"\nendstream"
        )
        page_id = add_object(
            (
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                f"/Resources << /Font << /F1 {font_regular_id} 0 R /F2 {font_bold_id} 0 R >> >> "
                f"/Contents {contents_id} 0 R >>"
            ).encode("ascii")
        )
        page_ids.append(page_id)

    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[pages_id - 1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")
    objects[catalog_id - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")

    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(payload)
        output.extend(b"\nendobj\n")

    xref_position = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_position}\n%%EOF"
        ).encode("ascii")
    )
    return bytes(output)


def write_pdf_report(
    output_path: Path,
    target: str,
    asset_type: str,
    scanner_backend: str,
    recipient_email: str,
    report: AssessmentReport,
    assessment_mode: str = "vulnerability_assessment",
    msp_details: dict[str, str] | None = None,
    owner_details: dict[str, str] | None = None,
    scan_metadata: dict[str, str | None] | None = None,
) -> bytes:
    pdf_bytes = _build_pdf_bytes(
        target=target,
        asset_type=asset_type,
        scanner_backend=scanner_backend,
        assessment_mode=assessment_mode,
        recipient_email=recipient_email,
        report=report,
        msp_details=msp_details,
        owner_details=owner_details,
        scan_metadata=scan_metadata,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(pdf_bytes)
    return pdf_bytes
