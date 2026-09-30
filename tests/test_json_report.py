from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app.models import AssessmentReport, Finding, SeverityCounts
from app.services.json_report import build_json_report, validate_json_report, write_json_report
from app.services.pdf_report import write_pdf_report


def sample_report(*, penetration_test: bool = False) -> tuple[dict, AssessmentReport]:
    finding = Finding(
        title="Deprecated TLS protocol",
        severity="high",
        cvss=8.1,
        category="TLS Posture",
        host="example.com",
        port="443/tcp",
        service="https",
        cve="CVE-2026-10001, CVE-2026-10002",
        cwe="CWE-326",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        validation_status="CONFIRMED",
        confidence=94,
        detected_by=["testssl.sh"],
        description="The service permits an obsolete protocol.",
        remediation="Disable the obsolete protocol. api_key=do-not-export",
        evidence="Authorization: Bearer secret-token TLSv1.0 accepted",
    )
    report = AssessmentReport(
        executive_summary="One high-severity finding requires remediation.",
        risk_score=62,
        risk_band="High",
        assessment_coverage=100,
        severity_counts=SeverityCounts(high=1),
        scope_summary="Authorized external assessment.",
        methodology=["Service discovery", "TLS validation"],
        limitations=[],
        findings=[finding],
        compliance_checks=[],
        remediation_plan=[],
        top_services=[],
        top_categories=[],
        trend=[],
        generated_at="2026-09-30T13:18:41+00:00",
    )
    scan = {
        "id": 123,
        "normalized_target": "example.com",
        "asset_type": "website",
        "assessment_mode": "ethical_pentesting" if penetration_test else "vulnerability_assessment",
        "scan_tier": "full_scan",
        "status": "completed",
        "created_at": "2026-09-30T13:04:59+00:00",
        "started_at": "2026-09-30T13:05:22+00:00",
        "completed_at": "2026-09-30T13:18:41+00:00",
    }
    return scan, report


class JsonReportTests(unittest.TestCase):
    def test_vulnerability_report_is_schema_valid_and_consistent(self) -> None:
        scan, report = sample_report()
        payload = build_json_report(scan, report)
        validate_json_report(payload)
        self.assertEqual(payload["report_type"], "vulnerability_assessment")
        self.assertEqual(payload["scan_id"], payload["scan"]["scan_id"])
        self.assertEqual(payload["statistics"]["total_findings"], len(report.findings))
        self.assertEqual(payload["statistics"]["findings_by_severity"]["high"], report.severity_counts.high)
        self.assertEqual(payload["findings"][0]["identifiers"]["cve"], ["CVE-2026-10001", "CVE-2026-10002"])

    def test_penetration_test_fields_are_present(self) -> None:
        scan, report = sample_report(penetration_test=True)
        payload = build_json_report(scan, report)
        self.assertEqual(payload["report_type"], "penetration_test")
        self.assertTrue(payload["penetration_test"]["validated"])

    def test_sensitive_evidence_is_redacted(self) -> None:
        scan, report = sample_report()
        serialized = json.dumps(build_json_report(scan, report))
        self.assertNotIn("secret-token", serialized)
        self.assertNotIn("do-not-export", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_pdf_and_json_use_same_canonical_counts_and_redact_secrets(self) -> None:
        scan, report = sample_report()
        payload = build_json_report(scan, report)
        with tempfile.TemporaryDirectory() as directory:
            pdf_bytes = write_pdf_report(
                Path(directory) / "report.pdf",
                target=scan["normalized_target"],
                asset_type=scan["asset_type"],
                scanner_backend="test",
                recipient_email="security@example.com",
                report=report,
                scan_metadata={"scan_id": payload["scan_id"], "report_id": payload["report_id"], "status": "completed", "started_at": scan["started_at"], "completed_at": scan["completed_at"]},
            )
        self.assertEqual(payload["statistics"]["total_findings"], len(report.findings))
        self.assertEqual(payload["executive_summary"]["high"], report.severity_counts.high)
        self.assertNotIn(b"secret-token", pdf_bytes)
        self.assertNotIn(b"do-not-export", pdf_bytes)

    def test_empty_findings_and_missing_identifiers(self) -> None:
        scan, report = sample_report()
        empty = report.model_copy(update={"findings": [], "severity_counts": SeverityCounts()})
        payload = build_json_report(scan, empty)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["statistics"]["total_findings"], 0)

    def test_multiple_hosts_informational_and_missing_cvss(self) -> None:
        scan, report = sample_report()
        informational = report.findings[0].model_copy(
            update={
                "title": "HTTP service observed",
                "severity": "info",
                "cvss": 0.0,
                "cvss_vector": None,
                "cve": None,
                "cwe": None,
                "host": "192.0.2.20",
                "port": "not-reported",
            }
        )
        report = report.model_copy(
            update={
                "findings": [*report.findings, informational],
                "severity_counts": SeverityCounts(high=1, info=1),
            }
        )
        payload = build_json_report(scan, report)
        self.assertEqual(len(payload["assets"]), 2)
        self.assertEqual(payload["findings"][1]["severity"], "informational")
        self.assertIsNone(payload["findings"][1]["cvss"]["base_score"])
        self.assertEqual(payload["findings"][1]["identifiers"]["cve"], [])

    def test_large_report(self) -> None:
        scan, report = sample_report()
        findings = [report.findings[0].model_copy(update={"title": f"Finding {index}"}) for index in range(250)]
        report = report.model_copy(update={"findings": findings, "severity_counts": SeverityCounts(high=250)})
        payload = build_json_report(scan, report)
        self.assertEqual(payload["statistics"]["total_findings"], 250)
        self.assertEqual(payload["findings"][-1]["finding_id"], "KS-F-0250")

    def test_schema_rejects_malformed_report(self) -> None:
        scan, report = sample_report()
        payload = build_json_report(scan, report)
        payload["findings"][0]["severity"] = "urgent-ish"
        with self.assertRaises(ValueError):
            validate_json_report(payload)

    def test_written_report_is_utf8_json(self) -> None:
        scan, report = sample_report()
        report = report.model_copy(update={"executive_summary": "Validated Unicode target: café.example"})
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            report_bytes = write_json_report(output, scan, report)
            self.assertEqual(json.loads(report_bytes)["executive_summary"]["narrative"], report.executive_summary)
            self.assertEqual(output.read_bytes(), report_bytes)


if __name__ == "__main__":
    unittest.main()
