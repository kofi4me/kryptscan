from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from app.models import AssessmentCheckResult, Finding
from app.services.reporting import build_assessment_report


WORKER_MAIN = Path(__file__).resolve().parents[1] / "scanner-worker" / "app" / "main.py"
SPEC = importlib.util.spec_from_file_location("kryptscan_accuracy_worker", WORKER_MAIN)
worker = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(worker)


def check(
    name: str,
    category: str,
    execution_status: str,
    security_result: str,
    detail: str = "",
) -> AssessmentCheckResult:
    return AssessmentCheckResult(
        name=name,
        category=category,
        execution_status=execution_status,
        security_result=security_result,
        detail=detail,
    )


class ReportingAccuracyTests(unittest.TestCase):
    def test_inconclusive_checks_do_not_become_low_risk(self) -> None:
        report = build_assessment_report(
            "192.0.2.10",
            [],
            check_results=[
                check("Nmap", "Network Exposure", "COMPLETED", "INCONCLUSIVE", "All ports filtered."),
                check("SSLyze", "TLS Posture", "FAILED", "INCONCLUSIVE", "TCP connection timed out."),
            ],
        )

        self.assertIsNone(report.risk_score)
        self.assertEqual(report.risk_band, "Undetermined")
        self.assertEqual(report.assessment_outcome, "INCONCLUSIVE")
        self.assertEqual(report.assessment_coverage, 0)
        self.assertIn("insufficient usable evidence", report.executive_summary.lower())

    def test_coverage_counts_only_usable_security_results(self) -> None:
        report = build_assessment_report(
            "example.com",
            [],
            check_results=[
                check("Nuclei", "Known Vulnerabilities", "COMPLETED", "NOT_VULNERABLE"),
                check("Nmap", "Network Exposure", "COMPLETED", "NOT_VULNERABLE"),
                check("SSLyze", "TLS Posture", "FAILED", "INCONCLUSIVE"),
            ],
        )

        self.assertEqual(report.assessment_coverage, 67)
        self.assertEqual(report.assessment_outcome, "PARTIAL")
        self.assertEqual(report.coverage_summary.successfully_evaluated, 2)
        self.assertEqual(report.coverage_summary.failed, 1)
        self.assertIsNone(report.risk_score)

    def test_all_operational_failures_produce_failed_outcome(self) -> None:
        report = build_assessment_report(
            "example.com",
            [],
            check_results=[
                check("Nmap", "Network Exposure", "FAILED", "INCONCLUSIVE"),
                check("SSLyze", "TLS Posture", "TIMED_OUT", "INCONCLUSIVE"),
            ],
        )

        self.assertEqual(report.assessment_outcome, "FAILED")
        self.assertIsNone(report.risk_score)

    def test_complete_no_finding_result_is_low_but_not_zero(self) -> None:
        report = build_assessment_report(
            "example.com",
            [],
            check_results=[
                check("Nmap", "Network Exposure", "COMPLETED", "NOT_VULNERABLE"),
                check("Nuclei", "Known Vulnerabilities", "COMPLETED", "NOT_VULNERABLE"),
            ],
        )

        self.assertEqual(report.assessment_outcome, "COMPLETED")
        self.assertEqual(report.risk_score, 5)
        self.assertEqual(report.risk_band, "Low")

    def test_confirmed_high_finding_respects_high_risk_floor(self) -> None:
        finding = Finding(
            title="Confirmed exposed administrative service",
            severity="high",
            cvss=8.0,
            category="Access Control",
            host="example.com",
            port="443/tcp",
            service="https",
            validation_status="CONFIRMED",
            confidence=95,
            detected_by=["Manual analyst review"],
            description="Authorized validation confirmed the exposure.",
            remediation="Restrict the interface and require MFA.",
            evidence="Manual tester evidence",
        )
        report = build_assessment_report(
            "example.com",
            [finding],
            check_results=[check("Nmap", "Network Exposure", "FAILED", "INCONCLUSIVE")],
        )

        self.assertGreaterEqual(report.risk_score or 0, 60)
        self.assertEqual(report.risk_band, "High")

    def test_scanner_names_are_not_customer_services_and_ansi_is_removed(self) -> None:
        internal = Finding(
            title="Nmap completed",
            severity="info",
            category="Tool Execution",
            host="example.com",
            service="nmap",
            finding_type="CHECK_RESULT",
            validation_status="INFORMATIONAL",
            description="\x1b[1;35mNmap completed\x1b[0m",
            remediation="Retain diagnostic evidence.",
            evidence="\x1b[1;35mtool output\x1b[0m",
        )
        service = Finding(
            title="SSH is externally reachable",
            severity="low",
            cvss=3.7,
            category="Network Exposure",
            host="example.com",
            port="22/tcp",
            service="ssh",
            description="Open SSH service.",
            remediation="Restrict administrative access.",
            evidence="22/tcp open ssh",
        )
        report = build_assessment_report("example.com", [internal, service])

        self.assertEqual([item.label for item in report.top_services], ["ssh"])
        self.assertNotIn("\x1b", report.model_dump_json())

    def test_worker_classifies_filtered_and_empty_evidence_honestly(self) -> None:
        self.assertEqual(
            worker._stage_security_result(
                "Nmap",
                "COMPLETED",
                "All 100 scanned ports on 192.0.2.10 are in ignored states. 100 filtered tcp ports.",
                [],
            ),
            "INCONCLUSIVE",
        )
        self.assertEqual(
            worker._stage_security_result("SSLyze", "FAILED", "Connection timed out", []),
            "INCONCLUSIVE",
        )
        self.assertEqual(worker._stage_security_result("Nuclei", "COMPLETED", "", []), "NOT_VULNERABLE")

    def test_worker_has_no_artificial_scan_dwell(self) -> None:
        source = WORKER_MAIN.read_text(encoding="utf-8")
        self.assertEqual(worker.MIN_FULL_SCAN_SECONDS, 0)
        self.assertNotIn("Professional scan dwell time enforced", source)
        self.assertNotIn("time.sleep(remaining)", source)


if __name__ == "__main__":
    unittest.main()
