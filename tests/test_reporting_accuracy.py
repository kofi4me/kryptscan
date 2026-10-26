from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

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
        self.assertEqual(worker._stage_security_result("Subfinder", "COMPLETED", "", []), "NOT_VULNERABLE")

    def test_worker_has_no_artificial_scan_dwell(self) -> None:
        source = WORKER_MAIN.read_text(encoding="utf-8")
        self.assertEqual(worker.MIN_FULL_SCAN_SECONDS, 0)
        self.assertNotIn("Professional scan dwell time enforced", source)
        self.assertNotIn("time.sleep(remaining)", source)

    def test_worker_blocks_hostname_resolving_to_private_address(self) -> None:
        private_resolution = [
            (worker.socket.AF_INET, worker.socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
        ]
        with (
            patch.object(worker, "ALLOW_PRIVATE_TARGETS", False),
            patch.object(worker.socket, "getaddrinfo", return_value=private_resolution),
            self.assertRaises(HTTPException) as raised,
        ):
            worker._validate_target("scanner-bypass.example")

        self.assertIn("resolves to a private", raised.exception.detail)

    def test_worker_allows_hostname_when_every_resolved_address_is_global(self) -> None:
        public_resolution = [
            (worker.socket.AF_INET, worker.socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (worker.socket.AF_INET6, worker.socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0)),
        ]
        with (
            patch.object(worker, "ALLOW_PRIVATE_TARGETS", False),
            patch.object(worker.socket, "getaddrinfo", return_value=public_resolution),
        ):
            self.assertEqual(worker._validate_target("example.com"), "example.com")

    def test_worker_rejects_credentials_and_non_http_url_schemes(self) -> None:
        with self.assertRaises(HTTPException):
            worker._validate_target("https://user:secret@example.com")
        with self.assertRaises(HTTPException):
            worker._validate_target("ftp://example.com")

    def test_worker_blocks_shared_and_multicast_ip_ranges(self) -> None:
        with patch.object(worker, "ALLOW_PRIVATE_TARGETS", False):
            with self.assertRaises(HTTPException):
                worker._validate_target("100.64.0.1")
            with self.assertRaises(HTTPException):
                worker._validate_target("224.0.0.1")


if __name__ == "__main__":
    unittest.main()
