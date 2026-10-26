from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
CERTIFICATION_SCRIPT = ROOT / "ops" / "kryptscan_production_certify.py"
EGRESS_SCRIPT = ROOT / "ops" / "kryptscan-worker-egress.sh"
SPEC = importlib.util.spec_from_file_location("kryptscan_production_certify", CERTIFICATION_SCRIPT)
certify = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = certify
SPEC.loader.exec_module(certify)


class ProductionCertificationTests(unittest.TestCase):
    def test_env_file_parser_does_not_execute_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.scanner"
            path.write_text(
                "# comment\nexport SCANNER_WORKER_TOKEN='secret-value'\nIGNORED_LINE\nNAME=value\n",
                encoding="utf-8",
            )

            values = certify.read_env_file(path)

        self.assertEqual(values["SCANNER_WORKER_TOKEN"], "secret-value")
        self.assertEqual(values["NAME"], "value")

    def test_target_validation_blocks_private_dns_resolution(self) -> None:
        private_resolution = [
            (2, 1, 6, "", ("10.0.0.10", 0)),
        ]
        with patch.object(certify.socket, "getaddrinfo", return_value=private_resolution):
            with self.assertRaises(ValueError):
                certify.validate_public_target("certification.example")

    def test_target_validation_allows_global_dns_resolution(self) -> None:
        public_resolution = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
        ]
        with patch.object(certify.socket, "getaddrinfo", return_value=public_resolution):
            self.assertEqual(
                certify.validate_public_target("https://certification.example"),
                "https://certification.example",
            )

    def test_standard_va_report_passes_release_evaluation(self) -> None:
        report_names = {
            "zap-baseline.py": "OWASP ZAP baseline",
        }
        report = {
            "check_results": [
                {
                    "name": report_names.get(tool, tool),
                    "execution_status": "COMPLETED",
                    "security_result": "NOT_VULNERABLE",
                }
                for tool in certify.PROFILE_TOOLS["va-standard"]
            ],
            "assessment_coverage": 100,
            "assessment_outcome": "COMPLETED",
            "risk_score": 5,
            "risk_band": "Low",
            "analyst_review_status": "NOT_PERFORMED",
            "top_services": [{"label": "https", "value": 1}],
        }

        results = certify.evaluate_report("va-standard", report, 90)

        self.assertTrue(all(passed for _, passed, _ in results), results)

    def test_release_evaluation_rejects_failed_or_inconclusive_engine(self) -> None:
        check_results = [
            {
                "name": tool,
                "execution_status": "COMPLETED",
                "security_result": "NOT_VULNERABLE",
            }
            for tool in certify.PROFILE_TOOLS["va-standard"]
        ]
        check_results[0]["execution_status"] = "TIMED_OUT"
        check_results[0]["security_result"] = "INCONCLUSIVE"
        report = {
            "check_results": check_results,
            "assessment_coverage": 88,
            "assessment_outcome": "COMPLETED_WITH_LIMITATIONS",
            "risk_score": None,
            "risk_band": "Undetermined",
            "analyst_review_status": "NOT_PERFORMED",
            "top_services": [],
        }

        results = dict((name, passed) for name, passed, _ in certify.evaluate_report("va-standard", report, 90))

        self.assertFalse(results["no-engine-execution-failures"])
        self.assertFalse(results["no-inconclusive-mandatory-results"])
        self.assertFalse(results["minimum-assessment-coverage"])

    def test_pt_release_evaluation_rejects_fabricated_approval(self) -> None:
        report = {
            "check_results": [
                {
                    "name": tool,
                    "execution_status": "COMPLETED",
                    "security_result": "NOT_VULNERABLE",
                }
                for tool in certify.PROFILE_TOOLS["pt-automated"]
            ],
            "assessment_coverage": 100,
            "assessment_outcome": "COMPLETED",
            "risk_score": 5,
            "risk_band": "Low",
            "analyst_review_status": "APPROVED",
            "top_services": [],
        }

        results = dict((name, passed) for name, passed, _ in certify.evaluate_report("pt-automated", report, 90))

        self.assertFalse(results["pt-does-not-fabricate-analyst-approval"])

    def test_secure_json_writer_returns_matching_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            digest = certify.write_json_secure(path, {"decision": "PASS"})
            written = path.read_bytes()

        self.assertEqual(digest, hashlib.sha256(written).hexdigest())

    def test_source_manifest_covers_shared_and_worker_code(self) -> None:
        manifest = certify.source_manifest()

        self.assertIn("app/models.py", manifest)
        self.assertIn("scanner_worker_app/main.py", manifest)
        self.assertEqual(len(certify.manifest_digest(manifest)), 64)

    def test_firewall_script_is_scoped_to_scanner_subnet(self) -> None:
        source = EGRESS_SCRIPT.read_text(encoding="utf-8")

        self.assertIn('-s "$ipv4_subnet" -j "$CHAIN"', source)
        self.assertNotIn("-F DOCKER-USER", source)
        self.assertIn("10.0.0.0/8", source)
        self.assertIn("169.254.0.0/16", source)


if __name__ == "__main__":
    unittest.main()
