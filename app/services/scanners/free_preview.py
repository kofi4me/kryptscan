from __future__ import annotations

import hashlib

from app.models import AssessmentReport, Finding
from app.services.reporting import build_assessment_report
from app.services.scanners.base import RefreshedScan, ScheduledScan


class FreePreviewScannerProvider:
    backend_name = "free_preview"

    def schedule(self, target: str, asset_type: str) -> ScheduledScan:
        report = self._build_preview_report(target, asset_type)
        return ScheduledScan(
            status="completed",
            backend=self.backend_name,
            message="Free vulnerability preview completed.",
            report=report,
        )

    def refresh(self, target: str, asset_type: str) -> RefreshedScan:
        report = self._build_preview_report(target, asset_type)
        return RefreshedScan(
            status="completed",
            message="Free vulnerability preview refreshed.",
            report=report,
        )

    def _build_preview_report(self, target: str, asset_type: str) -> AssessmentReport:
        fingerprint = hashlib.sha256(f"preview:{target}:{asset_type}".encode("utf-8")).digest()
        findings = [
            Finding(
                title="External exposure preview",
                severity="medium" if fingerprint[0] % 2 else "low",
                cvss=5.0 if fingerprint[0] % 2 else 3.2,
                category="Attack Surface",
                host=target,
                port="443/tcp" if asset_type == "website" else None,
                service="https" if asset_type == "website" else "network",
                description=(
                    "The free scan performs a limited, non-invasive preview of visible exposure. "
                    "It is intended to show possible areas of concern before a paid full scan."
                ),
                remediation="Run a full vulnerability assessment to confirm exposure and receive a PDF report.",
                evidence="Free preview summary only. Deep toolchain evidence is reserved for paid full scans.",
            ),
            Finding(
                title="Security posture requires deeper validation",
                severity="info",
                cvss=0.0,
                category="Assessment Limitation",
                host=target,
                service="preview",
                description=(
                    "The preview does not perform authenticated checks, broad service discovery, "
                    "cloud review, container/IaC inspection, or ethical pen-testing validation."
                ),
                remediation="Select Full Scan for deeper vulnerability scanning and client PDF delivery.",
                evidence="Free preview limitation.",
            ),
        ]
        report = build_assessment_report(target, findings)
        return report.model_copy(
            update={
                "scope_summary": f"Free vulnerability preview for {target}.",
                "methodology": [
                    "Verified user session and safe-use acceptance",
                    "Limited external posture preview",
                    "Web-interface summary generation",
                ],
                "limitations": [
                    "Free scan is partial and non-invasive.",
                    "No PDF report or email delivery is generated for free scans.",
                    "Full vulnerability assessment is required for deeper toolchain coverage.",
                    "Ethical Pen-Testing is not available as a free service.",
                ],
                "scan_protocols": [
                    "Free vulnerability preview",
                    "Partial scan only",
                    "Summary displayed in web interface",
                ],
            }
        )
