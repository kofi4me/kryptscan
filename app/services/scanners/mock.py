from __future__ import annotations

import hashlib

from app.models import Finding
from app.services.reporting import build_assessment_report, severity_from_cvss
from app.services.scanners.base import RefreshedScan, ScheduledScan


class MockScannerProvider:
    backend_name = "mock"

    _templates = [
        (
            "Outdated TLS configuration",
            8.7,
            "Transport Security",
            "https",
            "Enforce TLS 1.2+ only, disable weak ciphers, and rotate certificates where needed.",
        ),
        (
            "Administrative panel exposed to the internet",
            9.4,
            "Access Control",
            "https",
            "Restrict the management interface with VPN or IP allow-listing and require MFA.",
        ),
        (
            "Legacy SSH settings detected",
            6.8,
            "System Hardening",
            "ssh",
            "Disable password authentication, remove weak key exchange options, and rotate keys.",
        ),
        (
            "Known package vulnerability detected",
            7.9,
            "Patch Management",
            "https",
            "Update the affected package to the vendor-supported version and redeploy the service.",
        ),
        (
            "Missing security headers",
            5.6,
            "Web Application Security",
            "http",
            "Add HSTS, CSP, X-Content-Type-Options, and frame protections at the edge.",
        ),
        (
            "Information disclosure via service banner",
            3.7,
            "Information Exposure",
            "http",
            "Remove version banners and standardize error handling to limit recon data.",
        ),
    ]

    def schedule(self, target: str, asset_type: str) -> ScheduledScan:
        findings = self._build_findings(target, asset_type)
        report = build_assessment_report(target, findings)
        return ScheduledScan(
            status="completed",
            backend=self.backend_name,
            message="Mock scan completed successfully.",
            report=report,
        )

    def refresh(self, target: str, asset_type: str) -> RefreshedScan:
        findings = self._build_findings(target, asset_type)
        report = build_assessment_report(target, findings)
        return RefreshedScan(
            status="completed",
            message="Mock scan report refreshed.",
            report=report,
        )

    def _build_findings(self, target: str, asset_type: str) -> list[Finding]:
        fingerprint = hashlib.sha256(f"{target}:{asset_type}".encode("utf-8")).digest()
        total = 4 + (fingerprint[0] % 3)
        findings: list[Finding] = []

        for index in range(total):
            template = self._templates[index % len(self._templates)]
            title, base_cvss, category, service, remediation = template
            modifier = (fingerprint[index] % 12) / 10
            cvss = min(9.9, round(base_cvss + modifier, 1))
            severity = severity_from_cvss(cvss)
            port = {
                "http": "80/tcp",
                "https": "443/tcp",
                "ssh": "22/tcp",
            }.get(service, "0/tcp")
            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    cvss=cvss,
                    category=category,
                    host=target,
                    port=port,
                    service=service,
                    cve=f"CVE-2025-{1000 + fingerprint[index]}",
                    description=(
                        f"{title} was identified during the {asset_type} assessment for {target}. "
                        "The generated finding simulates the structure and prioritization of a real scanner result."
                    ),
                    remediation=remediation,
                    evidence=(
                        "Detected during product demo mode. Replace the mock provider with Greenbone "
                        "to collect live evidence."
                    ),
                )
            )

        return findings
