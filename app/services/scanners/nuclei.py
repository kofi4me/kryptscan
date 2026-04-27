from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from uuid import uuid4

from app.models import Finding
from app.services.reporting import build_assessment_report
from app.services.scanners.base import RefreshedScan, ScheduledScan


SEVERITY_TO_CVSS = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
}


class NucleiScannerProvider:
    backend_name = "nuclei"

    def __init__(self, settings) -> None:
        self.settings = settings

    @classmethod
    def is_available(cls, settings) -> bool:
        return shutil.which(settings.nuclei_path) is not None

    def schedule(self, target: str, asset_type: str) -> ScheduledScan:
        findings = self._run_nuclei(target, asset_type)
        report = build_assessment_report(target, findings)
        return ScheduledScan(
            status="completed",
            backend=self.backend_name,
            message="Nuclei scan completed successfully.",
            report=report,
        )

    def refresh(self, target: str, asset_type: str) -> RefreshedScan:
        findings = self._run_nuclei(target, asset_type)
        report = build_assessment_report(target, findings)
        return RefreshedScan(
            status="completed",
            message="Nuclei report refreshed.",
            report=report,
        )

    def _run_nuclei(self, target: str, asset_type: str) -> list[Finding]:
        if not self.is_available(self.settings):
            raise RuntimeError(
                "Nuclei CLI is not installed or not on PATH. "
                "Install Nuclei and set NUCLEI_PATH if needed."
            )

        output_dir = self.settings.base_dir / "data" / "nuclei"
        output_dir.mkdir(parents=True, exist_ok=True)
        appdata_dir = output_dir / "appdata"
        localappdata_dir = output_dir / "localappdata"
        appdata_dir.mkdir(parents=True, exist_ok=True)
        localappdata_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"nuclei-{uuid4().hex}.jsonl"
        error_path = output_dir / f"nuclei-{uuid4().hex}.stderr.log"

        command = [
            self.settings.nuclei_path,
            "-target",
            target,
            "-silent",
            "-no-color",
            "-or",
            "-jsonl-export",
            str(output_path),
            "-severity",
            self.settings.nuclei_severity,
            "-rate-limit",
            str(self.settings.nuclei_rate_limit),
            "-concurrency",
            str(self.settings.nuclei_concurrency),
            "-bulk-size",
            str(self.settings.nuclei_bulk_size),
        ]

        template_paths = [
            value.strip()
            for value in self.settings.nuclei_template_paths.split(",")
            if value.strip()
        ]
        if template_paths:
            command.append("-duc")
        for template_path in template_paths:
            command.extend(["-t", template_path])

        protocol_types = self._protocol_types(asset_type)
        if protocol_types:
            command.extend(["-type", protocol_types])
        if self.settings.nuclei_headless and asset_type == "website":
            command.append("-headless")

        run_env = dict(os.environ)
        run_env["APPDATA"] = str(appdata_dir)
        run_env["LOCALAPPDATA"] = str(localappdata_dir)
        run_env["USERPROFILE"] = str(self.settings.base_dir)
        run_env["HOME"] = str(self.settings.base_dir)

        with error_path.open("w", encoding="utf-8") as error_file:
            completed = subprocess.run(
                command,
                cwd=self.settings.base_dir,
                env=run_env,
                stdout=subprocess.PIPE,
                stderr=error_file,
                text=True,
                timeout=self.settings.nuclei_timeout_minutes * 60,
                check=False,
            )

        if completed.returncode not in {0, 1}:
            stderr = error_path.read_text(encoding="utf-8", errors="ignore").strip()
            raise RuntimeError(
                "Nuclei scan failed. "
                f"Exit code: {completed.returncode}. {stderr or 'See nuclei stderr log.'}"
            )

        findings = self._parse_output(output_path, target)
        return findings

    @staticmethod
    def _protocol_types(asset_type: str) -> str:
        if asset_type == "website":
            return "http,ssl,dns"
        return "http,tcp,ssl,dns"

    def _parse_output(self, output_path: Path, target: str) -> list[Finding]:
        if not output_path.exists():
            return []

        findings: list[Finding] = []
        with output_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue

                info = item.get("info", {})
                classification = info.get("classification", {}) or {}
                severity = str(info.get("severity", "info")).lower()
                severity = severity if severity in SEVERITY_TO_CVSS else "info"
                cvss = self._extract_cvss(classification, severity)
                template_id = item.get("template-id") or item.get("templateID") or "nuclei-template"
                references = info.get("reference") or []
                if isinstance(references, str):
                    references = [references]
                tags = info.get("tags") or []
                if isinstance(tags, str):
                    tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
                cve_value = classification.get("cve-id") or classification.get("cve") or []
                if isinstance(cve_value, list):
                    cve = cve_value[0] if cve_value else None
                else:
                    cve = cve_value

                matched = item.get("matched-at") or item.get("matched") or item.get("host") or target
                port = item.get("port")
                if port is not None:
                    port = str(port)
                protocol_type = item.get("type") or (tags[0] if tags else None)
                description = info.get("description") or (
                    f"Nuclei matched template {template_id} against {matched}."
                )
                remediation = (
                    "Review the matched template guidance, validate exposure, and apply the vendor or "
                    "configuration remediation. "
                    + (f"References: {', '.join(references[:2])}" if references else "References were not provided.")
                )

                findings.append(
                    Finding(
                        title=info.get("name") or template_id,
                        severity=severity,
                        cvss=cvss,
                        category=", ".join(tags[:3]) if tags else "Web Vulnerability",
                        host=item.get("host") or target,
                        port=port,
                        service=protocol_type,
                        cve=cve,
                        description=description,
                        remediation=remediation,
                        evidence=self._build_evidence(item),
                    )
                )

        return findings

    @staticmethod
    def _extract_cvss(classification: dict, severity: str) -> float:
        candidates = [
            classification.get("cvss-score"),
            classification.get("cvss_score"),
            classification.get("cvss"),
        ]
        for candidate in candidates:
            try:
                if candidate is not None:
                    return round(float(candidate), 1)
            except (TypeError, ValueError):
                continue
        return SEVERITY_TO_CVSS[severity]

    @staticmethod
    def _build_evidence(item: dict) -> str | None:
        matcher = item.get("matcher-name")
        extracted = item.get("extracted-results") or item.get("extracted_results") or []
        if isinstance(extracted, list):
            extracted = ", ".join(str(value) for value in extracted[:3])
        template = item.get("template-id") or item.get("template")
        parts = [part for part in [f"Template: {template}" if template else None, f"Matcher: {matcher}" if matcher else None, f"Extracted: {extracted}" if extracted else None] if part]
        return " | ".join(parts) if parts else None
