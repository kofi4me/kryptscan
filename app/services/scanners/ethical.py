from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4
from xml.etree import ElementTree

from app.models import Finding
from app.services.reporting import build_assessment_report
from app.services.scanners.base import RefreshedScan, ScheduledScan


class EthicalToolkitScannerProvider:
    backend_name = "ethical_toolkit"

    def __init__(self, settings) -> None:
        self.settings = settings

    def schedule(self, target: str, asset_type: str) -> ScheduledScan:
        findings = self._run_toolkit(target, asset_type)
        report = build_assessment_report(target, findings)
        return ScheduledScan(
            status="completed",
            backend=self.backend_name,
            message="Ethical toolkit scan completed.",
            report=report,
        )

    def refresh(self, target: str, asset_type: str) -> RefreshedScan:
        findings = self._run_toolkit(target, asset_type)
        report = build_assessment_report(target, findings)
        return RefreshedScan(
            status="completed",
            message="Ethical toolkit report refreshed.",
            report=report,
        )

    def _run_toolkit(self, target: str, asset_type: str) -> list[Finding]:
        output_dir = self.settings.base_dir / "data" / "ethical-toolkit" / uuid4().hex
        output_dir.mkdir(parents=True, exist_ok=True)
        findings: list[Finding] = []

        findings.extend(self._run_nmap(target, output_dir))
        if asset_type == "website":
            findings.extend(self._run_httpx(target, output_dir))
            findings.extend(self._run_naabu(target, output_dir))
            findings.extend(self._run_dnsx(target, output_dir))
            findings.extend(self._run_katana(target, output_dir))
            findings.extend(self._run_wafw00f(target, output_dir))
            findings.extend(self._run_whatweb(target, output_dir))
            findings.extend(self._run_sslyze(target, output_dir))
            findings.extend(self._run_testssl(target, output_dir))
            findings.extend(self._run_zap_baseline(target, output_dir))
            findings.extend(self._run_nikto(target, output_dir))
            findings.extend(self._run_recon(target, output_dir))
        findings.extend(self._run_trivy(target, output_dir))
        findings.extend(self._run_semgrep(target, output_dir))
        findings.extend(self._run_gitleaks(target, output_dir))
        findings.extend(self._run_grype(target, output_dir))
        findings.extend(self._run_checkov(target, output_dir))
        findings.extend(self._run_cloud_checks(target))
        findings.extend(self._run_ai_triage(target, findings))

        return findings or [
            self._info(
                target,
                "Ethical toolkit completed with no findings",
                "No supported tool returned a finding. Confirm tool installation and target reachability.",
                "No remediation is required from this connector result.",
                "ethical-toolkit",
            )
        ]

    def _run_httpx(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.httpx_path):
            return [self._missing(target, "ProjectDiscovery httpx", "HTTPX_PATH")]
        output_path = output_dir / "httpx.jsonl"
        result = self._run(
            [self.settings.httpx_path, "-json", "-silent", "-u", self._https_target(target), "-o", str(output_path)],
            output_dir,
            timeout=8 * 60,
        )
        if result.returncode != 0:
            return [self._tool_error(target, "ProjectDiscovery httpx", result)]
        return self._parse_httpx(target, output_path)

    def _run_naabu(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.naabu_path):
            return [self._missing(target, "Naabu", "NAABU_PATH")]
        output_path = output_dir / "naabu.jsonl"
        result = self._run(
            [
                self.settings.naabu_path,
                "-json",
                "-silent",
                "-top-ports",
                "100",
                "-rate",
                "50",
                "-host",
                self._host(target),
                "-o",
                str(output_path),
            ],
            output_dir,
            timeout=10 * 60,
        )
        if result.returncode != 0:
            return [self._tool_error(target, "Naabu", result)]
        return self._parse_jsonl_observations(target, output_path, "Naabu", "Network Exposure", "tcp", "Open port observation")

    def _run_dnsx(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.dnsx_path):
            return [self._missing(target, "dnsx", "DNSX_PATH")]
        output_path = output_dir / "dnsx.jsonl"
        result = self._run(
            [
                self.settings.dnsx_path,
                "-json",
                "-silent",
                "-a",
                "-aaaa",
                "-cname",
                "-d",
                self._host(target),
                "-o",
                str(output_path),
            ],
            output_dir,
            timeout=6 * 60,
        )
        if result.returncode != 0:
            return [self._tool_error(target, "dnsx", result)]
        return self._parse_jsonl_observations(target, output_path, "dnsx", "DNS Exposure", "dns", "DNS record observation")

    def _run_katana(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.katana_path):
            return [self._missing(target, "Katana", "KATANA_PATH")]
        output_path = output_dir / "katana.jsonl"
        result = self._run(
            [
                self.settings.katana_path,
                "-jsonl",
                "-silent",
                "-depth",
                "2",
                "-u",
                self._https_target(target),
                "-o",
                str(output_path),
            ],
            output_dir,
            timeout=10 * 60,
        )
        if result.returncode != 0:
            return [self._tool_error(target, "Katana", result)]
        return self._parse_katana(target, output_path)

    def _run_wafw00f(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.wafw00f_path):
            return [self._missing(target, "wafw00f", "WAFW00F_PATH")]
        output_path = output_dir / "wafw00f.json"
        result = self._run(
            [self.settings.wafw00f_path, "-a", "-f", "json", "-o", str(output_path), self._https_target(target)],
            output_dir,
            timeout=6 * 60,
        )
        if result.returncode != 0:
            return [self._tool_error(target, "wafw00f", result)]
        return self._parse_generic_json_tool(target, output_path, tool_name="wafw00f", service="waf", category="Web Protection")

    def _run_whatweb(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.whatweb_path):
            return [self._missing(target, "WhatWeb", "WHATWEB_PATH")]
        output_path = output_dir / "whatweb.json"
        result = self._run(
            [self.settings.whatweb_path, "--log-json", str(output_path), self._https_target(target)],
            output_dir,
            timeout=8 * 60,
        )
        if result.returncode != 0:
            return [self._tool_error(target, "WhatWeb", result)]
        return self._parse_generic_json_tool(target, output_path, tool_name="WhatWeb", service="fingerprint", category="Technology Fingerprinting")

    def _run_nmap(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.nmap_path):
            return [self._missing(target, "Nmap", "NMAP_PATH")]
        output_path = output_dir / "nmap.xml"
        result = self._run(
            [
                self.settings.nmap_path,
                "-sV",
                "--version-light",
                "-T3",
                "-oX",
                str(output_path),
                target,
            ],
            output_dir,
            timeout=12 * 60,
        )
        if result.returncode not in {0}:
            return [self._tool_error(target, "Nmap", result)]
        return self._parse_nmap(target, output_path)

    def _run_sslyze(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.sslyze_path):
            return [self._missing(target, "SSLyze", "SSLYZE_PATH")]
        output_path = output_dir / "sslyze.json"
        result = self._run(
            [self.settings.sslyze_path, "--json_out", str(output_path), self._https_target(target)],
            output_dir,
            timeout=10 * 60,
        )
        if result.returncode not in {0}:
            return [self._tool_error(target, "SSLyze", result)]
        return self._parse_generic_json_tool(
            target,
            output_path,
            tool_name="SSLyze",
            service="tls",
            category="TLS Posture",
        )

    def _run_testssl(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.testssl_path):
            return [self._missing(target, "testssl.sh", "TESTSSL_PATH")]
        output_path = output_dir / "testssl.json"
        result = self._run(
            [
                self.settings.testssl_path,
                "--warnings",
                "batch",
                "--jsonfile",
                str(output_path),
                self._https_target(target),
            ],
            output_dir,
            timeout=15 * 60,
        )
        if result.returncode not in {0}:
            return [self._tool_error(target, "testssl.sh", result)]
        return self._parse_testssl(target, output_path)

    def _run_zap_baseline(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.zap_baseline_path):
            return [self._missing(target, "OWASP ZAP baseline", "ZAP_BASELINE_PATH")]
        output_path = output_dir / "zap.json"
        result = self._run(
            [
                self.settings.zap_baseline_path,
                "-t",
                self._https_target(target),
                "-J",
                str(output_path),
                "-I",
            ],
            output_dir,
            timeout=20 * 60,
        )
        if result.returncode not in {0, 1, 2}:
            return [self._tool_error(target, "OWASP ZAP baseline", result)]
        return self._parse_zap(target, output_path)

    def _run_nikto(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.nikto_path):
            return [self._missing(target, "Nikto", "NIKTO_PATH")]
        output_path = output_dir / "nikto.json"
        result = self._run(
            [
                self.settings.nikto_path,
                "-h",
                self._https_target(target),
                "-Format",
                "json",
                "-output",
                str(output_path),
                "-nointeractive",
            ],
            output_dir,
            timeout=20 * 60,
        )
        if result.returncode not in {0, 1}:
            return [self._tool_error(target, "Nikto", result)]
        return self._parse_nikto(target, output_path)

    def _run_recon(self, target: str, output_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        domain = self._host(target)
        if self._available(self.settings.amass_path):
            output_path = output_dir / "amass.jsonl"
            result = self._run(
                [self.settings.amass_path, "enum", "-passive", "-d", domain, "-json", str(output_path)],
                output_dir,
                timeout=15 * 60,
            )
            findings.extend(self._parse_recon_jsonl(target, output_path, "Amass") if result.returncode == 0 else [self._tool_error(target, "Amass", result)])
        else:
            findings.append(self._missing(target, "Amass", "AMASS_PATH"))

        if self._available(self.settings.subfinder_path):
            output_path = output_dir / "subfinder.jsonl"
            result = self._run(
                [self.settings.subfinder_path, "-silent", "-json", "-d", domain, "-o", str(output_path)],
                output_dir,
                timeout=10 * 60,
            )
            findings.extend(self._parse_recon_jsonl(target, output_path, "Subfinder") if result.returncode == 0 else [self._tool_error(target, "Subfinder", result)])
        else:
            findings.append(self._missing(target, "Subfinder", "SUBFINDER_PATH"))
        return findings

    def _run_trivy(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.trivy_path):
            return [self._missing(target, "Trivy", "TRIVY_PATH")]
        output_path = output_dir / "trivy-config.json"
        result = self._run(
            [
                self.settings.trivy_path,
                "config",
                "--format",
                "json",
                "--output",
                str(output_path),
                str(self.settings.base_dir),
            ],
            output_dir,
            timeout=15 * 60,
        )
        if result.returncode not in {0, 1}:
            return [self._tool_error(target, "Trivy", result)]
        return self._parse_trivy(target, output_path)

    def _run_semgrep(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.semgrep_path):
            return [self._missing(target, "Semgrep", "SEMGREP_PATH")]
        output_path = output_dir / "semgrep.json"
        result = self._run(
            [
                self.settings.semgrep_path,
                "scan",
                "--config",
                "auto",
                "--json",
                "--output",
                str(output_path),
                str(self.settings.base_dir),
            ],
            output_dir,
            timeout=20 * 60,
        )
        if result.returncode not in {0, 1}:
            return [self._tool_error(target, "Semgrep", result)]
        return self._parse_semgrep(target, output_path)

    def _run_gitleaks(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.gitleaks_path):
            return [self._missing(target, "Gitleaks", "GITLEAKS_PATH")]
        output_path = output_dir / "gitleaks.json"
        result = self._run(
            [
                self.settings.gitleaks_path,
                "detect",
                "--source",
                str(self.settings.base_dir),
                "--report-format",
                "json",
                "--report-path",
                str(output_path),
                "--no-banner",
            ],
            output_dir,
            timeout=12 * 60,
        )
        if result.returncode not in {0, 1}:
            return [self._tool_error(target, "Gitleaks", result)]
        return self._parse_gitleaks(target, output_path)

    def _run_grype(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.grype_path):
            return [self._missing(target, "Grype", "GRYPE_PATH")]
        output_path = output_dir / "grype.json"
        result = self._run(
            [self.settings.grype_path, f"dir:{self.settings.base_dir}", "-o", "json"],
            output_dir,
            timeout=15 * 60,
        )
        output_path.write_text(result.stdout or "{}", encoding="utf-8")
        if result.returncode not in {0, 1}:
            return [self._tool_error(target, "Grype", result)]
        return self._parse_grype(target, output_path)

    def _run_checkov(self, target: str, output_dir: Path) -> list[Finding]:
        if not self._available(self.settings.checkov_path):
            return [self._missing(target, "Checkov", "CHECKOV_PATH")]
        output_path = output_dir / "checkov.json"
        result = self._run(
            [
                self.settings.checkov_path,
                "-d",
                str(self.settings.base_dir),
                "-o",
                "json",
                "--quiet",
            ],
            output_dir,
            timeout=20 * 60,
        )
        output_path.write_text(result.stdout or "{}", encoding="utf-8")
        if result.returncode not in {0, 1}:
            return [self._tool_error(target, "Checkov", result)]
        return self._parse_checkov(target, output_path)

    def _run_cloud_checks(self, target: str) -> list[Finding]:
        findings = []
        for tool_name, path_value, env_name in [
            ("Prowler", self.settings.prowler_path, "PROWLER_PATH"),
            ("ScoutSuite", self.settings.scoutsuite_path, "SCOUTSUITE_PATH"),
        ]:
            if not self._available(path_value):
                findings.append(self._missing(target, tool_name, env_name))

        if not self.settings.cloud_checks_enabled:
            findings.append(
                self._info(
                    target,
                    "Cloud security checks are not enabled",
                    "AWS, Azure, Microsoft 365, and Google Cloud checks require client-approved credentials and CLOUD_CHECKS_ENABLED=true.",
                    "Enable cloud checks only after written authorization and least-privilege read-only access are in place.",
                    "cloud-posture",
                    category="Cloud and SaaS",
                )
            )
            return findings
        configured = [
            name
            for name, env_name in [
                ("AWS", "AWS_PROFILE"),
                ("Azure", "AZURE_TENANT_ID"),
                ("Microsoft 365", "M365_TENANT_ID"),
                ("Google Cloud", "GOOGLE_APPLICATION_CREDENTIALS"),
            ]
            if os.getenv(env_name)
        ]
        findings.append(
            self._info(
                target,
                "Cloud posture connector ready",
                f"Configured cloud providers: {', '.join(configured) if configured else 'none detected'}.",
                "Run provider-specific read-only posture policies and import the evidence into the manual tester workspace.",
                "cloud-posture",
                category="Cloud and SaaS",
            )
        )
        return findings

    def _run_ai_triage(self, target: str, findings: list[Finding]) -> list[Finding]:
        if not self.settings.openai_api_key:
            return [
                self._info(
                    target,
                    "AI triage API is not configured",
                    "Set OPENAI_API_KEY to enable AI-assisted executive summaries and prioritization.",
                    "Configure the API key in the hosting secret manager, not in source code.",
                    "ai-triage",
                    category="AI Reporting",
                )
            ]
        prompt = {
            "target": target,
            "finding_count": len(findings),
            "top_findings": [
                {"title": item.title, "severity": item.severity, "category": item.category}
                for item in findings[:8]
            ],
        }
        try:
            body = json.dumps(
                {
                    "model": self.settings.openai_model,
                    "instructions": "Summarize authorized security findings for an MSP report. Do not provide exploit steps.",
                    "input": json.dumps(prompt),
                    "max_output_tokens": 300,
                }
            ).encode("utf-8")
            request = urllib.request.Request(
                f"{self.settings.openai_base_url.rstrip('/')}/responses",
                data=body,
                headers={
                    "Authorization": f"Bearer {self.settings.openai_api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
            text = self._extract_openai_text(payload) or "AI triage completed and returned a response."
            return [
                self._info(
                    target,
                    "AI-assisted finding prioritization",
                    text[:1200],
                    "Review the AI draft before sending client-facing reports.",
                    "ai-triage",
                    category="AI Reporting",
                )
            ]
        except Exception as exc:
            return [self._info(target, "AI triage API error", str(exc), "Review AI API configuration.", "ai-triage", category="AI Reporting")]

    def _parse_nmap(self, target: str, output_path: Path) -> list[Finding]:
        if not output_path.exists():
            return []
        root = ElementTree.parse(output_path).getroot()
        findings = []
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            service_name = service.get("name") if service is not None else "unknown"
            port_id = port.get("portid") or "unknown"
            findings.append(
                Finding(
                    title=f"Open service detected: {service_name}/{port_id}",
                    severity="info",
                    cvss=0.0,
                    category="Network Exposure",
                    host=target,
                    port=port_id,
                    service=service_name,
                    description=f"Nmap identified an open {service_name} service on port {port_id}.",
                    remediation="Confirm the service is required, patched, and restricted to approved source networks.",
                    evidence=ElementTree.tostring(port, encoding="unicode")[:1000],
                )
            )
        return findings

    def _parse_httpx(self, target: str, output_path: Path) -> list[Finding]:
        rows = self._read_jsonl(output_path)
        if not rows:
            return []
        summaries = []
        for row in rows[:10]:
            title = row.get("title") or "No page title"
            status_code = row.get("status_code") or "unknown"
            tech = ", ".join(row.get("tech", [])[:6]) if isinstance(row.get("tech"), list) else row.get("tech", "")
            summaries.append(f"{row.get('url', target)} status {status_code}, title {title}, tech {tech}".strip())
        return [
            self._info(
                target,
                "HTTP surface fingerprinted",
                "ProjectDiscovery httpx observed: " + " | ".join(summaries),
                "Review unexpected technologies, status codes, redirects, and exposed administrative panels.",
                "http",
                category="Technology Fingerprinting",
            )
        ]

    def _parse_katana(self, target: str, output_path: Path) -> list[Finding]:
        rows = self._read_jsonl(output_path)
        urls = sorted({row.get("request", {}).get("endpoint") or row.get("url") for row in rows if isinstance(row, dict)})
        urls = [url for url in urls if url]
        if not urls:
            return []
        return [
            self._info(
                target,
                "Application crawler mapped URLs",
                f"Katana discovered {len(urls)} URLs/endpoints. Examples: {', '.join(urls[:12])}.",
                "Review discovered URLs against scope and prioritize authentication, API, and sensitive workflow testing.",
                "crawler",
                category="Web and API",
            )
        ]

    @staticmethod
    def _extract_openai_text(payload: dict) -> str:
        if payload.get("output_text"):
            return str(payload["output_text"])
        chunks = []
        for item in payload.get("output", []):
            for content in item.get("content", []):
                if content.get("type") in {"output_text", "text"} and content.get("text"):
                    chunks.append(str(content["text"]))
        return "\n".join(chunks)

    def _parse_testssl(self, target: str, output_path: Path) -> list[Finding]:
        if not output_path.exists():
            return []
        try:
            payload = json.loads(output_path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return []
        rows = payload if isinstance(payload, list) else payload.get("scanResult", [])
        findings = []
        for row in rows:
            severity = "medium" if str(row.get("severity", "")).upper() in {"HIGH", "CRITICAL", "MEDIUM"} else "info"
            finding = row.get("finding") or row.get("id") or "TLS observation"
            findings.append(self._finding(target, f"testssl.sh: {finding}", severity, "TLS Posture", "tls", str(row)))
        return findings[:30]

    def _parse_zap(self, target: str, output_path: Path) -> list[Finding]:
        if not output_path.exists():
            return []
        payload = json.loads(output_path.read_text(encoding="utf-8", errors="ignore"))
        alerts = []
        for site in payload.get("site", []):
            alerts.extend(site.get("alerts", []))
        return [
            self._finding(
                target,
                f"OWASP ZAP: {alert.get('name', 'Web alert')}",
                self._risk_to_severity(alert.get("riskdesc") or alert.get("risk")),
                "Web and API",
                "http",
                alert.get("desc") or json.dumps(alert)[:1200],
                remediation=alert.get("solution") or "Review the ZAP alert and remediate the affected web control.",
            )
            for alert in alerts[:40]
        ]

    def _parse_nikto(self, target: str, output_path: Path) -> list[Finding]:
        if not output_path.exists():
            return []
        payload = json.loads(output_path.read_text(encoding="utf-8", errors="ignore"))
        vulnerabilities = []
        for host in payload.get("vulnerabilities", []):
            vulnerabilities.extend(host if isinstance(host, list) else [host])
        if not vulnerabilities and isinstance(payload.get("vulnerabilities"), list):
            vulnerabilities = payload["vulnerabilities"]
        return [
            self._finding(
                target,
                f"Nikto: {item.get('msg', item.get('id', 'Web server observation'))}",
                "medium",
                "Web Server",
                "http",
                json.dumps(item)[:1200],
                remediation="Review the Nikto observation and harden the affected web server configuration.",
            )
            for item in vulnerabilities[:40]
            if isinstance(item, dict)
        ]

    def _parse_jsonl_observations(
        self,
        target: str,
        output_path: Path,
        tool_name: str,
        category: str,
        service: str,
        label: str,
    ) -> list[Finding]:
        rows = self._read_jsonl(output_path)
        if not rows:
            return []
        examples = [json.dumps(row)[:180] for row in rows[:10]]
        return [
            self._info(
                target,
                f"{tool_name}: {label}",
                f"{tool_name} returned {len(rows)} observation(s). Examples: {' | '.join(examples)}",
                "Review observations against the approved scope and validate unexpected exposure.",
                service,
                category=category,
            )
        ]

    def _parse_recon_jsonl(self, target: str, output_path: Path, tool_name: str) -> list[Finding]:
        if not output_path.exists():
            return []
        names = []
        for line in output_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                item = json.loads(line)
                names.append(item.get("name") or item.get("host") or item.get("input"))
            except json.JSONDecodeError:
                names.append(line.strip())
        names = sorted({name for name in names if name})
        if not names:
            return []
        return [
            self._info(
                target,
                f"{tool_name} passive reconnaissance results",
                f"{tool_name} found {len(names)} in-scope hostnames. Examples: {', '.join(names[:12])}.",
                "Review discovered hostnames against the approved scope before launching deeper tests.",
                tool_name.lower(),
                category="Authorized Reconnaissance",
            )
        ]

    def _parse_trivy(self, target: str, output_path: Path) -> list[Finding]:
        if not output_path.exists():
            return []
        payload = json.loads(output_path.read_text(encoding="utf-8", errors="ignore"))
        findings = []
        for result in payload.get("Results", []):
            for item in result.get("Misconfigurations", [])[:40]:
                findings.append(
                    self._finding(
                        target,
                        f"Trivy: {item.get('Title', item.get('ID', 'Configuration issue'))}",
                        self._risk_to_severity(item.get("Severity")),
                        "Container, Cloud, and IaC",
                        "trivy",
                        item.get("Description") or json.dumps(item)[:1200],
                        remediation=item.get("Resolution") or "Review the Trivy policy result and update the affected configuration.",
                    )
                )
        return findings

    def _parse_semgrep(self, target: str, output_path: Path) -> list[Finding]:
        if not output_path.exists():
            return []
        payload = json.loads(output_path.read_text(encoding="utf-8", errors="ignore") or "{}")
        findings = []
        for item in payload.get("results", [])[:50]:
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {}) or {}
            findings.append(
                self._finding(
                    target,
                    f"Semgrep: {extra.get('message', item.get('check_id', 'Code security finding'))}",
                    self._risk_to_severity(metadata.get("impact") or extra.get("severity")),
                    "Code Security",
                    "semgrep",
                    json.dumps({"path": item.get("path"), "message": extra.get("message"), "check_id": item.get("check_id")})[:1200],
                    remediation="Review the flagged code path and apply the Semgrep rule guidance.",
                )
            )
        return findings

    def _parse_gitleaks(self, target: str, output_path: Path) -> list[Finding]:
        if not output_path.exists():
            return []
        payload = json.loads(output_path.read_text(encoding="utf-8", errors="ignore") or "[]")
        if not isinstance(payload, list):
            payload = payload.get("findings", [])
        return [
            self._finding(
                target,
                f"Gitleaks: potential secret in {item.get('File', 'repository')}",
                "high",
                "Secrets Exposure",
                "gitleaks",
                json.dumps({key: item.get(key) for key in ["RuleID", "Description", "File", "StartLine"]})[:1200],
                remediation="Rotate the exposed secret if valid, remove it from history, and add secret scanning controls.",
            )
            for item in payload[:50]
            if isinstance(item, dict)
        ]

    def _parse_grype(self, target: str, output_path: Path) -> list[Finding]:
        if not output_path.exists():
            return []
        payload = json.loads(output_path.read_text(encoding="utf-8", errors="ignore") or "{}")
        findings = []
        for match in payload.get("matches", [])[:60]:
            vulnerability = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            severity = self._risk_to_severity(vulnerability.get("severity"))
            findings.append(
                self._finding(
                    target,
                    f"Grype: {vulnerability.get('id', 'dependency vulnerability')} in {artifact.get('name', 'package')}",
                    severity,
                    "Software Composition",
                    "grype",
                    json.dumps({"package": artifact.get("name"), "version": artifact.get("version"), "vulnerability": vulnerability})[:1200],
                    remediation="Update or remove the vulnerable package based on vendor and distro guidance.",
                )
            )
        return findings

    def _parse_checkov(self, target: str, output_path: Path) -> list[Finding]:
        if not output_path.exists():
            return []
        payload = json.loads(output_path.read_text(encoding="utf-8", errors="ignore") or "{}")
        failed = []
        if isinstance(payload, dict) and isinstance(payload.get("results"), dict):
            failed = payload["results"].get("failed_checks", [])
        elif isinstance(payload, list):
            for report in payload:
                failed.extend((report.get("results") or {}).get("failed_checks", []))
        return [
            self._finding(
                target,
                f"Checkov: {item.get('check_name', item.get('check_id', 'IaC policy failure'))}",
                "medium",
                "Infrastructure as Code",
                "checkov",
                json.dumps({key: item.get(key) for key in ["check_id", "file_path", "resource", "guideline"]})[:1200],
                remediation=item.get("guideline") or "Review the failed IaC policy and update the configuration.",
            )
            for item in failed[:60]
            if isinstance(item, dict)
        ]

    def _parse_generic_json_tool(self, target: str, output_path: Path, *, tool_name: str, service: str, category: str) -> list[Finding]:
        if not output_path.exists():
            return []
        payload = output_path.read_text(encoding="utf-8", errors="ignore")
        return [
            self._info(
                target,
                f"{tool_name} completed",
                f"{tool_name} produced JSON evidence at {output_path.name}.",
                f"Review {tool_name} output for weak protocol, certificate, and cipher findings.",
                service,
                category=category,
                evidence=payload[:1200],
            )
        ]

    def _run(self, command: list[str], cwd: Path, *, timeout: int) -> subprocess.CompletedProcess:
        del cwd
        try:
            return subprocess.run(
                command,
                cwd=self.settings.base_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return subprocess.CompletedProcess(
                command,
                124,
                stdout=exc.stdout or "",
                stderr=f"Tool timed out after {timeout} seconds.",
            )

    @staticmethod
    def _available(path: str) -> bool:
        return shutil.which(path) is not None

    @staticmethod
    def _read_jsonl(output_path: Path) -> list[dict]:
        if not output_path.exists():
            return []
        rows = []
        for line in output_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                item = {"raw": line.strip()}
            if isinstance(item, dict):
                rows.append(item)
        return rows

    @staticmethod
    def _host(target: str) -> str:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        return parsed.hostname or target

    def _https_target(self, target: str) -> str:
        return target if "://" in target else f"https://{target}"

    @staticmethod
    def _risk_to_severity(value: object) -> str:
        text = str(value or "").lower()
        if "critical" in text:
            return "critical"
        if "high" in text:
            return "high"
        if "medium" in text or "warn" in text:
            return "medium"
        if "low" in text:
            return "low"
        return "info"

    def _missing(self, target: str, tool_name: str, env_name: str) -> Finding:
        return self._info(
            target,
            f"{tool_name} is not installed",
            f"{tool_name} was not found on PATH. Install it or set {env_name}.",
            f"Install {tool_name} on the scanner host before relying on this connector.",
            tool_name.lower(),
            category="Tool Readiness",
        )

    def _tool_error(self, target: str, tool_name: str, result: subprocess.CompletedProcess) -> Finding:
        return self._info(
            target,
            f"{tool_name} returned an error",
            (result.stderr or result.stdout or "No tool output was returned.")[:1200],
            f"Review {tool_name} installation, target reachability, and scanner permissions.",
            tool_name.lower(),
            category="Tool Execution",
        )

    def _finding(
        self,
        target: str,
        title: str,
        severity: str,
        category: str,
        service: str,
        description: str,
        *,
        remediation: str = "Review and remediate this issue within the approved scope.",
        evidence: str | None = None,
    ) -> Finding:
        cvss = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5, "info": 0.0}.get(severity, 0.0)
        return Finding(
            title=title,
            severity=severity,
            cvss=cvss,
            category=category,
            host=target,
            service=service,
            description=description,
            remediation=remediation,
            evidence=evidence,
        )

    def _info(
        self,
        target: str,
        title: str,
        description: str,
        remediation: str,
        service: str,
        *,
        category: str = "Tool Readiness",
        evidence: str | None = None,
    ) -> Finding:
        return self._finding(
            target,
            title,
            "info",
            category,
            service,
            description,
            remediation=remediation,
            evidence=evidence,
        )
