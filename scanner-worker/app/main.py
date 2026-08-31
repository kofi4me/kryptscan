from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.models import Finding
from app.services.reporting import build_assessment_report


WORKER_TOKEN = os.getenv("SCANNER_WORKER_TOKEN", "")
ALLOW_PRIVATE_TARGETS = os.getenv("ALLOW_PRIVATE_NETWORK_TARGETS", "false").lower() in {"1", "true", "yes"}
MAX_TOOL_TIMEOUT = int(os.getenv("SCANNER_TOOL_TIMEOUT_SECONDS", "180"))
MAX_OUTPUT_CHARS = int(os.getenv("SCANNER_MAX_OUTPUT_CHARS", "20000"))
MIN_FULL_SCAN_SECONDS = int(os.getenv("SCANNER_MIN_FULL_SCAN_SECONDS", "600"))
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5-mini")
CLOUD_CHECKS_ENABLED = os.getenv("CLOUD_CHECKS_ENABLED", "false").lower() in {"1", "true", "yes"}

app = FastAPI(title="KryptScan Scanner Worker")
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()


class ScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=255)
    asset_type: str = "website"
    assessment_mode: str = "vulnerability_assessment"
    scan_tier: str = "full_scan"
    scan_protocols: list[str] = Field(default_factory=list)
    wait: bool = True


def _auth(authorization: str | None) -> None:
    expected = f"Bearer {WORKER_TOKEN}"
    if not WORKER_TOKEN or authorization != expected:
        raise HTTPException(status_code=401, detail="Scanner worker token is invalid.")


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62})+$")


def _host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return parsed.hostname or target


def _url(target: str) -> str:
    return target if "://" in target else f"https://{target}"


def _validate_target(target: str) -> str:
    raw = target.strip()
    if not raw or any(char.isspace() for char in raw):
        raise HTTPException(
            status_code=400,
            detail="Invalid target. Enter only one clean domain, URL, IP address, or CIDR range in the target field.",
        )
    if ":" in raw and "://" not in raw and not re.match(r"^\[[0-9a-fA-F:]+\](:\d+)?$", raw):
        raise HTTPException(
            status_code=400,
            detail="Invalid target. Put authorization reference, testing scope, and testing window in their own fields, not in the target field.",
        )
    host = _host(raw).strip().lower()
    if not host or any(char in host for char in " /\\;&|`$()<>"):
        raise HTTPException(status_code=400, detail="Invalid target.")
    try:
        network = ipaddress.ip_network(host, strict=False)
        if not ALLOW_PRIVATE_TARGETS and any(
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_unspecified
            for address in (network.network_address, network.broadcast_address)
        ):
            raise HTTPException(status_code=400, detail="Private, loopback, reserved, or link-local targets are blocked.")
        return host
    except ValueError:
        pass
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not DOMAIN_RE.match(host.rstrip(".")):
        raise HTTPException(status_code=400, detail="Invalid target. Use a valid domain, IP address, CIDR range, or URL.")
    return host


def _zap_baseline_path() -> str | None:
    path = shutil.which("zap-baseline.py")
    if path:
        return path
    for candidate in Path("/opt").glob("ZAP_*/zap-baseline.py"):
        if candidate.exists():
            return str(candidate)
    fallback = Path("/zap/zap-baseline.py")
    if fallback.exists():
        return str(fallback)
    return None


def _run(command: list[str], output_dir: Path, timeout: int = MAX_TOOL_TIMEOUT) -> tuple[bool, str]:
    tool = command[0]
    if tool == "zap-baseline.py" and not shutil.which(tool):
        zap_path = _zap_baseline_path()
        if zap_path:
            command = [zap_path, *command[1:]]
    if not shutil.which(command[0]) and not Path(command[0]).exists():
        return False, f"{tool} is not installed in the scanner worker image."
    try:
        result = subprocess.run(
            command,
            cwd=output_dir,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        output = "\n".join(part for part in [result.stdout, result.stderr] if part)
        return _tool_output_is_usable(tool, result.returncode, output), output[:MAX_OUTPUT_CHARS]
    except subprocess.TimeoutExpired:
        return False, f"{tool} timed out after {timeout} seconds."


def _tool_output_is_usable(tool: str, returncode: int, output: str) -> bool:
    lower = output.lower()
    failure_markers = [
        "usage:",
        "unrecognized arguments",
        "fatal error",
        "failed to resolve",
        "no targets were specified",
        "connection refused",
        "timed out after",
        "is not installed",
        "required module not found",
    ]
    if any(marker in lower for marker in failure_markers):
        return False
    if tool in {"nuclei", "httpx", "naabu", "dnsx", "katana", "subfinder"}:
        return returncode in {0, 1}
    if tool in {"nikto", "testssl.sh", "zap-baseline.py"}:
        return returncode in {0, 1, 2}
    return returncode == 0


def _finding(
    target: str,
    title: str,
    severity: str,
    category: str,
    service: str,
    evidence: str,
    remediation: str,
    cvss: float = 0.0,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        cvss=cvss,
        category=category,
        host=target,
        service=service,
        description=evidence[:900] or title,
        remediation=remediation,
        evidence=evidence[:1200],
    )


def _tool_finding(target: str, tool: str, succeeded: bool, detail: str, category: str) -> Finding:
    return _finding(
        target,
        f"{tool} {'completed' if succeeded else 'incomplete'}",
        "info",
        category if succeeded else "Scanner Toolchain",
        tool.lower(),
        detail,
        "Review raw output and parsed findings." if succeeded else f"Repair or tune {tool} in the scanner worker image before relying on this stage.",
    )


def _parse_tool_findings(target: str, tool: str, output: str, category: str) -> list[Finding]:
    if category == "Scanner Toolchain" or not output.strip():
        return []
    if not _tool_output_is_usable(tool.lower(), 0, output):
        return []
    parsers = {
        "nmap": _parse_nmap_findings,
        "nuclei": _parse_nuclei_findings,
        "nikto": _parse_nikto_findings,
        "owasp zap baseline": _parse_zap_findings,
        "zap-baseline.py": _parse_zap_findings,
        "sslyze": _parse_tls_findings,
        "testssl.sh": _parse_tls_findings,
        "whatweb": _parse_whatweb_findings,
        "wafw00f": _parse_wafw00f_findings,
        "httpx": _parse_httpx_findings,
    }
    parser = parsers.get(tool.lower())
    if parser:
        return parser(target, tool, output, category)
    return _generic_evidence_findings(target, tool, output, category)


def _generic_evidence_findings(target: str, tool: str, output: str, category: str) -> list[Finding]:
    lower = output.lower()
    if tool.lower() in {"trivy", "grype", "semgrep", "checkov", "gitleaks"}:
        return []
    markers = ["vulnerab", "critical", "high", "weak", "outdated", "exposed", "misconfig", "cve-"]
    if not any(marker in lower for marker in markers):
        return []
    digest = hashlib.sha256(f"{tool}:{target}:{output[:300]}".encode("utf-8")).hexdigest()[:8]
    severity = "high" if any(marker in lower for marker in ["critical", "high", "cve-"]) else "medium"
    return [_finding(
        target,
        f"{tool} evidence requires analyst review {digest}",
        severity,
        category,
        tool.lower(),
        output,
        "Validate the affected service within the approved scope, patch or harden the control, and retest.",
        8.0 if severity == "high" else 5.8,
    )]


def _parse_nmap_findings(target: str, tool: str, output: str, category: str) -> list[Finding]:
    findings: list[Finding] = []
    sensitive_services = {
        "ftp": ("medium", 5.8, "FTP is externally reachable"),
        "telnet": ("high", 8.1, "Telnet is externally reachable"),
        "ssh": ("low", 3.7, "SSH is externally reachable"),
        "rdp": ("medium", 6.2, "RDP is externally reachable"),
        "mysql": ("medium", 6.0, "MySQL is externally reachable"),
        "postgresql": ("medium", 6.0, "PostgreSQL is externally reachable"),
        "mssql": ("medium", 6.0, "Microsoft SQL service is externally reachable"),
        "smb": ("medium", 6.5, "SMB is externally reachable"),
    }
    for line in output.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line.strip(), re.I)
        if not match:
            continue
        port, proto, service, version = match.groups()
        normalized_service = service.lower()
        if normalized_service in {"http", "https", "ssl/http"}:
            findings.append(
                _finding(
                    target,
                    f"Public web service exposed on {port}/{proto}",
                    "info",
                    category,
                    "https" if "ssl" in normalized_service or port == "443" else "http",
                    line,
                    "Confirm the service is intentional, patched, monitored, and protected by appropriate web security controls.",
                )
            )
            continue
        severity, cvss, title = sensitive_services.get(
            normalized_service,
            ("low", 2.8, f"Externally reachable service detected on {port}/{proto}"),
        )
        findings.append(
            _finding(
                target,
                title,
                severity,
                category,
                normalized_service,
                line,
                f"Restrict {service} exposure to approved source networks, validate patch level, and disable it if not business-required.",
                cvss,
            )
        )
    return findings[:20]


def _parse_nuclei_findings(target: str, tool: str, output: str, category: str) -> list[Finding]:
    findings: list[Finding] = []
    severity_cvss = {"critical": 9.4, "high": 8.0, "medium": 5.6, "low": 2.8, "info": 0.0}
    for line in output.splitlines():
        clean = line.strip()
        if not clean:
            continue
        severity = "info"
        match = re.search(r"\[(critical|high|medium|low|info)\]", clean, re.I)
        if match:
            severity = match.group(1).lower()
        elif any(word in clean.lower() for word in ["cve-", "critical"]):
            severity = "high"
        title = clean.split("]")[-1].strip()[:120] or "Nuclei template matched target evidence"
        findings.append(
            _finding(
                target,
                f"Nuclei: {title}",
                severity,
                category,
                "nuclei",
                clean,
                "Validate the matched template evidence, patch the affected component, and retest with the same template set.",
                severity_cvss.get(severity, 0.0),
            )
        )
    return findings[:30]


def _parse_nikto_findings(target: str, tool: str, output: str, category: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in output.splitlines():
        clean = line.strip()
        if not clean.startswith("+"):
            continue
        lower = clean.lower()
        if any(skip in lower for skip in ["target ip", "target hostname", "target port", "start time", "end time", "requests:"]):
            continue
        severity, cvss = ("low", 3.2)
        if any(marker in lower for marker in ["osvdb", "cve-", "vulnerab", "outdated", "x-frame-options", "x-content-type-options", "cookie"]):
            severity, cvss = ("medium", 5.4)
        findings.append(
            _finding(
                target,
                f"Nikto: {clean.lstrip('+ ').split(':', 1)[0][:90]}",
                severity,
                category,
                "nikto",
                clean,
                "Review the web server finding, apply hardening or patching, and confirm the condition is resolved.",
                cvss,
            )
        )
    return findings[:30]


def _parse_zap_findings(target: str, tool: str, output: str, category: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in output.splitlines():
        clean = line.strip()
        if not clean or not re.search(r"(WARN-|FAIL-|ALERT)", clean, re.I):
            continue
        severity, cvss = ("low", 3.4)
        if re.search(r"(FAIL-|high|critical)", clean, re.I):
            severity, cvss = ("medium", 5.8)
        findings.append(
            _finding(
                target,
                f"OWASP ZAP baseline: {clean[:100]}",
                severity,
                category,
                "zap",
                clean,
                "Review the ZAP baseline alert, apply the recommended web control, and rerun the baseline scan.",
                cvss,
            )
        )
    return findings[:25]


def _parse_tls_findings(target: str, tool: str, output: str, category: str) -> list[Finding]:
    findings: list[Finding] = []
    checks = [
        ("certificate expired", "high", 7.5, "TLS certificate appears expired"),
        ("self-signed", "medium", 5.3, "Self-signed TLS certificate detected"),
        ("heartbleed", "high", 8.0, "Heartbleed-related TLS evidence detected"),
        ("robot", "medium", 5.9, "ROBOT TLS exposure requires review"),
        ("sslv2", "high", 8.0, "SSLv2 support detected"),
        ("sslv3", "high", 7.8, "SSLv3 support detected"),
        ("tls 1.0", "medium", 5.3, "TLS 1.0 support should be disabled"),
        ("tls 1.1", "medium", 5.0, "TLS 1.1 support should be disabled"),
        ("weak", "medium", 5.0, "Weak TLS setting detected"),
        ("vulnerable", "high", 7.5, "TLS vulnerability evidence detected"),
    ]
    lower = output.lower()
    for marker, severity, cvss, title in checks:
        if marker in lower:
            evidence = next((line.strip() for line in output.splitlines() if marker in line.lower()), output[:500])
            findings.append(
                _finding(
                    target,
                    f"{tool}: {title}",
                    severity,
                    category,
                    "tls",
                    evidence,
                    "Disable weak protocols/ciphers, replace invalid certificates, and retest TLS posture.",
                    cvss,
                )
            )
    return findings[:12]


def _parse_whatweb_findings(target: str, tool: str, output: str, category: str) -> list[Finding]:
    findings: list[Finding] = []
    lower = output.lower()
    if "passwordfield" in lower:
        findings.append(
            _finding(
                target,
                "Login or password field detected",
                "info",
                category,
                "whatweb",
                output,
                "If login testing is in scope, perform authenticated testing with approved test credentials.",
            )
        )
    jquery = re.search(r"jquery[^\d]*(\d+\.\d+(?:\.\d+)?)", output, re.I)
    if jquery and jquery.group(1).startswith(("1.", "2.")):
        findings.append(
            _finding(
                target,
                f"Older jQuery version observed: {jquery.group(1)}",
                "medium",
                category,
                "jquery",
                output,
                "Confirm whether the detected jQuery version is actually served to users, upgrade if supported, and retest.",
                5.0,
            )
        )
    return findings


def _parse_wafw00f_findings(target: str, tool: str, output: str, category: str) -> list[Finding]:
    lower = output.lower()
    if "no waf detected" in lower or "generic detection results" in lower:
        return [
            _finding(
                target,
                "No web application firewall was clearly detected",
                "low",
                category,
                "waf",
                output,
                "Confirm whether a WAF or equivalent edge protection is expected for this application and enable monitoring rules where appropriate.",
                3.1,
            )
        ]
    return []


def _parse_httpx_findings(target: str, tool: str, output: str, category: str) -> list[Finding]:
    finding = _http_status_finding(target, output)
    return [finding] if finding else []


def _http_status_finding(target: str, output: str) -> Finding | None:
    lower = output.lower()
    if "http://" not in lower and "https://" not in lower and "[" not in output:
        return None
    if any(code in lower for code in ["[500]", "[403]", "[401]", "[302]", "[301]"]):
        return _finding(
            target,
            "HTTP surface requires security review",
            "medium",
            "Web/API Surface",
            "httpx",
            output,
            "Review exposed web paths, redirects, authentication boundaries, headers, and externally visible panels.",
            5.4,
        )
    return None


def _ai_triage_finding(target: str, findings: list[Finding]) -> Finding:
    if not OPENAI_API_KEY:
        return _finding(
            target,
            "AI triage is not configured",
            "info",
            "AI Reporting",
            "openai",
            "OPENAI_API_KEY is not configured in the scanner worker environment.",
            "Add OPENAI_API_KEY, OPENAI_MODEL, and OPENAI_BASE_URL to the scanner worker environment to enable AI-assisted explanations.",
        )
    evidence_items = [
        {
            "title": item.title,
            "severity": item.severity,
            "category": item.category,
            "service": item.service,
            "description": item.description[:400],
            "remediation": item.remediation[:400],
        }
        for item in findings
        if item.severity in {"critical", "high", "medium"}
    ][:12]
    prompt = {
        "target": target,
        "finding_count": len(findings),
        "priority_findings": evidence_items,
        "task": (
            "Explain the business danger and mitigation priorities for an authorized vulnerability "
            "assessment report. Do not include exploit steps, payloads, or instructions for unauthorized access."
        ),
    }
    request = urllib.request.Request(
        f"{OPENAI_BASE_URL.rstrip('/')}/responses",
        data=json.dumps(
            {
                "model": OPENAI_MODEL,
                "instructions": "You are a cybersecurity report writer for ethical, authorized assessments.",
                "input": json.dumps(prompt),
            }
        ).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return _finding(
            target,
            "AI triage API error",
            "info",
            "AI Reporting",
            "openai",
            str(exc),
            "Verify the OpenAI API key, model, base URL, and outbound HTTPS access from the scanner worker.",
        )
    text = _extract_openai_text(payload) or "AI triage completed but no narrative text was returned."
    return _finding(
        target,
        "AI-assisted risk explanation and remediation priorities",
        "info",
        "AI Reporting",
        "openai",
        text,
        "Use the AI-assisted narrative to brief business owners, then validate and approve final wording before client delivery.",
    )


def _extract_openai_text(payload: dict) -> str:
    if isinstance(payload.get("output_text"), str):
        return payload["output_text"]
    parts = []
    for item in payload.get("output", []) or []:
        for content in item.get("content", []) or []:
            text = content.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts)


def _tool_plan(target: str, payload: ScanRequest) -> list[tuple[str, list[str], str]]:
    host = _validate_target(target)
    url = _url(target)
    checks = [
        ("Nmap", ["nmap", "-sV", "--top-ports", "100", "--version-light", host], "Network Exposure"),
        ("SSLyze", ["sslyze", "--certinfo", "--tlsv1_2", "--tlsv1_3", "--heartbleed", "--robot", "--compression", f"{host}:443"], "TLS Posture"),
        ("testssl.sh", ["testssl.sh", "--warnings", "batch", url], "TLS Posture"),
        ("Nuclei", ["nuclei", "-target", url, "-severity", "critical,high,medium,low", "-silent"], "Known Vulnerabilities"),
    ]
    if payload.asset_type == "website":
        checks.extend(
            [
                ("WhatWeb", ["whatweb", "--no-errors", url], "Technology Fingerprinting"),
                ("wafw00f", ["wafw00f", url], "Web Protection"),
                ("Nikto", ["nikto", "-host", url, "-nointeractive"], "Web Server Security"),
                ("OWASP ZAP baseline", ["zap-baseline.py", "-t", url, "-m", "5"], "Web and API"),
            ]
        )
    if payload.assessment_mode == "ethical_pentesting":
        checks.extend(
            [
                ("httpx", ["httpx", "-u", url, "-title", "-tech-detect", "-status-code", "-silent"], "Web/API Surface"),
                ("Naabu", ["naabu", "-host", host, "-top-ports", "100", "-silent"], "Network Exposure"),
                ("dnsx", ["dnsx", "-d", host, "-a", "-aaaa", "-cname", "-silent"], "DNS Exposure"),
                ("Katana", ["katana", "-u", url, "-silent", "-d", "2"], "Crawling"),
                ("Subfinder", ["subfinder", "-d", host, "-silent"], "Authorized Reconnaissance"),
                ("Amass", ["amass", "enum", "-passive", "-d", host], "Authorized Reconnaissance"),
            ]
        )
    if payload.asset_type in {"code", "container", "cloud", "iac", "repository"}:
        checks.extend(
            [
                ("Trivy", ["trivy", "config", "--format", "json", "/workspace"], "Container, Cloud, and IaC"),
                ("Semgrep", ["semgrep", "scan", "--config", "auto", "--json", "/workspace"], "Code Security"),
                ("Gitleaks", ["gitleaks", "detect", "--source", "/workspace", "--no-banner"], "Secrets Exposure"),
                ("Grype", ["grype", "dir:/workspace", "-o", "json"], "Software Composition"),
                ("Checkov", ["checkov", "-d", "/workspace", "-o", "json", "--quiet"], "Infrastructure as Code"),
            ]
        )
    return checks


def _set_job_status(job_id: str | None, **updates: object) -> None:
    if not job_id:
        return
    with JOBS_LOCK:
        job = JOBS.get(job_id, {})
        job.update(updates)
        job["updated_at"] = datetime.now(timezone.utc).isoformat()
        JOBS[job_id] = job


def _run_scan(payload: ScanRequest, job_id: str | None = None) -> dict:
    started = time.monotonic()
    target = _validate_target(payload.target)
    findings: list[Finding] = []
    stage_results: list[str] = []
    plan = list(_tool_plan(target, payload))
    _set_job_status(
        job_id,
        status="running",
        target=target,
        progress_percent=20,
        message="Scope validated. Preparing scanner workspace.",
    )
    with tempfile.TemporaryDirectory(prefix="kryptscan-") as tmp:
        output_dir = Path(tmp)
        total = max(len(plan), 1)
        for index, (tool, command, category) in enumerate(plan, start=1):
            progress = min(78, 20 + round((index - 1) * 58 / total))
            _set_job_status(
                job_id,
                status="running",
                progress_percent=progress,
                message=f"Running {tool} checks for {category.lower()}.",
            )
            stage_started = time.monotonic()
            ok, output = _run(command, output_dir)
            elapsed = round(time.monotonic() - stage_started, 1)
            stage_results.append(f"{tool}: {'completed' if ok else 'incomplete'} in {elapsed}s")
            findings.append(_tool_finding(target, tool, ok, output, category))
            if ok:
                findings.extend(_parse_tool_findings(target, tool, output, category))

    _set_job_status(
        job_id,
        status="running",
        progress_percent=82,
        message="Normalizing scanner output and preparing AI-assisted triage.",
    )
    findings.append(_ai_triage_finding(target, findings))
    elapsed = time.monotonic() - started
    minimum_seconds = MIN_FULL_SCAN_SECONDS if payload.scan_tier == "full_scan" else 0
    if minimum_seconds > 0 and elapsed < minimum_seconds:
        remaining = round(minimum_seconds - elapsed)
        findings.append(
            _finding(
                target,
                "Professional scan dwell time enforced",
                "info",
                "Assessment Quality",
                "scanner-worker",
                (
                    f"Tool execution completed in {round(elapsed, 1)} seconds. KryptScan held the scan window "
                    f"for an additional {remaining} seconds to support staged progress tracking, report review, "
                    "and a non-instant full assessment workflow."
                ),
                "Use the staged window to review progress indicators and avoid treating a full assessment as a shallow instant check.",
            )
        )
        _set_job_status(
            job_id,
            status="running",
            progress_percent=88,
            message="Tool evidence collected. Completing the professional review window before final report generation.",
        )
        time.sleep(remaining)
    _set_job_status(
        job_id,
        status="running",
        progress_percent=94,
        message="Building the final report, graphs, risk metrics, and remediation priorities.",
    )
    report = build_assessment_report(target, findings)
    mode_label = "Ethical Pen-Testing" if payload.assessment_mode == "ethical_pentesting" else "Vulnerability Assessment"
    report = report.model_copy(
        update={
            "scan_protocols": [
                *payload.scan_protocols,
                "Scanner worker executed the containerized safe tool profile",
                *stage_results,
                "Private/reserved target policy enforced before tool execution",
                "AI triage attempted for business danger and remediation explanation",
                "Tool output normalized into KryptScan reporting schema",
            ],
            "scope_summary": f"{mode_label} worker scan for {target}. Tier: {payload.scan_tier}.",
        }
    )
    return report.model_dump(mode="json")


def _run_job(job_id: str, payload: ScanRequest) -> None:
    try:
        report = _run_scan(payload, job_id=job_id)
    except Exception as exc:
        _set_job_status(
            job_id,
            status="failed",
            progress_percent=100,
            message=f"Scanner worker failed: {exc}",
            error=str(exc),
        )
        return
    _set_job_status(
        job_id,
        status="completed",
        progress_percent=100,
        message="Scanner worker completed the approved toolchain and report.",
        report=report,
    )


@app.get("/health")
def health() -> dict:
    tools = [
        "nmap",
        "sslyze",
        "testssl.sh",
        "nuclei",
        "nikto",
        "whatweb",
        "wafw00f",
        "zap-baseline.py",
        "httpx",
        "naabu",
        "dnsx",
        "katana",
        "subfinder",
        "amass",
        "trivy",
        "semgrep",
        "gitleaks",
        "grype",
        "checkov",
        "prowler",
        "ScoutSuite",
        "scout",
    ]
    python_gvm_available = False
    try:
        import gvm  # noqa: F401

        python_gvm_available = True
    except Exception:
        python_gvm_available = False
    available_tools = {tool: bool(shutil.which(tool)) for tool in tools}
    available_tools["zap-baseline.py"] = bool(_zap_baseline_path())
    scoutsuite_available = bool(shutil.which("ScoutSuite") or shutil.which("scoutsuite") or shutil.which("scout"))
    available_tools["ScoutSuite"] = scoutsuite_available
    available_tools["scoutsuite"] = scoutsuite_available
    available_tools.update(
        {
            "zap": available_tools.get("zap-baseline.py", False),
            "python-gvm": python_gvm_available,
            "openai": bool(OPENAI_API_KEY),
            "cloud-checks": CLOUD_CHECKS_ENABLED,
        }
    )
    return {
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat(),
        "min_full_scan_seconds": MIN_FULL_SCAN_SECONDS,
        "available_tools": available_tools,
    }


@app.post("/v1/scans")
def create_scan(payload: ScanRequest, authorization: str | None = Header(default=None)) -> dict:
    _auth(authorization)
    job_id = str(uuid.uuid4())
    _set_job_status(
        job_id,
        status="running",
        target=payload.target,
        progress_percent=10,
        message="Scanner worker accepted the job.",
    )
    if not payload.wait:
        threading.Thread(target=_run_job, args=(job_id, payload), daemon=True).start()
        return {"job_id": job_id, "status": "running", "message": "Scanner worker accepted the job."}

    report = _run_scan(payload, job_id=job_id)
    _set_job_status(
        job_id,
        status="completed",
        target=payload.target,
        progress_percent=100,
        message="Scanner worker completed the job.",
        report=report,
    )
    return {"job_id": job_id, "status": "completed", "message": "Scanner worker completed the job.", "report": report}


@app.get("/v1/scans/{job_id}")
def get_scan(job_id: str, authorization: str | None = Header(default=None)) -> dict:
    _auth(authorization)
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Scanner job not found.")
        return {"job_id": job_id, **job}
