from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
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

app = FastAPI(title="KryptScan Scanner Worker")
JOBS: dict[str, dict] = {}


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


def _host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return parsed.hostname or target


def _url(target: str) -> str:
    return target if "://" in target else f"https://{target}"


def _validate_target(target: str) -> str:
    host = _host(target).strip().lower()
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
    except ValueError:
        pass
    return host


def _run(command: list[str], output_dir: Path, timeout: int = MAX_TOOL_TIMEOUT) -> tuple[bool, str]:
    tool = command[0]
    if not shutil.which(tool):
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
        return result.returncode in {0, 1, 2}, output[:MAX_OUTPUT_CHARS]
    except subprocess.TimeoutExpired:
        return False, f"{tool} timed out after {timeout} seconds."


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


def _tool_finding(target: str, tool: str, installed: bool, detail: str, category: str) -> Finding:
    return _finding(
        target,
        f"{tool} {'completed' if installed else 'not available'}",
        "info",
        category if installed else "Scanner Toolchain",
        tool.lower(),
        detail,
        "Review raw output and parsed findings." if installed else f"Install {tool} in the scanner worker image before relying on this stage.",
    )


def _risk_indicator(target: str, tool: str, output: str, category: str) -> Finding | None:
    lower = output.lower()
    markers = ["vulnerab", "critical", "high", "weak", "outdated", "exposed", "misconfig", "cve-"]
    if not any(marker in lower for marker in markers):
        return None
    digest = hashlib.sha256(f"{tool}:{target}:{output[:300]}".encode("utf-8")).hexdigest()[:8]
    severity = "high" if any(marker in lower for marker in ["critical", "high", "cve-"]) else "medium"
    return _finding(
        target,
        f"{tool} risk indicator {digest}",
        severity,
        category,
        tool.lower(),
        output,
        "Validate the affected service within the approved scope, patch or harden the control, and retest.",
        8.0 if severity == "high" else 5.8,
    )


def _tool_plan(target: str, payload: ScanRequest) -> list[tuple[str, list[str], str]]:
    host = _validate_target(target)
    url = _url(target)
    checks = [
        ("Nmap", ["nmap", "-sV", "--top-ports", "100", "--version-light", host], "Network Exposure"),
        ("SSLyze", ["sslyze", "--regular", host], "TLS Posture"),
        ("testssl.sh", ["testssl.sh", "--warnings", "batch", url], "TLS Posture"),
        ("Nuclei", ["nuclei", "-target", url, "-severity", "critical,high,medium,low", "-silent"], "Known Vulnerabilities"),
    ]
    if payload.asset_type == "website":
        checks.extend(
            [
                ("WhatWeb", ["whatweb", "--no-errors", url], "Technology Fingerprinting"),
                ("wafw00f", ["wafw00f", url], "Web Protection"),
                ("Nikto", ["nikto", "-host", url, "-nointeractive"], "Web Server Security"),
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


def _run_scan(payload: ScanRequest) -> dict:
    target = _validate_target(payload.target)
    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="kryptscan-") as tmp:
        output_dir = Path(tmp)
        for tool, command, category in _tool_plan(target, payload):
            ok, output = _run(command, output_dir)
            findings.append(_tool_finding(target, tool, ok, output, category))
            risk = _risk_indicator(target, tool, output, category) if ok else None
            if risk is not None:
                findings.append(risk)

    report = build_assessment_report(target, findings)
    mode_label = "Ethical Pen-Testing" if payload.assessment_mode == "ethical_pentesting" else "Vulnerability Assessment"
    report = report.model_copy(
        update={
            "scan_protocols": [
                *payload.scan_protocols,
                "Scanner worker executed the containerized safe tool profile",
                "Private/reserved target policy enforced before tool execution",
                "Tool output normalized into KryptScan reporting schema",
            ],
            "scope_summary": f"{mode_label} worker scan for {target}. Tier: {payload.scan_tier}.",
        }
    )
    return report.model_dump(mode="json")


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
    ]
    return {
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat(),
        "available_tools": {tool: bool(shutil.which(tool)) for tool in tools},
    }


@app.post("/v1/scans")
def create_scan(payload: ScanRequest, authorization: str | None = Header(default=None)) -> dict:
    _auth(authorization)
    job_id = str(uuid.uuid4())
    JOBS[job_id] = {"status": "running", "target": payload.target, "progress_percent": 20}
    report = _run_scan(payload)
    JOBS[job_id] = {"status": "completed", "target": payload.target, "progress_percent": 100, "report": report}
    return {"job_id": job_id, "status": "completed", "message": "Scanner worker completed the job.", "report": report}


@app.get("/v1/scans/{job_id}")
def get_scan(job_id: str, authorization: str | None = Header(default=None)) -> dict:
    _auth(authorization)
    if job_id not in JOBS:
        raise HTTPException(status_code=404, detail="Scanner job not found.")
    return {"job_id": job_id, **JOBS[job_id]}
