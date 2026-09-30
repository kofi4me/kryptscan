from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from app.models import AssessmentReport, Finding


SCHEMA_VERSION = "1.0"
SCHEMA_PATH = Path(__file__).with_name("kryptscan-report-schema-v1.json")
SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"),
    re.compile(r"(?i)((?:api[_-]?key|password|passwd|token|secret|cookie|private[_-]?key)\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
)


def _redact_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]" if match.lastindex else "[REDACTED PRIVATE KEY]", redacted)
    return redacted


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _iso_z(value: str | None) -> str | None:
    parsed = _parse_time(value)
    if parsed is None:
        return value
    return parsed.isoformat().replace("+00:00", "Z")


def _split_identifiers(value: str | None) -> list[str]:
    if not value:
        return []
    return list(dict.fromkeys(part.upper() for part in re.findall(r"(?:CVE|CWE)-[A-Za-z0-9-]+", value, re.IGNORECASE)))


def _severity(value: str) -> str:
    normalized = value.strip().lower()
    return "informational" if normalized in {"info", "informational"} else normalized


def _port_protocol(value: str | None) -> tuple[int | None, str | None]:
    if not value:
        return None, None
    match = re.search(r"(?P<port>\d{1,5})(?:/(?P<protocol>tcp|udp))?", value, re.IGNORECASE)
    if not match:
        return None, None
    port = int(match.group("port"))
    return (port if port <= 65535 else None), (match.group("protocol") or None)


def _target_payload(target: str, asset_type: str, findings: list[Finding]) -> dict[str, Any]:
    resolved_ips: list[str] = []
    for finding in findings:
        try:
            resolved_ips.append(str(ipaddress.ip_address(finding.host)))
        except ValueError:
            continue
    resolved_ips = list(dict.fromkeys(resolved_ips))
    try:
        ip_value = str(ipaddress.ip_address(target))
    except ValueError:
        ip_value = None
    payload: dict[str, Any] = {
        "input": target,
        "target_type": "ip" if ip_value else "domain",
        "asset_type": asset_type,
        "domain": None if ip_value else target,
        "hostname": None if ip_value else target,
        "ip_address": ip_value,
        "resolved_ips": resolved_ips,
    }
    return payload


def _assets(target_data: dict[str, Any], findings: list[Finding]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    hosts = list(dict.fromkeys([item.host for item in findings if item.host] or [target_data["input"]]))
    assets: list[dict[str, Any]] = []
    asset_ids: dict[str, str] = {}
    for index, host in enumerate(hosts, start=1):
        asset_id = f"AST-{index:03d}"
        asset_ids[host] = asset_id
        try:
            ip_value = str(ipaddress.ip_address(host))
        except ValueError:
            ip_value = None
        assets.append(
            {
                "asset_id": asset_id,
                "hostname": None if ip_value else host,
                "ip_address": ip_value,
                "operating_system": None,
                "cloud_provider": None,
                "internet_exposed": True,
            }
        )
    return assets, asset_ids


def _services(findings: list[Finding], asset_ids: dict[str, str]) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for finding in findings:
        port, protocol = _port_protocol(finding.port)
        if port is None and not finding.service:
            continue
        key = (finding.host, port, protocol, finding.service)
        if key in seen:
            continue
        seen.add(key)
        services.append(
            {
                "asset_id": asset_ids.get(finding.host),
                "port": port,
                "protocol": protocol,
                "state": "open" if port is not None else None,
                "service": finding.service,
                "product": None,
                "version": None,
                "banner": None,
                "tls_enabled": True if finding.service in {"https", "tls", "ssl"} else None,
            }
        )
    return services


def _finding_payload(finding: Finding, index: int, asset_ids: dict[str, str], observed_at: str | None) -> dict[str, Any]:
    port, protocol = _port_protocol(finding.port)
    cves = _split_identifiers(finding.cve)
    cwes = _split_identifiers(finding.cwe)
    severity = _severity(finding.severity)
    confidence_score = max(0, min(100, finding.confidence)) / 100
    references = [
        *({"type": "CVE", "id": item} for item in cves),
        *({"type": "CWE", "id": item} for item in cwes),
    ]
    return {
        "finding_id": f"KS-F-{index:04d}",
        "title": finding.title,
        "category": finding.category,
        "description": finding.description,
        "affected_asset": {
            "asset_id": asset_ids.get(finding.host),
            "hostname": finding.host or None,
            "ip_address": finding.host if _is_ip(finding.host) else None,
            "port": port,
            "protocol": protocol,
            "service": finding.service,
            "component": None,
            "version": None,
        },
        "severity": severity,
        "cvss": {
            "version": "3.1" if finding.cvss_vector and finding.cvss_vector.startswith("CVSS:3.1") else None,
            "base_score": finding.cvss if finding.cvss > 0 else None,
            "vector": finding.cvss_vector,
        },
        "identifiers": {"cve": cves, "cwe": cwes},
        "evidence": {
            "summary": finding.evidence,
            "source": ", ".join(finding.detected_by) if finding.detected_by else "KryptScan",
            "observed_value": None,
            "expected_value": None,
        },
        "risk": {"severity": severity, "cvss_score": finding.cvss if finding.cvss > 0 else None, "internet_exposed": True},
        "impact": finding.description,
        "remediation": {
            "recommendation": finding.remediation,
            "priority": _remediation_priority(severity),
            "verification": "Rescan the affected asset after remediation and confirm the finding is no longer detected.",
        },
        "references": references,
        "confidence": {"level": _confidence_level(confidence_score), "score": confidence_score},
        "validation_status": finding.validation_status.lower(),
        "finding_type": finding.finding_type.lower(),
        "provenance": {
            "finding_source": "KryptScan",
            "evidence_type": "scanner_observation" if finding.evidence else "derived_assessment",
            "observed_at": observed_at,
        },
    }


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _confidence_level(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def _remediation_priority(severity: str) -> str:
    return {"critical": "immediate", "high": "urgent", "medium": "planned", "low": "routine", "informational": "advisory"}.get(severity, "planned")


def _duration_seconds(started_at: str | None, completed_at: str | None) -> int | None:
    started = _parse_time(started_at)
    completed = _parse_time(completed_at)
    if not started or not completed:
        return None
    return max(0, int((completed - started).total_seconds()))


def build_json_report(scan: Mapping[str, Any], report: AssessmentReport) -> dict[str, Any]:
    completed_at = _iso_z(scan.get("completed_at"))
    started_at = _iso_z(scan.get("started_at") or scan.get("created_at"))
    year = (_parse_time(scan.get("created_at")) or datetime.now(timezone.utc)).year
    public_scan_id = f"KS-{year}-{int(scan['id']):06d}"
    report_type = "penetration_test" if scan.get("assessment_mode") in {"ethical_pentesting", "authorized_pentest"} else "vulnerability_assessment"
    target_data = _target_payload(scan["normalized_target"], scan["asset_type"], report.findings)
    assets, asset_ids = _assets(target_data, report.findings)
    services = _services(report.findings, asset_ids)
    findings = [_finding_payload(item, index, asset_ids, completed_at) for index, item in enumerate(report.findings, start=1)]
    severity_counts = {
        "critical": report.severity_counts.critical,
        "high": report.severity_counts.high,
        "medium": report.severity_counts.medium,
        "low": report.severity_counts.low,
        "informational": report.severity_counts.info,
    }
    category_counts = dict(Counter(item.category for item in report.findings))
    host_counts = dict(Counter(item.host for item in report.findings if item.host))
    highest_priority = [item["finding_id"] for item in findings if item["severity"] in {"critical", "high"}][:10]
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generator": {"product": "KryptScan", "report_format": "JSON"},
        "scan_id": public_scan_id,
        "report_id": f"KSR-{year}-{int(scan['id']):06d}",
        "report_type": report_type,
        "scan": {
            "scan_id": public_scan_id,
            "scan_type": report_type,
            "status": scan.get("status") or "completed",
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_seconds": _duration_seconds(started_at, completed_at),
            "profile": scan.get("scan_tier"),
            "scope": report.scope_summary,
            "methodology": report.methodology,
            "authenticated": None,
            "configuration_profile": None,
        },
        "target": target_data,
        "executive_summary": {
            "narrative": report.executive_summary,
            "overall_risk": report.risk_band.lower(),
            "risk_score": report.risk_score,
            "total_findings": len(findings),
            **severity_counts,
        },
        "assets": assets,
        "services": services,
        "findings": findings,
        "statistics": {
            "assets_scanned": len(assets),
            "services_discovered": len(services),
            "total_findings": len(findings),
            "findings_by_severity": severity_counts,
            "findings_by_host": host_counts,
            "findings_by_category": category_counts,
        },
        "assessment_summary": {
            "overall_risk_rating": report.risk_band.lower(),
            "highest_priority_findings": highest_priority,
            "recommended_next_step": "Prioritize confirmed critical and high findings, apply remediation, and perform verification scanning.",
            "assessment_coverage": report.assessment_coverage,
            "assessment_coverage_status": report.assessment_coverage_status,
        },
        "penetration_test": {
            "validated": any(item.validation_status in {"CONFIRMED", "LIKELY"} for item in report.findings),
            "attack_stage": None,
            "attack_path": [],
            "affected_assets": list(asset_ids.values()),
            "business_impact": None,
        } if report_type == "penetration_test" else None,
        "metadata": {
            "generated_at": _iso_z(report.generated_at),
            "classification": "confidential",
            "assessment_limitations": report.limitations,
            "data_quality": "Observed fields are preserved; unavailable values are represented as null or empty arrays.",
        },
    }
    sanitized = _sanitize(payload)
    validate_json_report(sanitized)
    return sanitized


def validate_json_report(payload: dict[str, Any]) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.path))
    if errors:
        detail = "; ".join(f"{'/'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors[:5])
        raise ValueError(f"KryptScan JSON report schema validation failed: {detail}")


def write_json_report(output_path: Path, scan: Mapping[str, Any], report: AssessmentReport) -> bytes:
    payload = build_json_report(scan, report)
    report_bytes = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False).encode("utf-8")
    output_path.write_bytes(report_bytes)
    return report_bytes
