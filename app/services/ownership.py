from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62})+$")


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _extract_host(target: str) -> str:
    candidate = target.strip().lower()
    if not candidate or any(char.isspace() for char in candidate):
        raise ValueError("Enter only one clean domain, URL, IP address, or CIDR range in the target field.")
    if ":" in candidate and "://" not in candidate and not candidate.startswith("["):
        raise ValueError(
            "Put authorization reference, testing scope, testing window, and emergency contact in their own fields, not in the target field."
        )
    if "://" in candidate:
        parsed = urlparse(candidate)
        if not parsed.hostname:
            raise ValueError("Unable to extract a hostname from that target.")
        candidate = parsed.hostname.lower()
    else:
        candidate = candidate.split("/", 1)[0].strip().lower()
    if any(char in candidate for char in " /\\;&|`$()<>"):
        raise ValueError("Target contains unsupported characters.")
    try:
        ipaddress.ip_network(candidate, strict=False)
        return candidate
    except ValueError:
        pass
    if not DOMAIN_RE.match(candidate.rstrip(".")):
        raise ValueError("Use a valid domain, URL, IP address, or CIDR range.")
    return candidate


def infer_asset_type(target: str) -> str:
    candidate = target.strip().lower()
    if "/" in candidate and "://" not in candidate:
        try:
            ipaddress.ip_network(candidate, strict=False)
            return "network"
        except ValueError:
            pass

    host = _extract_host(target)
    try:
        ipaddress.ip_address(host)
        return "network"
    except ValueError:
        return "website"


def normalize_assessment_mode(value: str | None) -> str:
    mode = (value or "vulnerability_assessment").strip().lower()
    if mode == "authorized_pentest":
        return "ethical_pentesting"
    if mode in {"vulnerability_assessment", "ethical_pentesting"}:
        return mode
    raise ValueError("Assessment mode must be vulnerability_assessment or ethical_pentesting.")


def build_scan_protocols(asset_type: str, target_kind: str, assessment_mode: str = "vulnerability_assessment") -> list[str]:
    assessment_mode = normalize_assessment_mode(assessment_mode)
    if assessment_mode == "ethical_pentesting":
        protocols = [
            "Verified account, completed payment, and authorized target validation",
            "Scoped reconnaissance limited to the approved target",
            "Network, service, web, API, and identity surface mapping",
            "Known vulnerability validation using non-destructive evidence",
            "Exploitability likelihood review with no persistence, brute force, or destructive payloads",
            "Manual tester notes and AI-assisted remediation drafting",
            "Client-ready ethical pen-testing report delivery",
        ]
        if asset_type == "website":
            protocols.insert(3, "OWASP-oriented web, API, authentication, and session control review")
        if target_kind in {"hostname"}:
            protocols.insert(2, "DNS-backed hostname resolution")
        return protocols

    if asset_type == "website":
        return [
            "DNS resolution and hostname validation",
            "Service and TLS fingerprinting",
            "HTTP response and header inspection",
            "Web vulnerability correlation and severity scoring",
            "Remediation prioritization and executive reporting",
        ]

    protocols = [
        "Host discovery and reachability validation",
        "Port and service fingerprinting",
        "Network vulnerability correlation and severity scoring",
        "Remediation prioritization and executive reporting",
    ]
    if target_kind in {"hostname"}:
        protocols.insert(1, "DNS-backed hostname resolution")
    return protocols


def normalize_target(target: str, asset_type: str) -> tuple[str, str]:
    raw = target.strip()
    if asset_type == "website":
        host = _extract_host(raw)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return host.rstrip("."), "hostname"
        raise ValueError("Website targets must be domain names or URLs, not bare IP addresses.")

    candidate = raw.lower()
    if "/" in candidate:
        network = ipaddress.ip_network(candidate, strict=False)
        return str(network), "cidr"

    try:
        address = ipaddress.ip_address(candidate)
        return str(address), "ip"
    except ValueError:
        host = _extract_host(raw)
        return host.rstrip("."), "hostname"


def authorize_target(
    organization_domain: str,
    target: str,
    asset_type: str,
    allow_attested_external: bool = False,
) -> dict:
    normalized_domain = normalize_domain(organization_domain)
    normalized_target, target_kind = normalize_target(target, asset_type)

    if asset_type == "website":
        if normalized_target == normalized_domain or normalized_target.endswith(
            "." + normalized_domain
        ):
            return {
                "normalized_target": normalized_target,
                "authorization_method": "verified-work-email-domain",
                "verification_note": (
                    "Website matches the verified organization domain or one of its subdomains."
                ),
                "target_kind": target_kind,
            }
        if allow_attested_external:
            return {
                "normalized_target": normalized_target,
                "authorization_method": "verified-user-target-attestation",
                "verification_note": (
                    "Website target is outside the verified email domain and was accepted "
                    "because the verified user attested they own the target or have written authorization."
                ),
                "target_kind": target_kind,
            }
        raise ValueError(
            "Website target is outside the verified ownership domain. "
            "Confirm written authorization for this target before launching the assessment."
        )

    if target_kind in {"ip", "cidr"}:
        return {
            "normalized_target": normalized_target,
            "authorization_method": "verified-work-email-domain-plus-network-attestation",
            "verification_note": (
                "Network target accepted under the verified organization domain. "
                "Production deployments should add DNS TXT proof or written authorization "
                "for IP range ownership."
            ),
            "target_kind": target_kind,
        }

    if normalized_target == normalized_domain or normalized_target.endswith(
        "." + normalized_domain
    ):
        return {
            "normalized_target": normalized_target,
            "authorization_method": "verified-work-email-domain",
            "verification_note": (
                "Hostname target matches the verified organization domain."
            ),
            "target_kind": target_kind,
        }

    if allow_attested_external:
        return {
            "normalized_target": normalized_target,
            "authorization_method": "verified-user-target-attestation",
            "verification_note": (
                "Network hostname is outside the verified email domain and was accepted "
                "because the verified user attested they own the target or have written authorization."
            ),
            "target_kind": target_kind,
        }

    raise ValueError(
        "Network hostname is outside the verified organization domain. "
        "Confirm written authorization for this target before launching the assessment."
    )
