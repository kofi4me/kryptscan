from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _extract_host(target: str) -> str:
    candidate = target.strip().lower()
    if "://" in candidate:
        parsed = urlparse(candidate)
        if not parsed.hostname:
            raise ValueError("Unable to extract a hostname from that target.")
        return parsed.hostname.lower()
    return candidate.split("/", 1)[0].strip().lower()


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


def build_scan_protocols(asset_type: str, target_kind: str) -> list[str]:
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
        raise ValueError(
            "Website target is outside the verified ownership domain. "
            "Use a work email from the same domain as the site you want to assess."
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

    raise ValueError(
        "Network hostname is outside the verified organization domain."
    )
