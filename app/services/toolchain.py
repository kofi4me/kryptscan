from __future__ import annotations


ETHICAL_PENTEST_TOOLCHAIN = [
    {
        "category": "Web and API",
        "tools": ["Nuclei", "OWASP ZAP baseline", "Nikto", "Katana crawler", "httpx", "WhatWeb", "HTTP header and session review"],
        "purpose": "Identify OWASP-style weaknesses, exposed panels, weak headers, and risky API behavior within approved scope.",
    },
    {
        "category": "Network and Services",
        "tools": ["Greenbone/OpenVAS", "Nmap", "Naabu", "service fingerprinting", "TLS posture checks"],
        "purpose": "Map exposed services, validate known vulnerabilities, and prioritize patchable network risk.",
    },
    {
        "category": "TLS and Certificate Security",
        "tools": ["SSLyze", "testssl.sh"],
        "purpose": "Review TLS protocol support, certificate posture, cipher exposure, and common SSL/TLS weaknesses.",
    },
    {
        "category": "Authorized Reconnaissance",
        "tools": ["Amass passive enum", "Subfinder passive enum", "dnsx", "wafw00f"],
        "purpose": "Discover in-scope hostnames using passive reconnaissance before analysts approve deeper testing.",
    },
    {
        "category": "Cloud and SaaS",
        "tools": ["Trivy config", "Checkov", "Prowler readiness", "ScoutSuite readiness", "AWS/Azure/M365/GCP readiness"],
        "purpose": "Guide MSP analysts through cloud posture checks without storing client cloud secrets in the app.",
    },
    {
        "category": "Code and Supply Chain",
        "tools": ["Semgrep", "Gitleaks", "Grype", "Trivy filesystem"],
        "purpose": "Review client-provided repositories for code security issues, exposed secrets, dependency risk, and deployment misconfiguration.",
    },
    {
        "category": "Identity and Access",
        "tools": ["MFA review workflow", "password policy checklist", "privileged access review"],
        "purpose": "Capture ethical testing evidence for account security, administrative access, and business risk.",
    },
    {
        "category": "Reporting and AI",
        "tools": ["OpenAI Responses API", "AI-assisted triage", "PDF report generator", "remediation queue"],
        "purpose": "Turn technical evidence into executive summaries, prioritized fixes, and client-ready deliverables.",
    },
]


def get_ethical_pentest_toolchain() -> list[dict[str, object]]:
    return ETHICAL_PENTEST_TOOLCHAIN


ASSESSMENT_PROFILES = [
    {
        "id": "vulnerability_assessment",
        "name": "Vulnerability Assessment",
        "summary": "Automated exposure review for recurring MSP monitoring and client risk visibility.",
        "categories": ["DNS", "TLS", "web exposure", "network services", "known CVE correlation"],
        "requires_engagement": False,
    },
    {
        "id": "ethical_pentesting",
        "name": "Ethical Pen-Testing",
        "summary": "Full-stack ethical testing workflow for verified, paid, authorized targets.",
        "categories": ["web", "API", "network", "identity", "cloud", "manual evidence", "AI reporting"],
        "requires_engagement": False,
    },
]


def get_assessment_profiles() -> list[dict[str, object]]:
    return ASSESSMENT_PROFILES
