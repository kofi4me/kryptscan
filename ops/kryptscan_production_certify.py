from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


PROFILE_TOOLS = {
    "va-standard": [
        "nmap",
        "sslyze",
        "testssl.sh",
        "nuclei",
        "whatweb",
        "wafw00f",
        "nikto",
        "zap-baseline.py",
    ],
    "va-deep": [
        "nmap",
        "sslyze",
        "testssl.sh",
        "nuclei",
        "whatweb",
        "wafw00f",
        "nikto",
        "zap-baseline.py",
        "naabu",
        "httpx",
        "dnsx",
        "katana",
        "subfinder",
        "amass",
    ],
    "pt-automated": [
        "nmap",
        "sslyze",
        "testssl.sh",
        "nuclei",
        "whatweb",
        "wafw00f",
        "nikto",
        "zap-baseline.py",
        "naabu",
        "httpx",
        "dnsx",
        "katana",
        "subfinder",
        "amass",
        "feroxbuster",
        "ffuf",
        "gobuster",
    ],
}

TOOL_PROBES = {
    "nmap": ["nmap", "--version"],
    "sslyze": ["sslyze", "--version"],
    "testssl.sh": ["testssl.sh", "--version"],
    "nuclei": ["nuclei", "-version"],
    "whatweb": ["whatweb", "--version"],
    "wafw00f": ["wafw00f", "--version"],
    "nikto": ["nikto", "-Version"],
    "zap-baseline.py": ["zap-baseline.py", "--help"],
    "naabu": ["naabu", "-version"],
    "httpx": ["httpx", "-version"],
    "dnsx": ["dnsx", "-version"],
    "katana": ["katana", "-version"],
    "subfinder": ["subfinder", "-version"],
    "amass": ["amass", "-version"],
    "feroxbuster": ["feroxbuster", "--version"],
    "ffuf": ["ffuf", "-V"],
    "gobuster": ["gobuster", "version"],
}

INTERNAL_SERVICE_NAMES = {
    "amass",
    "dnsx",
    "feroxbuster",
    "ffuf",
    "gobuster",
    "httpx",
    "katana",
    "naabu",
    "nikto",
    "nmap",
    "nuclei",
    "openai",
    "scanner-worker",
    "sslyze",
    "subfinder",
    "testssl.sh",
    "wafw00f",
    "whatweb",
    "zap",
    "zap-baseline.py",
}

REPORT_TOOL_ALIASES = {
    "owasp zap baseline": "zap-baseline.py",
}

SOURCE_EXTENSIONS = {".css", ".html", ".js", ".json", ".png", ".py"}
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    output: str


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utcnow().isoformat()


def run_command(command: list[str], timeout: int = 30, max_output: int = 4000) -> CommandResult:
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(command=command, returncode=124, output=f"{type(exc).__name__}: {exc}")
    output = "\n".join(part.strip() for part in [result.stdout, result.stderr] if part.strip())
    return CommandResult(command=command, returncode=result.returncode, output=output[:max_output])


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def worker_token(env_file: Path) -> str:
    token = os.getenv("SCANNER_WORKER_TOKEN", "").strip()
    if token:
        return token
    return read_env_file(env_file).get("SCANNER_WORKER_TOKEN", "").strip()


def request_json(
    url: str,
    *,
    method: str = "GET",
    token: str = "",
    payload: dict | None = None,
    timeout: int = 30,
) -> dict:
    headers = {"Accept": "application/json"}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:1000]
        raise RuntimeError(f"HTTP {exc.code} from {url}: {detail}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"Unable to reach {url}: {exc}") from exc
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Non-JSON response from {url}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"Unexpected JSON response from {url}")
    return parsed


def validate_public_target(value: str) -> str:
    raw = value.strip()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Certification target must use HTTP or HTTPS.")
    if parsed.username or parsed.password:
        raise ValueError("Certification target must not contain embedded credentials.")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        raise ValueError("Certification target must include a hostname or public IP address.")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0].split("%", 1)[0])
                for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            }
        except socket.gaierror as exc:
            raise ValueError("Certification target could not be resolved.") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("Certification target must resolve only to public, globally routable addresses.")
    return raw


def add_check(
    evidence: dict,
    name: str,
    passed: bool,
    detail: str,
    *,
    required: bool = True,
    data: dict | list | str | int | float | bool | None = None,
) -> None:
    entry = {
        "name": name,
        "passed": bool(passed),
        "required": required,
        "detail": detail[:1200],
        "recorded_at": iso_now(),
    }
    if data is not None:
        entry["data"] = data
    evidence["checks"].append(entry)


def required_checks_pass(evidence: dict) -> bool:
    return all(item["passed"] or not item["required"] for item in evidence["checks"])


def expected_tools(profiles: list[str]) -> list[str]:
    return sorted({tool for profile in profiles for tool in PROFILE_TOOLS[profile]})


def canonical_report_tool_name(value: object) -> str:
    name = str(value or "").strip().lower()
    return REPORT_TOOL_ALIASES.get(name, name)


def source_manifest() -> dict[str, str]:
    manifest: dict[str, str] = {}
    source_roots = [
        (REPOSITORY_ROOT / "app", "app"),
        (REPOSITORY_ROOT / "scanner-worker" / "app", "scanner_worker_app"),
    ]
    for source_root, container_root in source_roots:
        for path in sorted(source_root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            relative = path.relative_to(source_root).as_posix()
            manifest[f"{container_root}/{relative}"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest


def container_source_manifest(container: str) -> tuple[dict[str, str], CommandResult]:
    script = (
        "import hashlib,json,pathlib; "
        "roots=[(pathlib.Path('/workspace/app'),'app'),"
        "(pathlib.Path('/workspace/scanner_worker_app'),'scanner_worker_app')]; "
        "extensions={'.css','.html','.js','.json','.png','.py'}; "
        "files={f'{label}/{path.relative_to(root).as_posix()}':hashlib.sha256(path.read_bytes()).hexdigest() "
        "for root,label in roots for path in sorted(root.rglob('*')) "
        "if path.is_file() and path.suffix.lower() in extensions}; "
        "print(json.dumps(files,sort_keys=True))"
    )
    result = run_command(
        ["docker", "exec", container, "python", "-c", script],
        timeout=30,
        max_output=1_000_000,
    )
    if result.returncode != 0:
        return {}, result
    try:
        parsed = json.loads(result.output)
    except json.JSONDecodeError:
        return {}, CommandResult(result.command, 1, "Container source manifest was not valid JSON.")
    if not isinstance(parsed, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in parsed.items()):
        return {}, CommandResult(result.command, 1, "Container source manifest had an invalid structure.")
    return parsed, result


def manifest_digest(manifest: dict[str, str]) -> str:
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def collect_host_preflight(args: argparse.Namespace, evidence: dict) -> tuple[dict, str]:
    service = run_command(["systemctl", "is-active", "kryptnet-scan"])
    add_check(
        evidence,
        "application-service-active",
        service.returncode == 0 and service.output.strip() == "active",
        service.output or "systemctl returned no status",
    )

    container_health = run_command(
        ["docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}", args.container]
    )
    add_check(
        evidence,
        "scanner-container-healthy",
        container_health.returncode == 0 and container_health.output.strip() == "healthy",
        container_health.output or "Docker returned no container health status",
    )

    image_id = run_command(["docker", "inspect", "--format", "{{.Image}}", args.container])
    add_check(
        evidence,
        "scanner-image-identified",
        image_id.returncode == 0 and bool(image_id.output.strip()),
        image_id.output or "Unable to identify scanner image",
    )

    port_bindings = run_command(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", args.container]
    )
    try:
        parsed_bindings = json.loads(port_bindings.output) if port_bindings.returncode == 0 else {}
        worker_bindings = parsed_bindings.get("8000/tcp") if isinstance(parsed_bindings, dict) else None
    except json.JSONDecodeError:
        worker_bindings = None
    loopback_only = bool(worker_bindings) and all(
        isinstance(binding, dict) and binding.get("HostIp") in {"127.0.0.1", "::1"}
        for binding in worker_bindings
    )
    add_check(
        evidence,
        "scanner-worker-port-loopback-only",
        loopback_only,
        "Worker port 8000 is published only on host loopback."
        if loopback_only
        else "Worker port 8000 must be published only on 127.0.0.1 or ::1.",
        data=worker_bindings if isinstance(worker_bindings, list) else [],
    )

    git_revision = run_command(["git", "rev-parse", "HEAD"])
    add_check(
        evidence,
        "source-revision-identified",
        git_revision.returncode == 0 and len(git_revision.output.strip()) == 40,
        git_revision.output or "Unable to identify source revision",
    )
    tracked_status = run_command(["git", "status", "--porcelain", "--untracked-files=no"])
    add_check(
        evidence,
        "tracked-source-clean",
        tracked_status.returncode == 0 and not tracked_status.output.strip(),
        "Tracked source matches the recorded Git revision."
        if tracked_status.returncode == 0 and not tracked_status.output.strip()
        else (tracked_status.output or "Unable to inspect tracked source state."),
    )

    local_manifest = source_manifest()
    running_manifest, manifest_result = container_source_manifest(args.container)
    source_matches = bool(local_manifest) and local_manifest == running_manifest
    missing_from_image = sorted(set(local_manifest) - set(running_manifest))[:20]
    unexpected_in_image = sorted(set(running_manifest) - set(local_manifest))[:20]
    changed_in_image = sorted(
        key for key in set(local_manifest) & set(running_manifest) if local_manifest[key] != running_manifest[key]
    )[:20]
    add_check(
        evidence,
        "scanner-image-source-matches-revision",
        source_matches,
        "Running scanner source matches the checked-out application and worker source."
        if source_matches
        else (manifest_result.output or "Running scanner source differs from the checked-out revision."),
        data={
            "local_manifest_sha256": manifest_digest(local_manifest),
            "container_manifest_sha256": manifest_digest(running_manifest),
            "missing_from_image": missing_from_image,
            "unexpected_in_image": unexpected_in_image,
            "changed_in_image": changed_in_image,
        },
    )

    app_health = request_json(args.app_health_url)
    add_check(
        evidence,
        "application-health",
        app_health.get("status") == "ok" and app_health.get("scanner_backend") == "worker",
        f"status={app_health.get('status')} backend={app_health.get('scanner_backend')}",
        data=app_health,
    )

    worker_health = request_json(args.worker_health_url)
    preflight = worker_health.get("preflight") if isinstance(worker_health.get("preflight"), dict) else {}
    add_check(
        evidence,
        "worker-health",
        worker_health.get("status") == "ok",
        f"status={worker_health.get('status')}",
        data={"status": worker_health.get("status"), "preflight": preflight},
    )
    add_check(
        evidence,
        "testssl-dependencies",
        preflight.get("testssl_dependencies_ready") is True,
        f"testssl_dependencies_ready={preflight.get('testssl_dependencies_ready')}",
    )
    add_check(
        evidence,
        "nuclei-templates",
        preflight.get("nuclei_templates_ready") is True,
        f"nuclei_templates_ready={preflight.get('nuclei_templates_ready')}",
    )
    add_check(
        evidence,
        "no-artificial-scan-delay",
        preflight.get("artificial_scan_delay_enabled") is False,
        f"artificial_scan_delay_enabled={preflight.get('artificial_scan_delay_enabled')}",
    )

    available = worker_health.get("available_tools")
    available = available if isinstance(available, dict) else {}
    for tool in expected_tools(args.profiles):
        add_check(
            evidence,
            f"tool-installed:{tool}",
            available.get(tool) is True or (tool == "zap-baseline.py" and available.get("zap") is True),
            f"worker available_tools[{tool}]={available.get(tool)}",
        )

    for tool in expected_tools(args.profiles):
        probe = TOOL_PROBES[tool]
        result = run_command(["docker", "exec", args.container, *probe], timeout=args.probe_timeout_seconds)
        probe_passed = result.returncode in {0, 1} and bool(result.output.strip())
        add_check(
            evidence,
            f"tool-executable:{tool}",
            probe_passed,
            result.output or f"Probe exited with code {result.returncode} and no output",
            data={"returncode": result.returncode, "probe": probe},
        )

    firewall_chain = run_command(["iptables", "-S", "KRYPTSCAN-EGRESS"])
    docker_user_chain = run_command(["iptables", "-S", "DOCKER-USER"])
    network_name_result = run_command(
        [
            "docker",
            "inspect",
            "--format",
            "{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}",
            args.container,
        ]
    )
    network_name = network_name_result.output.splitlines()[0].strip() if network_name_result.output else ""
    network_subnet_result = (
        run_command(
            [
                "docker",
                "network",
                "inspect",
                "--format",
                "{{range .IPAM.Config}}{{println .Subnet}}{{end}}",
                network_name,
            ]
        )
        if network_name
        else CommandResult(command=[], returncode=1, output="")
    )
    ipv4_subnet = next(
        (line.strip() for line in network_subnet_result.output.splitlines() if "." in line),
        "",
    )
    firewall_text = firewall_chain.output
    required_blocks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
    firewall_ok = (
        firewall_chain.returncode == 0
        and docker_user_chain.returncode == 0
        and bool(ipv4_subnet)
        and "KRYPTSCAN-EGRESS" in docker_user_chain.output
        and f"-s {ipv4_subnet}" in docker_user_chain.output
        and all(block in firewall_text for block in required_blocks)
    )
    add_check(
        evidence,
        "scanner-private-egress-blocked",
        firewall_ok,
        "KRYPTSCAN-EGRESS chain is linked and blocks private/link-local ranges."
        if firewall_ok
        else "Install the KryptScan worker egress firewall before certification.",
        data={"network": network_name, "subnet": ipv4_subnet},
    )

    return worker_health, git_revision.output.strip()


def scan_payload(profile: str, target: str, authorization_reference: str) -> dict:
    context = {
        "service_level": "standard" if profile == "va-standard" else "deep",
        "authorization_reference": authorization_reference,
        "validation_mode": "safe_validation",
    }
    if profile == "pt-automated":
        context.update(
            {
                "pentest_depth": "deep",
                "pentest_scope": "Dedicated production-certification target only",
                "testing_window": "Current authorized certification window",
                "out_of_scope": "Every host and service other than the submitted certification target",
                "emergency_stop": "Stop immediately on instability or authorization withdrawal",
            }
        )
    return {
        "target": target,
        "asset_type": "website",
        "assessment_mode": "ethical_pentesting" if profile == "pt-automated" else "vulnerability_assessment",
        "scan_tier": "full_scan",
        "scan_protocols": [
            f"Automated production certification profile: {profile}",
            f"Authorization reference: {authorization_reference}",
        ],
        "testing_context": context,
        "wait": False,
    }


def run_worker_scan(
    args: argparse.Namespace,
    token: str,
    profile: str,
) -> tuple[dict, list[dict]]:
    worker_base = args.worker_health_url.rsplit("/health", 1)[0].rstrip("/")
    submitted = request_json(
        f"{worker_base}/v1/scans",
        method="POST",
        token=token,
        payload=scan_payload(profile, args.target, args.authorization_reference),
    )
    job_id = str(submitted.get("job_id") or "")
    if not job_id:
        raise RuntimeError(f"Worker did not return a job ID for {profile}.")
    progress: list[dict] = []
    deadline = time.monotonic() + args.scan_timeout_seconds
    while time.monotonic() < deadline:
        job = request_json(f"{worker_base}/v1/scans/{job_id}", token=token)
        sample = {
            "recorded_at": iso_now(),
            "status": job.get("status"),
            "progress_percent": job.get("progress_percent"),
            "message": str(job.get("message") or "")[:300],
        }
        if not progress or sample != {**progress[-1], "recorded_at": sample["recorded_at"]}:
            progress.append(sample)
        status = str(job.get("status") or "").lower()
        if status == "completed":
            report = job.get("report")
            if not isinstance(report, dict):
                raise RuntimeError(f"Worker completed {profile} without a report.")
            return report, progress
        if status in {"failed", "cancelled", "canceled"}:
            raise RuntimeError(f"Worker {profile} job ended with status {status}: {job.get('error') or job.get('message')}")
        time.sleep(args.poll_seconds)
    raise RuntimeError(f"Worker {profile} job exceeded {args.scan_timeout_seconds} seconds.")


def evaluate_report(profile: str, report: dict, minimum_coverage: int) -> list[tuple[str, bool, str]]:
    results: list[tuple[str, bool, str]] = []
    check_results = report.get("check_results")
    check_results = check_results if isinstance(check_results, list) else []
    observed_names = Counter(
        canonical_report_tool_name(item.get("name"))
        for item in check_results
        if isinstance(item, dict)
    )
    expected_names = Counter(name.lower() for name in PROFILE_TOOLS[profile])
    missing = list((expected_names - observed_names).elements())
    results.append(("planned-tools-recorded", not missing, "missing=" + ",".join(missing) if missing else "all planned tools recorded"))

    failed = [
        f"{item.get('name')}:{item.get('execution_status')}"
        for item in check_results
        if isinstance(item, dict) and item.get("execution_status") in {"FAILED", "TIMED_OUT", "CANCELLED"}
    ]
    results.append(("no-engine-execution-failures", not failed, ", ".join(failed) if failed else "no failed, timed-out, or cancelled engines"))

    inconclusive = [
        str(item.get("name"))
        for item in check_results
        if isinstance(item, dict) and item.get("security_result") in {"INCONCLUSIVE", "NOT_TESTED"}
    ]
    results.append(("no-inconclusive-mandatory-results", not inconclusive, ", ".join(inconclusive) if inconclusive else "all mandatory results were evaluated"))

    coverage = int(report.get("assessment_coverage") or 0)
    results.append(("minimum-assessment-coverage", coverage >= minimum_coverage, f"coverage={coverage}% required={minimum_coverage}%"))

    outcome = str(report.get("assessment_outcome") or "")
    results.append(
        (
            "defensible-assessment-outcome",
            outcome in {"COMPLETED", "COMPLETED_WITH_LIMITATIONS"},
            f"outcome={outcome or 'missing'}",
        )
    )

    risk_score = report.get("risk_score")
    risk_band = str(report.get("risk_band") or "")
    risk_consistent = (risk_score is None and risk_band == "Undetermined") or (
        isinstance(risk_score, int) and 0 <= risk_score <= 100 and risk_band != "Undetermined"
    )
    results.append(("risk-result-consistent", risk_consistent, f"score={risk_score} band={risk_band}"))

    analyst_status = str(report.get("analyst_review_status") or "NOT_PERFORMED")
    pt_honest = profile != "pt-automated" or analyst_status not in {"APPROVED", "COMPLETED"}
    results.append(("pt-does-not-fabricate-analyst-approval", pt_honest, f"analyst_review_status={analyst_status}"))

    serialized = json.dumps(report, ensure_ascii=True)
    results.append(("report-has-no-terminal-control-sequences", "\\u001b" not in serialized.lower(), "ANSI escape sequences absent"))

    internal_services = {
        str(item.get("label") or "").lower()
        for item in report.get("top_services", [])
        if isinstance(item, dict)
    } & INTERNAL_SERVICE_NAMES
    results.append(
        (
            "scanner-names-not-reported-as-services",
            not internal_services,
            ", ".join(sorted(internal_services)) if internal_services else "service chart contains customer-facing services only",
        )
    )
    return results


def write_json_secure(path: Path, payload: dict) -> str:
    encoded = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(encoded)
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    os.chmod(path, 0o600)
    return hashlib.sha256(encoded).hexdigest()


def create_run_directory(output_root: Path, run_id: str) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(output_root, 0o700)
    except OSError:
        pass
    run_directory = output_root / run_id
    run_directory.mkdir(mode=0o700, exist_ok=False)
    return run_directory


def parse_profiles(value: str) -> list[str]:
    profiles = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = sorted(set(profiles) - set(PROFILE_TOOLS))
    if unknown:
        raise argparse.ArgumentTypeError(f"Unknown profile(s): {', '.join(unknown)}")
    if not profiles:
        raise argparse.ArgumentTypeError("At least one profile is required.")
    return list(dict.fromkeys(profiles))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate point-in-time KryptScan automated production-readiness evidence.",
    )
    parser.add_argument("--target", help="Dedicated public staging target owned or authorized for testing.")
    parser.add_argument("--authorization-reference", help="Written authorization or internal approval reference.")
    parser.add_argument("--confirm-authorization", action="store_true", help="Confirm the target is owned or explicitly authorized.")
    parser.add_argument("--profiles", type=parse_profiles, default=parse_profiles("va-standard,va-deep,pt-automated"))
    parser.add_argument("--minimum-coverage", type=int, default=90)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--app-health-url", default="http://127.0.0.1:5102/health")
    parser.add_argument("--worker-health-url", default="http://127.0.0.1:5200/health")
    parser.add_argument("--env-file", type=Path, default=Path(".env.scanner"))
    parser.add_argument("--container", default="kryptnet-scanner")
    parser.add_argument("--output-dir", type=Path, default=Path("/var/lib/kryptscan/certification"))
    parser.add_argument("--probe-timeout-seconds", type=int, default=30)
    parser.add_argument("--scan-timeout-seconds", type=int, default=5400)
    parser.add_argument("--poll-seconds", type=int, default=10)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.minimum_coverage <= 100:
        parser.error("--minimum-coverage must be between 1 and 100.")
    if not args.preflight_only:
        if not args.target or not args.authorization_reference or not args.confirm_authorization:
            parser.error(
                "Full certification requires --target, --authorization-reference, and --confirm-authorization."
            )
        try:
            args.target = validate_public_target(args.target)
        except ValueError as exc:
            parser.error(str(exc))

    started = utcnow()
    run_id = started.strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
    run_directory = create_run_directory(args.output_dir, run_id)
    evidence: dict = {
        "schema_version": "1.0",
        "kind": "KryptScan automated production-readiness evidence",
        "run_id": run_id,
        "started_at": started.isoformat(),
        "completed_at": None,
        "valid_until": (started + timedelta(hours=24)).isoformat(),
        "decision": "RUNNING",
        "production_ready": False,
        "preflight_only": args.preflight_only,
        "profiles": args.profiles,
        "target": args.target if not args.preflight_only else None,
        "authorization_reference": args.authorization_reference if not args.preflight_only else None,
        "checks": [],
        "profile_results": {},
        "limitations": [
            "This is point-in-time technical release evidence, not legal, regulatory, or insurance certification.",
            "Automated PT validates scanner execution and safe evidence collection; it does not replace manual analyst review and sign-off.",
            "A PASS does not guarantee that the platform or assessed targets are free of vulnerabilities.",
        ],
    }

    try:
        _, git_revision = collect_host_preflight(args, evidence)
        evidence["git_revision"] = git_revision or None
    except Exception as exc:
        add_check(evidence, "host-preflight-completed", False, f"{type(exc).__name__}: {exc}")

    if not args.preflight_only and required_checks_pass(evidence):
        token = worker_token(args.env_file)
        add_check(
            evidence,
            "worker-token-loaded",
            bool(token),
            "Scanner worker token loaded without exposing its value." if token else "SCANNER_WORKER_TOKEN is missing.",
        )
        if token:
            for profile in args.profiles:
                profile_started = iso_now()
                try:
                    report, progress = run_worker_scan(args, token, profile)
                    report_path = run_directory / f"{profile}-report.json"
                    report_sha256 = write_json_secure(report_path, report)
                    evaluations = evaluate_report(profile, report, args.minimum_coverage)
                    for name, passed, detail in evaluations:
                        add_check(evidence, f"{profile}:{name}", passed, detail)
                    evidence["profile_results"][profile] = {
                        "started_at": profile_started,
                        "completed_at": iso_now(),
                        "outcome": report.get("assessment_outcome"),
                        "coverage": report.get("assessment_coverage"),
                        "risk_score": report.get("risk_score"),
                        "risk_band": report.get("risk_band"),
                        "report_file": report_path.name,
                        "report_sha256": report_sha256,
                        "progress": progress,
                    }
                except Exception as exc:
                    add_check(evidence, f"{profile}:scan-completed", False, f"{type(exc).__name__}: {exc}")
                    evidence["profile_results"][profile] = {
                        "started_at": profile_started,
                        "completed_at": iso_now(),
                        "error": f"{type(exc).__name__}: {exc}",
                    }

    all_required_passed = required_checks_pass(evidence)
    if args.preflight_only:
        evidence["decision"] = "PREFLIGHT_PASS" if all_required_passed else "FAIL"
        evidence["production_ready"] = False
    else:
        evidence["decision"] = "PASS" if all_required_passed else "FAIL"
        evidence["production_ready"] = all_required_passed
    evidence["completed_at"] = iso_now()

    evidence_path = run_directory / "production-readiness.json"
    evidence_sha256 = write_json_secure(evidence_path, evidence)
    checksum_path = run_directory / "SHA256SUMS"
    checksum_path.write_text(f"{evidence_sha256}  {evidence_path.name}\n", encoding="ascii")
    os.chmod(checksum_path, 0o600)

    failed = [item for item in evidence["checks"] if item["required"] and not item["passed"]]
    print(f"KryptScan production gate: {evidence['decision']}")
    print(f"Evidence: {evidence_path}")
    print(f"SHA-256: {evidence_sha256}")
    if failed:
        print("Failed required checks:")
        for item in failed:
            print(f"- {item['name']}: {item['detail']}")
    elif args.preflight_only:
        print("Preflight passed. Live authorized VA/PT profiles were not executed, so production_ready remains false.")
    else:
        print("All selected automated production-readiness checks passed.")
    return 0 if all_required_passed else 1


if __name__ == "__main__":
    sys.exit(main())
