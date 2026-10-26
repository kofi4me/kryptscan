# KryptScan Automated Production Readiness Gate

## Purpose

The production gate creates point-in-time technical evidence that the deployed KryptScan application and scanner worker can execute the configured VA and automated PT profiles. It is a release control, not a legal, regulatory, insurance, or vulnerability-free guarantee.

A full PASS is valid for 24 hours and applies only to the recorded Git revision, scanner image, target, configuration, and execution window.

## Required certification target

Use a dedicated public staging target that KryptNet owns or has explicit written authorization to test. The target should:

- Resolve only to public addresses.
- Provide stable HTTP and HTTPS services.
- Use no production customer data.
- Permit Nmap, TLS, Nuclei, Nikto, ZAP baseline, passive reconnaissance, crawling, and rate-limited content discovery.
- Be monitored during the test window.
- Have an emergency-stop contact.

Do not use a third-party demonstration service or a customer target for platform certification. Do not use the live KryptScan customer application when a dedicated staging target is available.

## What the gate verifies

- `kryptnet-scan` is active.
- The scanner container is healthy and its image is recorded.
- The worker is bound only to host loopback, not a public interface.
- Tracked source is clean and the running scanner source matches the recorded Git revision.
- The application and worker health endpoints return healthy states.
- `procps` and Nuclei templates pass worker preflight.
- Artificial scan delays are disabled.
- Every engine required by the selected profiles is installed and responds to a version/help probe.
- The scanner container is prevented from initiating connections to private, loopback, link-local, documentation, multicast, and reserved IPv4 ranges.
- Standard VA, deep VA, and automated PT jobs run through the real worker.
- Every planned check appears in the report.
- No required engine fails, times out, or returns an inconclusive result.
- Coverage meets the configured minimum, defaulting to 90 percent.
- Assessment outcome and risk fields are internally consistent.
- Automated PT does not fabricate manual analyst approval.
- Reports do not contain terminal escape sequences or scanner names presented as customer services.

## Install the scanner egress isolation

From the application directory on Ubuntu:

```bash
sudo install -m 0644 \
  ops/systemd/kryptscan-worker-egress.service \
  /etc/systemd/system/kryptscan-worker-egress.service

sudo chmod 0755 ops/kryptscan-worker-egress.sh
sudo systemctl daemon-reload
sudo systemctl enable --now kryptscan-worker-egress.service

sudo systemctl status kryptscan-worker-egress.service --no-pager
sudo iptables -S KRYPTSCAN-EGRESS
sudo iptables -S DOCKER-USER
```

The firewall rule is scoped to the KryptScan scanner container's Docker subnet. It does not intentionally modify the Guacamole containers or their network.

Reapply the service after recreating the scanner container or changing its Docker network:

```bash
sudo systemctl restart kryptscan-worker-egress.service
```

## Run preflight only

```bash
cd /opt/kryptnet-services/kryptscan-app
sudo venv/bin/python ops/kryptscan_production_certify.py --preflight-only
```

`PREFLIGHT_PASS` confirms the local services, tools, dependencies, image, and isolation checks. It deliberately leaves `production_ready` false because no live engine profiles were executed.

## Run the complete production gate

Replace the example values with the dedicated authorized staging target and written authorization reference:

```bash
cd /opt/kryptnet-services/kryptscan-app

sudo venv/bin/python ops/kryptscan_production_certify.py \
  --target certify.kryptnet.org \
  --authorization-reference KRYPTNET-INTERNAL-CERT-2026-001 \
  --confirm-authorization
```

The default run executes:

1. Standard vulnerability assessment.
2. Deep vulnerability assessment.
3. Automated ethical PT validation.

The command exits with code `0` only when every required release check passes. Any failed, timed-out, missing, or inconclusive required stage returns a nonzero exit code and a `FAIL` decision.

## Evidence

Evidence is stored with mode `0600` under:

```text
/var/lib/kryptscan/certification/<run-id>/
```

The directory contains:

- `production-readiness.json`
- One raw worker report per selected profile
- `SHA256SUMS`

Retain the evidence with the release record. It may contain target and vulnerability information and must not be placed in Git or exposed through the web application.

## Release decision

Release only when the current run says:

```text
KryptScan production gate: PASS
```

An automated PASS permits release of the automated VA and automated safe-validation capabilities represented by the selected profiles. It does not authorize marketing the result as a fully analyst-validated penetration test. Final professional PT delivery still requires qualified analyst review, evidence approval, and report sign-off.
