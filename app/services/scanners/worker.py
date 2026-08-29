from __future__ import annotations

import json
import urllib.error
import urllib.request

from app.models import AssessmentReport
from app.services.scanners.base import RefreshedScan, ScheduledScan


class WorkerScannerProvider:
    backend_name = "worker"

    def __init__(self, settings) -> None:
        self.settings = settings

    def _worker_error(self, exc: urllib.error.HTTPError, action: str) -> ValueError:
        detail = exc.read().decode("utf-8", "replace")
        if exc.code in {401, 403}:
            return ValueError(
                "Scanner worker authentication failed. Set the same SCANNER_WORKER_TOKEN in "
                ".env and .env.scanner, then restart kryptnet-scan and the scanner worker."
            )
        return ValueError(f"Scanner worker {action} failed: {detail}")

    def schedule(
        self,
        target: str,
        asset_type: str,
        *,
        assessment_mode: str = "vulnerability_assessment",
        scan_tier: str = "full_scan",
        scan_protocols: list[str] | None = None,
    ) -> ScheduledScan:
        if not self.settings.scanner_worker_url or not self.settings.scanner_worker_token:
            raise ValueError("SCANNER_WORKER_URL and SCANNER_WORKER_TOKEN must be configured.")

        payload = {
            "target": target,
            "asset_type": asset_type,
            "assessment_mode": assessment_mode,
            "scan_tier": scan_tier,
            "scan_protocols": scan_protocols or [],
            "wait": False,
        }
        request = urllib.request.Request(
            f"{self.settings.scanner_worker_url.rstrip('/')}/v1/scans",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.settings.scanner_worker_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.settings.scanner_worker_timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise self._worker_error(exc, "job submission") from exc

        if body.get("status") != "completed" or not body.get("report"):
            return ScheduledScan(
                status=body.get("status", "running"),
                backend=self.backend_name,
                message=body.get("message", "Scanner worker accepted the job."),
                external_task_id=body.get("job_id"),
            )

        return ScheduledScan(
            status="completed",
            backend=self.backend_name,
            message=body.get("message", "Scanner worker completed the job."),
            external_task_id=body.get("job_id"),
            report=AssessmentReport.model_validate(body["report"]),
        )

    def refresh(
        self,
        target: str,
        asset_type: str,
        task_id: str | None = None,
        report_id: str | None = None,
    ) -> RefreshedScan:
        del target, asset_type, report_id
        if not self.settings.scanner_worker_url or not self.settings.scanner_worker_token:
            raise ValueError("SCANNER_WORKER_URL and SCANNER_WORKER_TOKEN must be configured.")
        if not task_id:
            return RefreshedScan(status="running", message="Scanner worker job is still being created.")

        request = urllib.request.Request(
            f"{self.settings.scanner_worker_url.rstrip('/')}/v1/scans/{task_id}",
            headers={"Authorization": f"Bearer {self.settings.scanner_worker_token}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise self._worker_error(exc, "refresh") from exc

        report = None
        if body.get("report"):
            report = AssessmentReport.model_validate(body["report"])
        return RefreshedScan(
            status=body.get("status", "running"),
            message=body.get("message", "Scanner worker is running the approved toolchain."),
            report=report,
        )
