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
            "wait": True,
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
            detail = exc.read().decode("utf-8", "replace")
            raise ValueError(f"Scanner worker rejected the job: {detail}") from exc

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
        del task_id, report_id
        scheduled = self.schedule(target, asset_type)
        return RefreshedScan(
            status=scheduled.status,
            message=scheduled.message,
            report=scheduled.report,
        )
