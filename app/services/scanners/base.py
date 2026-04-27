from __future__ import annotations

from dataclasses import dataclass

from app.models import AssessmentReport


@dataclass
class ScheduledScan:
    status: str
    backend: str
    message: str
    external_task_id: str | None = None
    external_report_id: str | None = None
    report: AssessmentReport | None = None


@dataclass
class RefreshedScan:
    status: str
    message: str
    report: AssessmentReport | None = None
