from __future__ import annotations

from xml.etree.ElementTree import Element

from app.models import Finding
from app.services.reporting import build_assessment_report, severity_from_cvss
from app.services.scanners.base import RefreshedScan, ScheduledScan


class GreenboneScannerProvider:
    backend_name = "greenbone"

    def __init__(self, settings) -> None:
        self.settings = settings

        try:
            from gvm.connections import TLSConnection, UnixSocketConnection
            from gvm.errors import GvmError
            from gvm.protocols.gmp import GMP
            from gvm.transforms import EtreeCheckCommandTransform
        except ImportError as exc:  # pragma: no cover - dependency is optional
            raise RuntimeError(
                "Greenbone support requires the optional 'python-gvm' dependency. "
                "Install requirements-greenbone.txt."
            ) from exc

        self.TLSConnection = TLSConnection
        self.UnixSocketConnection = UnixSocketConnection
        self.GvmError = GvmError
        self.GMP = GMP
        self.EtreeCheckCommandTransform = EtreeCheckCommandTransform

    def schedule(self, target: str, asset_type: str) -> ScheduledScan:
        del asset_type
        connection = self._build_connection()
        with self.GMP(connection=connection, transform=self.EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(self.settings.greenbone_username, self.settings.greenbone_password)
            target_id = gmp.create_target(name=f"Sentinel Scope {target}", hosts=[target]).get("id")
            task_id = gmp.create_task(
                name=f"Assessment {target}",
                config_id=self.settings.greenbone_scan_config_id,
                target_id=target_id,
                scanner_id=self.settings.greenbone_scanner_id,
            ).get("id")
            response = gmp.start_task(task_id)
            report_id = response[0].text if len(response) else None

        return ScheduledScan(
            status="running",
            backend=self.backend_name,
            message="Greenbone task started successfully.",
            external_task_id=task_id,
            external_report_id=report_id,
        )

    def refresh(self, target: str, asset_type: str, task_id: str, report_id: str | None) -> RefreshedScan:
        del asset_type
        if not task_id:
            raise ValueError("Missing Greenbone task ID for refresh.")

        connection = self._build_connection()
        with self.GMP(connection=connection, transform=self.EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(self.settings.greenbone_username, self.settings.greenbone_password)
            task = gmp.get_task(task_id)
            status_text = self._text(task.find(".//status")) or "Running"

            if status_text.lower() not in {"done", "stopped"}:
                return RefreshedScan(
                    status="running",
                    message=f"Greenbone task is still {status_text.lower()}.",
                )

            if not report_id:
                report_element = task.find(".//last_report/report")
                report_id = report_element.get("id") if report_element is not None else None
            if not report_id:
                raise ValueError("Greenbone completed the task but did not return a report ID.")

            report_xml = gmp.get_report(report_id=report_id, details=True)
            report = build_assessment_report(target, self._parse_report(report_xml, target))

        return RefreshedScan(
            status="completed",
            message="Greenbone report synchronized.",
            report=report,
        )

    def _build_connection(self):
        if self.settings.greenbone_connection == "socket":
            return self.UnixSocketConnection(path=self.settings.greenbone_socket_path)
        return self.TLSConnection(
            hostname=self.settings.greenbone_host,
            port=self.settings.greenbone_port,
        )

    def _parse_report(self, root: Element, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for result in root.findall(".//result"):
            title = self._text(result.find("name")) or "Untitled finding"
            severity_value = self._float(self._text(result.find("severity")))
            severity = severity_from_cvss(severity_value)
            host = self._text(result.find("host")) or target
            port = self._text(result.find("port"))
            description = self._text(result.find("description")) or self._text(
                result.find(".//nvt/tags")
            ) or "No additional description was returned by Greenbone."
            remediation = self._text(result.find(".//nvt/solution")) or (
                "Review the Greenbone plugin output and apply the vendor remediation guidance."
            )
            cve = self._text(result.find(".//nvt/cve"))
            service = None
            if port and "/" in port:
                service = port.split("/", 1)[1]
            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    cvss=severity_value,
                    category=self._text(result.find(".//nvt/family")) or "Infrastructure",
                    host=host,
                    port=port,
                    service=service,
                    cve=cve,
                    description=description,
                    remediation=remediation,
                    evidence=self._text(result.find("qod")),
                )
            )

        if not findings:
            findings.append(
                Finding(
                    title="No Greenbone findings were returned",
                    severity="info",
                    cvss=0.0,
                    category="Scan Status",
                    host=target,
                    description="The Greenbone task completed without returned result nodes.",
                    remediation="Confirm the target was reachable and review the raw report output.",
                )
            )
        return findings

    @staticmethod
    def _text(element: Element | None) -> str | None:
        if element is None or element.text is None:
            return None
        value = element.text.strip()
        return value or None

    @staticmethod
    def _float(value: str | None) -> float:
        try:
            return round(float(value or 0), 1)
        except ValueError:
            return 0.0
