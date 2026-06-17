from __future__ import annotations

from pathlib import Path
from typing import Iterable

from app.models import AssessmentReport


PAGE_WIDTH = 612
PAGE_HEIGHT = 792
LEFT_MARGIN = 48
RIGHT_MARGIN = 48
TOP_MARGIN = 748
BOTTOM_MARGIN = 54
CONTENT_WIDTH = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN


def _escape_pdf_text(value: str) -> str:
    sanitized = value.encode("latin-1", "replace").decode("latin-1")
    return (
        sanitized.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _wrap_text(text: str, max_chars: int) -> list[str]:
    words = text.split()
    if not words:
        return [""]

    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if len(candidate) <= max_chars:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


class _Canvas:
    def __init__(self) -> None:
        self.pages: list[list[str]] = []
        self.page_commands: list[str] = []
        self.y = TOP_MARGIN
        self._new_page()

    def _new_page(self) -> None:
        self.page_commands = []
        self.pages.append(self.page_commands)
        self.y = TOP_MARGIN

    def _ensure_space(self, height: float) -> None:
        if self.y - height < BOTTOM_MARGIN:
            self._new_page()

    def spacer(self, height: float) -> None:
        self.y -= height

    def text(
        self,
        text: str,
        *,
        size: int = 10,
        bold: bool = False,
        color: tuple[float, float, float] = (0.12, 0.17, 0.22),
        indent: float = 0,
        extra_gap: float = 3,
    ) -> None:
        font = "F2" if bold else "F1"
        x = LEFT_MARGIN + indent
        max_chars = max(24, int((CONTENT_WIDTH - indent) / max(size * 0.5, 5)))
        lines = _wrap_text(text, max_chars=max_chars)
        line_height = size + extra_gap
        for line in lines:
            self._ensure_space(line_height)
            safe_line = _escape_pdf_text(line)
            self.page_commands.append(
                (
                    "BT "
                    f"/{font} {size} Tf "
                    f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg "
                    f"1 0 0 1 {x:.2f} {self.y:.2f} Tm "
                    f"({safe_line}) Tj ET"
                )
            )
            self.y -= line_height

    def divider(self) -> None:
        self._ensure_space(14)
        line_y = self.y
        self.page_commands.append(
            f"0.790 0.835 0.875 RG 0.8 w {LEFT_MARGIN} {line_y:.2f} m {PAGE_WIDTH - RIGHT_MARGIN} {line_y:.2f} l S"
        )
        self.y -= 14

    def bar_chart(
        self,
        title: str,
        items: Iterable[tuple[str, float, tuple[float, float, float]]],
    ) -> None:
        item_list = list(items)
        if not item_list:
            return

        self.text(title, size=13, bold=True)
        max_value = max(value for _, value, _ in item_list) or 1
        for label, value, color in item_list:
            self._ensure_space(28)
            label_y = self.y
            self.text(f"{label}: {value}", size=10)
            bar_y = label_y - 14
            track_width = 240
            self.page_commands.append(
                f"0.910 0.929 0.949 rg 290 {bar_y:.2f} {track_width} 9 re f"
            )
            fill_width = max(8, (value / max_value) * track_width)
            self.page_commands.append(
                f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg 290 {bar_y:.2f} {fill_width:.2f} 9 re f"
            )
            self.y -= 10
        self.spacer(8)


def _build_pdf_bytes(
    target: str,
    asset_type: str,
    scanner_backend: str,
    assessment_mode: str,
    recipient_email: str,
    report: AssessmentReport,
    msp_details: dict[str, str] | None = None,
    owner_details: dict[str, str] | None = None,
) -> bytes:
    canvas = _Canvas()
    title = "Sentinel Scope Ethical Pen-Testing" if assessment_mode in {"ethical_pentesting", "authorized_pentest"} else "Sentinel Scope Vulnerability Assessment"
    canvas.text(title, size=20, bold=True)
    canvas.text(target, size=15, bold=True, color=(0.18, 0.45, 0.62))
    canvas.spacer(4)
    canvas.text(f"Target type: {asset_type}")
    canvas.text(f"Assessment mode: {assessment_mode.replace('_', ' ').title()}")
    canvas.text(f"Scanner backend: {scanner_backend}")
    canvas.text(f"Report recipient: {recipient_email}")
    canvas.text(f"Generated at: {report.generated_at}")
    canvas.divider()

    if msp_details:
        canvas.text("MSP / Testing Provider", size=14, bold=True)
        for label, value in msp_details.items():
            if value:
                canvas.text(f"{label}: {value}", size=10, indent=8)
        canvas.divider()

    if owner_details:
        canvas.text("Domain / IP Owner", size=14, bold=True)
        for label, value in owner_details.items():
            if value:
                canvas.text(f"{label}: {value}", size=10, indent=8)
        canvas.divider()

    canvas.text("Executive Summary", size=14, bold=True)
    canvas.text(report.executive_summary, size=11, extra_gap=4)
    if report.scope_summary:
        canvas.spacer(4)
        canvas.text("Scope", size=12, bold=True)
        canvas.text(report.scope_summary, size=10, indent=8)
    canvas.spacer(4)
    canvas.text(f"Overall risk score: {report.risk_score}/100", size=12, bold=True)
    canvas.text(f"Risk band: {report.risk_band}", size=12)
    canvas.divider()

    if report.methodology:
        canvas.text("Methodology", size=14, bold=True)
        for item in report.methodology:
            canvas.text(f"- {item}", size=10, indent=8)
        canvas.divider()

    if report.limitations:
        canvas.text("Limitations", size=14, bold=True)
        for item in report.limitations:
            canvas.text(f"- {item}", size=10, indent=8)
        canvas.divider()

    canvas.bar_chart(
        "Severity Distribution",
        [
            ("Critical", report.severity_counts.critical, (1.0, 0.36, 0.45)),
            ("High", report.severity_counts.high, (1.0, 0.48, 0.35)),
            ("Medium", report.severity_counts.medium, (0.965, 0.678, 0.333)),
            ("Low", report.severity_counts.low, (0.545, 0.878, 0.545)),
            ("Info", report.severity_counts.info, (0.357, 0.753, 0.922)),
        ],
    )

    if report.scan_protocols:
        canvas.text("Applied Scan Protocols", size=14, bold=True)
        for protocol in report.scan_protocols:
            canvas.text(f"- {protocol}", size=11, indent=8)
        canvas.divider()

    canvas.text("Risk Severity Checks", size=14, bold=True)
    for check in report.compliance_checks:
        canvas.text(f"{check.name} [{check.status.upper()}]", size=11, bold=True)
        canvas.text(check.detail, size=10, indent=8)
        canvas.spacer(2)
    canvas.divider()

    canvas.text("Remediation Priorities", size=14, bold=True)
    for item in report.remediation_plan:
        canvas.text(f"{item.priority}: {item.title}", size=11, bold=True)
        canvas.text(item.action, size=10, indent=8)
        canvas.text(f"Owner: {item.owner}", size=10, indent=8, color=(0.35, 0.40, 0.45))
        canvas.spacer(2)
    canvas.divider()

    if report.top_services:
        canvas.bar_chart(
            "Top Affected Services",
            [(item.label, item.value, (0.31, 0.82, 0.77)) for item in report.top_services],
        )

    if report.top_categories:
        canvas.bar_chart(
            "Top Finding Categories",
            [(item.label, item.value, (0.35, 0.75, 0.92)) for item in report.top_categories],
        )

    canvas.text("Technical Findings", size=14, bold=True)
    for index, finding in enumerate(report.findings, start=1):
        canvas.text(
            f"{index}. {finding.title} [{finding.severity.upper()} | CVSS {finding.cvss}]",
            size=11,
            bold=True,
        )
        canvas.text(
            f"Host: {finding.host}  Port: {finding.port or 'n/a'}  Service: {finding.service or 'n/a'}",
            size=10,
            indent=8,
            color=(0.35, 0.40, 0.45),
        )
        if finding.cve:
            canvas.text(f"CVE: {finding.cve}", size=10, indent=8, color=(0.35, 0.40, 0.45))
        canvas.text(f"Description: {finding.description}", size=10, indent=8)
        canvas.text(f"Remediation: {finding.remediation}", size=10, indent=8)
        if finding.evidence:
            canvas.text(f"Evidence: {finding.evidence}", size=10, indent=8, color=(0.30, 0.37, 0.44))
        canvas.spacer(5)

    return _serialize_pdf(canvas.pages)


def _serialize_pdf(pages: list[list[str]]) -> bytes:
    objects: list[bytes] = []

    def add_object(payload: bytes) -> int:
        objects.append(payload)
        return len(objects)

    catalog_id = add_object(b"<< /Type /Catalog /Pages 2 0 R >>")
    pages_id = add_object(b"<< /Type /Pages /Kids [] /Count 0 >>")
    font_regular_id = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    font_bold_id = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

    page_ids: list[int] = []
    for commands in pages:
        stream_data = "\n".join(commands).encode("latin-1", "replace")
        contents_id = add_object(
            b"<< /Length " + str(len(stream_data)).encode("ascii") + b" >>\nstream\n" + stream_data + b"\nendstream"
        )
        page_id = add_object(
            (
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                f"/Resources << /Font << /F1 {font_regular_id} 0 R /F2 {font_bold_id} 0 R >> >> "
                f"/Contents {contents_id} 0 R >>"
            ).encode("ascii")
        )
        page_ids.append(page_id)

    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[pages_id - 1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")
    objects[catalog_id - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")

    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(payload)
        output.extend(b"\nendobj\n")

    xref_position = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_position}\n%%EOF"
        ).encode("ascii")
    )
    return bytes(output)


def write_pdf_report(
    output_path: Path,
    target: str,
    asset_type: str,
    scanner_backend: str,
    recipient_email: str,
    report: AssessmentReport,
    assessment_mode: str = "vulnerability_assessment",
    msp_details: dict[str, str] | None = None,
    owner_details: dict[str, str] | None = None,
) -> bytes:
    pdf_bytes = _build_pdf_bytes(
        target=target,
        asset_type=asset_type,
        scanner_backend=scanner_backend,
        assessment_mode=assessment_mode,
        recipient_email=recipient_email,
        report=report,
        msp_details=msp_details,
        owner_details=owner_details,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(pdf_bytes)
    return pdf_bytes
