"""Per-device PDF report: device identification + CIS findings + remediation.

Findings and remediation text are already fully deterministic by the time
they reach this module -- nothing here calls an LLM, and nothing here can.
"""

import io
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .version_info import DeviceIdentity


def generate_pdf_report(
    identity: DeviceIdentity,
    findings_by_framework: dict[str, list[dict[str, Any]]],
    iso_evidence: list[dict[str, Any]],
) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements: list[Any] = []

    elements.append(Paragraph("Network Device Compliance Report", styles["Title"]))
    elements.append(Spacer(1, 12))

    # Identity fields come from parsing arbitrary uploaded text, so they must
    # be escaped before going into a Paragraph -- reportlab parses Paragraph
    # text as a small pseudo-XML markup language, and an unescaped `<` or `&`
    # (both valid in a hostname/serial/version string) would break parsing.
    def _safe(value: str | None) -> str:
        return escape(value) if value else "Unknown"

    elements.append(Paragraph("Device Identification", styles["Heading2"]))
    elements.append(Paragraph(f"Model: {_safe(identity.model)}", styles["Normal"]))
    elements.append(
        Paragraph(f"Serial Number: {_safe(identity.serial_number)}", styles["Normal"])
    )
    elements.append(
        Paragraph(f"OS Version: {_safe(identity.os_version)}", styles["Normal"])
    )
    elements.append(Spacer(1, 12))

    # Title and remediation text can run well past the column width now that
    # the control set covers ~30-35 controls per framework (some remediation
    # strings are 100+ characters) -- these must be Paragraph flowables so
    # reportlab word-wraps them instead of drawing one un-wrapped line that
    # bleeds into the next column.
    cell_style = ParagraphStyle("cell", parent=styles["Normal"], fontSize=7, leading=8.5)

    def _cell(value: str) -> Paragraph:
        return Paragraph(escape(value), cell_style)

    # CIS, NIST SP 800-53, and DISA STIG map 1:1 at the technical-control
    # level, so each gets its own pass/fail findings table, broken out by
    # framework per the results-view/PDF requirement.
    for framework, findings in findings_by_framework.items():
        elements.append(Paragraph(f"{framework} Findings", styles["Heading2"]))
        table_data: list[list[Any]] = [
            ["Control", "Title", "Severity", "Status", "Remediation"]
        ]
        for finding in findings:
            table_data.append(
                [
                    finding["control_id"],
                    _cell(finding["title"]),
                    finding["severity"],
                    finding["status"].upper(),
                    _cell(finding["remediation"]) if finding["remediation"] else "-",
                ]
            )
        table = Table(table_data, colWidths=[55, 150, 42, 40, 168])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        elements.append(table)
        elements.append(Spacer(1, 12))

    # ISO/IEC 27001 Annex A maps many facts to one control objective, so it
    # is never rendered as a pass/fail line item -- each Annex A control gets
    # a heading plus a table of the facts cited as evidence toward it.
    elements.append(Paragraph("ISO/IEC 27001 Annex A (Evidentiary)", styles["Heading2"]))
    elements.append(
        Paragraph(
            "ISO/IEC 27001 Annex A controls are broad control objectives, not "
            "line-item technical checks. Each control below is supported by "
            "one or more facts, shown as evidence for that objective -- this "
            "is not a pass/fail verdict on the control itself.",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 8))
    for annex in iso_evidence:
        elements.append(
            Paragraph(f"{annex['control_id']} — {annex['title']}", styles["Heading3"])
        )
        evidence_table_data: list[list[Any]] = [
            ["Supporting fact", "Evidence", "Remediation (if gap)"]
        ]
        for item in annex["evidence"]:
            evidence_table_data.append(
                [
                    _cell(item["title"]),
                    "Present" if item["satisfied"] else "Gap",
                    _cell(item["remediation"]) if item["remediation"] else "-",
                ]
            )
        evidence_table = Table(evidence_table_data, colWidths=[220, 60, 175])
        evidence_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        elements.append(evidence_table)
        elements.append(Spacer(1, 8))

    doc.build(elements)
    return buffer.getvalue()
