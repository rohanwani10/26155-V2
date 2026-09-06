"""Per-device PDF report: device identification + CIS findings + remediation.

Findings and remediation text are already fully deterministic by the time
they reach this module -- nothing here calls an LLM, and nothing here can.
"""

import io
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .version_info import DeviceIdentity


def generate_pdf_report(
    identity: DeviceIdentity, findings: list[dict[str, Any]]
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

    elements.append(Paragraph("Compliance Findings", styles["Heading2"]))
    table_data = [["Control", "Framework", "Title", "Severity", "Status", "Remediation"]]
    for finding in findings:
        table_data.append(
            [
                finding["control_id"],
                finding["framework"],
                finding["title"],
                finding["severity"],
                finding["status"].upper(),
                finding["remediation"] or "-",
            ]
        )
    table = Table(table_data, colWidths=[55, 45, 110, 45, 40, 155])
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

    doc.build(elements)
    return buffer.getvalue()
