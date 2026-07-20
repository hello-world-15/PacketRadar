"""
Reusable table + badge builders shared by every section of the PDF.
Keeping this in one place is what makes every table in the report look
consistent — same header style, same zebra striping, same padding —
instead of each section reinventing it slightly differently.
"""

from __future__ import annotations

from typing import Optional, Sequence

from reportlab.lib import colors
from reportlab.platypus import Paragraph, Table, TableStyle

from app.report.styles import (
    BLUE,
    GRAY_LIGHT,
    GRAY_LIGHTER,
    NAVY,
    SEVERITY_BG,
    SEVERITY_COLORS,
    STYLES,
    WHITE,
    severity_label,
)


def styled_table(
    header: Sequence[str],
    rows: Sequence[Sequence[str]],
    col_widths: Optional[Sequence[float]] = None,
    align: Optional[Sequence[str]] = None,
) -> Table:
    """A modern, zebra-striped data table with a navy header row. Cell
    values are wrapped in Paragraphs so long strings (domains, evidence
    text) wrap instead of overflowing the page width."""
    header_row = [Paragraph(str(h), STYLES["TableHeader"]) for h in header]
    data = [header_row]
    for row in rows:
        data.append([Paragraph(str(c), STYLES["TableCell"]) for c in row])

    if not rows:
        data.append([Paragraph("No data available for this capture.", STYLES["TableCell"])]
                    + [Paragraph("", STYLES["TableCell"])] * (len(header) - 1))

    table = Table(data, colWidths=col_widths, repeatRows=1)

    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.3),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, 0), 0.75, NAVY),
        ("LINEBELOW", (0, -1), (-1, -1), 0.5, GRAY_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i in range(1, len(data)):
        bg = GRAY_LIGHTER if i % 2 == 0 else WHITE
        style.append(("BACKGROUND", (0, i), (-1, i), bg))
        style.append(("LINEBELOW", (0, i), (-1, i), 0.4, GRAY_LIGHT))

    if align:
        for col, a in enumerate(align):
            if a == "right":
                style.append(("ALIGN", (col, 0), (col, -1), "RIGHT"))
            elif a == "center":
                style.append(("ALIGN", (col, 0), (col, -1), "CENTER"))

    table.setStyle(TableStyle(style))
    return table


def severity_badge(sev: str) -> Table:
    """A small, rounded-looking colored pill for severity — implemented
    as a single-cell Table since ReportLab has no native rounded-rect
    flowable; the ROUNDEDCORNERS table command gives the pill shape."""
    label = severity_label(sev)
    color = SEVERITY_COLORS.get(sev, colors.HexColor("#5B6472"))
    bg = SEVERITY_BG.get(sev, colors.HexColor("#EBEDF0"))
    from reportlab.lib.styles import ParagraphStyle
    style = ParagraphStyle(
        f"Badge_{sev}", parent=STYLES["BadgeText"], textColor=color,
    )
    t = Table([[Paragraph(label, style)]], colWidths=[20 + len(label) * 5])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ("BOX", (0, 0), (-1, -1), 0.5, color),
    ]))
    return t
