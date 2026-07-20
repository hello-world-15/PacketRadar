"""
Shared design tokens for the PacketRadar PDF report — the single place
that defines the blue/gray cybersecurity theme so every other module
(tables.py, charts.py, pdf_generator.py) draws from the same palette
instead of hardcoding colors independently.
"""

from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------

NAVY = colors.HexColor("#0B1F3A")
BLUE = colors.HexColor("#1B4F9C")
BLUE_LIGHT = colors.HexColor("#3E7CC9")
ACCENT = colors.HexColor("#00B4D8")
GRAY_DARK = colors.HexColor("#2E3440")
GRAY = colors.HexColor("#5B6472")
GRAY_LIGHT = colors.HexColor("#E7EBF0")
GRAY_LIGHTER = colors.HexColor("#F4F6F9")
WHITE = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#C0392B"),
    "high": colors.HexColor("#E67E22"),
    "medium": colors.HexColor("#D4AC0D"),
    "low": colors.HexColor("#2E8B57"),
    "informational": colors.HexColor("#5B6472"),
}

SEVERITY_BG = {
    "critical": colors.HexColor("#FBE4E1"),
    "high": colors.HexColor("#FCEBD9"),
    "medium": colors.HexColor("#FBF3D3"),
    "low": colors.HexColor("#E1F0E6"),
    "informational": colors.HexColor("#EBEDF0"),
}

CHART_PALETTE = [
    "#1B4F9C", "#00B4D8", "#5B6472", "#E67E22", "#2E8B57",
    "#C0392B", "#8E7CC3", "#D4AC0D", "#3E7CC9", "#0B1F3A",
]

PAGE_SIZE = A4
MARGIN = 18 * mm

# ---------------------------------------------------------------------------
# Typography
# ---------------------------------------------------------------------------

_base = getSampleStyleSheet()

STYLES = {
    "CoverTitle": ParagraphStyle(
        "CoverTitle", parent=_base["Title"], fontName="Helvetica-Bold",
        fontSize=30, leading=34, textColor=WHITE, alignment=TA_LEFT,
    ),
    "CoverSubtitle": ParagraphStyle(
        "CoverSubtitle", parent=_base["Normal"], fontName="Helvetica",
        fontSize=14, leading=18, textColor=colors.HexColor("#C7D6EC"),
        alignment=TA_LEFT,
    ),
    "CoverMeta": ParagraphStyle(
        "CoverMeta", parent=_base["Normal"], fontName="Helvetica",
        fontSize=10, leading=15, textColor=colors.HexColor("#DCE6F5"),
    ),
    "SectionHeading": ParagraphStyle(
        "SectionHeading", parent=_base["Heading1"], fontName="Helvetica-Bold",
        fontSize=17, leading=21, textColor=NAVY, spaceBefore=0, spaceAfter=10,
        borderPadding=0,
    ),
    "SubHeading": ParagraphStyle(
        "SubHeading", parent=_base["Heading2"], fontName="Helvetica-Bold",
        fontSize=12.5, leading=16, textColor=BLUE, spaceBefore=12, spaceAfter=6,
    ),
    "Body": ParagraphStyle(
        "Body", parent=_base["Normal"], fontName="Helvetica", fontSize=9.5,
        leading=14, textColor=GRAY_DARK,
    ),
    "BodyMuted": ParagraphStyle(
        "BodyMuted", parent=_base["Normal"], fontName="Helvetica-Oblique",
        fontSize=8.5, leading=12, textColor=GRAY,
    ),
    "TocEntry": ParagraphStyle(
        "TocEntry", parent=_base["Normal"], fontName="Helvetica", fontSize=11,
        leading=20, textColor=GRAY_DARK,
    ),
    "CardLabel": ParagraphStyle(
        "CardLabel", parent=_base["Normal"], fontName="Helvetica", fontSize=8,
        leading=10, textColor=GRAY, alignment=TA_CENTER,
    ),
    "CardValue": ParagraphStyle(
        "CardValue", parent=_base["Normal"], fontName="Helvetica-Bold", fontSize=16,
        leading=19, textColor=NAVY, alignment=TA_CENTER,
    ),
    "TableHeader": ParagraphStyle(
        "TableHeader", parent=_base["Normal"], fontName="Helvetica-Bold",
        fontSize=8.5, leading=11, textColor=WHITE,
    ),
    "TableCell": ParagraphStyle(
        "TableCell", parent=_base["Normal"], fontName="Helvetica", fontSize=8.3,
        leading=11, textColor=GRAY_DARK,
    ),
    "BadgeText": ParagraphStyle(
        "BadgeText", parent=_base["Normal"], fontName="Helvetica-Bold", fontSize=8,
        leading=10, alignment=TA_CENTER,
    ),
}


def severity_label(sev: str) -> str:
    return {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
            "low": "LOW", "informational": "INFO"}.get(sev, sev.upper())
