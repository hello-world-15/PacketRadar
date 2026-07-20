"""
Chart generation for the PacketRadar PDF report.

Every function renders one Matplotlib figure to an in-memory PNG and
wraps it as a ReportLab `Image` flowable — `pdf_generator.py` never
touches Matplotlib directly, same separation of concerns as
`tables.py` for ReportLab `Table`s.
"""

from __future__ import annotations

import io
from typing import Sequence

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from reportlab.platypus import Image  # noqa: E402

from app.report.styles import CHART_PALETTE  # noqa: E402

_NAVY = "#0B1F3A"
_GRAY = "#5B6472"
_GRID = "#E7EBF0"

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 8.5,
    "text.color": _NAVY,
    "axes.edgecolor": _GRID,
    "axes.labelcolor": _GRAY,
    "xtick.color": _GRAY,
    "ytick.color": _GRAY,
    "axes.titlecolor": _NAVY,
    "axes.titleweight": "bold",
    "axes.titlesize": 10,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
})


def _fig_to_image(fig, width: float) -> Image:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    img = Image(buf)
    aspect = img.imageHeight / float(img.imageWidth)
    img.drawWidth = width
    img.drawHeight = width * aspect
    return img


def pie_chart(data: Sequence[tuple[str, float]], title: str, width: float = 250) -> Image:
    if not data:
        data = [("No data", 1)]
    labels = [d[0] for d in data]
    values = [d[1] for d in data]
    fig, ax = plt.subplots(figsize=(4.6, 3.4))
    wedges, _texts, autotexts = ax.pie(
        values, labels=None, autopct=lambda p: f"{p:.0f}%" if p >= 4 else "",
        startangle=90, colors=CHART_PALETTE, wedgeprops={"edgecolor": "white", "linewidth": 1.2},
        pctdistance=0.78,
    )
    for t in autotexts:
        t.set_color("white")
        t.set_fontsize(7.5)
        t.set_fontweight("bold")
    ax.legend(wedges, labels, loc="center left", bbox_to_anchor=(1.0, 0.5),
              fontsize=7.5, frameon=False)
    ax.set_title(title)
    ax.axis("equal")
    return _fig_to_image(fig, width)


def bar_chart(
    data: Sequence[tuple[str, float]], title: str, ylabel: str = "Packets",
    width: float = 250, horizontal: bool = False,
) -> Image:
    if not data:
        data = [("No data", 0)]
    labels = [str(d[0]) for d in data]
    values = [d[1] for d in data]
    fig, ax = plt.subplots(figsize=(4.8, 3.2))

    if horizontal:
        y_pos = range(len(labels))
        ax.barh(y_pos, values, color=CHART_PALETTE[0], height=0.6)
        ax.set_yticks(list(y_pos))
        ax.set_yticklabels(labels, fontsize=7.5)
        ax.invert_yaxis()
        ax.set_xlabel(ylabel)
        ax.grid(axis="x", color=_GRID, linewidth=0.8)
    else:
        ax.bar(labels, values, color=CHART_PALETTE[0], width=0.6)
        ax.set_ylabel(ylabel)
        ax.tick_params(axis="x", rotation=35)
        ax.grid(axis="y", color=_GRID, linewidth=0.8)

    ax.set_title(title)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    return _fig_to_image(fig, width)


def line_chart(
    points: Sequence[tuple[str, float]], title: str, ylabel: str,
    width: float = 480, color: str = "#1B4F9C",
) -> Image:
    if not points:
        points = [("", 0)]
    labels = [p[0] for p in points]
    values = [p[1] for p in points]
    fig, ax = plt.subplots(figsize=(8.6, 2.6))
    ax.plot(range(len(values)), values, color=color, linewidth=1.6)
    ax.fill_between(range(len(values)), values, color=color, alpha=0.12)
    step = max(1, len(labels) // 10)
    ax.set_xticks(range(0, len(labels), step))
    ax.set_xticklabels([labels[i] for i in range(0, len(labels), step)], fontsize=7, rotation=30)
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", color=_GRID, linewidth=0.8)
    ax.set_title(title)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    return _fig_to_image(fig, width)


def severity_distribution_chart(counts: dict[str, int], width: float = 250) -> Image:
    order = ["critical", "high", "medium", "low", "informational"]
    sev_colors = {
        "critical": "#C0392B", "high": "#E67E22", "medium": "#D4AC0D",
        "low": "#2E8B57", "informational": "#5B6472",
    }
    labels = [s.capitalize() for s in order]
    values = [counts.get(s, 0) for s in order]
    colors_ = [sev_colors[s] for s in order]

    fig, ax = plt.subplots(figsize=(4.8, 3.2))
    ax.bar(labels, values, color=colors_, width=0.55)
    ax.set_ylabel("Alerts")
    ax.set_title("Alerts by Severity")
    ax.grid(axis="y", color=_GRID, linewidth=0.8)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for i, v in enumerate(values):
        ax.text(i, v, str(v), ha="center", va="bottom", fontsize=8, color=_NAVY, fontweight="bold")
    fig.tight_layout()
    return _fig_to_image(fig, width)
