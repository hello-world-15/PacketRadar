"""
`GET /api/pcap/{capture_id}/report.pdf` — generates the professional
PCAP Analysis PDF report for an already-uploaded/analyzed capture.

Reads from the same `pcap_store` every other PCAP Analyzer endpoint in
`app.api.pcap` reads from (no re-parsing), builds the structured
`Report` object via `app.report.report_builder.build_report`, then
renders it to PDF bytes via `app.report.pdf_generator.generate_pdf`.
Kept in its own router/file (rather than folded into `app.api.pcap`)
since report generation is a meaningfully separate concern — heavier,
slower, and with its own dependency surface (ReportLab, Matplotlib) —
from the lightweight JSON endpoints there.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.api.pcap import UPLOAD_DIR
from app.cache.pcap_store import pcap_store
from app.report.pdf_generator import generate_pdf
from app.report.report_builder import build_report

router = APIRouter(prefix="/api/pcap", tags=["PCAP Analyzer"])


def _stored_file_size(capture_id: str) -> int:
    """Best-effort lookup of the original uploaded file's size on disk —
    `PcapAnalysis` doesn't carry this itself, so it's read from
    `UPLOAD_DIR` by capture_id prefix (same naming `_parse_and_store`
    in app.api.pcap uses: `{capture_id}{suffix}`). Falls back to 0
    (rendered as "0 B") if the file was since removed — report
    generation should never hard-fail just because this one field is
    unavailable.
    """
    for suffix in (".pcap", ".pcapng"):
        candidate = UPLOAD_DIR / f"{capture_id}{suffix}"
        if candidate.is_file():
            return candidate.stat().st_size
    return 0


@router.get("/{capture_id}/report.pdf")
async def get_pcap_report(capture_id: str) -> Response:
    """Generates and returns the full PCAP Analysis PDF report for a
    previously uploaded/analyzed capture."""
    analysis = pcap_store.get(capture_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Capture '{capture_id}' not found — it may have aged out "
                "(only the 5 most recent uploads are kept). Upload the file again."
            ),
        )

    report = build_report(analysis, file_size_bytes=_stored_file_size(capture_id))
    pdf_bytes = generate_pdf(report)

    safe_name = Path(analysis.filename).stem or "capture"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{safe_name}_report.pdf"'},
    )
