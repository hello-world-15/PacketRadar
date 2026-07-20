"""
`POST /api/pcap/upload` — accepts a .pcap/.pcapng file, parses it through
the same PacketParser live capture uses, stores the result, returns the
Capture Summary. See docs/contracts/pcap-upload.md for the full contract.

`GET /api/pcap/{capture_id}/insights` — DNS Analysis + Threat Analysis +
Network Health Score. See docs/contracts/pcap-analysis.md.

`GET /api/pcap/{capture_id}/hosts-conversations` — Top Hosts +
Conversations. See docs/contracts/pcap-hosts-conversations.md.

`GET /api/pcap/{capture_id}/threats` — dedicated Threat Analysis
(episode/aggregate-based). See docs/contracts/pcap-threat-analysis.md.

`GET /api/pcap/{capture_id}/packets` — paginated Packet Explorer. See
docs/contracts/pcap-packet-explorer.md.

`GET /api/pcap/{capture_id}/protocol-timeline` — Protocol Distribution +
Traffic Timeline. See docs/contracts/pcap-protocol-timeline.md.

`GET /api/pcap/captures` — lists the .pcap files Live Monitor's "Start/Stop
Recording" has already saved to backend/captures (see
app.capture.sniffer.CAPTURES_DIR), newest first, so the frontend can offer
them as an alternative to uploading a file from disk.

`POST /api/pcap/captures/{filename}/analyze` — same parse-and-store flow as
`/upload`, but reads one of those already-recorded files off disk instead
of an uploaded multipart body. Returns the identical `PcapUploadResponse`
shape so the frontend can treat both entry points the same way afterward.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from scapy.utils import PcapReader

from app.cache.pcap_store import pcap_store
from app.capture.sniffer import CAPTURES_DIR
from app.engines.pcap_hosts_conversations import compute_hosts_conversations
from app.engines.pcap_insights import compute_insights
from app.engines.pcap_packet_explorer import MAX_LIMIT, paginate_packets
from app.engines.pcap_protocol_timeline import compute_protocol_timeline
from app.engines.pcap_summary import compute_summary
from app.engines.pcap_threat_analysis import analyze_threats
from app.models.packet import PacketModel
from app.parser.packet_parser import PacketParser
from app.schemas.pcap import (
    HostsConversations,
    PcapInsights,
    PcapPacketsResponse,
    PcapThreatsResponse,
    PcapUploadResponse,
    ProtocolTimeline,
    RecordedCapture,
)

router = APIRouter(prefix="/api/pcap", tags=["PCAP Analyzer"])

UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent / "pcap_uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

# Sanity bound so one huge file can't hang the request indefinitely or
# exhaust memory. Parsing stops at this cap rather than failing outright
# — the summary then reflects only what was actually parsed. See
# docs/contracts/pcap-upload.md's "Known limitations".
MAX_PACKETS = 200_000


def _parse_and_store(contents: bytes, filename: str) -> PcapUploadResponse:
    """Shared by `/upload` (bytes from a multipart body) and
    `/captures/{filename}/analyze` (bytes read off a recorded file in
    CAPTURES_DIR) — both just need "some .pcap/.pcapng bytes plus the
    name to report back" from here on. Always writes its own copy into
    UPLOAD_DIR under a fresh capture_id, same as the old inline version
    of this did, so pcap_store's 5-most-recent eviction and the rest of
    the PCAP Analyzer endpoints below don't need to know or care which
    entry point a given capture_id came from.
    """
    suffix = Path(filename).suffix.lower()
    capture_id = uuid.uuid4().hex
    dest = UPLOAD_DIR / f"{capture_id}{suffix}"
    dest.write_bytes(contents)

    packets: list[PacketModel] = []
    try:
        with PcapReader(str(dest)) as reader:
            for i, pkt in enumerate(reader):
                if i >= MAX_PACKETS:
                    break
                model = PacketParser.parse(
                    pkt,
                    interface="pcap-upload",
                    # Real capture time from the file itself, not "now" —
                    # see docs/contracts/pcap-upload.md's "timestamp bug".
                    timestamp=datetime.fromtimestamp(float(pkt.time)),
                )
                if model is not None:
                    packets.append(model)
    except HTTPException:
        raise
    except Exception as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(
            status_code=400,
            detail=f"Could not parse this file as a packet capture: {exc}",
        )

    if not packets:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="No readable packets found in this file.")

    summary = compute_summary(packets)
    pcap_store.save(capture_id, filename, packets, summary)

    return PcapUploadResponse(capture_id=capture_id, filename=filename, summary=summary)


@router.post("/upload", response_model=PcapUploadResponse)
async def upload_pcap(file: UploadFile = File(...)) -> PcapUploadResponse:
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix or 'unknown'}'. Expected .pcap or .pcapng.",
        )

    contents = await file.read()
    return _parse_and_store(contents, file.filename or f"upload{suffix}")


@router.get("/captures", response_model=list[RecordedCapture])
async def list_recorded_captures() -> list[RecordedCapture]:
    """Files Live Monitor's Start/Stop Recording has already saved to
    backend/captures (see app.capture.sniffer.CAPTURES_DIR) — an
    alternative source for the PCAP Analyzer's file picker alongside
    uploading from disk. Newest first, by file mtime (when the
    recording was stopped and the file finalized), not filename
    parsing — robust to any future change in how recordings are named.
    """
    if not CAPTURES_DIR.exists():
        return []

    files = [
        p for p in CAPTURES_DIR.iterdir() if p.is_file() and p.suffix.lower() in ALLOWED_EXTENSIONS
    ]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    return [
        RecordedCapture(
            filename=p.name,
            size_bytes=p.stat().st_size,
            captured_at=datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(),
        )
        for p in files
    ]


@router.post("/captures/{filename}/analyze", response_model=PcapUploadResponse)
async def analyze_recorded_capture(filename: str) -> PcapUploadResponse:
    """Same parse-and-store flow `/upload` uses, but the bytes come from
    an already-recorded file in CAPTURES_DIR instead of a fresh upload.
    `filename` must be a bare name with no path segments — rejected
    outright otherwise, so this can't be used to read arbitrary files
    off disk via '../' traversal.
    """
    safe_name = Path(filename).name
    if safe_name != filename or safe_name in ("", ".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename.")

    suffix = Path(safe_name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix or 'unknown'}'. Expected .pcap or .pcapng.",
        )

    src = CAPTURES_DIR / safe_name
    if not src.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"No recorded capture named '{safe_name}' found in backend/captures.",
        )

    contents = src.read_bytes()
    return _parse_and_store(contents, safe_name)


@router.get("/{capture_id}/insights", response_model=PcapInsights)
async def get_pcap_insights(capture_id: str) -> PcapInsights:
    """DNS Analysis + Threat Analysis + Network Health Score for an
    already-uploaded capture. Reads from the same pcap_store an earlier
    /upload call populated — does not re-parse the file. See
    docs/contracts/pcap-analysis.md."""
    analysis = pcap_store.get(capture_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail=f"No stored capture found for id '{capture_id}'. "
            "It may have expired (only the 5 most recent uploads are kept) "
            "or never existed — try re-uploading the file.",
        )

    return compute_insights(analysis.packets)


@router.get("/{capture_id}/hosts-conversations", response_model=HostsConversations)
async def get_hosts_conversations(capture_id: str) -> HostsConversations:
    """Top Hosts + Conversations for an already-uploaded capture. See
    docs/contracts/pcap-hosts-conversations.md. Reads from the same
    PcapAnalysisStore entry the upload endpoint above populated — no
    re-parsing."""
    analysis = pcap_store.get(capture_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Capture '{capture_id}' not found — it may have aged out "
                "(only the 5 most recent uploads are kept). Upload the file again."
            ),
        )
    return compute_hosts_conversations(analysis.packets, analysis.summary.duration_seconds)


@router.get("/{capture_id}/threats", response_model=PcapThreatsResponse)
async def get_pcap_threats(capture_id: str) -> PcapThreatsResponse:
    """Threat Analysis for an already-uploaded capture — Port Scan
    Detection and ARP Spoofing Detection, run once over the full stored
    capture. See docs/contracts/pcap-threat-analysis.md. This is the
    dedicated, episode/aggregate-based engine (app.engines.pcap_threat_analysis),
    not the simpler per-packet version bundled into /insights above."""
    analysis = pcap_store.get(capture_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail=f"No stored capture found for capture_id '{capture_id}'.",
        )
    return PcapThreatsResponse(threats=analyze_threats(analysis.packets))


@router.get("/{capture_id}/packets", response_model=PcapPacketsResponse)
async def get_pcap_packets(
    capture_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
) -> PcapPacketsResponse:
    """Paginated Packet Explorer rows for an already-uploaded capture —
    reads from the same stored parse, never re-reads the file. See
    docs/contracts/pcap-packet-explorer.md."""
    analysis = pcap_store.get(capture_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail=f"No stored capture found for capture_id '{capture_id}'.",
        )
    return paginate_packets(analysis.packets, offset=offset, limit=limit)


@router.get("/{capture_id}/protocol-timeline", response_model=ProtocolTimeline)
async def get_protocol_timeline(capture_id: str) -> ProtocolTimeline:
    """Protocol Distribution + Traffic Timeline for an already-uploaded
    capture. See docs/contracts/pcap-protocol-timeline.md. Reads from
    the same PcapAnalysisStore entry the upload endpoint above
    populated — no re-parsing."""
    analysis = pcap_store.get(capture_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Capture '{capture_id}' not found — it may have aged out "
                "(only the 5 most recent uploads are kept). Upload the file again."
            ),
        )
    return compute_protocol_timeline(analysis.packets)
