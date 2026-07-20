"""
Capture status + Start/Stop Recording + Export PCAP (Phase 5, Module 4).

Sniffing itself is always-on (started once at app boot — see
app.main's lifespan) and isn't controlled from here. What *is* exposed
here is "recording": a start/stop toggle that streams the
already-running capture out to a .pcap file, independent of whether
sniffing itself is up.

Plain REST rather than another WebSocket event type — starting/stopping
a recording is a one-shot command, not a stream, and the frontend's
Navbar already polls `/status` on an interval to drive its indicator and
elapsed timer (see src/hooks/useCaptureControl.ts).
"""

from __future__ import annotations

from pydantic import BaseModel

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.state import capture

router = APIRouter(prefix="/api/capture", tags=["Capture"])


class CaptureStatus(BaseModel):
    capturing: bool  # true only if the sniffer thread is actually alive right now
    capture_error: str | None  # set if start() failed, or if a running sniffer's thread died
    interface: str | None
    last_packet_at: float | None  # unix seconds; heartbeat — see PacketCapture.last_packet_at
    recording: bool
    recording_started_at: float | None  # unix seconds
    packet_count: int  # packets in the current/last recording session
    export_ready: bool


def _status() -> CaptureStatus:
    started_at = capture.recording_started_at
    session = capture.last_session
    running = capture.is_running
    # start_error covers "start() itself failed" (e.g. missing root).
    # sniffer_exception covers the other failure mode this module adds:
    # a thread that started fine but died later. Only surface the latter
    # once we know the thread is actually down — while it's alive,
    # `.exception` would be stale from a previous run, not this one.
    capture_error = capture.start_error or (None if running else capture.sniffer_exception)
    return CaptureStatus(
        capturing=running,
        capture_error=capture_error,
        interface=capture.interface,
        last_packet_at=capture.last_packet_at,
        recording=capture.is_recording,
        recording_started_at=started_at.timestamp() if started_at else None,
        packet_count=capture.recording_packet_count,
        export_ready=session is not None and session.path.exists(),
    )


@router.get("/status", response_model=CaptureStatus)
def get_status() -> CaptureStatus:
    return _status()


@router.post("/record/start", response_model=CaptureStatus)
def start_recording() -> CaptureStatus:
    try:
        capture.start_recording()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _status()


@router.post("/record/stop", response_model=CaptureStatus)
def stop_recording() -> CaptureStatus:
    if not capture.is_recording:
        raise HTTPException(status_code=409, detail="Recording is not active.")
    capture.stop_recording()
    return _status()


@router.get("/export")
def export_pcap() -> FileResponse:
    session = capture.last_session
    if session is None or not session.path.exists():
        raise HTTPException(
            status_code=404,
            detail="No completed recording yet — start and stop a recording first.",
        )
    return FileResponse(
        path=str(session.path),
        media_type="application/vnd.tcpdump.pcap",
        filename=session.path.name,
    )
