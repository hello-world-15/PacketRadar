"""
PacketRadar backend — entrypoint.

Phase 5, Module 4: Continuous Capture + Start/Stop Recording + Export
PCAP (Modules 1-3 were the KPI cards, Passive Host Discovery, and Live
Packet Stream — see docs/contracts/).
Run with: uvicorn app.main:app --reload
(requires elevated privileges to capture packets — see README)

Sniffing starts here, once, at process boot via the lifespan handler
below, and runs for the app's lifetime — see app.capture.sniffer for why
that's now separate from "recording" (pcap export), which is toggled
on demand through app.api.capture. The watchdog task started alongside
it (app.capture.watchdog) detects a dead or stalled sniffer thread and
restarts it automatically — see that module's docstring.
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.capture import router as capture_router
from app.api.packets import router as packets_router
from app.api.pcap import router as pcap_router
from app.api.report import router as report_router
from app.capture.watchdog import capture_watchdog_loop
from app.state import capture
from app.ws.live_socket import router as live_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        capture.start()
    except Exception as exc:
        # Don't crash the whole API if e.g. we're not running as
        # root/Administrator — surface it via /api/capture/status
        # instead (capture.start_error) so the frontend can show a
        # clear message rather than the backend refusing to boot. The
        # watchdog task below still starts either way: if root gets
        # granted later without a full process restart, needs_restart()
        # won't fire for a sniffer that never started (see its
        # `ever_started` guard) — this failure mode still needs a
        # person to notice and act, same as before this task existed.
        print(f"[PacketRadar] Warning: packet capture did not start: {exc}")

    watchdog_task = asyncio.create_task(capture_watchdog_loop(capture))

    yield

    watchdog_task.cancel()
    capture.stop()


app = FastAPI(title="PacketRadar API", lifespan=lifespan)

# Vite dev server origin. Tighten this before shipping anything beyond
# local development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(live_router)
app.include_router(packets_router)
app.include_router(capture_router)
app.include_router(pcap_router)
app.include_router(report_router)


@app.get("/api/health")
def health_check() -> dict:
    return {"status": "ok"}
