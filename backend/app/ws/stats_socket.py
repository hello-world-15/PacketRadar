"""
`/ws/stats` — pushes a LiveStats snapshot once per second, per the
docs/contracts/stats.md cadence.

Capture lifecycle for this first module: starts capturing when the first
client connects, stops when the last client disconnects. This is a
deliberate simplification — the real Start/Stop Capture button (a
separate widget, not yet built) will eventually own this instead. Noted
here so it isn't mistaken for the final design.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.capture.sniffer import PacketCapture
from app.engines.statistics import StatisticsEngine
from app.schemas.stats import StatsUpdateEvent
from app.ws.manager import ConnectionManager

router = APIRouter()

stats_engine = StatisticsEngine()
manager = ConnectionManager()
capture = PacketCapture(stats_engine)

BROADCAST_INTERVAL_SECONDS = 1.0
_broadcast_task: asyncio.Task | None = None


async def _broadcast_loop() -> None:
    while True:
        await asyncio.sleep(BROADCAST_INTERVAL_SECONDS)
        if manager.active_count == 0:
            continue
        event = StatsUpdateEvent(data=stats_engine.snapshot())
        await manager.broadcast_json(event.model_dump())


@router.websocket("/ws/stats")
async def stats_socket(websocket: WebSocket) -> None:
    global _broadcast_task

    await manager.connect(websocket)

    if not capture.is_running:
        capture.start()

    if _broadcast_task is None or _broadcast_task.done():
        _broadcast_task = asyncio.create_task(_broadcast_loop())

    try:
        while True:
            # We don't expect the client to send anything on this socket
            # today; this just keeps the connection open and detects
            # disconnects promptly.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        if manager.active_count == 0:
            capture.stop()
