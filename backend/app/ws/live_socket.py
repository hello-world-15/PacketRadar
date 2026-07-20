"""
`/ws/live` — a single shared WebSocket multiplexing multiple event types
by their `type` field, rather than one socket per widget.

This replaces Module 1's `/ws/stats` (see git history / stats.md) — Host
Discovery (Module 2) needed a second event type, and a second socket
would have meant duplicating capture-lifecycle management for no real
benefit. `ws/manager.py` already anticipated this.

Event types on this socket:
  - "stats:update"    — every 1s    (docs/contracts/stats.md)
  - "hosts:update"    — every 3s    (docs/contracts/hosts.md)
  - "packets:update"  — every 0.5s, delta-only (docs/contracts/packets.md)
  - "talkers:update"  — every 2s    (docs/contracts/talkers.md)
  - "threats:update"  — every 1s, delta-only (docs/contracts/threats.md)
  - "applications:update" — every 2s (docs/contracts/applications.md)

Capture lifecycle (Phase 5, Module 4): capture start/stop is now driven
explicitly by the Start/Stop Capture button — see `app.api.capture` —
rather than implicitly by WebSocket connect/disconnect. This socket only
manages its own broadcast loops now; if no capture session is running,
`stats:update`/`packets:update` simply keep reporting zeros, which is the
correct idle state for the dashboard to show.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.schemas.applications import ApplicationsUpdateEvent
from app.schemas.hosts import HostsUpdateEvent
from app.schemas.packets import PacketsUpdateEvent
from app.schemas.stats import StatsUpdateEvent
from app.schemas.talkers import TalkersUpdateEvent
from app.schemas.threats_live import ThreatsUpdateEvent
from app.state import (
    apps_engine,
    host_engine,
    manager,
    packet_engine,
    stats_engine,
    talkers_engine,
    threat_engine,
)

router = APIRouter()

STATS_INTERVAL_SECONDS = 1.0
HOSTS_INTERVAL_SECONDS = 3.0
PACKETS_INTERVAL_SECONDS = 0.5
TALKERS_INTERVAL_SECONDS = 2.0
THREATS_INTERVAL_SECONDS = 1.0
APPLICATIONS_INTERVAL_SECONDS = 2.0
PACKETS_BACKLOG_ON_CONNECT = 100
THREATS_BACKLOG_ON_CONNECT = 50

_stats_task: asyncio.Task | None = None
_hosts_task: asyncio.Task | None = None
_packets_task: asyncio.Task | None = None
_talkers_task: asyncio.Task | None = None
_threats_task: asyncio.Task | None = None
_applications_task: asyncio.Task | None = None

# Shared cursor for the packets:update broadcast loop. Deliberately a
# single module-level value, not per-connection state — `manager` is a
# broadcast-to-everyone registry on purpose (see ws/manager.py), and
# tracking a separate cursor per client would mean building the pub/sub
# system that module's docstring explicitly avoids. The trade-off: a
# client that connects mid-tick only gets packets from that point
# forward via the loop — which is why we also send a one-time backlog
# frame directly to it on connect (see `live_socket` below).
_last_broadcast_no = 0

# Same pattern, same trade-off, for threats:update — see docs/contracts/threats.md.
_last_threat_broadcast_no = 0


async def _stats_loop() -> None:
    while True:
        await asyncio.sleep(STATS_INTERVAL_SECONDS)
        if manager.active_count == 0:
            continue
        stats = stats_engine.snapshot()
        # lan_device_count was stubbed at 0 in Module 1 — now real.
        stats.lan_device_count = host_engine.online_count()
        # threat_alert_count was stubbed at 0 in Module 1 — now real,
        # same pattern (see docs/contracts/threats.md).
        stats.threat_alert_count = threat_engine.alert_count
        event = StatsUpdateEvent(data=stats)
        await manager.broadcast_json(event.model_dump())


async def _hosts_loop() -> None:
    while True:
        await asyncio.sleep(HOSTS_INTERVAL_SECONDS)
        if manager.active_count == 0:
            continue
        event = HostsUpdateEvent(data=host_engine.snapshot())
        await manager.broadcast_json(event.model_dump())


async def _packets_loop() -> None:
    global _last_broadcast_no
    while True:
        await asyncio.sleep(PACKETS_INTERVAL_SECONDS)
        if manager.active_count == 0:
            continue
        new_rows = packet_engine.since(_last_broadcast_no)
        if not new_rows:
            continue
        _last_broadcast_no = new_rows[-1].no
        event = PacketsUpdateEvent(data=new_rows)
        await manager.broadcast_json(event.model_dump())


async def _talkers_loop() -> None:
    while True:
        await asyncio.sleep(TALKERS_INTERVAL_SECONDS)
        if manager.active_count == 0:
            continue
        # Borrow host_engine's IP->hostname map rather than giving
        # TopTalkersEngine its own resolver — one resolver, one cache,
        # one cooldown; see docs/contracts/talkers.md.
        event = TalkersUpdateEvent(
            data=talkers_engine.snapshot(hostname_lookup=host_engine.ip_hostnames())
        )
        await manager.broadcast_json(event.model_dump())


async def _threats_loop() -> None:
    global _last_threat_broadcast_no
    while True:
        await asyncio.sleep(THREATS_INTERVAL_SECONDS)
        if manager.active_count == 0:
            continue
        new_rows = threat_engine.since(_last_threat_broadcast_no)
        if not new_rows:
            continue
        _last_threat_broadcast_no = new_rows[-1].no
        event = ThreatsUpdateEvent(data=new_rows)
        await manager.broadcast_json(event.model_dump())


async def _applications_loop() -> None:
    while True:
        await asyncio.sleep(APPLICATIONS_INTERVAL_SECONDS)
        if manager.active_count == 0:
            continue
        event = ApplicationsUpdateEvent(data=apps_engine.snapshot())
        await manager.broadcast_json(event.model_dump())


@router.websocket("/ws/live")
async def live_socket(websocket: WebSocket) -> None:
    global _stats_task, _hosts_task, _packets_task, _talkers_task, _threats_task, _applications_task

    await manager.connect(websocket)

    if _stats_task is None or _stats_task.done():
        _stats_task = asyncio.create_task(_stats_loop())
    if _hosts_task is None or _hosts_task.done():
        _hosts_task = asyncio.create_task(_hosts_loop())
    if _packets_task is None or _packets_task.done():
        _packets_task = asyncio.create_task(_packets_loop())
    if _talkers_task is None or _talkers_task.done():
        _talkers_task = asyncio.create_task(_talkers_loop())
    if _threats_task is None or _threats_task.done():
        _threats_task = asyncio.create_task(_threats_loop())
    if _applications_task is None or _applications_task.done():
        _applications_task = asyncio.create_task(_applications_loop())

    # One-time backlog so a client that just connected doesn't stare at
    # an empty table until the next 0.5s tick — see docs/contracts/packets.md.
    backlog = packet_engine.backlog(PACKETS_BACKLOG_ON_CONNECT)
    if backlog:
        await websocket.send_json(PacketsUpdateEvent(data=backlog).model_dump())

    # Same idea for threats — see docs/contracts/threats.md.
    threats_backlog = threat_engine.backlog(THREATS_BACKLOG_ON_CONNECT)
    if threats_backlog:
        await websocket.send_json(ThreatsUpdateEvent(data=threats_backlog).model_dump())

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
