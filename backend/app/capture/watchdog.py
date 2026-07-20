"""
Capture watchdog — background task that detects a dead or stalled
sniffer thread and restarts it automatically.

Two independent failure modes this exists to catch (see
PacketCapture.is_running / last_packet_at's docstrings in sniffer.py
for the full reasoning behind each signal):

  1. Thread death: the AsyncSniffer thread exits on its own (NIC
     sleep/wake, an interface dropping, an unhandled exception inside
     Scapy's own recv loop) without anything else calling stop().
     `is_running` — fixed to check real thread liveness, not just
     object presence — catches this.
  2. Silent stall: the thread is alive but the OS capture buffer has
     stopped delivering packets to it. `is_running` alone can't see
     this; only the packet heartbeat (`last_packet_at`) can.

Runs independently of whether any WebSocket client is connected, tied
to the app's lifespan (see app.main) rather than to `/ws/live` — the
sniffer itself is always-on regardless of WS connections, so its
watchdog needs to be too. This is also why it lives here rather than
alongside the broadcast loops in app.ws.live_socket: those are
WS-broadcast concerns, this is a capture-lifecycle concern.
"""

from __future__ import annotations

import asyncio
import time

from app.capture.sniffer import PacketCapture

CHECK_INTERVAL_SECONDS = 2.0

# How long without a packet, while the thread claims to be alive,
# before treating capture as stalled. Deliberately well above normal
# lulls in traffic so a quiet LAN doesn't trigger spurious restarts —
# matches the frontend's own (advisory-only) STALE_HEARTBEAT_SECONDS in
# src/hooks/useCaptureControl.ts. Kept in sync manually since one lives
# in Python and the other in TypeScript; if you change one, change both.
STALE_HEARTBEAT_SECONDS = 15.0

# Minimum time between restart attempts. A sniffer that fails to (re)start
# for a persistent reason (e.g. permissions revoked mid-session, interface
# removed) would otherwise spin this loop as fast as CHECK_INTERVAL_SECONDS
# allows. Fixed cooldown rather than exponential backoff — simple, and
# this should fire rarely enough that backoff isn't worth the complexity
# yet; a natural follow-up if repeated-failure logs ever show otherwise.
RESTART_COOLDOWN_SECONDS = 5.0


def needs_restart(
    *,
    is_running: bool,
    ever_started: bool,
    last_packet_at: float | None,
    now: float,
    stale_after_seconds: float = STALE_HEARTBEAT_SECONDS,
) -> bool:
    """Pure decision function, deliberately kept separate from the
    asyncio loop below so it's unit-testable without threads or timers.

    `ever_started` guards the dead-thread branch: a sniffer that has
    never successfully started (e.g. missing root — already surfaced
    via capture_error) shouldn't be treated as "died," since it never
    lived. That's a startup problem for the person running the app to
    fix, not something restarting will resolve.
    """
    if not is_running:
        return ever_started
    if last_packet_at is None:
        return False  # just (re)started, hasn't seen a packet yet
    return (now - last_packet_at) > stale_after_seconds


async def capture_watchdog_loop(capture: PacketCapture) -> None:
    """Checks capture health every CHECK_INTERVAL_SECONDS and calls
    capture.restart() when needs_restart() says to, subject to
    RESTART_COOLDOWN_SECONDS. Runs forever — cancel the task to stop it
    (see app.main's lifespan)."""
    last_attempt_at = 0.0
    while True:
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
        now = time.time()

        if not needs_restart(
            is_running=capture.is_running,
            ever_started=capture.ever_started,
            last_packet_at=capture.last_packet_at,
            now=now,
        ):
            continue

        if now - last_attempt_at < RESTART_COOLDOWN_SECONDS:
            continue
        last_attempt_at = now

        try:
            capture.restart()
        except Exception:
            # restart() -> start() already records failure via
            # start_error, which the API/frontend already surface.
            # Nothing more to do here than try again next tick, same
            # as any other transient start() failure.
            pass
