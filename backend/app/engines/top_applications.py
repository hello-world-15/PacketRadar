"""
Top Applications Engine.

Aggregates per-process traffic — smoothed upload/download rate plus
active connection count — so the "Top Applications" table (ProcessTable
on the frontend) can rank which local process is responsible for the
most bandwidth. Structurally a near-mirror of TopTalkersEngine (same 5s
smoothing window, same connection-TTL pruning) with two differences that
fall directly out of what this widget needs instead of Top Talkers:

  - Credited by (pid, name), not IP — a process can hold many
    connections to many remote IPs; per-talker attribution already
    exists, this widget answers a different question ("what's using my
    bandwidth locally", not "who am I talking to").
  - Upload and download are tracked as two separate rolling windows
    instead of one combined figure, since the whole point of this
    widget is showing the up/down split per app (ProcessTable has
    separate Upload/Download columns) — Top Talkers only ever shows one
    number because "talker" doesn't have a meaningful direction of its
    own the way "my own process's traffic" does.

Only ever sees plain values handed in by the capture layer — no Scapy,
independently unit-testable. Which packets even reach this engine (only
ones the capture layer could attribute to a local pid via
ProcessResolver) is entirely the capture layer's concern, not this one's
— see docs/contracts/applications.md.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock

from app.schemas.applications import TopApplication

WINDOW_SECONDS = 5.0
CONNECTION_TTL = 30.0
DEFAULT_LIMIT = 12


@dataclass
class ByteEvent:
    timestamp: float
    length: int


@dataclass
class AppRecord:
    name: str
    upload_bytes: "deque[ByteEvent]" = field(default_factory=deque)
    download_bytes: "deque[ByteEvent]" = field(default_factory=deque)
    flows: dict = field(default_factory=dict)  # flow_key -> last_seen


class TopApplicationsEngine:
    def __init__(self) -> None:
        self._lock = Lock()
        self._apps: dict[int, AppRecord] = {}  # keyed by pid

    def record_packet(
        self, pid: int, name: str, length: int, direction: str, flow_key: str
    ) -> None:
        """Called by the capture layer for every TCP/UDP packet the
        capture layer could attribute to a local process. `direction`
        is "upload" or "download" — anything else is a caller bug and
        is dropped rather than guessed at."""
        if direction not in ("upload", "download"):
            return

        now = time.time()
        with self._lock:
            record = self._apps.get(pid)
            if record is None or record.name != name:
                # Either the first packet for this pid, or the OS
                # reused a pid for a different process since we last
                # saw it — start a fresh record rather than blending
                # one process's history into another's under a reused
                # pid. Same "don't let stale identity leak forward"
                # rule ProcessResolver's per-refresh name cache follows.
                record = AppRecord(name=name)
                self._apps[pid] = record

            bucket = record.upload_bytes if direction == "upload" else record.download_bytes
            bucket.append(ByteEvent(now, length))
            record.flows[flow_key] = now

    @staticmethod
    def _windowed_kbps(events: "deque[ByteEvent]", now: float) -> float:
        cutoff = now - WINDOW_SECONDS
        while events and events[0].timestamp < cutoff:
            events.popleft()
        total_bytes = sum(e.length for e in events)
        return round((total_bytes * 8) / 1000 / WINDOW_SECONDS, 2)

    def snapshot(self, limit: int = DEFAULT_LIMIT) -> list[TopApplication]:
        now = time.time()
        results: list[TopApplication] = []

        with self._lock:
            for pid, record in self._apps.items():
                upload_kbps = self._windowed_kbps(record.upload_bytes, now)
                download_kbps = self._windowed_kbps(record.download_bytes, now)

                active_flows = {
                    key: last_seen
                    for key, last_seen in record.flows.items()
                    if now - last_seen <= CONNECTION_TTL
                }
                record.flows = active_flows  # prune stale flows in place

                results.append(
                    TopApplication(
                        pid=pid,
                        name=record.name,
                        upload_kbps=upload_kbps,
                        download_kbps=download_kbps,
                        connections=len(active_flows),
                    )
                )

        results.sort(key=lambda a: a.upload_kbps + a.download_kbps, reverse=True)
        return results[:limit]
