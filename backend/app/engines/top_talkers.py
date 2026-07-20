"""
Top Talkers Engine.

Aggregates per-IP traffic — cumulative packet counts plus a smoothed
bandwidth rate — so the Top Talkers table can rank hosts by how much of
the network they're responsible for. Like the other engines, this only
ever sees plain strings/ints handed in by the capture layer; no Scapy.

See docs/contracts/talkers.md for the full field-by-field reasoning,
in particular why bandwidth is smoothed over 5s instead of reusing
StatisticsEngine's 1s window, and why both the source and destination
IP of every packet get credited.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock

from app.schemas.talkers import TopTalker

WINDOW_SECONDS = 5.0
CONNECTION_TTL = 30.0
DEFAULT_LIMIT = 12


@dataclass
class ByteEvent:
    timestamp: float
    length: int


@dataclass
class HostRecord:
    packets: int = 0
    recent_bytes: "deque[ByteEvent]" = field(default_factory=deque)
    flows: dict = field(default_factory=dict)  # flow_key -> last_seen


class TopTalkersEngine:
    def __init__(self) -> None:
        self._lock = Lock()
        self._hosts: dict[str, HostRecord] = {}

    def _credit(self, ip: str, length: int, flow_key: str, now: float) -> None:
        record = self._hosts.setdefault(ip, HostRecord())
        record.packets += 1
        record.recent_bytes.append(ByteEvent(now, length))
        record.flows[flow_key] = now

    def record_packet(self, src_ip: str, dst_ip: str, length: int, flow_key: str) -> None:
        """Called by the capture layer for every IP packet. Both source
        and destination are credited — see contract for why."""
        now = time.time()
        with self._lock:
            self._credit(src_ip, length, flow_key, now)
            if dst_ip != src_ip:
                self._credit(dst_ip, length, flow_key, now)

    @staticmethod
    def _evict_old_bytes(record: HostRecord, now: float) -> None:
        cutoff = now - WINDOW_SECONDS
        while record.recent_bytes and record.recent_bytes[0].timestamp < cutoff:
            record.recent_bytes.popleft()

    def snapshot(
        self, limit: int = DEFAULT_LIMIT, hostname_lookup: dict[str, str] | None = None
    ) -> list[TopTalker]:
        """`hostname_lookup` is an optional IP -> hostname map, borrowed
        from HostDiscoveryEngine.ip_hostnames() by the caller (see
        app.ws.live_socket) rather than resolved here — this engine
        stays IP-only and dependency-free, the same independence every
        other engine in this module keeps from the others; it just
        takes a plain dict, not a reference to another engine."""
        now = time.time()
        results: list[TopTalker] = []

        with self._lock:
            for ip, record in self._hosts.items():
                self._evict_old_bytes(record, now)
                windowed_bytes = sum(e.length for e in record.recent_bytes)
                bandwidth_mbps = round(
                    (windowed_bytes * 8) / 1_000_000 / WINDOW_SECONDS, 3
                )

                active_flows = {
                    key: last_seen
                    for key, last_seen in record.flows.items()
                    if now - last_seen <= CONNECTION_TTL
                }
                record.flows = active_flows  # prune stale flows in place

                results.append(
                    TopTalker(
                        ip=ip,
                        hostname=(hostname_lookup or {}).get(ip),
                        packets=record.packets,
                        bandwidth_mbps=bandwidth_mbps,
                        connections=len(active_flows),
                    )
                )

        results.sort(key=lambda t: t.bandwidth_mbps, reverse=True)
        top = results[:limit]

        max_bandwidth = top[0].bandwidth_mbps if top else 0.0
        for talker in top:
            talker.bandwidth_pct = (
                round((talker.bandwidth_mbps / max_bandwidth) * 100) if max_bandwidth > 0 else 0
            )

        return top
