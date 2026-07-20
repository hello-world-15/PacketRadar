"""
Statistics Engine.

Owns a rolling 1-second window of packet events and derives the numbers
the "stats" widget group needs. This is intentionally the only place that
computes these numbers — the WebSocket layer just reads a snapshot and
serializes it; it must never do its own math.

Design notes:
- We keep a small deque of (timestamp, length) tuples rather than a full
  packet history, so memory stays bounded regardless of capture duration.
- "Active connections" uses a TTL-based flow table: a flow is considered
  active if a packet was seen for it within the last CONNECTION_TTL
  seconds. This avoids connections accumulating forever in a long capture.
- "Dropped packets" counts events the capture layer couldn't enqueue fast
  enough for us to process (see capture/sniffer.py) — it is NOT a Scapy/
  libpcap-level drop counter, since that isn't reliably exposed cross
  platform. Documented as a known limitation, not hidden.
- "Protocol distribution" is a *cumulative* Counter, not windowed like
  packets_per_sec — a distribution pie that resets every second and
  flickers back to empty is useless. It just grows for the process's
  lifetime, the same way dropped_packets already does. The frontend
  computes percentages from the raw counts, we just hand over totals.
- "Upload/download split" (Module 6) reuses this same rolling 1s window
  rather than a second one — direction is just another dimension of the
  same per-packet event, not a different cadence or data source. Each
  PacketEvent optionally carries a `direction` ("upload"/"download"/None)
  decided by the capture layer (see app.capture.sniffer and
  app.capture.local_ip); packets with no determinable direction (traffic
  between two other LAN hosts, or if local-IP resolution failed
  entirely) still count toward the combined `bandwidth_mbps` total but
  are excluded from both `upload_mbps` and `download_mbps` rather than
  guessed at. See docs/contracts/stats.md for the full reasoning.
"""

from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass, field
from threading import Lock

from app.schemas.stats import LiveStats, ProtocolCount

WINDOW_SECONDS = 1.0
CONNECTION_TTL = 30.0


@dataclass
class PacketEvent:
    timestamp: float
    length: int
    flow_key: str
    # "upload" | "download" | None (unknown/excluded) — defaults to None
    # so existing call sites/tests that predate Module 6 don't need to
    # supply it.
    direction: str | None = None


class StatisticsEngine:
    def __init__(self) -> None:
        self._lock = Lock()
        self._recent: deque[PacketEvent] = deque()
        self._flows: dict[str, float] = {}
        self._dropped_packets = 0
        self._protocol_counts: Counter[str] = Counter()

    def record_packet(
        self,
        length: int,
        flow_key: str,
        protocol: str = "Other",
        direction: str | None = None,
    ) -> None:
        """Called by the capture layer for every parsed packet.

        `protocol` defaults to "Other" and `direction` defaults to None
        so existing call sites (and tests) that only care about the
        windowed/protocol stats don't need to supply every argument —
        each is an additive concern layered on top of the same event.
        `direction` should be "upload", "download", or None (unknown —
        see module docstring for when that happens).
        """
        now = time.time()
        with self._lock:
            self._recent.append(PacketEvent(now, length, flow_key, direction))
            self._flows[flow_key] = now
            self._protocol_counts[protocol] += 1
            self._evict_old(now)

    def record_dropped(self, count: int = 1) -> None:
        """Called by the capture layer when it has to discard packets
        because the processing queue is full."""
        with self._lock:
            self._dropped_packets += count

    def _evict_old(self, now: float) -> None:
        cutoff = now - WINDOW_SECONDS
        while self._recent and self._recent[0].timestamp < cutoff:
            self._recent.popleft()

    def snapshot(self) -> LiveStats:
        """Compute a point-in-time view of current stats. Safe to call
        from the asyncio broadcast loop on a timer."""
        now = time.time()
        with self._lock:
            self._evict_old(now)
            packets_in_window = list(self._recent)

            active_flows = [
                key for key, last_seen in self._flows.items()
                if now - last_seen <= CONNECTION_TTL
            ]
            # Periodically prune stale flows so the dict doesn't grow forever.
            self._flows = {k: v for k, v in self._flows.items() if k in active_flows}

            total_bytes = sum(p.length for p in packets_in_window)
            packets_per_sec = len(packets_in_window)
            bandwidth_mbps = round((total_bytes * 8) / 1_000_000, 2)

            # Same windowed events, just partitioned by direction — see
            # module docstring. Packets with direction=None (excluded,
            # not guessed at) contribute to bandwidth_mbps above but
            # neither of these.
            upload_bytes = sum(p.length for p in packets_in_window if p.direction == "upload")
            download_bytes = sum(p.length for p in packets_in_window if p.direction == "download")
            upload_mbps = round((upload_bytes * 8) / 1_000_000, 2)
            download_mbps = round((download_bytes * 8) / 1_000_000, 2)

            # Cumulative, not windowed — see module docstring. Snapshotted
            # under the same lock as everything else so a concurrent
            # record_packet() can't be observed mid-update.
            protocol_distribution = [
                ProtocolCount(label=label, value=count)
                for label, count in self._protocol_counts.items()
            ]

            return LiveStats(
                packets_per_sec=packets_per_sec,
                bandwidth_mbps=bandwidth_mbps,
                upload_mbps=upload_mbps,
                download_mbps=download_mbps,
                active_connections=len(active_flows),
                threat_alert_count=0,  # TODO: wire up once Threat Detection Engine exists
                lan_device_count=0,    # TODO: wire up once Host Discovery module exists
                dropped_packets=self._dropped_packets,
                protocol_distribution=protocol_distribution,
            )
