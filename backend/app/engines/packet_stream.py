"""
Packet Stream Engine.

Owns a bounded ring buffer of parsed packets for the Live Packet Stream
table and assigns each one a monotonically increasing sequence number
(`no`). Like StatisticsEngine and HostDiscoveryEngine, this class knows
nothing about Scapy — it only ever receives plain fields the capture
layer has already extracted, so it's independently unit-testable
without a live capture or root privileges.

Unlike Host Discovery, this is a **delta** feed, not a snapshot: asking
"give me everything" every broadcast tick would mean re-serializing the
whole buffer to deliver one new row. Callers instead ask for "everything
after sequence N" — see docs/contracts/packets.md for the reasoning.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Optional

from app.schemas.packets import PacketStreamRow

DEFAULT_MAX_BUFFER = 2000


@dataclass
class ParsedPacket:
    """What the capture layer hands us per packet — already Scapy-free."""

    source: str
    destination: str
    protocol: str
    length: int
    info: str = ""
    process: Optional[str] = None
    dns_query: Optional[str] = None
    dns_answer: Optional[str] = None


class PacketStreamEngine:
    def __init__(self, max_buffer: int = DEFAULT_MAX_BUFFER) -> None:
        self._lock = Lock()
        self._buffer: deque[PacketStreamRow] = deque(maxlen=max_buffer)
        self._seq = 0

    def record(self, packet: ParsedPacket) -> PacketStreamRow:
        """Called by the capture layer for every parsed packet."""
        with self._lock:
            self._seq += 1
            row = PacketStreamRow(
                no=self._seq,
                time=time.time(),
                source=packet.source,
                destination=packet.destination,
                protocol=packet.protocol,
                length=packet.length,
                process=packet.process,
                info=packet.info,
                dns_query=packet.dns_query,
                dns_answer=packet.dns_answer,
            )
            self._buffer.append(row)
            return row

    def since(self, last_no: int, limit: int = 500) -> list[PacketStreamRow]:
        """Every buffered row with `no` greater than `last_no`, oldest
        first, capped at `limit` — protects a stalled client's next
        frame from ballooning to thousands of rows."""
        with self._lock:
            rows = [r for r in self._buffer if r.no > last_no]
        return rows[-limit:] if len(rows) > limit else rows

    def backlog(self, limit: int = 100) -> list[PacketStreamRow]:
        """Most recently buffered rows, oldest first — used to populate
        a newly connected client immediately instead of leaving the
        table blank until the next broadcast tick."""
        with self._lock:
            rows = list(self._buffer)
        return rows[-limit:]

    @property
    def latest_seq(self) -> int:
        with self._lock:
            return self._seq
