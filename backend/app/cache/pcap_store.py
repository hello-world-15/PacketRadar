"""
In-memory store for parsed PCAP uploads, keyed by capture_id.

Every later PCAP Analyzer module (Protocol Distribution, Timeline, Top
Hosts, Conversations, DNS Analysis, Threat Analysis, Packet Explorer)
reads from the same stored parse via capture_id instead of re-uploading
or re-parsing the file — this is the shared foundation those modules
build on. See docs/contracts/pcap-upload.md.

Bounded to MAX_ENTRIES most recent uploads (oldest evicted first) so
repeated uploads in one session can't grow memory without bound. This is
a single-user local app with no requirement to survive a server restart
— an in-memory dict is the right scope, not a database.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Optional

from app.models.packet import PacketModel
from app.schemas.pcap import CaptureSummary

MAX_ENTRIES = 5


@dataclass
class PcapAnalysis:
    capture_id: str
    filename: str
    packets: list[PacketModel]
    summary: CaptureSummary


class PcapAnalysisStore:
    def __init__(self, max_entries: int = MAX_ENTRIES) -> None:
        self._lock = Lock()
        self._max_entries = max_entries
        self._entries: dict[str, PcapAnalysis] = {}
        self._order: list[str] = []  # oldest first

    def save(
        self,
        capture_id: str,
        filename: str,
        packets: list[PacketModel],
        summary: CaptureSummary,
    ) -> None:
        with self._lock:
            self._entries[capture_id] = PcapAnalysis(capture_id, filename, packets, summary)
            self._order.append(capture_id)
            while len(self._order) > self._max_entries:
                oldest = self._order.pop(0)
                self._entries.pop(oldest, None)

    def get(self, capture_id: str) -> Optional[PcapAnalysis]:
        with self._lock:
            return self._entries.get(capture_id)


pcap_store = PcapAnalysisStore()
