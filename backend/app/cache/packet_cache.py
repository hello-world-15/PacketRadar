from collections import deque
from threading import Lock

from app.models.packet import PacketModel


class PacketCache:
    """
    Stores the latest captured packets in memory.

    Used by:
    - Live Packet Table
    - Packet Details
    - Future Search & Filters
    """

    def __init__(self, max_packets: int = 500):
        self._packets = deque(maxlen=max_packets)
        self._lock = Lock()

    def add(self, packet: PacketModel) -> None:
        with self._lock:
            self._packets.appendleft(packet)

    def latest(self, limit: int | None = None):
        with self._lock:
            packets = list(self._packets)

        if limit:
            return packets[:limit]

        return packets

    def clear(self):
        with self._lock:
            self._packets.clear()

    def size(self):
        return len(self._packets)