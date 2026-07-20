"""
Packet Explorer pagination for uploaded PCAP files.

Pure function over a `list[PacketModel]` — no file I/O, no Scapy, same
convention as `pcap_summary.py`/`pcap_threat_analysis.py`. Slicing and
row-mapping is genuinely simple enough that a class/engine object would
be pure ceremony; a single function is the honest shape here.

See docs/contracts/pcap-packet-explorer.md for why `no` is computed
against the packet's position in the whole capture rather than restarted
per page, and for why this row shape carries more fields
(src_mac/dst_mac/src_port/dst_port) than the live packets:update event.
"""

from __future__ import annotations

from app.models.packet import PacketModel
from app.schemas.pcap import PcapPacketRow, PcapPacketsResponse

# Hard ceiling on `limit`, enforced again here (not just at the FastAPI
# parameter level) so this function is safe to call directly from a test
# or a future caller that doesn't go through the HTTP layer.
MAX_LIMIT = 500


def _to_row(index: int, packet: PacketModel) -> PcapPacketRow:
    return PcapPacketRow(
        no=index + 1,
        time=packet.timestamp.timestamp(),
        source=packet.src_ip,
        destination=packet.dst_ip,
        protocol=packet.protocol,
        length=packet.length,
        info=packet.info,
        src_mac=packet.src_mac,
        dst_mac=packet.dst_mac,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        dns_query=packet.dns_query,
        dns_answer=packet.dns_answer,
    )


def paginate_packets(packets: list[PacketModel], offset: int, limit: int) -> PcapPacketsResponse:
    """Returns the `[offset, offset+limit)` slice of `packets`, mapped to
    the wire shape, alongside the true total count. Tolerant of an
    out-of-range `offset` (returns an empty page, not an error) since a
    client re-fetching a stale page after a capture was replaced
    shouldn't crash — 404 for an unknown capture_id is handled one layer
    up, by the API route, not here."""
    offset = max(offset, 0)
    limit = max(min(limit, MAX_LIMIT), 1)

    total = len(packets)
    page = packets[offset : offset + limit]
    rows = [_to_row(offset + i, packet) for i, packet in enumerate(page)]

    return PcapPacketsResponse(packets=rows, total=total, offset=offset, limit=limit)
