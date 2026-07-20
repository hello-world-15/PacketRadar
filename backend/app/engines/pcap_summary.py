"""
Capture Summary computation for uploaded PCAP files.

Pure aggregation over an already-parsed list of PacketModel — no file
I/O, no Scapy. The actual parsing (reading the file, calling
PacketParser) lives in app/api/pcap.py; this module only knows how to
summarize the result, which is what keeps it testable with synthetic
PacketModel instances exactly like every other engine in this codebase,
with no real .pcap file required to run its tests.

See docs/contracts/pcap-upload.md for the field-by-field reasoning.
"""

from __future__ import annotations

from app.models.packet import PacketModel
from app.schemas.pcap import CaptureSummary

UNKNOWN_HOST = "Unknown"


def compute_summary(packets: list[PacketModel]) -> CaptureSummary:
    if not packets:
        return CaptureSummary(
            packet_count=0,
            duration_seconds=0.0,
            avg_packet_size_bytes=0,
            unique_hosts=0,
            connection_count=0,
            dns_request_count=0,
        )

    timestamps = [p.timestamp for p in packets]
    duration = (max(timestamps) - min(timestamps)).total_seconds()

    hosts: set[str] = set()
    for p in packets:
        if p.src_ip and p.src_ip != UNKNOWN_HOST:
            hosts.add(p.src_ip)
        if p.dst_ip and p.dst_ip != UNKNOWN_HOST:
            hosts.add(p.dst_ip)

    connections = {p.flow_key for p in packets}

    # A DNS *query* specifically, not the response — the same condition
    # PacketParser itself uses internally to tell query from response
    # (dst_port == 53), recomputed here from the already-parsed
    # PacketModel rather than re-inspecting the raw packet.
    dns_requests = sum(1 for p in packets if p.protocol == "DNS" and p.dst_port == 53)

    total_length = sum(p.length for p in packets)
    avg_size = round(total_length / len(packets))

    return CaptureSummary(
        packet_count=len(packets),
        duration_seconds=round(duration, 3),
        avg_packet_size_bytes=avg_size,
        unique_hosts=len(hosts),
        connection_count=len(connections),
        dns_request_count=dns_requests,
    )
