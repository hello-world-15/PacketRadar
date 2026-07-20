"""
Top Hosts + Conversations for uploaded PCAP files.

Pure aggregation over an already-parsed list of PacketModel, same
convention as app.engines.pcap_summary and app.engines.pcap_insights — no
file I/O, no Scapy, fully testable with synthetic PacketModel instances
and no real .pcap file.

Conceptually the offline version of app.engines.top_talkers: both source
and destination IP get credited on every packet (see docs/contracts/
talkers.md for why), but the *windowing* doesn't carry over — an
uploaded file is a fixed, finite dataset, so "bandwidth" here is one
honest average-over-the-whole-capture number, not a live rolling rate.
See docs/contracts/pcap-hosts-conversations.md for the full reasoning.
"""

from __future__ import annotations

from app.models.packet import PacketModel
from app.schemas.pcap import Conversation, HostsConversations, PcapTopHost

UNKNOWN_HOST = "Unknown"
TOP_HOSTS_LIMIT = 8

_BYTE_UNITS = ("B", "KB", "MB", "GB", "TB")


def _format_bytes(n: int) -> str:
    """Binary units (1024-based), one decimal place above B — matches
    the pre-existing mock data's own display style ('1.2 MB'). See
    contract's "Format decision"."""
    size = float(n)
    unit = _BYTE_UNITS[0]
    for unit in _BYTE_UNITS:
        if size < 1024 or unit == _BYTE_UNITS[-1]:
            break
        size /= 1024
    return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"


def _format_duration(seconds: float) -> str:
    """'0s' .. '59s', then 'Xm Ys' (Ys omitted if zero), then 'Xh Ym'
    past an hour (Ym omitted if zero). Plain and human-scannable —
    deliberately not mixing fractional units."""
    total = int(round(seconds))
    if total < 60:
        return f"{total}s"

    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s" if secs else f"{minutes}m"

    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m" if minutes else f"{hours}h"


def _is_real_host(ip: str) -> bool:
    return bool(ip) and ip != UNKNOWN_HOST


def compute_top_hosts(
    packets: list[PacketModel],
    duration_seconds: float,
    limit: int = TOP_HOSTS_LIMIT,
) -> list[PcapTopHost]:
    """Ranks hosts by average bandwidth over the whole capture.
    `duration_seconds` is the capture's total span — reused from the
    already-computed CaptureSummary rather than recomputed here, see
    contract. `duration_seconds == 0` (every packet shares one
    timestamp) yields 0.0 Mbps for every host rather than dividing by
    zero — an average rate genuinely isn't defined over zero elapsed
    time."""
    packet_counts: dict[str, int] = {}
    byte_totals: dict[str, int] = {}
    flows: dict[str, set[str]] = {}

    for p in packets:
        for ip in (p.src_ip, p.dst_ip):
            if not _is_real_host(ip):
                continue
            packet_counts[ip] = packet_counts.get(ip, 0) + 1
            byte_totals[ip] = byte_totals.get(ip, 0) + p.length
            flows.setdefault(ip, set()).add(p.flow_key)

    hosts = [
        PcapTopHost(
            ip=ip,
            hostname=None,
            packets=packet_counts[ip],
            bandwidth_mbps=(
                round((byte_totals[ip] * 8) / duration_seconds / 1_000_000, 3)
                if duration_seconds > 0
                else 0.0
            ),
            connections=len(flows[ip]),
        )
        for ip in packet_counts
    ]

    hosts.sort(key=lambda h: h.bandwidth_mbps, reverse=True)
    top = hosts[:limit]

    max_bandwidth = top[0].bandwidth_mbps if top else 0.0
    for host in top:
        host.bandwidth_pct = (
            round((host.bandwidth_mbps / max_bandwidth) * 100) if max_bandwidth > 0 else 0
        )

    return top


def compute_conversations(packets: list[PacketModel]) -> list[Conversation]:
    """Groups packets into direction-agnostic host-pair conversations —
    A->B and B->A collapse into one entry, keyed by the sorted IP pair.
    Duration is each pair's *own* first-to-last timestamp span, not the
    whole capture's — see contract."""
    pair_packets: dict[tuple[str, str], int] = {}
    pair_bytes: dict[tuple[str, str], int] = {}
    pair_timestamps: dict[tuple[str, str], list] = {}

    for p in packets:
        if not (_is_real_host(p.src_ip) and _is_real_host(p.dst_ip)):
            continue
        if p.src_ip == p.dst_ip:
            # A host "talking to itself" (e.g. loopback) isn't a
            # conversation between two hosts.
            continue

        pair = tuple(sorted((p.src_ip, p.dst_ip)))
        pair_packets[pair] = pair_packets.get(pair, 0) + 1
        pair_bytes[pair] = pair_bytes.get(pair, 0) + p.length
        pair_timestamps.setdefault(pair, []).append(p.timestamp)

    conversations = [
        Conversation(
            a=pair[0],
            b=pair[1],
            packets=pair_packets[pair],
            bytes=_format_bytes(pair_bytes[pair]),
            duration=_format_duration(
                (max(pair_timestamps[pair]) - min(pair_timestamps[pair])).total_seconds()
            ),
        )
        for pair in pair_packets
    ]

    conversations.sort(key=lambda c: pair_bytes[(c.a, c.b)], reverse=True)
    return conversations


def compute_hosts_conversations(
    packets: list[PacketModel], duration_seconds: float
) -> HostsConversations:
    return HostsConversations(
        top_hosts=compute_top_hosts(packets, duration_seconds),
        conversations=compute_conversations(packets),
    )
