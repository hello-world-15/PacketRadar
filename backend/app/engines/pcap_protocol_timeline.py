"""
Protocol Distribution + Traffic Timeline for uploaded PCAP files.

Pure aggregation over an already-parsed list of PacketModel, same
convention as app.engines.pcap_summary / pcap_hosts_conversations /
pcap_insights — no file I/O, no Scapy, fully testable with synthetic
PacketModel instances and no real .pcap file.

Named pcap_protocol_timeline.py rather than folding into pcap_summary.py
or pcap_insights.py: those two already have well-scoped meanings
(Capture Summary cards; DNS/Threat/Health) and this module pairs two
genuinely new aggregations (protocol counts, time-bucketed packet
counts) that don't belong in either. See
docs/contracts/pcap-protocol-timeline.md.
"""

from __future__ import annotations

from datetime import timedelta

from app.models.packet import PacketModel
from app.schemas.pcap import ProtocolTimeline, TimelineBucket
from app.schemas.stats import ProtocolCount

TIMELINE_BUCKET_COUNT = 24


def compute_protocol_distribution(packets: list[PacketModel]) -> list[ProtocolCount]:
    """Counts packets by their already-classified `protocol` field — no
    reclassification, PacketParser already did that at parse time (see
    contract). Sorted descending by count so the largest slice of the
    pie always renders first, matching this codebase's existing
    sorted-list convention (e.g. app.engines.pcap_insights's Top
    Domains)."""
    counts: dict[str, int] = {}
    for p in packets:
        counts[p.protocol] = counts.get(p.protocol, 0) + 1

    return sorted(
        (ProtocolCount(label=label, value=value) for label, value in counts.items()),
        key=lambda c: -c.value,
    )


def compute_timeline(
    packets: list[PacketModel], bucket_count: int = TIMELINE_BUCKET_COUNT
) -> list[TimelineBucket]:
    """Buckets packets into `bucket_count` equal-width, evenly-spaced
    windows spanning the capture's own real min-to-max timestamp range —
    never a fixed 24-hour clock. A capture spanning 3 minutes gets
    `bucket_count` buckets of ~7.5s each; a 3-hour capture gets the same
    number of buckets, each ~7.5min wide. See contract for why (the old
    mock's 24 fake hourly buckets were meaningless for a file of any
    other length).

    Zero-duration case (a single packet, or every packet sharing one
    timestamp) has no time axis to spread across — returns one bucket
    holding every packet rather than dividing by a zero-width window."""
    if not packets:
        return []

    timestamps = [p.timestamp for p in packets]
    start = min(timestamps)
    end = max(timestamps)
    duration = (end - start).total_seconds()

    if duration <= 0:
        return [TimelineBucket(label=start.strftime("%H:%M"), value=len(packets))]

    bucket_width = duration / bucket_count
    counts = [0] * bucket_count
    for p in packets:
        offset = (p.timestamp - start).total_seconds()
        index = int(offset / bucket_width)
        if index >= bucket_count:
            # The packet at the exact max timestamp lands one past the
            # end under plain division — clamp into the last bucket
            # rather than drop it or raise an index error. See contract's
            # "Boundary packet".
            index = bucket_count - 1
        counts[index] += 1

    return [
        TimelineBucket(
            label=(start + timedelta(seconds=bucket_width * i)).strftime("%H:%M"),
            value=count,
        )
        for i, count in enumerate(counts)
    ]


def compute_protocol_timeline(packets: list[PacketModel]) -> ProtocolTimeline:
    return ProtocolTimeline(
        protocol_distribution=compute_protocol_distribution(packets),
        timeline=compute_timeline(packets),
    )
