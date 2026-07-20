"""
Protocol Distribution for uploaded PCAP files.

The simplest PCAP Analyzer module so far — PacketParser.parse() has
already classified every packet's `protocol` field (one of exactly six
values: TCP, UDP, ICMP, DNS, ARP, OTHER) by the time it's sitting in
PcapAnalysisStore. This is a Counter over a field that already exists,
not a new classification. See docs/contracts/pcap-protocol-distribution.md
for the full reasoning, including why this doesn't reuse
app.capture.sniffer._protocol_label (that one exists only because live
capture's fast path skips the full parser; an uploaded file never took
that shortcut).
"""

from __future__ import annotations

from collections import Counter

from app.models.packet import PacketModel
from app.schemas.stats import ProtocolCount

# Tie-break order when two protocols share a count, so the response is
# deterministic across repeated requests for the same capture — see
# contract's "Sorted by count, descending".
_CANONICAL_ORDER = ("TCP", "UDP", "DNS", "ICMP", "ARP", "Other")


def _normalize_label(protocol: str) -> str:
    """PacketParser's own fallback label is "OTHER" (its internal
    convention); the frontend Protocol union and stats.md both use
    "Other". Every other value already matches and passes through
    unchanged."""
    return "Other" if protocol == "OTHER" else protocol


def compute_protocol_distribution(packets: list[PacketModel]) -> list[ProtocolCount]:
    counts = Counter(_normalize_label(p.protocol) for p in packets)

    def sort_key(label: str) -> tuple[int, int]:
        tie_break = _CANONICAL_ORDER.index(label) if label in _CANONICAL_ORDER else len(_CANONICAL_ORDER)
        return (-counts[label], tie_break)

    return [ProtocolCount(label=label, value=counts[label]) for label in sorted(counts, key=sort_key)]
