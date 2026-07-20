"""
Unit tests for app.engines.pcap_protocol_distribution — feeds synthetic
PacketModel instances directly, no file I/O or Scapy required.
"""

from datetime import datetime

from app.engines.pcap_protocol_distribution import compute_protocol_distribution
from app.models.packet import PacketModel
from app.schemas.stats import ProtocolCount

BASE_TIME = datetime(2026, 1, 1, 12, 0, 0)


def _packet(protocol: str) -> PacketModel:
    return PacketModel(
        timestamp=BASE_TIME,
        interface="pcap-upload",
        direction="UNKNOWN",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=443,
        protocol=protocol,
        length=100,
        payload_size=50,
        flow_key="f",
        info="",
    )


def test_empty_packet_list_gives_empty_distribution():
    assert compute_protocol_distribution([]) == []


def test_counts_are_tallied_per_protocol():
    packets = [_packet("TCP")] * 3 + [_packet("UDP")] * 2 + [_packet("ARP")]
    dist = {c.label: c.value for c in compute_protocol_distribution(packets)}
    assert dist == {"TCP": 3, "UDP": 2, "ARP": 1}


def test_other_label_is_normalized_from_parser_convention():
    # PacketParser's own fallback label is "OTHER" — must appear as
    # "Other" to match the frontend Protocol union / stats.md.
    packets = [_packet("OTHER"), _packet("OTHER")]
    dist = compute_protocol_distribution(packets)
    assert dist == [ProtocolCount(label="Other", value=2)]


def test_absent_protocols_are_omitted_not_zero():
    packets = [_packet("TCP")]
    labels = [c.label for c in compute_protocol_distribution(packets)]
    assert labels == ["TCP"]
    assert "ICMP" not in labels


def test_sorted_by_count_descending():
    packets = [_packet("UDP")] * 2 + [_packet("TCP")] * 5 + [_packet("ARP")] * 1
    labels = [c.label for c in compute_protocol_distribution(packets)]
    assert labels == ["TCP", "UDP", "ARP"]


def test_ties_broken_by_canonical_order_deterministically():
    packets = [_packet("ARP"), _packet("DNS"), _packet("TCP")]  # all count 1
    labels = [c.label for c in compute_protocol_distribution(packets)]
    # Canonical order is TCP, UDP, DNS, ICMP, ARP, Other
    assert labels == ["TCP", "DNS", "ARP"]


def test_all_six_protocol_labels_handled():
    packets = [
        _packet("TCP"),
        _packet("UDP"),
        _packet("DNS"),
        _packet("ICMP"),
        _packet("ARP"),
        _packet("OTHER"),
    ]
    labels = {c.label for c in compute_protocol_distribution(packets)}
    assert labels == {"TCP", "UDP", "DNS", "ICMP", "ARP", "Other"}


def test_response_is_deterministic_across_repeated_calls():
    packets = [_packet("ARP"), _packet("DNS"), _packet("TCP"), _packet("UDP")] * 2
    first = compute_protocol_distribution(packets)
    second = compute_protocol_distribution(packets)
    assert [c.label for c in first] == [c.label for c in second]
