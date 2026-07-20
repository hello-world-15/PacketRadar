"""
Unit tests for compute_summary — feeds synthetic PacketModel instances
directly, no file I/O or Scapy required.
"""

from datetime import datetime, timedelta

from app.engines.pcap_summary import compute_summary
from app.models.packet import PacketModel


def _packet(**overrides) -> PacketModel:
    defaults = dict(
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        interface="pcap-upload",
        direction="UNKNOWN",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        length=100,
        payload_size=50,
        flow_key="10.0.0.1:1234-10.0.0.2:80-TCP",
        info="TCP",
    )
    defaults.update(overrides)
    return PacketModel(**defaults)


def test_empty_list_returns_all_zeros():
    summary = compute_summary([])
    assert summary.packet_count == 0
    assert summary.duration_seconds == 0.0
    assert summary.avg_packet_size_bytes == 0
    assert summary.unique_hosts == 0
    assert summary.connection_count == 0
    assert summary.dns_request_count == 0


def test_packet_count_matches_list_length():
    packets = [_packet() for _ in range(5)]
    assert compute_summary(packets).packet_count == 5


def test_duration_is_max_minus_min_timestamp():
    base = datetime(2026, 1, 1, 12, 0, 0)
    packets = [
        _packet(timestamp=base),
        _packet(timestamp=base + timedelta(seconds=90)),
        _packet(timestamp=base + timedelta(seconds=30)),
    ]
    assert compute_summary(packets).duration_seconds == 90.0


def test_single_packet_has_zero_duration():
    summary = compute_summary([_packet()])
    assert summary.duration_seconds == 0.0


def test_avg_packet_size_is_rounded_mean_length():
    packets = [_packet(length=100), _packet(length=200), _packet(length=201)]
    # mean = 167.0 -> rounds to 167
    assert compute_summary(packets).avg_packet_size_bytes == 167


def test_unique_hosts_counts_distinct_src_and_dst():
    packets = [
        _packet(src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        _packet(src_ip="10.0.0.1", dst_ip="10.0.0.3"),
        _packet(src_ip="10.0.0.2", dst_ip="10.0.0.1"),
    ]
    # distinct: 10.0.0.1, 10.0.0.2, 10.0.0.3
    assert compute_summary(packets).unique_hosts == 3


def test_unknown_placeholder_ips_are_excluded_from_unique_hosts():
    packets = [_packet(src_ip="Unknown", dst_ip="10.0.0.2")]
    assert compute_summary(packets).unique_hosts == 1


def test_connection_count_is_distinct_flow_keys():
    packets = [
        _packet(flow_key="a"),
        _packet(flow_key="a"),
        _packet(flow_key="b"),
    ]
    assert compute_summary(packets).connection_count == 2


def test_dns_request_count_only_counts_query_direction():
    packets = [
        _packet(protocol="DNS", dst_port=53),  # query -> counted
        _packet(protocol="DNS", src_port=53, dst_port=54321),  # response -> not counted
        _packet(protocol="TCP", dst_port=53),  # not DNS protocol -> not counted
    ]
    assert compute_summary(packets).dns_request_count == 1
