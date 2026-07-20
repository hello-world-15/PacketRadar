"""
Unit tests for app.engines.pcap_hosts_conversations — feeds synthetic
PacketModel instances directly, no file I/O or Scapy required. Matches
the style of test_pcap_summary.py / test_pcap_insights.py.
"""

from datetime import datetime, timedelta

from app.engines.pcap_hosts_conversations import (
    _format_bytes,
    _format_duration,
    compute_conversations,
    compute_hosts_conversations,
    compute_top_hosts,
)
from app.models.packet import PacketModel

BASE_TIME = datetime(2026, 1, 1, 12, 0, 0)


def _packet(**overrides) -> PacketModel:
    defaults = dict(
        timestamp=BASE_TIME,
        interface="pcap-upload",
        direction="UNKNOWN",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=443,
        protocol="TCP",
        length=1000,
        payload_size=950,
        flow_key="10.0.0.1:1234-10.0.0.2:443-TCP",
        info="TCP",
    )
    defaults.update(overrides)
    return PacketModel(**defaults)


# ---------------------------------------------------------------------------
# _format_bytes / _format_duration
# ---------------------------------------------------------------------------


def test_format_bytes_under_1kb():
    assert _format_bytes(500) == "500 B"


def test_format_bytes_kb():
    assert _format_bytes(1536) == "1.5 KB"


def test_format_bytes_mb():
    assert _format_bytes(1_258_291) == "1.2 MB"  # 1.2 * 1024 * 1024, rounded


def test_format_bytes_gb():
    assert _format_bytes(2 * 1024 * 1024 * 1024) == "2.0 GB"


def test_format_duration_under_a_minute():
    assert _format_duration(45) == "45s"


def test_format_duration_zero():
    assert _format_duration(0) == "0s"


def test_format_duration_minutes_and_seconds():
    assert _format_duration(252) == "4m 12s"  # 4m 12s


def test_format_duration_exact_minutes_omits_seconds():
    assert _format_duration(180) == "3m"


def test_format_duration_hours_and_minutes():
    assert _format_duration(3900) == "1h 5m"


def test_format_duration_exact_hour_omits_minutes():
    assert _format_duration(3600) == "1h"


# ---------------------------------------------------------------------------
# compute_top_hosts
# ---------------------------------------------------------------------------


def test_empty_packet_list_gives_no_hosts():
    assert compute_top_hosts([], duration_seconds=10.0) == []


def test_both_source_and_destination_are_credited():
    packets = [_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2")]
    hosts = {h.ip: h for h in compute_top_hosts(packets, duration_seconds=10.0)}
    assert hosts["10.0.0.1"].packets == 1
    assert hosts["10.0.0.2"].packets == 1


def test_bandwidth_is_averaged_over_whole_capture_duration():
    # 10 packets * 1000 bytes = 10000 bytes over a 10s capture.
    packets = [_packet() for _ in range(10)]
    hosts = {h.ip: h for h in compute_top_hosts(packets, duration_seconds=10.0)}
    expected = round((10_000 * 8) / 10.0 / 1_000_000, 3)
    assert hosts["10.0.0.1"].bandwidth_mbps == expected
    assert hosts["10.0.0.2"].bandwidth_mbps == expected


def test_zero_duration_gives_zero_bandwidth_without_crashing():
    packets = [_packet() for _ in range(5)]
    hosts = compute_top_hosts(packets, duration_seconds=0.0)
    assert all(h.bandwidth_mbps == 0.0 for h in hosts)


def test_ranked_by_bandwidth_descending():
    packets = (
        [_packet(src_ip="10.0.0.1", dst_ip="10.0.0.9", length=5000) for _ in range(20)]
        + [_packet(src_ip="10.0.0.5", dst_ip="10.0.0.8", length=100) for _ in range(2)]
    )
    hosts = compute_top_hosts(packets, duration_seconds=10.0)
    ips = [h.ip for h in hosts]
    assert ips.index("10.0.0.1") < ips.index("10.0.0.5")


def test_top_host_has_100_percent_bandwidth_pct():
    packets = [_packet()]
    hosts = compute_top_hosts(packets, duration_seconds=10.0)
    assert hosts[0].bandwidth_pct == 100


def test_limit_caps_returned_hosts():
    packets = [
        _packet(src_ip=f"10.0.0.{i}", dst_ip="10.0.0.254", flow_key=f"f{i}") for i in range(20)
    ]
    hosts = compute_top_hosts(packets, duration_seconds=10.0, limit=5)
    assert len(hosts) == 5


def test_connections_counts_distinct_flow_keys_no_ttl():
    packets = [
        _packet(dst_ip="10.0.0.2", flow_key="flow-a"),
        _packet(dst_ip="10.0.0.3", flow_key="flow-b"),
        _packet(dst_ip="10.0.0.2", flow_key="flow-a"),  # repeat, same flow
    ]
    hosts = {h.ip: h for h in compute_top_hosts(packets, duration_seconds=10.0)}
    assert hosts["10.0.0.1"].connections == 2


def test_unknown_placeholder_ip_excluded_from_top_hosts():
    packets = [_packet(src_ip="Unknown", dst_ip="10.0.0.2")]
    hosts = {h.ip: h for h in compute_top_hosts(packets, duration_seconds=10.0)}
    assert "Unknown" not in hosts
    assert "10.0.0.2" in hosts


def test_hostname_is_always_none():
    hosts = compute_top_hosts([_packet()], duration_seconds=10.0)
    assert all(h.hostname is None for h in hosts)


# ---------------------------------------------------------------------------
# compute_conversations
# ---------------------------------------------------------------------------


def test_empty_packet_list_gives_no_conversations():
    assert compute_conversations([]) == []


def test_a_to_b_and_b_to_a_collapse_into_one_conversation():
    packets = [
        _packet(src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        _packet(src_ip="10.0.0.2", dst_ip="10.0.0.1"),  # reverse direction
    ]
    conversations = compute_conversations(packets)
    assert len(conversations) == 1
    assert conversations[0].packets == 2


def test_conversation_pair_ips_are_sorted_deterministically():
    packets = [_packet(src_ip="10.0.0.9", dst_ip="10.0.0.1")]
    conv = compute_conversations(packets)[0]
    assert conv.a == "10.0.0.1"
    assert conv.b == "10.0.0.9"


def test_different_ports_same_hosts_are_one_conversation():
    # Host-pair granularity, not full flow_key — same two hosts on
    # different ports/protocols are still one "conversation".
    packets = [
        _packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=443, flow_key="f1"),
        _packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, flow_key="f2"),
    ]
    conversations = compute_conversations(packets)
    assert len(conversations) == 1
    assert conversations[0].packets == 2


def test_conversation_duration_is_its_own_span_not_capture_wide():
    packets = [
        _packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", timestamp=BASE_TIME),
        _packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            timestamp=BASE_TIME + timedelta(seconds=40),
        ),
        # Unrelated pair spanning much longer — must not affect the pair above.
        _packet(
            src_ip="10.0.0.5",
            dst_ip="10.0.0.6",
            timestamp=BASE_TIME + timedelta(minutes=20),
        ),
    ]
    conversations = {(c.a, c.b): c for c in compute_conversations(packets)}
    assert conversations[("10.0.0.1", "10.0.0.2")].duration == "40s"


def test_single_packet_conversation_has_zero_duration():
    conv = compute_conversations([_packet()])[0]
    assert conv.duration == "0s"


def test_conversation_bytes_is_pre_formatted_string():
    packets = [_packet(length=1_258_291)]  # 1.2 MB
    conv = compute_conversations(packets)[0]
    assert conv.bytes == "1.2 MB"


def test_conversations_ranked_by_bytes_descending():
    packets = (
        [_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", length=5000)]
        + [_packet(src_ip="10.0.0.5", dst_ip="10.0.0.6", length=100)]
    )
    conversations = compute_conversations(packets)
    pairs = [(c.a, c.b) for c in conversations]
    assert pairs.index(("10.0.0.1", "10.0.0.2")) < pairs.index(("10.0.0.5", "10.0.0.6"))


def test_host_talking_to_itself_is_not_a_conversation():
    packets = [_packet(src_ip="127.0.0.1", dst_ip="127.0.0.1")]
    assert compute_conversations(packets) == []


def test_unknown_placeholder_ip_excludes_conversation():
    packets = [_packet(src_ip="Unknown", dst_ip="10.0.0.2")]
    assert compute_conversations(packets) == []


# ---------------------------------------------------------------------------
# compute_hosts_conversations — end-to-end
# ---------------------------------------------------------------------------


def test_compute_hosts_conversations_combines_both():
    packets = [_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2")]
    result = compute_hosts_conversations(packets, duration_seconds=10.0)
    assert len(result.top_hosts) == 2
    assert len(result.conversations) == 1
