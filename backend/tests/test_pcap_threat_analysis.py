"""
Unit tests for app.engines.pcap_threat_analysis — feeds synthetic
PacketModel instances directly, no file I/O or Scapy required. Matches
the style of test_pcap_summary.py and test_threat_detection_engine.py.
"""

from datetime import datetime, timedelta

from app.engines.pcap_threat_analysis import (
    _DEFAULT_RECOMMENDATION,
    _RECOMMENDATIONS,
    analyze_threats,
    detect_arp_spoofing,
    detect_beaconing,
    detect_data_exfiltration,
    detect_dns_tunneling,
    detect_port_scans,
    detect_syn_floods,
)
from app.engines.threat_detection import (
    ARP_CONFLICT_DEBOUNCE_SECONDS,
    DNS_TUNNEL_DISTINCT_THRESHOLD,
    DNS_TUNNEL_LABEL_LENGTH_THRESHOLD,
    EXFIL_BYTE_THRESHOLD,
    EXFIL_WINDOW_SECONDS,
    MIN_BEACON_OBSERVATIONS,
    PORT_SCAN_DISTINCT_THRESHOLD,
    SYN_FLOOD_COUNT_THRESHOLD,
)
from app.models.packet import PacketModel

BASE_TIME = datetime(2026, 1, 1, 12, 0, 0)
_LONG_LEAF = "a" * DNS_TUNNEL_LABEL_LENGTH_THRESHOLD


def _tcp_info(src_port: int, dst_port: int, flags: str) -> str:
    """Matches PacketParser's own TCP `info` format exactly."""
    return f"TCP {src_port} \u2192 {dst_port} [{flags}]"


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
        length=100,
        payload_size=50,
        flow_key="10.0.0.1:1234-10.0.0.2:443-TCP",
        info="TCP",
    )
    defaults.update(overrides)
    return PacketModel(**defaults)


def _scan_packets(src_ip: str, dst_ip: str, start: datetime, count: int, step_ms: int = 100):
    return [
        _packet(
            timestamp=start + timedelta(milliseconds=i * step_ms),
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=1000 + i,
        )
        for i in range(count)
    ]


def _tunnel_packets(src_ip: str, start: datetime, count: int, parent: str = "evil.example.com", step_ms: int = 100):
    return [
        _packet(
            timestamp=start + timedelta(milliseconds=i * step_ms),
            src_ip=src_ip,
            dst_ip="8.8.8.8",
            src_port=51000 + i,
            dst_port=53,
            protocol="DNS",
            dns_query=f"{_LONG_LEAF}{i}.{parent} (TXT)",
        )
        for i in range(count)
    ]


def _syn_packets(src_ip: str, dst_ip: str, dst_port: int, start: datetime, count: int, step_ms: int = 50):
    return [
        _packet(
            timestamp=start + timedelta(milliseconds=i * step_ms),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=50000 + i,
            dst_port=dst_port,
            protocol="TCP",
            info=_tcp_info(50000 + i, dst_port, "S"),
        )
        for i in range(count)
    ]


def _arp_packet(ip: str, mac: str, at: datetime):
    return _packet(
        timestamp=at,
        protocol="ARP",
        src_ip=ip,
        dst_ip="192.168.1.255",
        src_port=None,
        dst_port=None,
        src_mac=mac,
    )


def _beacon_packets(
    src_ip: str, dst_ip: str, dst_port: int, start: datetime, count: int, interval_seconds: float = 30.0
):
    return [
        _packet(
            timestamp=start + timedelta(seconds=i * interval_seconds),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=50000 + i,
            dst_port=dst_port,
        )
        for i in range(count)
    ]


def _exfil_packets(src_ip: str, dst_ip: str, start: datetime, count: int, payload_size: int, step_ms: int = 1000):
    return [
        _packet(
            timestamp=start + timedelta(milliseconds=i * step_ms),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=50000 + i,
            payload_size=payload_size,
        )
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Port Scan Detection
# ---------------------------------------------------------------------------


def test_no_packets_gives_no_port_scan_findings():
    assert detect_port_scans([]) == []


def test_normal_traffic_gives_no_findings():
    packets = [_packet(dst_port=443 + i) for i in range(3)]
    assert detect_port_scans(packets) == []


def test_repeated_identical_pair_never_triggers():
    packets = [_packet(dst_port=443) for _ in range(100)]
    assert detect_port_scans(packets) == []


def test_scan_pattern_produces_exactly_one_finding_not_one_per_packet():
    packets = _scan_packets("203.0.113.44", "10.0.0.9", BASE_TIME, PORT_SCAN_DISTINCT_THRESHOLD + 10)
    findings = detect_port_scans(packets)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].reason == "Port Scan Detected"
    assert findings[0].source == "203.0.113.44"
    assert "203.0.113.44" in findings[0].evidence
    assert findings[0].recommendation == _RECOMMENDATIONS["Port Scan Detected"]


def test_finding_reports_real_computed_numbers_not_a_template():
    packets = _scan_packets("203.0.113.44", "10.0.0.9", BASE_TIME, PORT_SCAN_DISTINCT_THRESHOLD)
    findings = detect_port_scans(packets)
    assert len(findings) == 1
    # Exactly threshold distinct pairs, all to the same single host.
    assert f"{PORT_SCAN_DISTINCT_THRESHOLD} distinct host:port pairs" in findings[0].evidence
    assert "across 1 host(s)" in findings[0].evidence


def test_scan_spread_across_multiple_hosts_counts_distinct_hosts():
    start = BASE_TIME
    packets = [
        _packet(timestamp=start + timedelta(milliseconds=i * 50), src_ip="203.0.113.44", dst_ip=f"10.0.0.{i}", dst_port=1000 + i)
        for i in range(PORT_SCAN_DISTINCT_THRESHOLD)
    ]
    findings = detect_port_scans(packets)
    assert len(findings) == 1
    assert f"across {PORT_SCAN_DISTINCT_THRESHOLD} host(s)" in findings[0].evidence


def test_two_well_separated_episodes_from_same_source_produce_two_findings():
    # First episode.
    episode_1 = _scan_packets("203.0.113.44", "10.0.0.9", BASE_TIME, PORT_SCAN_DISTINCT_THRESHOLD)
    # A long real gap in the capture's own timeline — far beyond the
    # window, so this is a second, genuinely separate incident, not a
    # continuation of the first.
    episode_2_start = BASE_TIME + timedelta(minutes=10)
    episode_2 = _scan_packets("203.0.113.44", "10.0.0.50", episode_2_start, PORT_SCAN_DISTINCT_THRESHOLD)

    findings = detect_port_scans(episode_1 + episode_2)
    assert len(findings) == 2
    assert all(f.source == "203.0.113.44" for f in findings)


def test_scan_ending_mid_capture_is_still_reported_when_loop_ends_in_episode():
    # Threshold reached and the packet list simply ends while still
    # "in episode" — must still emit the finding (not require a
    # trailing non-matching packet to close it).
    packets = _scan_packets("203.0.113.44", "10.0.0.9", BASE_TIME, PORT_SCAN_DISTINCT_THRESHOLD)
    findings = detect_port_scans(packets)
    assert len(findings) == 1


def test_different_source_ips_tracked_independently():
    packets = _scan_packets("10.0.0.1", "10.0.0.9", BASE_TIME, PORT_SCAN_DISTINCT_THRESHOLD) + _scan_packets(
        "10.0.0.2", "10.0.0.9", BASE_TIME, PORT_SCAN_DISTINCT_THRESHOLD
    )
    findings = detect_port_scans(packets)
    assert len(findings) == 2
    assert {f.source for f in findings} == {"10.0.0.1", "10.0.0.2"}


def test_packets_out_of_order_in_the_input_list_are_still_detected_correctly():
    packets = _scan_packets("203.0.113.44", "10.0.0.9", BASE_TIME, PORT_SCAN_DISTINCT_THRESHOLD)
    shuffled = list(reversed(packets))
    findings = detect_port_scans(shuffled)
    assert len(findings) == 1


def test_packets_without_dst_port_are_ignored():
    packets = [_packet(protocol="ARP", dst_port=None, src_port=None) for _ in range(50)]
    assert detect_port_scans(packets) == []


# ---------------------------------------------------------------------------
# ARP Spoofing Detection
# ---------------------------------------------------------------------------


def test_no_packets_gives_no_arp_findings():
    assert detect_arp_spoofing([]) == []


def test_first_sighting_of_an_ip_never_triggers():
    packets = [_arp_packet("192.168.1.1", "AA:AA:AA:AA:AA:AA", BASE_TIME)]
    assert detect_arp_spoofing(packets) == []


def test_repeated_consistent_sightings_never_trigger():
    packets = [
        _arp_packet("192.168.1.1", "AA:AA:AA:AA:AA:AA", BASE_TIME + timedelta(seconds=i))
        for i in range(10)
    ]
    assert detect_arp_spoofing(packets) == []


def test_single_stray_conflicting_packet_does_not_trigger():
    packets = [
        _arp_packet("192.168.1.1", "AA:AA:AA:AA:AA:AA", BASE_TIME),
        _arp_packet("192.168.1.1", "BB:BB:BB:BB:BB:BB", BASE_TIME + timedelta(seconds=1)),
    ]
    assert detect_arp_spoofing(packets) == []


def test_confirmed_conflict_within_debounce_produces_one_high_severity_finding():
    packets = [
        _arp_packet("192.168.1.1", "AA:AA:AA:AA:AA:AA", BASE_TIME),
        _arp_packet("192.168.1.1", "BB:BB:BB:BB:BB:BB", BASE_TIME + timedelta(seconds=1)),
        _arp_packet("192.168.1.1", "BB:BB:BB:BB:BB:BB", BASE_TIME + timedelta(seconds=1, milliseconds=500)),
    ]
    findings = detect_arp_spoofing(packets)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].reason == "Possible ARP Spoofing"
    assert findings[0].source == "192.168.1.1"
    assert "AA:AA:AA:AA:AA:AA" in findings[0].evidence
    assert "BB:BB:BB:BB:BB:BB" in findings[0].evidence
    assert findings[0].recommendation == _RECOMMENDATIONS["Possible ARP Spoofing"]


def test_conflict_confirmed_too_late_after_debounce_does_not_trigger():
    packets = [
        _arp_packet("192.168.1.1", "AA:AA:AA:AA:AA:AA", BASE_TIME),
        _arp_packet("192.168.1.1", "BB:BB:BB:BB:BB:BB", BASE_TIME + timedelta(seconds=1)),
        _arp_packet(
            "192.168.1.1",
            "BB:BB:BB:BB:BB:BB",
            BASE_TIME + timedelta(seconds=1) + timedelta(seconds=ARP_CONFLICT_DEBOUNCE_SECONDS + 5),
        ),
    ]
    assert detect_arp_spoofing(packets) == []


def test_multiple_confirmed_flips_for_the_same_ip_aggregate_into_one_finding():
    packets = [
        _arp_packet("192.168.1.1", "AA:AA:AA:AA:AA:AA", BASE_TIME),
        _arp_packet("192.168.1.1", "BB:BB:BB:BB:BB:BB", BASE_TIME + timedelta(seconds=1)),
        _arp_packet("192.168.1.1", "BB:BB:BB:BB:BB:BB", BASE_TIME + timedelta(seconds=1, milliseconds=200)),
        _arp_packet("192.168.1.1", "AA:AA:AA:AA:AA:AA", BASE_TIME + timedelta(seconds=5)),
        _arp_packet("192.168.1.1", "AA:AA:AA:AA:AA:AA", BASE_TIME + timedelta(seconds=5, milliseconds=200)),
    ]
    findings = detect_arp_spoofing(packets)
    assert len(findings) == 1
    assert "2 confirmed conflicts" in findings[0].evidence


def test_different_ips_tracked_independently():
    packets = [
        _arp_packet("192.168.1.1", "AA:AA:AA:AA:AA:AA", BASE_TIME),
        _arp_packet("192.168.1.1", "BB:BB:BB:BB:BB:BB", BASE_TIME + timedelta(seconds=1)),
        _arp_packet("192.168.1.1", "BB:BB:BB:BB:BB:BB", BASE_TIME + timedelta(seconds=1, milliseconds=200)),
        _arp_packet("192.168.1.2", "11:11:11:11:11:11", BASE_TIME),
    ]
    findings = detect_arp_spoofing(packets)
    assert len(findings) == 1
    assert findings[0].source == "192.168.1.1"


def test_arp_packet_without_src_mac_is_skipped_safely():
    packets = [_arp_packet("192.168.1.1", None, BASE_TIME)]
    assert detect_arp_spoofing(packets) == []


def test_non_arp_traffic_is_ignored_by_arp_detection():
    packets = [_packet(protocol="TCP") for _ in range(10)]
    assert detect_arp_spoofing(packets) == []


# ---------------------------------------------------------------------------
# DNS Tunneling Detection
# ---------------------------------------------------------------------------


def test_no_packets_gives_no_dns_tunneling_findings():
    assert detect_dns_tunneling([]) == []


def test_ordinary_dns_traffic_gives_no_findings():
    packets = [_packet(protocol="DNS", dst_port=53, dns_query=f"host{i}.example.com (A)") for i in range(50)]
    assert detect_dns_tunneling(packets) == []


def test_non_dns_traffic_is_ignored_by_tunneling_detection():
    packets = _scan_packets("203.0.113.44", "10.0.0.9", BASE_TIME, DNS_TUNNEL_DISTINCT_THRESHOLD + 10)
    assert detect_dns_tunneling(packets) == []


def test_tunnel_pattern_produces_exactly_one_finding():
    packets = _tunnel_packets("203.0.113.44", BASE_TIME, DNS_TUNNEL_DISTINCT_THRESHOLD + 10)
    findings = detect_dns_tunneling(packets)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].reason == "Possible DNS Tunneling"
    assert findings[0].source == "203.0.113.44"
    assert "evil.example.com" in findings[0].evidence


def test_two_separate_tunneling_episodes_produce_two_findings():
    first = _tunnel_packets("203.0.113.44", BASE_TIME, DNS_TUNNEL_DISTINCT_THRESHOLD)
    second = _tunnel_packets(
        "203.0.113.44", BASE_TIME + timedelta(minutes=5), DNS_TUNNEL_DISTINCT_THRESHOLD
    )
    findings = detect_dns_tunneling(first + second)
    assert len(findings) == 2


def test_different_parent_domains_tracked_independently_in_batch():
    one = _tunnel_packets("203.0.113.44", BASE_TIME, DNS_TUNNEL_DISTINCT_THRESHOLD, parent="one.evil.com")
    two = _tunnel_packets("203.0.113.44", BASE_TIME, DNS_TUNNEL_DISTINCT_THRESHOLD, parent="two.evil.com")
    findings = detect_dns_tunneling(one + two)
    assert len(findings) == 2
    assert any("one.evil.com" in f.evidence for f in findings)
    assert any("two.evil.com" in f.evidence for f in findings)


def test_packets_without_dns_query_are_skipped_safely():
    packets = [_packet(protocol="DNS", dst_port=53, dns_query=None) for _ in range(10)]
    assert detect_dns_tunneling(packets) == []


# ---------------------------------------------------------------------------
# SYN Flood Detection
# ---------------------------------------------------------------------------


def test_no_packets_gives_no_syn_flood_findings():
    assert detect_syn_floods([]) == []


def test_ordinary_tcp_traffic_gives_no_syn_flood_findings():
    packets = [
        _packet(dst_port=443, protocol="TCP", info=_tcp_info(50000 + i, 443, "A")) for i in range(50)
    ]
    assert detect_syn_floods(packets) == []


def test_syn_ack_replies_are_not_counted_as_bare_syns():
    packets = [
        _packet(
            src_ip="10.0.0.9",
            dst_ip="203.0.113.44",
            dst_port=50000 + i,
            protocol="TCP",
            info=_tcp_info(80, 50000 + i, "SA"),
        )
        for i in range(SYN_FLOOD_COUNT_THRESHOLD + 10)
    ]
    assert detect_syn_floods(packets) == []


def test_non_tcp_traffic_is_ignored_by_syn_flood_detection():
    packets = _tunnel_packets("203.0.113.44", BASE_TIME, SYN_FLOOD_COUNT_THRESHOLD + 10)
    assert detect_syn_floods(packets) == []


def test_syn_flood_pattern_produces_exactly_one_finding():
    packets = _syn_packets("203.0.113.44", "10.0.0.9", 80, BASE_TIME, SYN_FLOOD_COUNT_THRESHOLD + 15)
    findings = detect_syn_floods(packets)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].reason == "Possible SYN Flood"
    assert findings[0].source == "203.0.113.44"
    assert "10.0.0.9:80" in findings[0].evidence


def test_two_separate_syn_flood_episodes_produce_two_findings():
    first = _syn_packets("203.0.113.44", "10.0.0.9", 80, BASE_TIME, SYN_FLOOD_COUNT_THRESHOLD)
    second = _syn_packets(
        "203.0.113.44", "10.0.0.9", 80, BASE_TIME + timedelta(minutes=5), SYN_FLOOD_COUNT_THRESHOLD
    )
    findings = detect_syn_floods(first + second)
    assert len(findings) == 2


def test_different_destination_ports_tracked_independently_for_syn_flood():
    one = _syn_packets("203.0.113.44", "10.0.0.9", 80, BASE_TIME, SYN_FLOOD_COUNT_THRESHOLD)
    two = _syn_packets("203.0.113.44", "10.0.0.9", 443, BASE_TIME, SYN_FLOOD_COUNT_THRESHOLD)
    findings = detect_syn_floods(one + two)
    assert len(findings) == 2
    assert any("10.0.0.9:80" in f.evidence for f in findings)
    assert any("10.0.0.9:443" in f.evidence for f in findings)


# ---------------------------------------------------------------------------
# Beaconing Detection
# ---------------------------------------------------------------------------


def test_no_packets_gives_no_beaconing_findings():
    assert detect_beaconing([]) == []


def test_ordinary_traffic_gives_no_beaconing_findings():
    # A different destination port on every connection never accumulates
    # enough history against any single (dst_ip, dst_port) triple.
    packets = _scan_packets("10.0.0.5", "93.184.216.34", BASE_TIME, MIN_BEACON_OBSERVATIONS + 5)
    assert detect_beaconing(packets) == []


def test_irregular_intervals_give_no_beaconing_findings():
    intervals = [5, 40, 12, 300, 8, 90, 15, 600, 22, 3]
    ts = BASE_TIME
    packets = []
    for i, gap in enumerate(intervals):
        packets.append(
            _packet(timestamp=ts, src_ip="10.0.0.5", dst_ip="93.184.216.34", dst_port=443, src_port=50000 + i)
        )
        ts += timedelta(seconds=gap)
    assert detect_beaconing(packets) == []


def test_beacon_pattern_produces_exactly_one_finding():
    packets = _beacon_packets("10.0.0.7", "203.0.113.9", 443, BASE_TIME, MIN_BEACON_OBSERVATIONS + 10)
    findings = detect_beaconing(packets)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].reason == "Possible Beaconing Detected"
    assert findings[0].source == "10.0.0.7"
    assert "203.0.113.9:443" in findings[0].evidence
    assert findings[0].recommendation == _RECOMMENDATIONS["Possible Beaconing Detected"]


def test_beacon_episode_breaks_on_irregular_gap_then_resumes():
    first = _beacon_packets("10.0.0.7", "203.0.113.9", 443, BASE_TIME, MIN_BEACON_OBSERVATIONS + 1)
    gap_start = first[-1].timestamp + timedelta(seconds=10_000)
    second = _beacon_packets("10.0.0.7", "203.0.113.9", 443, gap_start, MIN_BEACON_OBSERVATIONS + 1)
    findings = detect_beaconing(first + second)
    assert len(findings) == 2


def test_different_destination_triples_tracked_independently_for_beaconing():
    one = _beacon_packets("10.0.0.7", "203.0.113.9", 443, BASE_TIME, MIN_BEACON_OBSERVATIONS + 1)
    two = _beacon_packets("10.0.0.7", "203.0.113.9", 8443, BASE_TIME, MIN_BEACON_OBSERVATIONS + 1)
    findings = detect_beaconing(one + two)
    assert len(findings) == 2
    assert any("203.0.113.9:443" in f.evidence for f in findings)
    assert any("203.0.113.9:8443" in f.evidence for f in findings)


def test_beacon_ignores_packets_without_dst_port():
    packets = [
        _packet(protocol="ARP", src_ip="10.0.0.5", dst_ip="192.168.1.255", src_port=None, dst_port=None)
        for _ in range(20)
    ]
    assert detect_beaconing(packets) == []


# ---------------------------------------------------------------------------
# Data Exfiltration Detection
# ---------------------------------------------------------------------------


def test_no_packets_gives_no_exfil_findings():
    assert detect_data_exfiltration([]) == []


def test_ordinary_transfer_volume_gives_no_exfil_findings():
    packets = _exfil_packets("10.0.0.5", "93.184.216.34", BASE_TIME, 20, payload_size=5_000)
    assert detect_data_exfiltration(packets) == []


def test_exfil_pattern_produces_exactly_one_finding():
    packets = _exfil_packets("203.0.113.44", "10.0.0.9", BASE_TIME, 1, payload_size=EXFIL_BYTE_THRESHOLD)
    findings = detect_data_exfiltration(packets)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].reason == "Possible Data Exfiltration"
    assert findings[0].source == "203.0.113.44"
    assert "10.0.0.9" in findings[0].evidence
    assert findings[0].recommendation == _RECOMMENDATIONS["Possible Data Exfiltration"]


def test_two_separate_exfil_episodes_produce_two_findings():
    # Several packets whose sum only crosses the threshold partway
    # through — same "climb, then a real gap, then climb again" shape
    # the other rules' two-episode tests use, so the gap can actually be
    # observed causing the running total to drop back below threshold.
    chunk = EXFIL_BYTE_THRESHOLD // 5 + 1_000
    first = _exfil_packets("203.0.113.44", "10.0.0.9", BASE_TIME, 6, payload_size=chunk, step_ms=1000)
    second_start = BASE_TIME + timedelta(minutes=10)
    second = _exfil_packets("203.0.113.44", "10.0.0.9", second_start, 6, payload_size=chunk, step_ms=1000)
    findings = detect_data_exfiltration(first + second)
    assert len(findings) == 2


def test_different_destination_pairs_tracked_independently_for_exfil():
    one = _exfil_packets("10.0.0.1", "10.0.0.9", BASE_TIME, 1, payload_size=EXFIL_BYTE_THRESHOLD)
    two = _exfil_packets("10.0.0.2", "10.0.0.9", BASE_TIME, 1, payload_size=EXFIL_BYTE_THRESHOLD)
    findings = detect_data_exfiltration(one + two)
    assert len(findings) == 2
    assert {f.source for f in findings} == {"10.0.0.1", "10.0.0.2"}


def test_old_exfil_volume_falls_out_of_the_window():
    # A big transfer, then a real gap beyond the window, then a small
    # additional transfer that should NOT combine with the now-expired
    # earlier bytes to cross the threshold.
    packets = [
        _packet(timestamp=BASE_TIME, src_ip="10.0.0.1", dst_ip="10.0.0.9", payload_size=EXFIL_BYTE_THRESHOLD - 100),
        _packet(
            timestamp=BASE_TIME + timedelta(seconds=EXFIL_WINDOW_SECONDS + 5),
            src_ip="10.0.0.1",
            dst_ip="10.0.0.9",
            payload_size=50,
        ),
    ]
    assert detect_data_exfiltration(packets) == []


# ---------------------------------------------------------------------------
# Recommendation fallback
# ---------------------------------------------------------------------------


def test_unrecognized_reason_falls_back_to_default_recommendation():
    from app.engines.pcap_threat_analysis import _recommendation_for

    assert _recommendation_for("Some Future Rule") == _DEFAULT_RECOMMENDATION


# ---------------------------------------------------------------------------
# analyze_threats — combined entry point
# ---------------------------------------------------------------------------


def test_analyze_threats_combines_all_six_rules():
    scan_packets = _scan_packets("203.0.113.44", "10.0.0.9", BASE_TIME, PORT_SCAN_DISTINCT_THRESHOLD)
    arp_packets = [
        _arp_packet("192.168.1.1", "AA:AA:AA:AA:AA:AA", BASE_TIME),
        _arp_packet("192.168.1.1", "BB:BB:BB:BB:BB:BB", BASE_TIME + timedelta(seconds=1)),
        _arp_packet("192.168.1.1", "BB:BB:BB:BB:BB:BB", BASE_TIME + timedelta(seconds=1, milliseconds=200)),
    ]
    tunnel_packets = _tunnel_packets("172.16.0.50", BASE_TIME, DNS_TUNNEL_DISTINCT_THRESHOLD)
    syn_packets = _syn_packets("198.51.100.7", "10.0.0.20", 80, BASE_TIME, SYN_FLOOD_COUNT_THRESHOLD)
    beacon_packets = _beacon_packets("192.0.2.15", "203.0.113.99", 443, BASE_TIME, MIN_BEACON_OBSERVATIONS + 1)
    exfil_packets = _exfil_packets("192.0.2.30", "198.51.100.44", BASE_TIME, 1, payload_size=EXFIL_BYTE_THRESHOLD)
    findings = analyze_threats(
        scan_packets + arp_packets + tunnel_packets + syn_packets + beacon_packets + exfil_packets
    )
    assert len(findings) == 6
    assert {f.reason for f in findings} == {
        "Port Scan Detected",
        "Possible ARP Spoofing",
        "Possible DNS Tunneling",
        "Possible SYN Flood",
        "Possible Beaconing Detected",
        "Possible Data Exfiltration",
    }


def test_analyze_threats_orders_high_severity_first():
    scan_packets = _scan_packets("203.0.113.44", "10.0.0.9", BASE_TIME, PORT_SCAN_DISTINCT_THRESHOLD)
    arp_packets = [
        _arp_packet("192.168.1.1", "AA:AA:AA:AA:AA:AA", BASE_TIME),
        _arp_packet("192.168.1.1", "BB:BB:BB:BB:BB:BB", BASE_TIME + timedelta(seconds=1)),
        _arp_packet("192.168.1.1", "BB:BB:BB:BB:BB:BB", BASE_TIME + timedelta(seconds=1, milliseconds=200)),
    ]
    findings = analyze_threats(scan_packets + arp_packets)
    assert findings[0].severity == "high"
    assert findings[1].severity == "medium"


def test_analyze_threats_empty_for_clean_capture():
    packets = [_packet(dst_port=443 + i) for i in range(5)]
    assert analyze_threats(packets) == []
