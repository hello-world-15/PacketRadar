"""
Unit tests for ThreatDetectionEngine — feeds synthetic port-activity and
ARP-sighting events directly, no Scapy or live capture required.

Time is controlled with a fake clock (monkeypatched onto
`app.engines.threat_detection.time.time`) rather than real `time.sleep`,
so cooldown/debounce edges can be tested precisely and deterministically
instead of relying on flaky wall-clock timing.
"""

import pytest

from app.engines import threat_detection as td_module
from app.engines.threat_detection import (
    ARP_CONFLICT_COOLDOWN_SECONDS,
    ARP_CONFLICT_DEBOUNCE_SECONDS,
    BEACON_COOLDOWN_SECONDS,
    BEACON_CV_THRESHOLD,
    BEACON_HISTORY_SIZE,
    BEACON_MAX_INTERVAL_SECONDS,
    BEACON_MIN_INTERVAL_SECONDS,
    DNS_TUNNEL_COOLDOWN_SECONDS,
    DNS_TUNNEL_DISTINCT_THRESHOLD,
    DNS_TUNNEL_LABEL_LENGTH_THRESHOLD,
    DNS_TUNNEL_WINDOW_SECONDS,
    EXFIL_BYTE_THRESHOLD,
    EXFIL_COOLDOWN_SECONDS,
    EXFIL_WINDOW_SECONDS,
    MIN_BEACON_OBSERVATIONS,
    PORT_SCAN_COOLDOWN_SECONDS,
    PORT_SCAN_DISTINCT_THRESHOLD,
    SYN_FLOOD_COOLDOWN_SECONDS,
    SYN_FLOOD_COUNT_THRESHOLD,
    ThreatDetectionEngine,
    beacon_pattern_stats,
    dns_tunnel_candidate,
    is_bare_syn,
)

# A leaf label at/above DNS_TUNNEL_LABEL_LENGTH_THRESHOLD, formatted the
# way PacketParser._parse_dns produces dns_query strings.
_LONG_LEAF = "a" * DNS_TUNNEL_LABEL_LENGTH_THRESHOLD


def _tunnel_query(i: int, parent: str = "evil.example.com", qtype: str = "TXT") -> str:
    """A distinct-per-call oversized-label query against `parent`."""
    return f"{_LONG_LEAF}{i}.{parent} ({qtype})"


def _tcp_info(src_port: int, dst_port: int, flags: str) -> str:
    """Matches PacketParser's own TCP `info` format exactly — see
    packet_parser.py: f"TCP {src_port} \u2192 {dst_port} [{flags}]"."""
    return f"TCP {src_port} \u2192 {dst_port} [{flags}]"


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(td_module.time, "time", fake.time)
    return fake


# ---------------------------------------------------------------------------
# Rule 1 — Port Scan Detection
# ---------------------------------------------------------------------------


def test_normal_traffic_produces_no_alerts(clock):
    engine = ThreatDetectionEngine()
    # A handful of distinct ports, well under the threshold.
    for port in range(5):
        result = engine.record_port_activity("10.0.0.5", "93.184.216.34", 443 + port)
        assert result is None
    assert engine.alert_count == 0


def test_repeated_identical_pair_never_alerts(clock):
    engine = ThreatDetectionEngine()
    # Same (dst_ip, dst_port) over and over is one distinct pair, not many.
    for _ in range(100):
        result = engine.record_port_activity("10.0.0.5", "93.184.216.34", 443)
        assert result is None
    assert engine.alert_count == 0


def test_port_scan_pattern_triggers_exactly_one_alert():
    engine = ThreatDetectionEngine()
    alerts = []
    for port in range(PORT_SCAN_DISTINCT_THRESHOLD + 10):
        result = engine.record_port_activity("203.0.113.44", "10.0.0.9", 1000 + port)
        if result is not None:
            alerts.append(result)
    assert len(alerts) == 1
    assert alerts[0].threat == "Port Scan Detected"
    assert alerts[0].source == "203.0.113.44"
    assert alerts[0].severity == "medium"


def test_port_scan_alert_fires_on_the_packet_that_crosses_threshold():
    engine = ThreatDetectionEngine()
    result = None
    for port in range(PORT_SCAN_DISTINCT_THRESHOLD):
        result = engine.record_port_activity("203.0.113.44", "10.0.0.9", 1000 + port)
    # The Nth distinct pair (reaching the threshold exactly) should trip it.
    assert result is not None


def test_cooldown_prevents_duplicate_alerts_until_it_expires(clock):
    engine = ThreatDetectionEngine()
    for port in range(PORT_SCAN_DISTINCT_THRESHOLD):
        engine.record_port_activity("203.0.113.44", "10.0.0.9", 2000 + port)
    assert engine.alert_count == 1

    # Keep scanning immediately after — still within cooldown, must not re-alert.
    for port in range(PORT_SCAN_DISTINCT_THRESHOLD, PORT_SCAN_DISTINCT_THRESHOLD + 20):
        result = engine.record_port_activity("203.0.113.44", "10.0.0.9", 2000 + port)
        assert result is None
    assert engine.alert_count == 1

    # Once the cooldown has fully elapsed, a fresh scan-like burst can alert again.
    clock.advance(PORT_SCAN_COOLDOWN_SECONDS + 1)
    fired_again = False
    for port in range(PORT_SCAN_DISTINCT_THRESHOLD):
        result = engine.record_port_activity("203.0.113.44", "10.0.0.200", 3000 + port)
        if result is not None:
            fired_again = True
    assert fired_again
    assert engine.alert_count == 2


def test_different_source_ips_are_tracked_independently():
    engine = ThreatDetectionEngine()
    for port in range(PORT_SCAN_DISTINCT_THRESHOLD):
        engine.record_port_activity("10.0.0.1", "10.0.0.9", 1000 + port)
    assert engine.alert_count == 1
    # A second, unrelated source scanning shouldn't be suppressed by the
    # first source's cooldown.
    for port in range(PORT_SCAN_DISTINCT_THRESHOLD):
        engine.record_port_activity("10.0.0.2", "10.0.0.9", 1000 + port)
    assert engine.alert_count == 2


def test_old_port_activity_falls_out_of_the_window(clock):
    engine = ThreatDetectionEngine()
    # Touch threshold - 1 distinct pairs, then let time pass beyond the
    # window, then touch a couple more — should NOT combine with the
    # now-expired earlier activity to cross the threshold.
    for port in range(PORT_SCAN_DISTINCT_THRESHOLD - 1):
        engine.record_port_activity("10.0.0.1", "10.0.0.9", 1000 + port)
    clock.advance(15.0)  # beyond PORT_SCAN_WINDOW_SECONDS (10s)
    result = engine.record_port_activity("10.0.0.1", "10.0.0.9", 9999)
    assert result is None
    assert engine.alert_count == 0


# ---------------------------------------------------------------------------
# Rule 2 — ARP Spoofing Detection
# ---------------------------------------------------------------------------


def test_first_sighting_of_an_ip_never_alerts():
    engine = ThreatDetectionEngine()
    result = engine.record_arp_sighting(mac="AA:AA:AA:AA:AA:AA", ip="192.168.1.1")
    assert result is None
    assert engine.alert_count == 0


def test_repeated_consistent_sightings_never_alert():
    engine = ThreatDetectionEngine()
    for _ in range(10):
        result = engine.record_arp_sighting(mac="AA:AA:AA:AA:AA:AA", ip="192.168.1.1")
        assert result is None
    assert engine.alert_count == 0


def test_single_stray_conflicting_packet_does_not_alert(clock):
    engine = ThreatDetectionEngine()
    engine.record_arp_sighting(mac="AA:AA:AA:AA:AA:AA", ip="192.168.1.1")
    # One single conflicting sighting — must not be treated as confirmed.
    result = engine.record_arp_sighting(mac="BB:BB:BB:BB:BB:BB", ip="192.168.1.1")
    assert result is None
    assert engine.alert_count == 0


def test_confirmed_conflict_within_debounce_window_alerts(clock):
    engine = ThreatDetectionEngine()
    engine.record_arp_sighting(mac="AA:AA:AA:AA:AA:AA", ip="192.168.1.1")
    engine.record_arp_sighting(mac="BB:BB:BB:BB:BB:BB", ip="192.168.1.1")  # pending
    clock.advance(0.5)  # well within debounce
    result = engine.record_arp_sighting(mac="BB:BB:BB:BB:BB:BB", ip="192.168.1.1")
    assert result is not None
    assert result.threat == "Possible ARP Spoofing"
    assert result.source == "192.168.1.1"
    assert result.severity == "high"
    assert "AA:AA:AA:AA:AA:AA" in result.description
    assert "BB:BB:BB:BB:BB:BB" in result.description


def test_conflict_confirmed_too_late_after_debounce_does_not_alert(clock):
    engine = ThreatDetectionEngine()
    engine.record_arp_sighting(mac="AA:AA:AA:AA:AA:AA", ip="192.168.1.1")
    engine.record_arp_sighting(mac="BB:BB:BB:BB:BB:BB", ip="192.168.1.1")  # pending
    clock.advance(ARP_CONFLICT_DEBOUNCE_SECONDS + 5)  # well past the debounce window
    result = engine.record_arp_sighting(mac="BB:BB:BB:BB:BB:BB", ip="192.168.1.1")
    assert result is None  # too late to count as the original pending conflict


def test_original_mac_reasserting_clears_pending_conflict(clock):
    engine = ThreatDetectionEngine()
    engine.record_arp_sighting(mac="AA:AA:AA:AA:AA:AA", ip="192.168.1.1")
    engine.record_arp_sighting(mac="BB:BB:BB:BB:BB:BB", ip="192.168.1.1")  # pending conflict
    clock.advance(0.1)
    # The original, legitimate MAC reasserts itself before the conflict is confirmed.
    result = engine.record_arp_sighting(mac="AA:AA:AA:AA:AA:AA", ip="192.168.1.1")
    assert result is None
    clock.advance(0.1)
    # BB shows up again — but the pending record was cleared, so this is
    # treated as a fresh single stray sighting, not a reconfirmation.
    result = engine.record_arp_sighting(mac="BB:BB:BB:BB:BB:BB", ip="192.168.1.1")
    assert result is None


def test_arp_cooldown_prevents_duplicate_alerts_until_it_expires(clock):
    engine = ThreatDetectionEngine()
    engine.record_arp_sighting(mac="AA:AA:AA:AA:AA:AA", ip="192.168.1.1")
    engine.record_arp_sighting(mac="BB:BB:BB:BB:BB:BB", ip="192.168.1.1")
    clock.advance(0.5)
    first = engine.record_arp_sighting(mac="BB:BB:BB:BB:BB:BB", ip="192.168.1.1")
    assert first is not None
    assert engine.alert_count == 1

    # Flip back and forth again quickly — still within the ARP cooldown.
    clock.advance(0.2)
    engine.record_arp_sighting(mac="AA:AA:AA:AA:AA:AA", ip="192.168.1.1")
    clock.advance(0.2)
    engine.record_arp_sighting(mac="CC:CC:CC:CC:CC:CC", ip="192.168.1.1")
    clock.advance(0.2)
    second = engine.record_arp_sighting(mac="CC:CC:CC:CC:CC:CC", ip="192.168.1.1")
    assert second is None  # confirmed conflict, but suppressed by cooldown
    assert engine.alert_count == 1

    # After the cooldown fully elapses, a new confirmed conflict can alert again.
    clock.advance(ARP_CONFLICT_COOLDOWN_SECONDS + 1)
    engine.record_arp_sighting(mac="DD:DD:DD:DD:DD:DD", ip="192.168.1.1")
    clock.advance(0.1)
    third = engine.record_arp_sighting(mac="DD:DD:DD:DD:DD:DD", ip="192.168.1.1")
    assert third is not None
    assert engine.alert_count == 2


def test_different_ips_tracked_independently_for_arp():
    engine = ThreatDetectionEngine()
    engine.record_arp_sighting(mac="AA:AA:AA:AA:AA:AA", ip="192.168.1.1")
    engine.record_arp_sighting(mac="BB:BB:BB:BB:BB:BB", ip="192.168.1.1")
    engine.record_arp_sighting(mac="BB:BB:BB:BB:BB:BB", ip="192.168.1.1")
    assert engine.alert_count == 1

    # A totally separate IP conflict must not be affected by the first IP's state.
    engine.record_arp_sighting(mac="11:11:11:11:11:11", ip="192.168.1.2")
    engine.record_arp_sighting(mac="22:22:22:22:22:22", ip="192.168.1.2")
    result = engine.record_arp_sighting(mac="22:22:22:22:22:22", ip="192.168.1.2")
    assert result is not None
    assert engine.alert_count == 2


# ---------------------------------------------------------------------------
# Rule 3 — DNS Tunneling Detection
# ---------------------------------------------------------------------------


def test_dns_tunnel_candidate_rejects_ordinary_queries():
    assert dns_tunnel_candidate("example.com (A)") is None  # only 2 labels
    assert dns_tunnel_candidate("www.example.com (A)") is None  # leaf too short


def test_dns_tunnel_candidate_accepts_oversized_leaf():
    result = dns_tunnel_candidate(_tunnel_query(1))
    assert result is not None
    leaf, parent = result
    assert leaf == f"{_LONG_LEAF}1"
    assert parent == "evil.example.com"


def test_ordinary_dns_traffic_produces_no_alerts():
    engine = ThreatDetectionEngine()
    for i in range(50):
        result = engine.record_dns_activity("10.0.0.5", f"host{i}.example.com (A)")
        assert result is None
    assert engine.alert_count == 0


def test_dns_tunnel_pattern_triggers_exactly_one_alert():
    engine = ThreatDetectionEngine()
    alerts = []
    for i in range(DNS_TUNNEL_DISTINCT_THRESHOLD + 10):
        result = engine.record_dns_activity("203.0.113.44", _tunnel_query(i))
        if result is not None:
            alerts.append(result)
    assert len(alerts) == 1
    assert alerts[0].threat == "Possible DNS Tunneling"
    assert alerts[0].source == "203.0.113.44"
    assert alerts[0].severity == "medium"


def test_dns_tunnel_alert_fires_on_the_query_that_crosses_threshold():
    engine = ThreatDetectionEngine()
    result = None
    for i in range(DNS_TUNNEL_DISTINCT_THRESHOLD):
        result = engine.record_dns_activity("203.0.113.44", _tunnel_query(i))
    assert result is not None


def test_dns_tunnel_cooldown_prevents_duplicate_alerts_until_it_expires(clock):
    engine = ThreatDetectionEngine()
    for i in range(DNS_TUNNEL_DISTINCT_THRESHOLD):
        engine.record_dns_activity("203.0.113.44", _tunnel_query(i))
    assert engine.alert_count == 1

    # Keep tunneling immediately after — still within cooldown, must not re-alert.
    for i in range(DNS_TUNNEL_DISTINCT_THRESHOLD, DNS_TUNNEL_DISTINCT_THRESHOLD + 20):
        result = engine.record_dns_activity("203.0.113.44", _tunnel_query(i))
        assert result is None
    assert engine.alert_count == 1

    # Once the cooldown has fully elapsed, a fresh burst can alert again.
    clock.advance(DNS_TUNNEL_COOLDOWN_SECONDS + 1)
    fired_again = False
    for i in range(DNS_TUNNEL_DISTINCT_THRESHOLD):
        result = engine.record_dns_activity("203.0.113.44", _tunnel_query(i, parent="second.evil.com"))
        if result is not None:
            fired_again = True
    assert fired_again
    assert engine.alert_count == 2


def test_different_parent_domains_are_tracked_independently():
    engine = ThreatDetectionEngine()
    for i in range(DNS_TUNNEL_DISTINCT_THRESHOLD):
        engine.record_dns_activity("203.0.113.44", _tunnel_query(i, parent="one.evil.com"))
    assert engine.alert_count == 1
    # A second, unrelated domain from the same source shouldn't be
    # suppressed by the first domain's cooldown.
    for i in range(DNS_TUNNEL_DISTINCT_THRESHOLD):
        engine.record_dns_activity("203.0.113.44", _tunnel_query(i, parent="two.evil.com"))
    assert engine.alert_count == 2


def test_old_dns_activity_falls_out_of_the_window(clock):
    engine = ThreatDetectionEngine()
    for i in range(DNS_TUNNEL_DISTINCT_THRESHOLD - 1):
        engine.record_dns_activity("10.0.0.1", _tunnel_query(i))
    clock.advance(30.0)  # beyond DNS_TUNNEL_WINDOW_SECONDS (20s)
    result = engine.record_dns_activity("10.0.0.1", _tunnel_query(9999))
    assert result is None
    assert engine.alert_count == 0


def test_dns_tunnel_ignores_empty_query():
    engine = ThreatDetectionEngine()
    result = engine.record_dns_activity("10.0.0.1", None)
    assert result is None
    assert engine.alert_count == 0


# ---------------------------------------------------------------------------
# Rule 4 — SYN Flood Detection
# ---------------------------------------------------------------------------


def test_is_bare_syn_accepts_only_the_syn_flag():
    assert is_bare_syn(_tcp_info(50000, 443, "S")) is True
    assert is_bare_syn(_tcp_info(443, 50000, "SA")) is False  # SYN-ACK reply
    assert is_bare_syn(_tcp_info(50000, 443, "A")) is False
    assert is_bare_syn(_tcp_info(50000, 443, "PA")) is False
    assert is_bare_syn(_tcp_info(50000, 443, "FA")) is False
    assert is_bare_syn(_tcp_info(50000, 443, "RA")) is False


def test_is_bare_syn_handles_missing_or_malformed_info():
    assert is_bare_syn(None) is False
    assert is_bare_syn("") is False
    assert is_bare_syn("UDP") is False
    assert is_bare_syn("DNS query: example.com") is False


def test_ordinary_tcp_traffic_produces_no_syn_flood_alerts():
    engine = ThreatDetectionEngine()
    for i in range(50):
        result = engine.record_syn_activity(
            "10.0.0.5", "93.184.216.34", 443, info=_tcp_info(50000 + i, 443, "A")
        )
        assert result is None
    assert engine.alert_count == 0


def test_syn_flood_pattern_triggers_exactly_one_alert():
    engine = ThreatDetectionEngine()
    alerts = []
    for i in range(SYN_FLOOD_COUNT_THRESHOLD + 20):
        result = engine.record_syn_activity(
            "203.0.113.44", "10.0.0.9", 80, info=_tcp_info(50000 + i, 80, "S")
        )
        if result is not None:
            alerts.append(result)
    assert len(alerts) == 1
    assert alerts[0].threat == "Possible SYN Flood"
    assert alerts[0].source == "203.0.113.44"
    assert alerts[0].severity == "medium"


def test_syn_flood_alert_fires_on_the_packet_that_crosses_threshold():
    engine = ThreatDetectionEngine()
    result = None
    for i in range(SYN_FLOOD_COUNT_THRESHOLD):
        result = engine.record_syn_activity(
            "203.0.113.44", "10.0.0.9", 80, info=_tcp_info(50000 + i, 80, "S")
        )
    assert result is not None


def test_syn_flood_cooldown_prevents_duplicate_alerts_until_it_expires(clock):
    engine = ThreatDetectionEngine()
    for i in range(SYN_FLOOD_COUNT_THRESHOLD):
        engine.record_syn_activity("203.0.113.44", "10.0.0.9", 80, info=_tcp_info(50000 + i, 80, "S"))
    assert engine.alert_count == 1

    for i in range(SYN_FLOOD_COUNT_THRESHOLD, SYN_FLOOD_COUNT_THRESHOLD + 20):
        result = engine.record_syn_activity(
            "203.0.113.44", "10.0.0.9", 80, info=_tcp_info(50000 + i, 80, "S")
        )
        assert result is None
    assert engine.alert_count == 1

    clock.advance(SYN_FLOOD_COOLDOWN_SECONDS + 1)
    fired_again = False
    for i in range(SYN_FLOOD_COUNT_THRESHOLD):
        result = engine.record_syn_activity(
            "203.0.113.44", "10.0.0.9", 80, info=_tcp_info(50000 + i, 80, "S")
        )
        if result is not None:
            fired_again = True
    assert fired_again
    assert engine.alert_count == 2


def test_different_destinations_are_tracked_independently_for_syn_flood():
    engine = ThreatDetectionEngine()
    for i in range(SYN_FLOOD_COUNT_THRESHOLD):
        engine.record_syn_activity("203.0.113.44", "10.0.0.9", 80, info=_tcp_info(50000 + i, 80, "S"))
    assert engine.alert_count == 1
    # A flood against a second port on the same target shouldn't be
    # suppressed by the first port's cooldown.
    for i in range(SYN_FLOOD_COUNT_THRESHOLD):
        engine.record_syn_activity("203.0.113.44", "10.0.0.9", 443, info=_tcp_info(50000 + i, 443, "S"))
    assert engine.alert_count == 2


def test_old_syn_activity_falls_out_of_the_window(clock):
    engine = ThreatDetectionEngine()
    for i in range(SYN_FLOOD_COUNT_THRESHOLD - 1):
        engine.record_syn_activity("10.0.0.1", "10.0.0.9", 80, info=_tcp_info(50000 + i, 80, "S"))
    clock.advance(10.0)  # beyond SYN_FLOOD_WINDOW_SECONDS (5s)
    result = engine.record_syn_activity("10.0.0.1", "10.0.0.9", 80, info=_tcp_info(60000, 80, "S"))
    assert result is None
    assert engine.alert_count == 0


# ---------------------------------------------------------------------------
# Rule 5 — Beaconing Detection
# ---------------------------------------------------------------------------


def _beacon(engine, src_ip, dst_ip, dst_port, clock, interval, count):
    """Fire `count` connections `interval` seconds apart, advancing the
    fake clock between each, returning the list of any alerts raised."""
    alerts = []
    for _ in range(count):
        result = engine.record_beacon_activity(src_ip, dst_ip, dst_port)
        if result is not None:
            alerts.append(result)
        clock.advance(interval)
    return alerts


def test_beacon_pattern_stats_needs_enough_intervals():
    ts = [1000.0 + i * 30 for i in range(MIN_BEACON_OBSERVATIONS)]  # one short
    assert beacon_pattern_stats(ts) is None


def test_beacon_pattern_stats_rejects_high_variance():
    # Wildly varying intervals: not remotely regular.
    ts = [1000.0]
    t = 1000.0
    for i in range(MIN_BEACON_OBSERVATIONS):
        t += 30 if i % 2 == 0 else 300
        ts.append(t)
    assert beacon_pattern_stats(ts) is None


def test_beacon_pattern_stats_rejects_out_of_range_mean():
    # Perfectly regular, but far too fast (sub-second-ish/active transfer).
    fast_ts = [1000.0 + i * 1.0 for i in range(MIN_BEACON_OBSERVATIONS + 1)]
    assert beacon_pattern_stats(fast_ts) is None

    # Perfectly regular, but far too slow.
    slow_ts = [1000.0 + i * (BEACON_MAX_INTERVAL_SECONDS * 2) for i in range(MIN_BEACON_OBSERVATIONS + 1)]
    assert beacon_pattern_stats(slow_ts) is None


def test_beacon_pattern_stats_accepts_tight_regular_interval():
    ts = [1000.0 + i * 30.0 for i in range(MIN_BEACON_OBSERVATIONS + 1)]
    stats = beacon_pattern_stats(ts)
    assert stats is not None
    mean, cv, count = stats
    assert mean == pytest.approx(30.0)
    assert cv < BEACON_CV_THRESHOLD
    assert count == MIN_BEACON_OBSERVATIONS


def test_irregular_traffic_produces_no_beacon_alerts(clock):
    engine = ThreatDetectionEngine()
    intervals = [5, 40, 12, 300, 8, 90, 15, 600, 22, 3, 250, 9]
    for interval in intervals:
        result = engine.record_beacon_activity("10.0.0.5", "93.184.216.34", 443)
        assert result is None
        clock.advance(interval)
    assert engine.alert_count == 0


def test_beacon_pattern_triggers_exactly_one_alert(clock):
    engine = ThreatDetectionEngine()
    alerts = _beacon(engine, "10.0.0.7", "203.0.113.9", 443, clock, 30.0, MIN_BEACON_OBSERVATIONS + 1)
    assert len(alerts) == 1
    assert alerts[0].threat == "Possible Beaconing Detected"
    assert alerts[0].source == "10.0.0.7"
    assert alerts[0].severity == "medium"


def test_beacon_alert_fires_on_the_connection_that_crosses_threshold(clock):
    engine = ThreatDetectionEngine()
    result = None
    for _ in range(MIN_BEACON_OBSERVATIONS + 1):
        result = engine.record_beacon_activity("10.0.0.7", "203.0.113.9", 443)
        clock.advance(30.0)
    assert result is not None


def test_beacon_cooldown_prevents_duplicate_alerts_until_it_expires(clock):
    engine = ThreatDetectionEngine()
    _beacon(engine, "10.0.0.7", "203.0.113.9", 443, clock, 30.0, MIN_BEACON_OBSERVATIONS + 1)
    assert engine.alert_count == 1

    # Keep beaconing at the same regular interval — still within cooldown.
    for _ in range(5):
        result = engine.record_beacon_activity("10.0.0.7", "203.0.113.9", 443)
        assert result is None
        clock.advance(30.0)
    assert engine.alert_count == 1

    # Once the cooldown has fully elapsed, the still-ongoing regular
    # pattern can alert again.
    clock.advance(BEACON_COOLDOWN_SECONDS + 1)
    fired_again = False
    for _ in range(MIN_BEACON_OBSERVATIONS + 1):
        result = engine.record_beacon_activity("10.0.0.7", "203.0.113.9", 443)
        if result is not None:
            fired_again = True
        clock.advance(30.0)
    assert fired_again
    assert engine.alert_count == 2


def test_different_destination_triples_tracked_independently_for_beaconing(clock):
    engine = ThreatDetectionEngine()
    _beacon(engine, "10.0.0.7", "203.0.113.9", 443, clock, 30.0, MIN_BEACON_OBSERVATIONS + 1)
    assert engine.alert_count == 1
    # A second, unrelated destination port shouldn't be suppressed by the
    # first triple's cooldown.
    _beacon(engine, "10.0.0.7", "203.0.113.9", 8443, clock, 30.0, MIN_BEACON_OBSERVATIONS + 1)
    assert engine.alert_count == 2


def test_intervals_faster_than_minimum_never_trigger_beaconing(clock):
    engine = ThreatDetectionEngine()
    alerts = _beacon(engine, "10.0.0.7", "203.0.113.9", 443, clock, BEACON_MIN_INTERVAL_SECONDS - 1, 30)
    assert alerts == []
    assert engine.alert_count == 0


def test_intervals_slower_than_maximum_never_trigger_beaconing(clock):
    engine = ThreatDetectionEngine()
    alerts = _beacon(
        engine, "10.0.0.7", "203.0.113.9", 443, clock, BEACON_MAX_INTERVAL_SECONDS + 1, MIN_BEACON_OBSERVATIONS + 1
    )
    assert alerts == []
    assert engine.alert_count == 0


def test_old_irregular_history_falls_out_of_the_beacon_window(clock):
    engine = ThreatDetectionEngine()
    # Build up a regular pattern that trips the rule once.
    _beacon(engine, "10.0.0.7", "203.0.113.9", 443, clock, 30.0, MIN_BEACON_OBSERVATIONS + 1)
    assert engine.alert_count == 1

    # One huge, irregular gap — the trailing history right after this is
    # no longer tight enough to qualify.
    clock.advance(10_000.0)
    result = engine.record_beacon_activity("10.0.0.7", "203.0.113.9", 443)
    assert result is None

    # Well past cooldown, resume the same regular cadence. Once enough
    # fresh, regular connections have pushed the one irregular gap out of
    # the fixed-size history, the pattern should be trusted again.
    clock.advance(BEACON_COOLDOWN_SECONDS + 1)
    fired_again = False
    for _ in range(BEACON_HISTORY_SIZE + 1):
        result = engine.record_beacon_activity("10.0.0.7", "203.0.113.9", 443)
        if result is not None:
            fired_again = True
        clock.advance(30.0)
    assert fired_again


# ---------------------------------------------------------------------------
# Rule 6 — Data Exfiltration Detection
# ---------------------------------------------------------------------------


def test_ordinary_transfer_volume_produces_no_exfil_alerts(clock):
    engine = ThreatDetectionEngine()
    for _ in range(20):
        result = engine.record_data_transfer("10.0.0.5", "93.184.216.34", payload_size=5_000)
        assert result is None
        clock.advance(2.0)
    assert engine.alert_count == 0


def test_exfil_pattern_triggers_exactly_one_alert(clock):
    engine = ThreatDetectionEngine()
    result = engine.record_data_transfer("203.0.113.44", "10.0.0.9", payload_size=EXFIL_BYTE_THRESHOLD)
    assert result is not None
    assert result.threat == "Possible Data Exfiltration"
    assert result.source == "203.0.113.44"
    assert result.severity == "medium"
    assert engine.alert_count == 1


def test_exfil_alert_fires_on_the_packet_that_crosses_threshold(clock):
    engine = ThreatDetectionEngine()
    chunk = EXFIL_BYTE_THRESHOLD // 5
    result = None
    for _ in range(5):
        result = engine.record_data_transfer("203.0.113.44", "10.0.0.9", payload_size=chunk)
        clock.advance(1.0)
    assert result is not None


def test_exfil_cooldown_prevents_duplicate_alerts_until_it_expires(clock):
    engine = ThreatDetectionEngine()
    engine.record_data_transfer("203.0.113.44", "10.0.0.9", payload_size=EXFIL_BYTE_THRESHOLD)
    assert engine.alert_count == 1

    for _ in range(5):
        result = engine.record_data_transfer("203.0.113.44", "10.0.0.9", payload_size=EXFIL_BYTE_THRESHOLD)
        assert result is None
    assert engine.alert_count == 1

    clock.advance(EXFIL_COOLDOWN_SECONDS + 1)
    result = engine.record_data_transfer("203.0.113.44", "10.0.0.9", payload_size=EXFIL_BYTE_THRESHOLD)
    assert result is not None
    assert engine.alert_count == 2


def test_different_destination_pairs_tracked_independently_for_exfil(clock):
    engine = ThreatDetectionEngine()
    engine.record_data_transfer("10.0.0.1", "10.0.0.9", payload_size=EXFIL_BYTE_THRESHOLD)
    assert engine.alert_count == 1
    # A second, unrelated source shouldn't be suppressed by the first
    # pair's cooldown.
    engine.record_data_transfer("10.0.0.2", "10.0.0.9", payload_size=EXFIL_BYTE_THRESHOLD)
    assert engine.alert_count == 2


def test_old_exfil_activity_falls_out_of_the_window(clock):
    engine = ThreatDetectionEngine()
    # Just under threshold, then let time pass beyond the window, then
    # send a bit more — should NOT combine with the now-expired earlier
    # bytes to cross the threshold.
    engine.record_data_transfer("10.0.0.1", "10.0.0.9", payload_size=EXFIL_BYTE_THRESHOLD - 100)
    clock.advance(EXFIL_WINDOW_SECONDS + 5)
    result = engine.record_data_transfer("10.0.0.1", "10.0.0.9", payload_size=50)
    assert result is None
    assert engine.alert_count == 0


# ---------------------------------------------------------------------------
# Delta feed / backlog — mirrors PacketStreamEngine's contract
# ---------------------------------------------------------------------------


def test_empty_engine_has_no_backlog_and_zero_seq():
    engine = ThreatDetectionEngine()
    assert engine.backlog() == []
    assert engine.since(0) == []
    assert engine.latest_seq == 0
    assert engine.alert_count == 0


def test_since_only_returns_alerts_after_given_sequence():
    engine = ThreatDetectionEngine()
    for i in range(3):
        for port in range(PORT_SCAN_DISTINCT_THRESHOLD):
            engine.record_port_activity(f"10.0.0.{i}", "10.0.0.9", 1000 + port)
    assert engine.latest_seq == 3
    rows = engine.since(1)
    assert [r.no for r in rows] == [2, 3]


def test_backlog_returns_most_recent_alerts():
    engine = ThreatDetectionEngine()
    for i in range(5):
        for port in range(PORT_SCAN_DISTINCT_THRESHOLD):
            engine.record_port_activity(f"10.0.0.{i}", "10.0.0.9", 1000 + port)
    assert engine.latest_seq == 5
    rows = engine.backlog(limit=2)
    assert [r.no for r in rows] == [4, 5]


def test_ring_buffer_evicts_oldest_when_full():
    engine = ThreatDetectionEngine(max_buffer=2)
    for i in range(3):
        for port in range(PORT_SCAN_DISTINCT_THRESHOLD):
            engine.record_port_activity(f"10.0.0.{i}", "10.0.0.9", 1000 + port)
    rows = engine.since(0)
    assert [r.no for r in rows] == [2, 3]
    assert engine.latest_seq == 3  # counter itself is unaffected by eviction


def test_alert_id_and_no_are_consistent():
    engine = ThreatDetectionEngine()
    for port in range(PORT_SCAN_DISTINCT_THRESHOLD):
        result = engine.record_port_activity("10.0.0.1", "10.0.0.9", 1000 + port)
    assert result is not None
    assert result.id == f"threat-{result.no}"
