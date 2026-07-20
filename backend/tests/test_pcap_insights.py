"""
Unit tests for app.engines.pcap_insights — feeds synthetic PacketModel
instances directly, no file I/O or Scapy required. Matches the style of
test_pcap_summary.py and test_threat_detection_engine.py.
"""

from datetime import datetime, timedelta

from app.engines.pcap_insights import (
    REPEATED_QUERY_MIN_COUNT,
    _RECOMMENDATIONS,
    _DEFAULT_RECOMMENDATION,
    compute_dns_analysis,
    compute_health_score,
    compute_insights,
    compute_threat_findings,
)
from app.models.packet import PacketModel
from app.schemas.pcap import ThreatFinding

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
        length=100,
        payload_size=50,
        flow_key="10.0.0.1:1234-10.0.0.2:443-TCP",
        info="TCP",
    )
    defaults.update(overrides)
    return PacketModel(**defaults)


def _dns_query(domain: str, qtype: str = "A", at=BASE_TIME, src_ip="10.0.0.1"):
    return _packet(
        timestamp=at,
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        src_port=51000,
        dst_port=53,
        protocol="DNS",
        dns_query=f"{domain} ({qtype})",
        dns_answer=None,
    )


def _dns_response(domain: str, qtype: str = "A", answer: str | None = "93.184.216.34", at=BASE_TIME):
    return _packet(
        timestamp=at,
        src_ip="8.8.8.8",
        dst_ip="10.0.0.1",
        src_port=53,
        dst_port=51000,
        protocol="DNS",
        dns_query=f"{domain} ({qtype})",
        dns_answer=answer,
    )


# ---------------------------------------------------------------------------
# DNS Analysis
# ---------------------------------------------------------------------------


def test_empty_packet_list_gives_empty_dns_analysis():
    result = compute_dns_analysis([])
    assert result.top_domains == []
    assert result.repeated_queries == []
    assert result.failed_queries == []


def test_top_domains_ranked_by_query_count_descending():
    packets = (
        [_dns_query("a.com") for _ in range(5)]
        + [_dns_query("b.com") for _ in range(2)]
        + [_dns_query("c.com") for _ in range(8)]
    )
    result = compute_dns_analysis(packets)
    assert [d.domain for d in result.top_domains] == ["c.com", "a.com", "b.com"]
    assert result.top_domains[0].count == 8


def test_top_domains_does_not_double_count_responses():
    packets = [_dns_query("a.com"), _dns_response("a.com")]
    result = compute_dns_analysis(packets)
    assert result.top_domains[0].count == 1  # only the query counted


def test_repeated_queries_only_includes_domains_over_threshold():
    packets = [_dns_query("popular.com") for _ in range(REPEATED_QUERY_MIN_COUNT - 1)]
    result = compute_dns_analysis(packets)
    assert result.repeated_queries == []  # under threshold, not flagged


def test_repeated_queries_includes_domain_at_or_over_threshold():
    packets = [_dns_query("beacon.example.net") for _ in range(REPEATED_QUERY_MIN_COUNT)]
    result = compute_dns_analysis(packets)
    assert len(result.repeated_queries) == 1
    assert result.repeated_queries[0].domain == "beacon.example.net"
    assert result.repeated_queries[0].count == REPEATED_QUERY_MIN_COUNT


def test_failed_queries_only_counts_responses_with_no_answer():
    packets = [
        _dns_response("good.com", answer="1.2.3.4"),
        _dns_response("bad.invalid", answer=None),
        _dns_response("bad.invalid", answer=None),
        _dns_query("bad.invalid"),  # query side must not count as a failure
    ]
    result = compute_dns_analysis(packets)
    assert len(result.failed_queries) == 1
    assert result.failed_queries[0].domain == "bad.invalid"
    assert result.failed_queries[0].count == 2


def test_non_dns_packets_are_ignored_by_dns_analysis():
    packets = [_packet(protocol="TCP"), _packet(protocol="ARP", src_ip="1.1.1.1", dst_ip="1.1.1.2")]
    result = compute_dns_analysis(packets)
    assert result.top_domains == []
    assert result.failed_queries == []


def test_domain_extraction_strips_qtype_suffix():
    packets = [_dns_query("example.com", qtype="AAAA")]
    result = compute_dns_analysis(packets)
    assert result.top_domains[0].domain == "example.com"


# ---------------------------------------------------------------------------
# Threat Analysis
# ---------------------------------------------------------------------------


def test_no_packets_gives_no_threat_findings():
    assert compute_threat_findings([]) == []


def test_normal_traffic_gives_no_findings():
    packets = [_packet(dst_port=443 + i) for i in range(3)]
    assert compute_threat_findings(packets) == []


def test_port_scan_pattern_produces_one_finding():
    packets = [
        _packet(
            timestamp=BASE_TIME + timedelta(milliseconds=i * 10),
            src_ip="203.0.113.44",
            dst_ip="10.0.0.9",
            dst_port=1000 + i,
        )
        for i in range(20)
    ]
    findings = compute_threat_findings(packets)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].reason == "Port Scan Detected"
    assert "203.0.113.44" in findings[0].evidence
    assert findings[0].recommendation == _RECOMMENDATIONS["Port Scan Detected"]


def test_arp_conflict_pattern_produces_one_high_severity_finding():
    packets = [
        _packet(
            timestamp=BASE_TIME,
            protocol="ARP",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.42",
            src_port=None,
            dst_port=None,
            src_mac="AA:AA:AA:AA:AA:AA",
        ),
        _packet(
            timestamp=BASE_TIME + timedelta(seconds=1),
            protocol="ARP",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.42",
            src_port=None,
            dst_port=None,
            src_mac="BB:BB:BB:BB:BB:BB",
        ),
        _packet(
            timestamp=BASE_TIME + timedelta(seconds=1, milliseconds=500),
            protocol="ARP",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.42",
            src_port=None,
            dst_port=None,
            src_mac="BB:BB:BB:BB:BB:BB",
        ),
    ]
    findings = compute_threat_findings(packets)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].reason == "Possible ARP Spoofing"
    assert findings[0].recommendation == _RECOMMENDATIONS["Possible ARP Spoofing"]


def test_findings_are_replayed_in_chronological_order_regardless_of_list_order():
    # Same scan pattern as above, but shuffled in the input list — the
    # engine must sort by timestamp before replaying, or this either
    # misses the scan or fires on the wrong packet.
    packets = [
        _packet(
            timestamp=BASE_TIME + timedelta(milliseconds=i * 10),
            src_ip="203.0.113.44",
            dst_ip="10.0.0.9",
            dst_port=1000 + i,
        )
        for i in range(20)
    ]
    shuffled = list(reversed(packets))
    findings = compute_threat_findings(shuffled)
    assert len(findings) == 1


def test_arp_packet_without_src_mac_is_skipped_safely():
    # Defensive: a malformed/legacy record with no src_mac must not crash.
    packets = [
        _packet(protocol="ARP", src_ip="192.168.1.1", dst_ip="192.168.1.42", src_port=None, dst_port=None, src_mac=None)
    ]
    assert compute_threat_findings(packets) == []


def test_unrecognized_threat_label_falls_back_to_default_recommendation():
    assert _RECOMMENDATIONS.get("Some Future Rule", _DEFAULT_RECOMMENDATION) == _DEFAULT_RECOMMENDATION


# ---------------------------------------------------------------------------
# Network Health Score
# ---------------------------------------------------------------------------


def test_clean_capture_scores_100_with_explanatory_factor():
    result = compute_health_score([_packet()], threats=[])
    assert result.score == 100
    assert result.factors == ["No threat, DNS, or cleartext-traffic anomalies found in this capture."]


def test_high_severity_threat_deducts_20():
    threat = ThreatFinding(severity="high", reason="Possible ARP Spoofing", evidence="e", recommendation="r")
    result = compute_health_score([_packet()], threats=[threat])
    assert result.score == 80
    assert any("threat finding" in f for f in result.factors)


def test_medium_severity_threat_deducts_10():
    threat = ThreatFinding(severity="medium", reason="Port Scan Detected", evidence="e", recommendation="r")
    result = compute_health_score([_packet()], threats=[threat])
    assert result.score == 90


def test_multiple_threats_stack_additively():
    threats = [
        ThreatFinding(severity="high", reason="Possible ARP Spoofing", evidence="e", recommendation="r"),
        ThreatFinding(severity="medium", reason="Port Scan Detected", evidence="e", recommendation="r"),
    ]
    result = compute_health_score([_packet()], threats=threats)
    assert result.score == 70


def test_score_floors_at_zero_even_with_many_threats():
    threats = [
        ThreatFinding(severity="high", reason="Possible ARP Spoofing", evidence="e", recommendation="r")
        for _ in range(10)
    ]
    result = compute_health_score([_packet()], threats=threats)
    assert result.score == 0


def test_dns_failure_ratio_deducts_scaled_penalty():
    # 2 failed out of 2 total responses -> 100% failure ratio -> full DNS penalty.
    packets = [
        _dns_response("bad.invalid", answer=None),
        _dns_response("bad.invalid", answer=None),
    ]
    result = compute_health_score(packets, threats=[])
    assert result.score == 100 - 15  # _MAX_DNS_FAILURE_PENALTY
    assert any("failed DNS lookup" in f for f in result.factors)


def test_no_dns_responses_means_no_dns_penalty():
    result = compute_health_score([_dns_query("fine.com")], threats=[])
    assert result.score == 100


def test_repeated_domains_deduct_capped_penalty():
    # 5 distinct domains each over the repeated-query threshold -> would
    # be 5*3=15 uncapped, but capped at 10.
    packets = []
    for i in range(5):
        packets += [_dns_query(f"beacon{i}.example.net") for _ in range(REPEATED_QUERY_MIN_COUNT)]
    result = compute_health_score(packets, threats=[])
    assert result.score == 90  # 100 - 10 (capped)


def test_cleartext_port_traffic_deducts_scaled_penalty():
    # All TCP traffic on port 80 -> 100% cleartext ratio -> full penalty.
    packets = [_packet(dst_port=80) for _ in range(10)]
    result = compute_health_score(packets, threats=[])
    assert result.score == 100 - 15  # _MAX_ENCRYPTION_PENALTY
    assert any("plaintext ports" in f for f in result.factors)


def test_encrypted_only_traffic_has_no_encryption_penalty():
    packets = [_packet(dst_port=443) for _ in range(10)]
    result = compute_health_score(packets, threats=[])
    assert result.score == 100


# ---------------------------------------------------------------------------
# compute_insights — end-to-end
# ---------------------------------------------------------------------------


def test_compute_insights_combines_all_three():
    packets = [
        _packet(
            timestamp=BASE_TIME + timedelta(milliseconds=i * 10),
            src_ip="203.0.113.44",
            dst_ip="10.0.0.9",
            dst_port=1000 + i,
        )
        for i in range(20)
    ] + [_dns_query("example.com")]

    insights = compute_insights(packets)
    assert len(insights.threats) == 1
    assert insights.threats[0].reason == "Port Scan Detected"
    assert insights.dns.top_domains[0].domain == "example.com"
    assert insights.health.score == 90  # 100 - 10 (medium threat penalty)
