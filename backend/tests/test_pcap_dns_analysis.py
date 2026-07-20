"""
Unit tests for app.engines.pcap_dns_analysis — feeds synthetic
PacketModel instances directly, no file I/O or Scapy required. Matches
the style of test_pcap_summary.py / test_pcap_insights.py.
"""

from datetime import datetime

from app.engines.pcap_dns_analysis import (
    REPEATED_QUERY_MIN_COUNT,
    compute_dns_analysis,
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
        length=100,
        payload_size=50,
        flow_key="10.0.0.1:1234-10.0.0.2:443-TCP",
        info="TCP",
    )
    defaults.update(overrides)
    return PacketModel(**defaults)


def _dns_query(domain: str, qtype: str = "A", src_ip: str = "10.0.0.1") -> PacketModel:
    return _packet(
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        src_port=51000,
        dst_port=53,
        protocol="DNS",
        dns_query=f"{domain} ({qtype})",
        dns_answer=None,
        dns_rcode=None,
    )


def _dns_response(
    domain: str, qtype: str = "A", answer: str | None = "93.184.216.34", rcode: str = "NOERROR"
) -> PacketModel:
    return _packet(
        src_ip="8.8.8.8",
        dst_ip="10.0.0.1",
        src_port=53,
        dst_port=51000,
        protocol="DNS",
        dns_query=f"{domain} ({qtype})",
        dns_answer=answer,
        dns_rcode=rcode,
    )


# ---------------------------------------------------------------------------
# Top Domains
# ---------------------------------------------------------------------------


def test_empty_packet_list_gives_empty_lists_not_an_error():
    result = compute_dns_analysis([])
    assert result.top_domains == []
    assert result.repeated_queries == []
    assert result.failed_queries == []


def test_capture_with_no_dns_traffic_gives_empty_lists():
    packets = [_packet(protocol="TCP"), _packet(protocol="UDP", dst_port=51820)]
    result = compute_dns_analysis(packets)
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
    assert result.top_domains[0].queries == 8


def test_top_domains_does_not_count_responses_only_queries():
    packets = [_dns_query("a.com"), _dns_response("a.com")]
    result = compute_dns_analysis(packets)
    assert result.top_domains[0].queries == 1


def test_top_domains_respects_the_limit():
    packets = []
    for i in range(12):
        packets += [_dns_query(f"domain{i}.com") for _ in range(i + 1)]
    result = compute_dns_analysis(packets)
    assert len(result.top_domains) == 8
    # Highest-count domains win the cutoff.
    assert result.top_domains[0].domain == "domain11.com"


def test_domain_extraction_strips_qtype_suffix():
    result = compute_dns_analysis([_dns_query("example.com", qtype="AAAA")])
    assert result.top_domains[0].domain == "example.com"


# ---------------------------------------------------------------------------
# Repeated Queries
# ---------------------------------------------------------------------------


def test_repeated_queries_excludes_domains_under_threshold():
    packets = [_dns_query("popular.com") for _ in range(REPEATED_QUERY_MIN_COUNT - 1)]
    result = compute_dns_analysis(packets)
    assert result.repeated_queries == []


def test_repeated_queries_includes_domain_at_threshold():
    packets = [_dns_query("beacon.example.net") for _ in range(REPEATED_QUERY_MIN_COUNT)]
    result = compute_dns_analysis(packets)
    assert len(result.repeated_queries) == 1
    assert result.repeated_queries[0].domain == "beacon.example.net"
    assert result.repeated_queries[0].count == REPEATED_QUERY_MIN_COUNT


def test_repeated_queries_is_not_a_duplicate_of_top_domains():
    # A handful of moderately popular domains, all well under the
    # repeated-query threshold, plus one domain that actually crosses it.
    packets = (
        [_dns_query("cdn-a.com") for _ in range(20)]
        + [_dns_query("cdn-b.com") for _ in range(15)]
        + [_dns_query("cdn-c.com") for _ in range(10)]
        + [_dns_query("beacon.example.net") for _ in range(REPEATED_QUERY_MIN_COUNT)]
    )
    result = compute_dns_analysis(packets)
    # Top Domains surfaces the popular CDN domains (and the beacon domain,
    # since it's also the single highest count here).
    assert {d.domain for d in result.top_domains} == {
        "cdn-a.com",
        "cdn-b.com",
        "cdn-c.com",
        "beacon.example.net",
    }
    # Repeated Queries surfaces only the domain that actually crossed the
    # abnormality threshold — not the same ranked list.
    assert [d.domain for d in result.repeated_queries] == ["beacon.example.net"]


def test_repeated_queries_may_overlap_top_domains_by_design():
    # A single very-high-volume domain can legitimately appear in both
    # lists — see docs/contracts/pcap-dns-analysis.md.
    packets = [_dns_query("huge.example.com") for _ in range(REPEATED_QUERY_MIN_COUNT + 50)]
    result = compute_dns_analysis(packets)
    assert result.top_domains[0].domain == "huge.example.com"
    assert result.repeated_queries[0].domain == "huge.example.com"


# ---------------------------------------------------------------------------
# Failed Queries
# ---------------------------------------------------------------------------


def test_failed_queries_uses_dns_rcode_not_missing_answer():
    packets = [
        _dns_response("good.com", answer="1.2.3.4", rcode="NOERROR"),
        _dns_response("bad.invalid", answer=None, rcode="NXDOMAIN"),
        _dns_response("bad.invalid", answer=None, rcode="NXDOMAIN"),
        _dns_response("timeout.example.com", answer=None, rcode="SERVFAIL"),
    ]
    result = compute_dns_analysis(packets)
    counts = {d.domain: d.count for d in result.failed_queries}
    assert counts == {"bad.invalid": 2, "timeout.example.com": 1}


def test_noerror_response_is_never_counted_as_failed_even_with_no_answer():
    # A NOERROR response with no answer records is legitimate (e.g. a
    # query type with genuinely nothing to return) — dns_rcode, not
    # answer presence, is what decides failure here.
    packets = [_dns_response("fine.com", answer=None, rcode="NOERROR")]
    result = compute_dns_analysis(packets)
    assert result.failed_queries == []


def test_query_side_never_counts_as_a_failure():
    packets = [_dns_query("bad.invalid")]  # dns_rcode is always None on queries
    result = compute_dns_analysis(packets)
    assert result.failed_queries == []


def test_non_dns_packets_are_ignored_entirely():
    packets = [_packet(protocol="TCP"), _packet(protocol="ARP", src_ip="1.1.1.1", dst_ip="1.1.1.2")]
    result = compute_dns_analysis(packets)
    assert result.top_domains == []
    assert result.failed_queries == []
