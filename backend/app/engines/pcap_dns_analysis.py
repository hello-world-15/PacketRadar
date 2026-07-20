"""
DNS Analysis for GET /api/pcap/{capture_id}/dns.

Pure aggregation over an already-parsed list of PacketModel — no file
I/O, no Scapy, same convention as app.engines.pcap_summary. Built from
`dns_query` (already populated by PacketParser for every DNS packet) and
the new `dns_rcode` field (see docs/contracts/pcap-dns-analysis.md for
why `dns_rcode` replaces a fragile substring-match against `info`).
"""

from __future__ import annotations

import re

from app.models.packet import PacketModel
from app.schemas.pcap_dns import DnsAnalysisResponse, DomainCountRow, TopDomainRow

# Kept consistent with app.engines.pcap_insights's own already-established
# constants for the same underlying concepts (that module's DNS Analysis
# predates this one but was never wired to a route — see this endpoint's
# contract doc) rather than picking a third arbitrary number for "how many
# domains is enough to show".
TOP_DOMAINS_LIMIT = 8
REPEATED_QUERIES_LIMIT = 8
FAILED_QUERIES_LIMIT = 8

# A domain queried this many times or more is flagged as "repeated" — see
# docs/contracts/pcap-dns-analysis.md for the full justification. Same
# value as app.engines.pcap_insights.REPEATED_QUERY_MIN_COUNT; duplicated
# rather than imported so this endpoint has no dependency on that
# separate, unwired module.
REPEATED_QUERY_MIN_COUNT = 40

# `dns_query` is formatted by PacketParser as "example.com (A)" — strip
# the trailing " (TYPE)" to get just the domain. Same small regex as
# app.engines.pcap_insights._extract_domain; duplicated rather than
# imported for the same independence reason as REPEATED_QUERY_MIN_COUNT
# above — this is a two-line utility, not complex logic worth coupling
# two otherwise-unrelated modules over.
_QTYPE_SUFFIX = re.compile(r"\s*\([A-Z0-9]+\)$")


def _extract_domain(dns_query: str) -> str:
    return _QTYPE_SUFFIX.sub("", dns_query).strip()


def compute_dns_analysis(packets: list[PacketModel]) -> DnsAnalysisResponse:
    query_counts: dict[str, int] = {}
    fail_counts: dict[str, int] = {}

    for p in packets:
        if p.protocol != "DNS" or not p.dns_query:
            continue
        domain = _extract_domain(p.dns_query)

        if p.dst_port == 53:
            # Query direction — the same condition
            # app.engines.pcap_summary's dns_request_count already uses
            # to distinguish a query from a response.
            query_counts[domain] = query_counts.get(domain, 0) + 1
        elif p.dns_rcode not in (None, "NOERROR"):
            # Response direction with a real failure rcode (NXDOMAIN,
            # SERVFAIL, REFUSED, etc.) — the precise signal dns_rcode
            # exists to provide, instead of proxying via "no answer".
            fail_counts[domain] = fail_counts.get(domain, 0) + 1

    top_domains = sorted(
        (TopDomainRow(domain=d, queries=c) for d, c in query_counts.items()),
        key=lambda row: -row.queries,
    )[:TOP_DOMAINS_LIMIT]

    repeated_queries = sorted(
        (
            DomainCountRow(domain=d, count=c)
            for d, c in query_counts.items()
            if c >= REPEATED_QUERY_MIN_COUNT
        ),
        key=lambda row: -row.count,
    )[:REPEATED_QUERIES_LIMIT]

    failed_queries = sorted(
        (DomainCountRow(domain=d, count=c) for d, c in fail_counts.items()),
        key=lambda row: -row.count,
    )[:FAILED_QUERIES_LIMIT]

    return DnsAnalysisResponse(
        top_domains=top_domains,
        repeated_queries=repeated_queries,
        failed_queries=failed_queries,
    )
