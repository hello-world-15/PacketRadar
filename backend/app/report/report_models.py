"""
Structured Report Object for PacketRadar's PCAP Analysis PDF Report.

This is the contract in the middle of the pipeline described in the
PacketRadar AI Prompt:

    PCAP -> Packet Analysis Engine -> Report Object -> PDF Generator

`app.report.report_builder.build_report()` is the only thing that
constructs a `Report`. `app.report.pdf_generator.generate_pdf()` is the
only thing that reads one. Nothing in `pdf_generator.py` ever touches a
`PacketModel` directly — this file is the seam that keeps the two sides
independently testable, exactly like every other engine/schema pair in
this codebase (see app.schemas.pcap for the live precedent).

Every list here is already sorted and already trimmed to a sane display
length by the builder — the PDF generator never re-sorts or re-slices.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]
RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ---------------------------------------------------------------------------
# 1. Cover page / metadata
# ---------------------------------------------------------------------------


class ReportMetadata(BaseModel):
    report_title: str = "PCAP Analysis Report"
    generated_at: str  # human-readable, e.g. "20 Jul 2026, 14:32 UTC"
    filename: str
    capture_duration: str  # pre-formatted, e.g. "12m 4s"
    packetradar_version: str = "PacketRadar v1.0"
    author: str = "PacketRadar Automated Analysis Engine"
    confidentiality_notice: str = (
        "This report was generated automatically and may contain sensitive "
        "network information. Distribute only to authorized personnel."
    )


# ---------------------------------------------------------------------------
# 3. Executive summary
# ---------------------------------------------------------------------------


class SummaryCard(BaseModel):
    label: str
    value: str


class ExecutiveSummary(BaseModel):
    cards: list[SummaryCard]
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    narrative: str


# ---------------------------------------------------------------------------
# 4. Capture information
# ---------------------------------------------------------------------------


class CaptureInfo(BaseModel):
    filename: str
    file_size: str
    start_time: str
    end_time: str
    duration: str
    link_layer: str
    ipv4_packets: int
    ipv6_packets: int
    avg_packet_size_bytes: int
    avg_bandwidth_mbps: float
    avg_packets_per_sec: float
    total_bytes: str


# ---------------------------------------------------------------------------
# 5. Traffic overview / statistics
# ---------------------------------------------------------------------------


class ProtocolStat(BaseModel):
    protocol: str
    packets: int
    pct: float


class TrafficStatistics(BaseModel):
    protocol_counts: list[ProtocolStat]
    top_packet_sizes: list[tuple[str, int]]  # (size bucket, count)
    inbound_packets: int
    outbound_packets: int
    inbound_pct: float
    outbound_pct: float


# ---------------------------------------------------------------------------
# 6. Host discovery
# ---------------------------------------------------------------------------


class HostRow(BaseModel):
    ip: str
    mac: str
    vendor: str
    hostname: str
    packets: int
    bytes: str
    first_seen: str
    last_seen: str
    role: str  # Local / Gateway / DNS Server / Broadcast / Multicast / External


# ---------------------------------------------------------------------------
# 7. Top talkers
# ---------------------------------------------------------------------------


class TalkerRow(BaseModel):
    ip: str
    packets: int
    bytes: str
    pct: float
    bandwidth_mbps: float


class ConversationRow(BaseModel):
    a: str
    b: str
    packets: int
    bytes: str
    duration: str


class TopTalkers(BaseModel):
    top_sources: list[TalkerRow]
    top_destinations: list[TalkerRow]
    top_conversations: list[ConversationRow]


# ---------------------------------------------------------------------------
# 8. Flow analysis
# ---------------------------------------------------------------------------


class FlowRow(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    protocol: str
    packets: int
    bytes: str
    duration: str
    state: str


# ---------------------------------------------------------------------------
# 9. Protocol analysis subsections
# ---------------------------------------------------------------------------


class TcpAnalysis(BaseModel):
    connections: int
    syn: int
    fin: int
    rst: int
    retransmissions: int
    failed_connections: int
    connection_resets: int


class UdpAnalysis(BaseModel):
    streams: int
    top_ports: list[tuple[str, int]]
    dhcp: int
    dns: int
    ntp: int
    quic: int


class DnsProtocolAnalysis(BaseModel):
    total_queries: int
    unique_domains: int
    unique_dns_servers: int
    top_domains: list[tuple[str, int]]
    nxdomain_count: int
    longest_domain: str
    most_queried_domain: str
    suspicious_domains: list[str]
    repeated_queries: list[tuple[str, int]]
    random_looking_domains: list[str]


class HttpAnalysis(BaseModel):
    hosts: list[tuple[str, int]]
    methods: list[tuple[str, int]]
    top_requested_resources: list[tuple[str, int]]
    note: str = (
        "PacketRadar's parser currently classifies traffic by transport "
        "layer only; HTTP application-layer decoding (methods, status "
        "codes, headers) is not yet implemented, so this section reflects "
        "port-80 TCP traffic volume rather than parsed HTTP requests."
    )


class HttpsAnalysis(BaseModel):
    most_contacted_hosts: list[tuple[str, int]]
    note: str = (
        "TLS handshake decoding (SNI, certificate subject, cipher suite) "
        "is not yet implemented; this section reflects port-443 TCP "
        "traffic volume."
    )


class IcmpAnalysis(BaseModel):
    total: int
    echo_requests: int
    echo_replies: int
    other: int
    note: str = (
        "PacketRadar's parser currently classifies ICMP traffic by "
        "protocol only, not by ICMP type/code, so Echo Request/Reply are "
        "shown as 0 pending that classification being added."
    )


class ArpAnalysis(BaseModel):
    requests: int
    replies: int
    duplicate_arp: int
    potential_spoofing_incidents: int


class ProtocolAnalysis(BaseModel):
    tcp: TcpAnalysis
    udp: UdpAnalysis
    dns: DnsProtocolAnalysis
    http: HttpAnalysis
    https: HttpsAnalysis
    icmp: IcmpAnalysis
    arp: ArpAnalysis


# ---------------------------------------------------------------------------
# 10. Port analysis
# ---------------------------------------------------------------------------


class PortRow(BaseModel):
    port: int
    service: str
    packets: int
    pct: float
    flagged: bool = False  # unexpected / rare port


class PortAnalysis(BaseModel):
    top_ports: list[PortRow]
    unexpected_ports: list[PortRow]


# ---------------------------------------------------------------------------
# 11. DNS intelligence (dedicated section — reuses DnsProtocolAnalysis data
# plus a few additional threat-oriented lists)
# ---------------------------------------------------------------------------


class DnsIntelligence(BaseModel):
    top_domains: list[tuple[str, int]]
    top_dns_servers: list[tuple[str, int]]
    external_domains: list[tuple[str, int]]
    suspicious_domains: list[str]
    very_long_domains: list[str]
    high_frequency_domains: list[tuple[str, int]]
    tunneling_indicators: list[str]


# ---------------------------------------------------------------------------
# 12. Timeline
# ---------------------------------------------------------------------------


class TimelinePoint(BaseModel):
    label: str
    value: float


class TimelineData(BaseModel):
    packets_per_bucket: list[TimelinePoint]
    bandwidth_per_bucket: list[TimelinePoint]
    alerts_over_time: list[TimelinePoint]


# ---------------------------------------------------------------------------
# 13. Security findings
# ---------------------------------------------------------------------------


class SecurityFinding(BaseModel):
    severity: Severity
    category: str
    timestamp: str
    affected_host: str
    description: str
    evidence: str
    confidence: str  # "High" / "Medium" / "Low"
    recommendation: str


# ---------------------------------------------------------------------------
# 14. Alerts summary
# ---------------------------------------------------------------------------


class AlertsSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.informational


# ---------------------------------------------------------------------------
# 15. Recommendations
# ---------------------------------------------------------------------------


class Recommendation(BaseModel):
    priority: Severity
    text: str


# ---------------------------------------------------------------------------
# 16. Appendix
# ---------------------------------------------------------------------------


class Appendix(BaseModel):
    top_ips: list[tuple[str, int]]
    top_domains: list[tuple[str, int]]
    top_flows: list[FlowRow]
    protocol_counts: list[ProtocolStat]
    packet_size_distribution: list[tuple[str, int]]
    glossary: list[tuple[str, str]]


# ---------------------------------------------------------------------------
# Top-level report object
# ---------------------------------------------------------------------------


class Report(BaseModel):
    metadata: ReportMetadata
    summary: ExecutiveSummary
    capture: CaptureInfo
    traffic_statistics: TrafficStatistics
    hosts: list[HostRow]
    top_talkers: TopTalkers
    flows: list[FlowRow]
    protocols: ProtocolAnalysis
    ports: PortAnalysis
    dns_intelligence: DnsIntelligence
    timeline: TimelineData
    security_findings: list[SecurityFinding]
    alerts_summary: AlertsSummary
    recommendations: list[Recommendation]
    appendix: Appendix
