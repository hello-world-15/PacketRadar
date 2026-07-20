"""
Pydantic models for PCAP Analyzer uploads. Field names/types are a
direct implementation of docs/contracts/pcap-upload.md and
docs/contracts/pcap-analysis.md.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from app.schemas.stats import ProtocolCount


class CaptureSummary(BaseModel):
    packet_count: int
    duration_seconds: float
    avg_packet_size_bytes: int
    unique_hosts: int
    connection_count: int
    dns_request_count: int


class PcapUploadResponse(BaseModel):
    capture_id: str
    filename: str
    summary: CaptureSummary


class RecordedCapture(BaseModel):
    filename: str
    size_bytes: int = Field(..., ge=0)
    captured_at: str = Field(
        ..., description="ISO 8601 UTC timestamp, from the file's mtime — see app.api.pcap"
    )


class DomainCount(BaseModel):
    domain: str
    count: int


class DnsAnalysis(BaseModel):
    top_domains: list[DomainCount]
    repeated_queries: list[DomainCount]
    failed_queries: list[DomainCount]


class ThreatFinding(BaseModel):
    severity: str = Field(..., description="'high' or 'medium' — see docs/contracts/threats.md")
    reason: str
    evidence: str
    recommendation: str


class HealthScore(BaseModel):
    score: int = Field(..., ge=0, le=100)
    factors: list[str]


class PcapInsights(BaseModel):
    dns: DnsAnalysis
    threats: list[ThreatFinding]
    health: HealthScore


# ---------------------------------------------------------------------------
# Top Hosts + Conversations (docs/contracts/pcap-hosts-conversations.md —
# app.engines.pcap_hosts_conversations)
# ---------------------------------------------------------------------------


class PcapTopHost(BaseModel):
    ip: str
    hostname: Optional[str] = Field(
        None, description="Not resolved — see docs/contracts/hosts.md (same limitation)"
    )
    packets: int = Field(..., ge=0)
    bandwidth_mbps: float = Field(
        ..., ge=0, description="Average across the whole capture, not a live rate — see contract"
    )
    bandwidth_pct: float = Field(0, ge=0, le=100, description="Relative to the top host in this top-N list")
    connections: int = Field(..., ge=0, description="Distinct flow_keys touching this IP, no TTL")


class Conversation(BaseModel):
    a: str
    b: str
    packets: int = Field(..., ge=0)
    bytes: str = Field(..., description="Pre-formatted, e.g. '1.2 MB' — see contract's format decision")
    duration: str = Field(..., description="Pre-formatted, this pair's own span, e.g. '4m 12s'")


class HostsConversations(BaseModel):
    top_hosts: list[PcapTopHost]
    conversations: list[Conversation]


# ---------------------------------------------------------------------------
# Threat Analysis, dedicated endpoint (docs/contracts/pcap-threat-analysis.md
# — app.engines.pcap_threat_analysis). Deliberately a separate class from
# `ThreatFinding` above (which backs the older, simpler bundled /insights
# endpoint) — this one adds `source`, which that episode/aggregate-based
# engine needs to report and the simpler one never captured.
# ---------------------------------------------------------------------------


class PcapThreatFinding(BaseModel):
    severity: str = Field(..., description="'high' or 'medium' — see docs/contracts/threats.md")
    source: str
    reason: str
    evidence: str
    recommendation: str


class PcapThreatsResponse(BaseModel):
    threats: list[PcapThreatFinding]


# ---------------------------------------------------------------------------
# Packet Explorer, paginated (docs/contracts/pcap-packet-explorer.md —
# app.engines.pcap_packet_explorer). Carries more fields than the live
# packets:update PacketStreamRow (src_mac/dst_mac/src_port/dst_port) — see
# the contract's "Why this response carries more fields" section for why
# that budget difference is fine here but wasn't for the live broadcast.
# ---------------------------------------------------------------------------


class PcapPacketRow(BaseModel):
    no: int = Field(..., description="Position in the whole capture (offset + index + 1), not per-page")
    time: float = Field(..., description="Unix timestamp (seconds) from the capture file itself")
    source: str
    destination: str
    protocol: str
    length: int = Field(..., ge=0)
    info: str
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    dns_query: Optional[str] = None
    dns_answer: Optional[str] = None


class PcapPacketsResponse(BaseModel):
    packets: list[PcapPacketRow]
    total: int = Field(..., ge=0, description="Total packets stored for this capture, not just this page")
    offset: int = Field(..., ge=0)
    limit: int = Field(..., ge=1)


# ---------------------------------------------------------------------------
# Protocol Distribution + Traffic Timeline
# (docs/contracts/pcap-protocol-timeline.md — app.engines.pcap_protocol_timeline)
# ---------------------------------------------------------------------------


class TimelineBucket(BaseModel):
    label: str = Field(..., description="Real clock time, e.g. '14:32' — see contract's justification")
    value: int = Field(..., ge=0, description="Packet count in this bucket")


class ProtocolTimeline(BaseModel):
    # protocol_distribution reuses ProtocolCount from app.schemas.stats
    # (the live dashboard's identical {label, value} shape) rather than
    # redefining an equivalent class here — see contract's "Schema reuse,
    # not duplication".
    protocol_distribution: list[ProtocolCount]
    timeline: list[TimelineBucket]
