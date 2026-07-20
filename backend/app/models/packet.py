# backend/app/models/packet.py

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


class PacketModel(BaseModel):
    """
    Standard internal representation of every captured packet.

    Every backend module (statistics, cache, threat detection,
    host discovery, reporting, WebSockets) works with this model
    instead of directly using Scapy packets.
    """

    # -------------------------
    # Capture Metadata
    # -------------------------

    timestamp: datetime = Field(
        description="Time when the packet was captured"
    )

    interface: str = Field(
        description="Network interface used for capture"
    )

    direction: Literal[
        "INBOUND",
        "OUTBOUND",
        "LOCAL",
        "UNKNOWN"
    ] = "UNKNOWN"

    # -------------------------
    # Network Information
    # -------------------------

    src_ip: str
    dst_ip: str

    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    protocol: str

    # -------------------------
    # Link-Layer Information
    # -------------------------
    # Only populated where PacketParser can read an Ethernet/ARP layer.
    # Added specifically so PCAP Analyzer's batch Threat Analysis
    # (app/engines/pcap_insights.py) can run ARP Spoofing Detection over
    # already-parsed, stored packets — the live capture path gets MAC
    # addresses directly from the raw Scapy packet in
    # app/capture/sniffer.py instead and never reads these fields, but
    # they're populated for every packet regardless of caller so the two
    # paths don't silently diverge in what a "parsed packet" contains.

    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None

    # -------------------------
    # Packet Information
    # -------------------------

    length: int

    payload_size: int = 0

    flow_key: str

    info: str = ""

    # -------------------------
    # DNS Details
    # -------------------------
    # Only populated for protocol == "DNS" — see PacketParser._parse_dns.
    # dns_query includes the record type, e.g. "example.com (A)".
    # dns_answer is a comma-joined string of resolved values (present
    # only on responses that actually resolved something).

    dns_query: Optional[str] = None
    dns_answer: Optional[str] = None

    # rcode of a DNS *response* (never set on the query half) — "NOERROR"
    # on success, "NXDOMAIN"/"SERVFAIL"/etc. on failure. The authoritative
    # signal for "did this DNS response actually resolve", used by
    # app.engines.pcap_dns_analysis's Failed Queries. See
    # docs/contracts/pcap-dns-analysis.md.
    dns_rcode: Optional[str] = None

    # -------------------------
    # Future Expansion
    # -------------------------

    process_name: Optional[str] = None