"""
Report Builder — PCAP -> Structured Report Object.

This is the only module that turns a stored `PcapAnalysis` (already
parsed by `PacketParser`, already summarized by the existing engines)
into a `Report` for the PDF generator. It reuses every existing engine
it can (`pcap_summary`, `pcap_insights`, `pcap_hosts_conversations`,
`pcap_protocol_timeline`, `pcap_threat_analysis`) rather than
recomputing what they already compute, and only adds new aggregation
for the things no existing engine covers yet (link-layer breakdown,
TCP flag counts, port/service mapping, per-host role heuristics, flow
list, DNS intelligence).

Two honesty notes carried through from the underlying parser
(`app.parser.packet_parser`), documented here once rather than
scattered across every call site:

  * HTTP/HTTPS sections reflect port-based TCP traffic volume, not
    decoded application-layer requests or TLS handshakes — the parser
    doesn't do that decoding yet.
  * ICMP type/code (echo request vs reply, etc.) isn't classified by
    the parser, so those counts are 0.

Both sections still carry a `note` field (see report_models.py) so the
PDF surfaces this honestly instead of silently showing empty-looking
zeros.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.cache.pcap_store import PcapAnalysis
from app.engines.pcap_hosts_conversations import (
    _format_bytes,
    _format_duration,
    compute_hosts_conversations,
)
from app.engines.pcap_insights import compute_dns_analysis as compute_dns_insights
from app.engines.pcap_protocol_timeline import compute_protocol_timeline
from app.engines.pcap_threat_analysis import (
    DNS_TUNNEL_LABEL_LENGTH_THRESHOLD,
    analyze_threats,
    detect_dns_tunneling,
)
from app.models.packet import PacketModel
from app.report import recommendations as rec_mod
from app.report import summary as summary_mod
from app.report.report_models import (
    Appendix,
    ArpAnalysis,
    CaptureInfo,
    ConversationRow,
    DnsIntelligence,
    DnsProtocolAnalysis,
    ExecutiveSummary,
    FlowRow,
    HostRow,
    HttpAnalysis,
    HttpsAnalysis,
    IcmpAnalysis,
    PortAnalysis,
    PortRow,
    ProtocolAnalysis,
    ProtocolStat,
    Report,
    ReportMetadata,
    SecurityFinding,
    AlertsSummary,
    SummaryCard,
    TalkerRow,
    TcpAnalysis,
    TimelineData,
    TimelinePoint,
    TopTalkers,
    TrafficStatistics,
    UdpAnalysis,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KNOWN_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 500: "IKE/IPsec", 587: "SMTP-SUB",
    993: "IMAPS", 995: "POP3S", 1900: "SSDP", 3306: "MySQL",
    3389: "RDP", 5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT",
}

CLEARTEXT_PORTS = {21, 23, 80, 110, 143}
PRIVATE_RANGES = re.compile(
    r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"
)
_TCP_FLAGS_RE = re.compile(r"\[([A-Z]+)\]")

TOP_N = 15
TOP_N_LARGE = 25
LONG_DOMAIN_THRESHOLD = 50


def _is_private(ip: str) -> bool:
    return bool(PRIVATE_RANGES.match(ip))


def _tcp_flags(info: str) -> str:
    m = _TCP_FLAGS_RE.search(info)
    return m.group(1) if m else ""


def _fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _pct(part: float, whole: float) -> float:
    return round((part / whole) * 100, 1) if whole else 0.0


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _build_capture_info(packets: list[PacketModel], filename: str, file_size_bytes: int) -> CaptureInfo:
    timestamps = [p.timestamp for p in packets]
    start, end = min(timestamps), max(timestamps)
    duration = max((end - start).total_seconds(), 0.0)
    total_bytes = sum(p.length for p in packets)
    ipv4 = sum(1 for p in packets if p.protocol != "ARP" and ":" not in p.src_ip)
    ipv6 = sum(1 for p in packets if ":" in p.src_ip)

    return CaptureInfo(
        filename=filename,
        file_size=_format_bytes(file_size_bytes),
        start_time=_fmt_dt(start),
        end_time=_fmt_dt(end),
        duration=_format_duration(duration),
        link_layer="Ethernet",
        ipv4_packets=ipv4,
        ipv6_packets=ipv6,
        avg_packet_size_bytes=round(total_bytes / len(packets)) if packets else 0,
        avg_bandwidth_mbps=round((total_bytes * 8) / duration / 1_000_000, 3) if duration > 0 else 0.0,
        avg_packets_per_sec=round(len(packets) / duration, 2) if duration > 0 else float(len(packets)),
        total_bytes=_format_bytes(total_bytes),
    )


def _build_traffic_statistics(packets: list[PacketModel]) -> TrafficStatistics:
    counts: dict[str, int] = defaultdict(int)
    for p in packets:
        counts[p.protocol] += 1
    total = len(packets)
    protocol_counts = sorted(
        (ProtocolStat(protocol=k, packets=v, pct=_pct(v, total)) for k, v in counts.items()),
        key=lambda s: -s.packets,
    )

    size_buckets = [("0-128 B", 0), ("129-512 B", 0), ("513-1024 B", 0),
                     ("1025-1500 B", 0), ("1500+ B", 0)]
    bounds = [128, 512, 1024, 1500]
    for p in packets:
        idx = next((i for i, b in enumerate(bounds) if p.length <= b), 4)
        size_buckets[idx] = (size_buckets[idx][0], size_buckets[idx][1] + 1)

    inbound = sum(1 for p in packets if p.direction == "INBOUND")
    outbound = sum(1 for p in packets if p.direction == "OUTBOUND")
    # Direction is largely unpopulated for pcap-upload analysis (only the
    # live-capture path sets it — see PacketModel docstring), so fall
    # back to a private/external heuristic when nothing is tagged.
    if inbound == 0 and outbound == 0:
        inbound = sum(1 for p in packets if _is_private(p.dst_ip) and not _is_private(p.src_ip))
        outbound = sum(1 for p in packets if _is_private(p.src_ip) and not _is_private(p.dst_ip))

    return TrafficStatistics(
        protocol_counts=protocol_counts,
        top_packet_sizes=size_buckets,
        inbound_packets=inbound,
        outbound_packets=outbound,
        inbound_pct=_pct(inbound, total),
        outbound_pct=_pct(outbound, total),
    )


def _build_hosts(packets: list[PacketModel]) -> list[HostRow]:
    packet_count: dict[str, int] = defaultdict(int)
    byte_count: dict[str, int] = defaultdict(int)
    first_seen: dict[str, datetime] = {}
    last_seen: dict[str, datetime] = {}
    mac_of: dict[str, str] = {}
    dns_servers: set[str] = set()

    for p in packets:
        if p.protocol == "DNS" and p.src_port == 53:
            dns_servers.add(p.src_ip)
        for ip, mac in ((p.src_ip, p.src_mac), (p.dst_ip, p.dst_mac)):
            if not ip or ip == "Unknown":
                continue
            packet_count[ip] += 1
            byte_count[ip] += p.length
            first_seen[ip] = min(first_seen.get(ip, p.timestamp), p.timestamp)
            last_seen[ip] = max(last_seen.get(ip, p.timestamp), p.timestamp)
            if mac and ip not in mac_of:
                mac_of[ip] = mac

    def _role(ip: str) -> str:
        if ip in ("255.255.255.255",) or mac_of.get(ip) == "ff:ff:ff:ff:ff:ff":
            return "Broadcast"
        if ip.startswith("224.") or ip.startswith("239.") or (mac_of.get(ip) or "").startswith("01:00:5e"):
            return "Multicast"
        if ip in dns_servers:
            return "DNS Server"
        return "Local Network" if _is_private(ip) else "External"

    hosts = [
        HostRow(
            ip=ip,
            mac=mac_of.get(ip, "-"),
            vendor="Unknown",
            hostname="-",
            packets=packet_count[ip],
            bytes=_format_bytes(byte_count[ip]),
            first_seen=_fmt_dt(first_seen[ip]),
            last_seen=_fmt_dt(last_seen[ip]),
            role=_role(ip),
        )
        for ip in packet_count
    ]
    hosts.sort(key=lambda h: h.packets, reverse=True)
    return hosts


def _build_top_talkers(packets: list[PacketModel]) -> TopTalkers:
    src_bytes: dict[str, int] = defaultdict(int)
    src_packets: dict[str, int] = defaultdict(int)
    dst_bytes: dict[str, int] = defaultdict(int)
    dst_packets: dict[str, int] = defaultdict(int)
    timestamps = [p.timestamp for p in packets]
    duration = (max(timestamps) - min(timestamps)).total_seconds() if timestamps else 0.0

    for p in packets:
        if p.src_ip and p.src_ip != "Unknown":
            src_bytes[p.src_ip] += p.length
            src_packets[p.src_ip] += 1
        if p.dst_ip and p.dst_ip != "Unknown":
            dst_bytes[p.dst_ip] += p.length
            dst_packets[p.dst_ip] += 1

    def _rows(byte_map: dict[str, int], pkt_map: dict[str, int]) -> list[TalkerRow]:
        total = sum(byte_map.values())
        ranked = sorted(byte_map.items(), key=lambda kv: -kv[1])[:TOP_N]
        return [
            TalkerRow(
                ip=ip, packets=pkt_map[ip], bytes=_format_bytes(b), pct=_pct(b, total),
                bandwidth_mbps=round((b * 8) / duration / 1_000_000, 3) if duration > 0 else 0.0,
            )
            for ip, b in ranked
        ]

    hc = compute_hosts_conversations(packets, duration)
    conversations = [
        ConversationRow(a=c.a, b=c.b, packets=c.packets, bytes=c.bytes, duration=c.duration)
        for c in hc.conversations[:TOP_N]
    ]

    return TopTalkers(
        top_sources=_rows(src_bytes, src_packets),
        top_destinations=_rows(dst_bytes, dst_packets),
        top_conversations=conversations,
    )


def _build_flows(packets: list[PacketModel]) -> list[FlowRow]:
    groups: dict[str, list[PacketModel]] = defaultdict(list)
    for p in packets:
        groups[p.flow_key].append(p)

    flows: list[tuple[int, FlowRow]] = []
    for key, pkts in groups.items():
        first = pkts[0]
        total_bytes = sum(p.length for p in pkts)
        times = [p.timestamp for p in pkts]
        flags_seen = set()
        for p in pkts:
            if p.protocol == "TCP":
                flags_seen.update(_tcp_flags(p.info))
        if "R" in flags_seen:
            state = "Reset"
        elif "F" in flags_seen:
            state = "Closed"
        elif "S" in flags_seen and "A" in flags_seen:
            state = "Established"
        elif first.protocol == "TCP":
            state = "Attempted"
        else:
            state = "N/A"

        flows.append((total_bytes, FlowRow(
            src_ip=first.src_ip, dst_ip=first.dst_ip,
            src_port=str(first.src_port) if first.src_port else "-",
            dst_port=str(first.dst_port) if first.dst_port else "-",
            protocol=first.protocol, packets=len(pkts), bytes=_format_bytes(total_bytes),
            duration=_format_duration((max(times) - min(times)).total_seconds()),
            state=state,
        )))

    flows.sort(key=lambda t: -t[0])
    return [f for _, f in flows[:TOP_N_LARGE]]


def _build_protocol_analysis(packets: list[PacketModel]) -> ProtocolAnalysis:
    # --- TCP ---
    tcp_packets = [p for p in packets if p.protocol == "TCP"]
    conn_flags: dict[tuple, set[str]] = defaultdict(set)
    syn_seen: dict[tuple, int] = defaultdict(int)
    syn_count = fin_count = rst_count = 0
    for p in tcp_packets:
        flags = _tcp_flags(p.info)
        syn_count += flags.count("S")
        fin_count += "F" in flags
        rst_count += "R" in flags
        conn_id = tuple(sorted((f"{p.src_ip}:{p.src_port}", f"{p.dst_ip}:{p.dst_port}")))
        conn_flags[conn_id].update(flags)
        if "S" in flags and "A" not in flags:
            syn_seen[conn_id] += 1

    retransmissions = sum(max(0, c - 1) for c in syn_seen.values())
    failed_connections = sum(1 for flags in conn_flags.values() if "S" in flags and "A" not in flags)
    connection_resets = sum(1 for flags in conn_flags.values() if "R" in flags)

    tcp = TcpAnalysis(
        connections=len(conn_flags), syn=syn_count, fin=fin_count, rst=rst_count,
        retransmissions=retransmissions, failed_connections=failed_connections,
        connection_resets=connection_resets,
    )

    # --- UDP (excluding DNS, which the parser classifies separately) ---
    udp_packets = [p for p in packets if p.protocol == "UDP"]
    udp_port_counts: dict[int, int] = defaultdict(int)
    dhcp = ntp = quic = 0
    for p in udp_packets:
        for port in (p.src_port, p.dst_port):
            if port:
                udp_port_counts[port] += 1
        if p.src_port in (67, 68) or p.dst_port in (67, 68):
            dhcp += 1
        if p.src_port == 123 or p.dst_port == 123:
            ntp += 1
        if p.src_port == 443 or p.dst_port == 443:
            quic += 1
    top_udp_ports = sorted(udp_port_counts.items(), key=lambda kv: -kv[1])[:10]
    udp = UdpAnalysis(
        streams=len({p.flow_key for p in udp_packets}),
        top_ports=[(f"{port} ({KNOWN_SERVICES.get(port, 'Unknown')})", c) for port, c in top_udp_ports],
        dhcp=dhcp, dns=sum(1 for p in packets if p.protocol == "DNS"), ntp=ntp, quic=quic,
    )

    # --- DNS ---
    dns_insights = compute_dns_insights(packets)
    dns_packets = [p for p in packets if p.protocol == "DNS"]
    query_domains = {re.sub(r"\s*\([A-Z0-9]+\)$", "", p.dns_query).strip()
                      for p in dns_packets if p.dns_query}
    servers = {p.src_ip for p in dns_packets if p.src_port == 53}
    nxdomain = sum(1 for p in dns_packets if p.dns_rcode not in (None, "NOERROR"))
    longest = max(query_domains, key=len, default="-")
    top_domain_pairs = [(d.domain, d.count) for d in dns_insights.top_domains]
    most_queried = top_domain_pairs[0][0] if top_domain_pairs else "-"
    long_domains = sorted((d for d in query_domains if len(d) > LONG_DOMAIN_THRESHOLD), key=len, reverse=True)
    random_looking = [
        d for d in query_domains
        if len(d.split(".")[0]) >= 20 and re.fullmatch(r"[a-z0-9]+", d.split(".")[0] or "")
    ][:10]

    dns = DnsProtocolAnalysis(
        total_queries=sum(1 for p in dns_packets if p.dst_port == 53),
        unique_domains=len(query_domains), unique_dns_servers=len(servers),
        top_domains=top_domain_pairs, nxdomain_count=nxdomain, longest_domain=longest,
        most_queried_domain=most_queried,
        suspicious_domains=long_domains[:10] or random_looking,
        repeated_queries=[(d.domain, d.count) for d in dns_insights.repeated_queries],
        random_looking_domains=random_looking,
    )

    # --- HTTP / HTTPS (port-based; see module docstring) ---
    http_packets = [p for p in tcp_packets if p.src_port == 80 or p.dst_port == 80]
    https_packets = [p for p in tcp_packets if p.src_port == 443 or p.dst_port == 443]

    def _top_hosts(pkts: list[PacketModel]) -> list[tuple[str, int]]:
        c: dict[str, int] = defaultdict(int)
        for p in pkts:
            server_ip = p.dst_ip if p.dst_port in (80, 443) else p.src_ip
            c[server_ip] += 1
        return sorted(c.items(), key=lambda kv: -kv[1])[:10]

    http = HttpAnalysis(hosts=_top_hosts(http_packets), methods=[], top_requested_resources=[])
    https = HttpsAnalysis(most_contacted_hosts=_top_hosts(https_packets))

    # --- ICMP (see IcmpAnalysis.note) ---
    icmp_count = sum(1 for p in packets if p.protocol == "ICMP")
    icmp = IcmpAnalysis(total=icmp_count, echo_requests=0, echo_replies=0, other=icmp_count)

    # --- ARP ---
    arp_packets = [p for p in packets if p.protocol == "ARP"]
    requests = sum(1 for p in arp_packets if p.info.startswith("Who has"))
    replies = len(arp_packets) - requests
    seen_pairs: dict[str, set[str]] = defaultdict(set)
    duplicate = 0
    for p in arp_packets:
        if p.src_mac:
            if p.src_mac in seen_pairs[p.src_ip]:
                duplicate += 1
            seen_pairs[p.src_ip].add(p.src_mac)
    arp = ArpAnalysis(
        requests=requests, replies=replies, duplicate_arp=duplicate,
        potential_spoofing_incidents=0,  # filled in by caller with threat findings
    )

    return ProtocolAnalysis(tcp=tcp, udp=udp, dns=dns, http=http, https=https, icmp=icmp, arp=arp)


def _build_ports(packets: list[PacketModel]) -> PortAnalysis:
    port_counts: dict[int, int] = defaultdict(int)
    for p in packets:
        if p.protocol in ("TCP", "UDP") and p.dst_port:
            port_counts[p.dst_port] += 1
    total = sum(port_counts.values())
    ranked = sorted(port_counts.items(), key=lambda kv: -kv[1])
    top_ports = [
        PortRow(port=port, service=KNOWN_SERVICES.get(port, "Unknown"), packets=c, pct=_pct(c, total))
        for port, c in ranked[:15]
    ]
    unexpected = [
        PortRow(port=port, service=KNOWN_SERVICES.get(port, "Unknown"), packets=c, pct=_pct(c, total), flagged=True)
        for port, c in ranked
        if port not in KNOWN_SERVICES and port > 1024
    ][:15]
    return PortAnalysis(top_ports=top_ports, unexpected_ports=unexpected)


def _build_dns_intelligence(packets: list[PacketModel]) -> DnsIntelligence:
    dns_insights = compute_dns_insights(packets)
    dns_packets = [p for p in packets if p.protocol == "DNS"]
    servers: dict[str, int] = defaultdict(int)
    for p in dns_packets:
        if p.src_port == 53:
            servers[p.src_ip] += 1

    query_domains = {re.sub(r"\s*\([A-Z0-9]+\)$", "", p.dns_query).strip()
                      for p in dns_packets if p.dns_query}
    long_domains = sorted((d for d in query_domains if len(d) > LONG_DOMAIN_THRESHOLD), key=len, reverse=True)[:10]

    tunneling = detect_dns_tunneling(packets)
    tunneling_indicators = [
        f"{f.source}: {f.evidence}" for f in tunneling
    ] or [
        f"No queries with subdomain labels \u2265 {DNS_TUNNEL_LABEL_LENGTH_THRESHOLD} characters "
        "were observed at volumes consistent with tunneling."
    ]

    return DnsIntelligence(
        top_domains=[(d.domain, d.count) for d in dns_insights.top_domains],
        top_dns_servers=sorted(servers.items(), key=lambda kv: -kv[1])[:10],
        external_domains=[(d.domain, d.count) for d in dns_insights.top_domains],
        suspicious_domains=long_domains,
        very_long_domains=long_domains,
        high_frequency_domains=[(d.domain, d.count) for d in dns_insights.repeated_queries],
        tunneling_indicators=tunneling_indicators,
    )


def _build_timeline(packets: list[PacketModel], findings: list[SecurityFinding]) -> TimelineData:
    pt = compute_protocol_timeline(packets)
    packets_pts = [TimelinePoint(label=b.label, value=b.value) for b in pt.timeline]

    # Bandwidth per the same buckets — recompute using byte sums instead
    # of packet counts, over the same bucket boundaries pcap_protocol_timeline
    # already established, so the two charts share an x-axis.
    if packets:
        timestamps = [p.timestamp for p in packets]
        start, end = min(timestamps), max(timestamps)
        duration = (end - start).total_seconds()
        n = len(pt.timeline) or 1
        bandwidth_pts: list[TimelinePoint] = []
        if duration > 0:
            width = duration / n
            byte_buckets = [0] * n
            for p in packets:
                idx = min(int((p.timestamp - start).total_seconds() / width), n - 1)
                byte_buckets[idx] += p.length
            bandwidth_pts = [
                TimelinePoint(label=pt.timeline[i].label if i < len(pt.timeline) else "",
                               value=round((b * 8) / width / 1_000_000, 4) if width > 0 else 0.0)
                for i, b in enumerate(byte_buckets)
            ]
        else:
            bandwidth_pts = [TimelinePoint(label="", value=0.0)]
    else:
        bandwidth_pts = []

    alert_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        bucket = f.timestamp[:16] if f.timestamp else "unknown"
        alert_counts[bucket] += 1
    alerts_pts = [TimelinePoint(label=k, value=v) for k, v in sorted(alert_counts.items())]

    return TimelineData(
        packets_per_bucket=packets_pts, bandwidth_per_bucket=bandwidth_pts, alerts_over_time=alerts_pts,
    )


_SEVERITY_MAP = {"high": "high", "medium": "medium", "low": "low"}


def _build_security_findings(packets: list[PacketModel]) -> list[SecurityFinding]:
    threats = analyze_threats(packets)  # richer, episode-based engine (source + reason)
    findings: list[SecurityFinding] = []
    for t in threats:
        findings.append(SecurityFinding(
            severity=_SEVERITY_MAP.get(t.severity, "medium"),
            category=t.reason,
            timestamp="-",  # episode engine reports duration in evidence text, not a single timestamp
            affected_host=t.source,
            description=t.reason,
            evidence=t.evidence,
            confidence="High" if t.severity == "high" else "Medium",
            recommendation=t.recommendation,
        ))
    return findings


def _build_alerts_summary(findings: list[SecurityFinding]) -> AlertsSummary:
    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        counts[f.severity] += 1
    return AlertsSummary(
        critical=counts.get("critical", 0), high=counts.get("high", 0),
        medium=counts.get("medium", 0), low=counts.get("low", 0),
        informational=counts.get("informational", 0),
    )


def _build_executive_summary(
    packets: list[PacketModel], filename: str, findings: list[SecurityFinding],
    protocol_counts: list[ProtocolStat], flow_count: int, host_count: int,
) -> ExecutiveSummary:
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    risk_score = min(100, high * 20 + medium * 10)
    risk_level = summary_mod.risk_level_for_score(risk_score)

    timestamps = [p.timestamp for p in packets]
    duration = (max(timestamps) - min(timestamps)).total_seconds() if timestamps else 0.0
    total_bytes = sum(p.length for p in packets)
    top_protocol = protocol_counts[0].protocol if protocol_counts else "N/A"

    cards = [
        SummaryCard(label="Total Packets", value=f"{len(packets):,}"),
        SummaryCard(label="Total Bytes", value=_format_bytes(total_bytes)),
        SummaryCard(label="Capture Duration", value=_format_duration(duration)),
        SummaryCard(label="Unique Hosts", value=str(host_count)),
        SummaryCard(label="Network Flows", value=f"{flow_count:,}"),
        SummaryCard(label="Protocols Detected", value=str(len(protocol_counts))),
        SummaryCard(label="Alerts Generated", value=str(len(findings))),
        SummaryCard(label="Risk Level", value=risk_level),
    ]

    narrative = summary_mod.build_narrative(
        packet_count=len(packets), unique_hosts=host_count, flow_count=flow_count,
        protocol_count=len(protocol_counts), finding_count=len(findings),
        risk_level=risk_level, top_protocol=top_protocol,
        duration_desc=_format_duration(duration),
    )

    return ExecutiveSummary(cards=cards, risk_score=risk_score, risk_level=risk_level, narrative=narrative)


def _build_appendix(
    packets: list[PacketModel], hosts: list[HostRow], flows: list[FlowRow],
    protocol_counts: list[ProtocolStat], dns_top_domains: list[tuple[str, int]],
) -> Appendix:
    size_buckets: dict[str, int] = defaultdict(int)
    for p in packets:
        if p.length <= 128:
            size_buckets["0-128 B"] += 1
        elif p.length <= 512:
            size_buckets["129-512 B"] += 1
        elif p.length <= 1024:
            size_buckets["513-1024 B"] += 1
        elif p.length <= 1500:
            size_buckets["1025-1500 B"] += 1
        else:
            size_buckets["1500+ B"] += 1

    glossary = [
        ("SYN", "TCP flag indicating a connection request (start of the three-way handshake)."),
        ("ACK", "TCP flag acknowledging receipt of data or a connection request."),
        ("FIN", "TCP flag indicating a graceful connection close."),
        ("RST", "TCP flag indicating an abrupt connection reset."),
        ("NXDOMAIN", "DNS response code meaning the queried domain does not exist."),
        ("Beaconing", "Regular, periodic outbound connections often associated with malware C2 traffic."),
        ("DNS Tunneling", "Encoding non-DNS data inside DNS queries, often used to exfiltrate data or bypass firewalls."),
        ("Port Scan", "Systematic probing of multiple ports/hosts to discover open services."),
        ("ARP Spoofing", "Forging ARP replies to associate an attacker's MAC address with another host's IP."),
    ]

    return Appendix(
        top_ips=[(h.ip, h.packets) for h in hosts[:100]],
        top_domains=dns_top_domains[:100],
        top_flows=flows[:100],
        protocol_counts=protocol_counts,
        packet_size_distribution=list(size_buckets.items()),
        glossary=glossary,
    )


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def build_report(analysis: PcapAnalysis, file_size_bytes: int = 0) -> Report:
    """Builds the full structured `Report` for one stored capture. This
    is the pipeline's sole entry point — `pdf_generator.generate_pdf`
    never sees a `PacketModel` and never re-derives anything this
    function already computed."""
    packets = analysis.packets

    capture_info = _build_capture_info(packets, analysis.filename, file_size_bytes)
    traffic_stats = _build_traffic_statistics(packets)
    hosts = _build_hosts(packets)
    top_talkers = _build_top_talkers(packets)
    flows = _build_flows(packets)
    protocols = _build_protocol_analysis(packets)
    ports = _build_ports(packets)
    dns_intel = _build_dns_intelligence(packets)
    findings = _build_security_findings(packets)

    # Fold ARP-spoofing findings into the ARP subsection count now that
    # `findings` exists (kept out of _build_protocol_analysis to avoid
    # running threat analysis twice).
    protocols.arp.potential_spoofing_incidents = sum(
        1 for f in findings if f.category == "Possible ARP Spoofing"
    )

    timeline = _build_timeline(packets, findings)
    alerts_summary = _build_alerts_summary(findings)
    executive_summary = _build_executive_summary(
        packets, analysis.filename, findings, traffic_stats.protocol_counts,
        len({p.flow_key for p in packets}), len(hosts),
    )

    cleartext = sum(1 for p in packets if p.protocol == "TCP" and (p.dst_port in CLEARTEXT_PORTS or p.src_port in CLEARTEXT_PORTS))
    tcp_total = max(1, sum(1 for p in packets if p.protocol == "TCP"))
    recs = rec_mod.build_recommendations(
        findings, cleartext_pct=_pct(cleartext, tcp_total),
        dns_failure_count=protocols.dns.nxdomain_count,
    )

    appendix = _build_appendix(packets, hosts, flows, traffic_stats.protocol_counts, dns_intel.top_domains)

    metadata = ReportMetadata(
        generated_at=datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC"),
        filename=analysis.filename,
        capture_duration=capture_info.duration,
    )

    return Report(
        metadata=metadata, summary=executive_summary, capture=capture_info,
        traffic_statistics=traffic_stats, hosts=hosts, top_talkers=top_talkers,
        flows=flows, protocols=protocols, ports=ports, dns_intelligence=dns_intel,
        timeline=timeline, security_findings=findings, alerts_summary=alerts_summary,
        recommendations=recs, appendix=appendix,
    )
