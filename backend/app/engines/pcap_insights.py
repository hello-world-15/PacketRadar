"""
DNS Analysis + Threat Analysis + Network Health Score for uploaded PCAP
files.

Pure aggregation over an already-parsed list of PacketModel, same
convention as app.engines.pcap_summary — no file I/O, no Scapy, fully
testable with synthetic PacketModel instances and no real .pcap file.

Threat Analysis reuses ThreatDetectionEngine's four live rules (Port
Scan, ARP Spoofing, DNS Tunneling, SYN Flood) rather than
re-implementing detection logic for static files. A **fresh**
ThreatDetectionEngine instance is created per call —
this is a one-shot batch computation, not the shared live singleton in
app.state. See docs/contracts/pcap-analysis.md for why this required
adding an optional `now` override to both of ThreatDetectionEngine's
recording methods: the live engine's windows/cooldowns are defined in
real elapsed seconds, and replaying a whole file back-to-back at
wall-clock speed (rather than at each packet's own historical time)
would either wrongly swallow a second, genuinely separate incident into
the first one's cooldown, or falsely confirm an ARP conflict between two
sightings that were actually minutes apart in the real capture.
"""

from __future__ import annotations

import re

from app.engines.threat_detection import ThreatDetectionEngine
from app.models.packet import PacketModel
from app.schemas.pcap import DnsAnalysis, DomainCount, HealthScore, PcapInsights, ThreatFinding
from app.schemas.threats_live import ThreatAlertRow

# ---------------------------------------------------------------------------
# DNS Analysis
# ---------------------------------------------------------------------------

TOP_DOMAINS_LIMIT = 8
FAILED_QUERIES_LIMIT = 8
REPEATED_QUERIES_LIMIT = 8

# A domain queried this many times or more is flagged as "repeated" — a
# possible sign of beaconing/tunneling rather than ordinary app traffic.
# Deliberately much higher than a typical #1 entry in Top Domains (a busy
# capture's most-queried domain might sit around 20-50 from ordinary
# CDN/API chatter) so this list highlights outliers instead of just
# duplicating Top Domains with a lower ceiling. See
# docs/contracts/pcap-analysis.md.
REPEATED_QUERY_MIN_COUNT = 40

_QTYPE_SUFFIX = re.compile(r"\s*\([A-Z0-9]+\)$")


def _extract_domain(dns_query: str) -> str:
    """`dns_query` is formatted by PacketParser as "example.com (A)" —
    strip the trailing " (TYPE)" to get just the domain. No case
    normalization or subdomain grouping — see contract's known limitations."""
    return _QTYPE_SUFFIX.sub("", dns_query).strip()


def _dns_domain_maps(packets: list[PacketModel]) -> tuple[dict[str, int], dict[str, int]]:
    """Full, untruncated (domain -> count) maps for queries and failed
    responses — shared by compute_dns_analysis (which trims these to
    top-N for display) and compute_health_score (which needs the real
    totals, not just what's visible in a trimmed list)."""
    query_counts: dict[str, int] = {}
    fail_counts: dict[str, int] = {}

    for p in packets:
        if p.protocol != "DNS" or not p.dns_query:
            continue
        domain = _extract_domain(p.dns_query)

        if p.dst_port == 53:
            # Question direction.
            query_counts[domain] = query_counts.get(domain, 0) + 1
        elif p.src_port == 53 and p.dns_answer is None:
            # Response direction with no resolved answer — NXDOMAIN,
            # SERVFAIL, REFUSED, etc.
            fail_counts[domain] = fail_counts.get(domain, 0) + 1

    return query_counts, fail_counts


def compute_dns_analysis(packets: list[PacketModel]) -> DnsAnalysis:
    query_counts, fail_counts = _dns_domain_maps(packets)

    top_domains = sorted(
        (DomainCount(domain=d, count=c) for d, c in query_counts.items()),
        key=lambda x: -x.count,
    )[:TOP_DOMAINS_LIMIT]

    repeated = sorted(
        (
            DomainCount(domain=d, count=c)
            for d, c in query_counts.items()
            if c >= REPEATED_QUERY_MIN_COUNT
        ),
        key=lambda x: -x.count,
    )[:REPEATED_QUERIES_LIMIT]

    failed = sorted(
        (DomainCount(domain=d, count=c) for d, c in fail_counts.items()),
        key=lambda x: -x.count,
    )[:FAILED_QUERIES_LIMIT]

    return DnsAnalysis(top_domains=top_domains, repeated_queries=repeated, failed_queries=failed)


# ---------------------------------------------------------------------------
# Threat Analysis
# ---------------------------------------------------------------------------

# Canned guidance per threat type. Keyed on ThreatDetectionEngine's fixed
# `threat` labels rather than free text — if a third rule is ever added
# there without a matching entry here, the fallback below still produces
# a safe (if generic) result instead of crashing this endpoint. A
# deliberate, documented coupling — see docs/contracts/pcap-analysis.md.
_RECOMMENDATIONS = {
    "Port Scan Detected": (
        "Review firewall rules and consider rate-limiting or blocking this "
        "source if the scan wasn't an authorized security assessment."
    ),
    "Possible ARP Spoofing": (
        "Confirm which device legitimately owns the claimed MAC address. "
        "Consider static ARP entries or dynamic ARP inspection for "
        "critical hosts such as the gateway."
    ),
    "Possible DNS Tunneling": (
        "Investigate this source for DNS tunneling or exfiltration tools. "
        "Check what process is generating the queries, and consider "
        "blocking or rate-limiting DNS to the named parent domain if it "
        "isn't a known service."
    ),
    "Possible SYN Flood": (
        "Check the targeted host's connection backlog and firewall/rate-"
        "limiting rules. If this traffic isn't a known load test or "
        "monitoring tool, consider blocking or throttling the source IP "
        "and enabling SYN cookies on the target if not already in place."
    ),
    "Possible Beaconing Detected": (
        "Investigate the process on this host making these regular "
        "connections for C2/malware behavior. Check the destination's "
        "reputation, and rule out known legitimate periodic clients "
        "(health checks, chat apps, telemetry) before escalating."
    ),
    "Possible Data Exfiltration": (
        "Determine what process and data are behind this transfer. If "
        "it isn't a known backup, sync, or file-transfer job, treat this "
        "as a potential data-loss incident and consider blocking or "
        "rate-limiting traffic to this destination pending investigation."
    ),
}
_DEFAULT_RECOMMENDATION = (
    "Investigate this finding manually — no automated guidance is available "
    "for this alert type yet."
)


def compute_threat_findings(packets: list[PacketModel]) -> list[ThreatFinding]:
    """Replays every packet with a destination port (TCP/UDP/DNS), every
    DNS query, every TCP packet, and every ARP sighting, in chronological
    order, through a fresh ThreatDetectionEngine — the same Port Scan,
    ARP Spoofing, DNS Tunneling, and SYN Flood rules used for live
    capture, run once over a static file. See module docstring for why
    each call passes the packet's own historical timestamp as `now`."""
    engine = ThreatDetectionEngine()
    findings: list[ThreatFinding] = []

    for p in sorted(packets, key=lambda p: p.timestamp):
        now = p.timestamp.timestamp()
        alerts: list[ThreatAlertRow] = []

        if p.protocol == "ARP" and p.src_mac:
            arp_alert = engine.record_arp_sighting(mac=p.src_mac, ip=p.src_ip, now=now)
            if arp_alert is not None:
                alerts.append(arp_alert)
        elif p.dns_query:
            # Checked before the generic port-activity branch below —
            # DNS queries also carry a dst_port (53), but they're not
            # port-scan signal, and record_dns_activity() is a no-op for
            # them unless the query is itself a tunneling candidate, so
            # this doesn't cost anything on ordinary DNS traffic.
            dns_alert = engine.record_dns_activity(src_ip=p.src_ip, dns_query=p.dns_query, now=now)
            if dns_alert is not None:
                alerts.append(dns_alert)
        elif p.dst_port is not None:
            port_alert = engine.record_port_activity(
                src_ip=p.src_ip, dst_ip=p.dst_ip, dst_port=p.dst_port, now=now
            )
            if port_alert is not None:
                alerts.append(port_alert)
            # SYN Flood Detection (Rule 4) looks at the same TCP packets
            # Port Scan does, but for a different signal — raw SYN
            # volume aimed at one target, not distinct targets touched —
            # so a single packet can legitimately trip both rules at
            # once. Not an elif for that reason.
            if p.protocol == "TCP":
                syn_alert = engine.record_syn_activity(
                    src_ip=p.src_ip, dst_ip=p.dst_ip, dst_port=p.dst_port, info=p.info, now=now
                )
                if syn_alert is not None:
                    alerts.append(syn_alert)
            # Beaconing Detection (Rule 5) looks at the same
            # (src_ip, dst_ip, dst_port) connections Port Scan does, but
            # for a different signal — timing regularity to one target,
            # not distinct targets touched — so this can also legitimately
            # fire alongside Port Scan/SYN Flood on the same packet.
            beacon_alert = engine.record_beacon_activity(
                src_ip=p.src_ip, dst_ip=p.dst_ip, dst_port=p.dst_port, now=now
            )
            if beacon_alert is not None:
                alerts.append(beacon_alert)

        # Data Exfiltration Detection (Rule 6) is protocol-agnostic (it
        # only ever looks at payload volume, never content) and applies
        # to every packet regardless of which branch above matched, so
        # it isn't nested inside the ARP/DNS/port branching like the
        # other rules.
        exfil_alert = engine.record_data_transfer(
            src_ip=p.src_ip, dst_ip=p.dst_ip, payload_size=p.payload_size, now=now
        )
        if exfil_alert is not None:
            alerts.append(exfil_alert)

        for alert in alerts:
            findings.append(
                ThreatFinding(
                    severity=alert.severity,
                    reason=alert.threat,
                    evidence=alert.description,
                    recommendation=_RECOMMENDATIONS.get(alert.threat, _DEFAULT_RECOMMENDATION),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Network Health Score
# ---------------------------------------------------------------------------
# An explicitly heuristic, relative indicator — not a security audit. No
# real TLS/protocol inspection, no CVE or malware-signature matching, no
# ground truth to calibrate against. Weights are chosen so no single
# factor can zero out the score by itself, and are documented here rather
# than tuned silently. See docs/contracts/pcap-analysis.md.

_HIGH_SEVERITY_PENALTY = 20
_MEDIUM_SEVERITY_PENALTY = 10

_MAX_DNS_FAILURE_PENALTY = 15.0
_REPEATED_DOMAIN_PENALTY_PER_DOMAIN = 3
_MAX_REPEATED_DOMAIN_PENALTY = 10

# Well-known plaintext application ports — a port-number proxy for
# "encryption posture", not real inspection of what's actually inside.
_CLEARTEXT_PORTS = {21, 23, 80, 110, 143}
_MAX_ENCRYPTION_PENALTY = 15.0


def compute_health_score(packets: list[PacketModel], threats: list[ThreatFinding]) -> HealthScore:
    factors: list[str] = []
    score = 100.0

    # Factor 1 — threat signatures.
    threat_penalty = sum(
        _HIGH_SEVERITY_PENALTY if t.severity == "high" else _MEDIUM_SEVERITY_PENALTY
        for t in threats
    )
    if threat_penalty:
        score -= threat_penalty
        factors.append(f"-{threat_penalty} for {len(threats)} threat finding(s)")

    # Factor 2 — DNS anomaly volume (failed lookups + repeated/beaconing-like queries).
    # Recomputed from the full untruncated maps, not the top-N DnsAnalysis
    # lists, so a capture with many more than 8 failing domains still
    # scores its real failure ratio instead of only what's visible.
    query_counts, fail_counts = _dns_domain_maps(packets)
    total_dns_responses = sum(1 for p in packets if p.protocol == "DNS" and p.src_port == 53)
    failed_count = sum(fail_counts.values())

    if total_dns_responses > 0 and failed_count > 0:
        fail_ratio = min(failed_count / total_dns_responses, 1.0)
        dns_penalty = round(fail_ratio * _MAX_DNS_FAILURE_PENALTY)
        if dns_penalty:
            score -= dns_penalty
            factors.append(
                f"-{dns_penalty} for {failed_count} failed DNS lookup(s) "
                f"({fail_ratio:.0%} of {total_dns_responses} response(s))"
            )

    repeated_domain_count = sum(1 for c in query_counts.values() if c >= REPEATED_QUERY_MIN_COUNT)
    if repeated_domain_count:
        repeated_penalty = min(
            repeated_domain_count * _REPEATED_DOMAIN_PENALTY_PER_DOMAIN,
            _MAX_REPEATED_DOMAIN_PENALTY,
        )
        score -= repeated_penalty
        factors.append(
            f"-{repeated_penalty} for {repeated_domain_count} domain(s) "
            "with unusually repetitive queries"
        )

    # Factor 3 — encryption posture (coarse port-based heuristic, see above).
    tcp_packets = [p for p in packets if p.protocol == "TCP"]
    if tcp_packets:
        cleartext = sum(
            1
            for p in tcp_packets
            if p.dst_port in _CLEARTEXT_PORTS or p.src_port in _CLEARTEXT_PORTS
        )
        if cleartext:
            cleartext_ratio = cleartext / len(tcp_packets)
            enc_penalty = round(cleartext_ratio * _MAX_ENCRYPTION_PENALTY)
            if enc_penalty:
                score -= enc_penalty
                factors.append(
                    f"-{enc_penalty} for {cleartext_ratio:.0%} of TCP traffic on "
                    "plaintext ports (21/23/80/110/143)"
                )

    score = max(0, min(100, round(score)))
    if not factors:
        factors.append("No threat, DNS, or cleartext-traffic anomalies found in this capture.")

    return HealthScore(score=score, factors=factors)


def compute_insights(packets: list[PacketModel]) -> PcapInsights:
    dns = compute_dns_analysis(packets)
    threats = compute_threat_findings(packets)
    health = compute_health_score(packets, threats)
    return PcapInsights(dns=dns, threats=threats, health=health)
