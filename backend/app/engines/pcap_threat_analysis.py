"""
Threat Analysis for uploaded PCAP files — Port Scan Detection, ARP
Spoofing Detection, DNS Tunneling Detection, SYN Flood Detection,
Beaconing Detection, and Data Exfiltration Detection, run once over a
full stored capture.

Pure functions over a `list[PacketModel]`, same convention as
`app.engines.pcap_summary` — no file I/O, no Scapy, fully testable with
synthetic PacketModel instances and no real .pcap file.

This deliberately does NOT use `ThreatDetectionEngine`
(`app.engines.threat_detection`) — that class is built for live, ongoing
capture (wall-clock `time.time()`, a rolling cooldown to stop one
ongoing incident from flooding a live panel). Neither concept fits
analyzing a file you already have in full: "now" is meaningless for a
closed dataset, and a cooldown answers "don't tell me about the same
ongoing thing again for N seconds" — not what a batch report wants,
which is every genuinely distinct incident found anywhere in the file.

What IS reused: `PORT_SCAN_WINDOW_SECONDS`, `PORT_SCAN_DISTINCT_THRESHOLD`,
`ARP_CONFLICT_DEBOUNCE_SECONDS`, `DNS_TUNNEL_WINDOW_SECONDS`,
`DNS_TUNNEL_DISTINCT_THRESHOLD`, `DNS_TUNNEL_LABEL_LENGTH_THRESHOLD`,
`SYN_FLOOD_WINDOW_SECONDS`, `SYN_FLOOD_COUNT_THRESHOLD`,
`MIN_BEACON_OBSERVATIONS`, `BEACON_HISTORY_SIZE`, `EXFIL_WINDOW_SECONDS`,
`EXFIL_BYTE_THRESHOLD`, and the `dns_tunnel_candidate`/`is_bare_syn`/
`beacon_pattern_stats` helpers — all imported directly from
`threat_detection.py` so the two detection surfaces can't silently drift
apart on what counts as a scan, a confirmed conflict, a tunneling
candidate, a bare SYN, or a beacon. See docs/contracts/pcap-threat-analysis.md
for the full reasoning behind replacing "cooldown" with "episode" (Port
Scan, DNS Tunneling, SYN Flood, Beaconing, Data Exfiltration) and
"aggregate per contested IP" (ARP Spoofing) instead.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

from app.engines.threat_detection import (
    ARP_CONFLICT_DEBOUNCE_SECONDS,
    BEACON_HISTORY_SIZE,
    DNS_TUNNEL_DISTINCT_THRESHOLD,
    DNS_TUNNEL_LABEL_LENGTH_THRESHOLD,
    DNS_TUNNEL_WINDOW_SECONDS,
    EXFIL_BYTE_THRESHOLD,
    EXFIL_WINDOW_SECONDS,
    PORT_SCAN_DISTINCT_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    SYN_FLOOD_COUNT_THRESHOLD,
    SYN_FLOOD_WINDOW_SECONDS,
    beacon_pattern_stats,
    dns_tunnel_candidate,
    is_bare_syn,
)
from app.models.packet import PacketModel
from app.schemas.pcap import PcapThreatFinding

# Canned guidance per finding type. Keyed on the fixed `reason` labels
# below rather than free text — if a third rule is ever added without a
# matching entry here, the fallback still produces a safe (if generic)
# result instead of crashing this endpoint. Same deliberate, documented
# coupling `threats.md`'s live recommendations use.
_RECOMMENDATIONS = {
    "Port Scan Detected": (
        "Investigate this host for scanning tools or malware; review firewall "
        "rules and consider rate-limiting or blocking this source if the scan "
        "wasn't an authorized security assessment."
    ),
    "Possible ARP Spoofing": (
        "Confirm which device legitimately owns the claimed MAC address. "
        "Consider static ARP entries or dynamic ARP inspection for critical "
        "hosts such as the gateway."
    ),
    "Possible DNS Tunneling": (
        "Investigate this source for DNS tunneling or exfiltration tools "
        "(iodine, dnscat2, dns2tcp). Check what process on this host is "
        "generating the queries, and consider blocking or rate-limiting "
        "DNS to the named parent domain if it isn't a known service."
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
    "for this finding type yet."
)


def _recommendation_for(reason: str) -> str:
    return _RECOMMENDATIONS.get(reason, _DEFAULT_RECOMMENDATION)


# ---------------------------------------------------------------------------
# Port Scan Detection
# ---------------------------------------------------------------------------


def _port_scan_finding(
    src_ip: str, pairs: set[tuple[str, int]], start: datetime, end: datetime
) -> PcapThreatFinding:
    hosts = {ip for ip, _ in pairs}
    duration = max((end - start).total_seconds(), 0.0)
    return PcapThreatFinding(
        severity="medium",
        source=src_ip,
        reason="Port Scan Detected",
        evidence=(
            f"{src_ip} touched {len(pairs)} distinct host:port pairs across "
            f"{len(hosts)} host(s) over a {duration:.1f}s episode."
        ),
        recommendation=_recommendation_for("Port Scan Detected"),
    )


def detect_port_scans(packets: list[PacketModel]) -> list[PcapThreatFinding]:
    """One finding per **episode** — a maximal, time-contiguous stretch
    during which a source IP's trailing `PORT_SCAN_WINDOW_SECONDS`-second
    window of distinct `(dst_ip, dst_port)` pairs stays at or above
    `PORT_SCAN_DISTINCT_THRESHOLD`. Two genuinely separate scanning
    episodes from the same source, far enough apart in the file's real
    timeline, correctly produce two findings — not one packet-per-row,
    and not artificially merged or split by a fixed cooldown duration."""
    by_src: dict[str, list[PacketModel]] = defaultdict(list)
    for p in packets:
        if p.dst_port is not None:
            by_src[p.src_ip].append(p)

    findings: list[PcapThreatFinding] = []

    for src_ip, pkts in by_src.items():
        pkts.sort(key=lambda p: p.timestamp)
        window: "deque[PacketModel]" = deque()
        in_episode = False
        episode_start: Optional[datetime] = None
        episode_end: Optional[datetime] = None
        episode_pairs: set[tuple[str, int]] = set()

        for p in pkts:
            window.append(p)
            cutoff = p.timestamp - timedelta(seconds=PORT_SCAN_WINDOW_SECONDS)
            while window and window[0].timestamp < cutoff:
                window.popleft()

            distinct_in_window = {(w.dst_ip, w.dst_port) for w in window}

            if len(distinct_in_window) >= PORT_SCAN_DISTINCT_THRESHOLD:
                if not in_episode:
                    in_episode = True
                    episode_start = window[0].timestamp
                    episode_pairs = set(distinct_in_window)
                else:
                    episode_pairs |= distinct_in_window
                episode_end = p.timestamp
            elif in_episode:
                findings.append(
                    _port_scan_finding(src_ip, episode_pairs, episode_start, episode_end)
                )
                in_episode = False
                episode_pairs = set()

        if in_episode:
            findings.append(_port_scan_finding(src_ip, episode_pairs, episode_start, episode_end))

    return findings


# ---------------------------------------------------------------------------
# ARP Spoofing Detection
# ---------------------------------------------------------------------------


def detect_arp_spoofing(packets: list[PacketModel]) -> list[PcapThreatFinding]:
    """One finding per **contested IP** with at least one confirmed
    conflict anywhere in the file — not one per confirmed flip. A
    conflicting MAC must be confirmed by a second sighting within
    `ARP_CONFLICT_DEBOUNCE_SECONDS` of the first (same rule as the live
    engine), so a single stray or retransmitted packet still can't
    trigger a finding by itself."""
    by_ip: dict[str, list[PacketModel]] = defaultdict(list)
    for p in packets:
        if p.protocol == "ARP" and p.src_mac:
            by_ip[p.src_ip].append(p)

    findings: list[PcapThreatFinding] = []

    for ip, pkts in by_ip.items():
        pkts.sort(key=lambda p: p.timestamp)

        current_mac: Optional[str] = None
        pending_mac: Optional[str] = None
        pending_first_seen: Optional[datetime] = None
        confirmed_macs: set[str] = set()
        confirmed_count = 0

        for p in pkts:
            mac = p.src_mac
            if current_mac is None:
                # First sighting ever for this IP — nothing to compare
                # against yet.
                current_mac = mac
                continue

            if mac == current_mac:
                # Consistent with what we already trust. Any pending
                # conflict for a *different* MAC naturally lapses since
                # it won't be reconfirmed.
                pending_mac = None
                pending_first_seen = None
                continue

            # A different MAC is claiming this IP.
            if (
                pending_mac == mac
                and pending_first_seen is not None
                and (p.timestamp - pending_first_seen).total_seconds() <= ARP_CONFLICT_DEBOUNCE_SECONDS
            ):
                # Same conflicting MAC seen a second time within the
                # debounce window — confirmed, not a stray packet.
                confirmed_macs.add(current_mac)
                confirmed_macs.add(mac)
                confirmed_count += 1
                current_mac = mac
                pending_mac = None
                pending_first_seen = None
            else:
                # Either the first sighting of this particular
                # conflicting MAC, or a previous pending conflict aged
                # out before being reconfirmed.
                pending_mac = mac
                pending_first_seen = p.timestamp

        if confirmed_count > 0:
            plural = "s" if confirmed_count != 1 else ""
            findings.append(
                PcapThreatFinding(
                    severity="high",
                    source=ip,
                    reason="Possible ARP Spoofing",
                    evidence=(
                        f"{ip} was claimed by {len(confirmed_macs)} different MAC addresses "
                        f"({', '.join(sorted(confirmed_macs))}) across {confirmed_count} "
                        f"confirmed conflict{plural}."
                    ),
                    recommendation=_recommendation_for("Possible ARP Spoofing"),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# DNS Tunneling Detection
# ---------------------------------------------------------------------------


def _dns_tunnel_finding(
    src_ip: str, parent: str, count: int, start: datetime, end: datetime
) -> PcapThreatFinding:
    duration = max((end - start).total_seconds(), 0.0)
    return PcapThreatFinding(
        severity="medium",
        source=src_ip,
        reason="Possible DNS Tunneling",
        evidence=(
            f"{src_ip} sent {count} DNS queries with abnormally long subdomain "
            f"labels (>= {DNS_TUNNEL_LABEL_LENGTH_THRESHOLD} chars) to *.{parent} "
            f"over a {duration:.1f}s episode."
        ),
        recommendation=_recommendation_for("Possible DNS Tunneling"),
    )


def detect_dns_tunneling(packets: list[PacketModel]) -> list[PcapThreatFinding]:
    """One finding per **episode** — a maximal, time-contiguous stretch
    during which a (source IP, parent domain) pair's trailing
    `DNS_TUNNEL_WINDOW_SECONDS`-second window of oversized-label queries
    stays at or above `DNS_TUNNEL_DISTINCT_THRESHOLD`. Same episode
    convention as `detect_port_scans` — see its docstring for why this
    is not simply "count queries and threshold once" the way a live
    cooldown would."""
    by_key: dict[tuple[str, str], list[PacketModel]] = defaultdict(list)
    for p in packets:
        if not p.dns_query:
            continue
        candidate = dns_tunnel_candidate(p.dns_query)
        if candidate is None:
            continue
        _, parent = candidate
        by_key[(p.src_ip, parent)].append(p)

    findings: list[PcapThreatFinding] = []

    for (src_ip, parent), pkts in by_key.items():
        pkts.sort(key=lambda p: p.timestamp)
        window: "deque[PacketModel]" = deque()
        in_episode = False
        episode_start: Optional[datetime] = None
        episode_end: Optional[datetime] = None
        episode_count = 0

        for p in pkts:
            window.append(p)
            cutoff = p.timestamp - timedelta(seconds=DNS_TUNNEL_WINDOW_SECONDS)
            while window and window[0].timestamp < cutoff:
                window.popleft()

            if len(window) >= DNS_TUNNEL_DISTINCT_THRESHOLD:
                if not in_episode:
                    in_episode = True
                    episode_start = window[0].timestamp
                episode_count = len(window)
                episode_end = p.timestamp
            elif in_episode:
                findings.append(
                    _dns_tunnel_finding(src_ip, parent, episode_count, episode_start, episode_end)
                )
                in_episode = False
                episode_count = 0

        if in_episode:
            findings.append(
                _dns_tunnel_finding(src_ip, parent, episode_count, episode_start, episode_end)
            )

    return findings


# ---------------------------------------------------------------------------
# SYN Flood Detection
# ---------------------------------------------------------------------------


def _syn_flood_finding(
    src_ip: str, dst_ip: str, dst_port: int, count: int, start: datetime, end: datetime
) -> PcapThreatFinding:
    duration = max((end - start).total_seconds(), 0.0)
    return PcapThreatFinding(
        severity="medium",
        source=src_ip,
        reason="Possible SYN Flood",
        evidence=(
            f"{src_ip} sent {count} bare TCP SYN packets to {dst_ip}:{dst_port} without "
            f"completing the handshake, over a {duration:.1f}s episode."
        ),
        recommendation=_recommendation_for("Possible SYN Flood"),
    )


def detect_syn_floods(packets: list[PacketModel]) -> list[PcapThreatFinding]:
    """One finding per **episode** — a maximal, time-contiguous stretch
    during which a (source IP, destination IP, destination port)
    triple's trailing `SYN_FLOOD_WINDOW_SECONDS`-second window of bare
    SYNs stays at or above `SYN_FLOOD_COUNT_THRESHOLD`. Same episode
    convention as `detect_port_scans` and `detect_dns_tunneling` — see
    the former's docstring for why this isn't simply "count and
    threshold once" the way a live cooldown would."""
    by_key: dict[tuple[str, str, int], list[PacketModel]] = defaultdict(list)
    for p in packets:
        if p.protocol != "TCP" or p.dst_port is None:
            continue
        if not is_bare_syn(p.info):
            continue
        by_key[(p.src_ip, p.dst_ip, p.dst_port)].append(p)

    findings: list[PcapThreatFinding] = []

    for (src_ip, dst_ip, dst_port), pkts in by_key.items():
        pkts.sort(key=lambda p: p.timestamp)
        window: "deque[PacketModel]" = deque()
        in_episode = False
        episode_start: Optional[datetime] = None
        episode_end: Optional[datetime] = None
        episode_count = 0

        for p in pkts:
            window.append(p)
            cutoff = p.timestamp - timedelta(seconds=SYN_FLOOD_WINDOW_SECONDS)
            while window and window[0].timestamp < cutoff:
                window.popleft()

            if len(window) >= SYN_FLOOD_COUNT_THRESHOLD:
                if not in_episode:
                    in_episode = True
                    episode_start = window[0].timestamp
                episode_count = len(window)
                episode_end = p.timestamp
            elif in_episode:
                findings.append(
                    _syn_flood_finding(src_ip, dst_ip, dst_port, episode_count, episode_start, episode_end)
                )
                in_episode = False
                episode_count = 0

        if in_episode:
            findings.append(
                _syn_flood_finding(src_ip, dst_ip, dst_port, episode_count, episode_start, episode_end)
            )

    return findings


# ---------------------------------------------------------------------------
# Beaconing Detection
# ---------------------------------------------------------------------------


def _beacon_finding(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    count: int,
    mean: float,
    cv: float,
    start: datetime,
    end: datetime,
) -> PcapThreatFinding:
    duration = max((end - start).total_seconds(), 0.0)
    return PcapThreatFinding(
        severity="medium",
        source=src_ip,
        reason="Possible Beaconing Detected",
        evidence=(
            f"{src_ip} connected to {dst_ip}:{dst_port} at {count} consecutive "
            f"~{mean:.1f}s intervals (coefficient of variation {cv:.2f}) over a "
            f"{duration:.1f}s span — suspiciously regular, possible C2 beaconing."
        ),
        recommendation=_recommendation_for("Possible Beaconing Detected"),
    )


def detect_beaconing(packets: list[PacketModel]) -> list[PcapThreatFinding]:
    """One finding per **episode** — a maximal, time-contiguous stretch
    during which a (source IP, destination IP, destination port)
    triple's trailing `BEACON_HISTORY_SIZE`-timestamp history qualifies
    as a beaconing candidate per `beacon_pattern_stats` (the same shared
    helper `ThreatDetectionEngine.record_beacon_activity` uses). Unlike
    Rules 1/3/4, the underlying signal isn't a wall-clock rolling window
    — it's a fixed-size deque of connection timestamps — but the episode
    concept still applies cleanly: at each new connection, either the
    trailing history currently qualifies as a beacon or it doesn't, and
    a maximal contiguous run of "yes" is one distinct incident."""
    by_key: dict[tuple[str, str, int], list[PacketModel]] = defaultdict(list)
    for p in packets:
        if p.dst_port is not None:
            by_key[(p.src_ip, p.dst_ip, p.dst_port)].append(p)

    findings: list[PcapThreatFinding] = []

    for (src_ip, dst_ip, dst_port), pkts in by_key.items():
        pkts.sort(key=lambda p: p.timestamp)
        history: "deque[datetime]" = deque(maxlen=BEACON_HISTORY_SIZE)
        in_episode = False
        episode_start: Optional[datetime] = None
        episode_end: Optional[datetime] = None
        episode_stats: Optional[tuple[float, float, int]] = None

        for p in pkts:
            history.append(p.timestamp)
            stats = beacon_pattern_stats([t.timestamp() for t in history])

            if stats is not None:
                if not in_episode:
                    in_episode = True
                    episode_start = history[0]
                episode_end = p.timestamp
                episode_stats = stats
            elif in_episode:
                mean, cv, count = episode_stats
                findings.append(
                    _beacon_finding(src_ip, dst_ip, dst_port, count, mean, cv, episode_start, episode_end)
                )
                in_episode = False
                episode_stats = None

        if in_episode:
            mean, cv, count = episode_stats
            findings.append(
                _beacon_finding(src_ip, dst_ip, dst_port, count, mean, cv, episode_start, episode_end)
            )

    return findings


# ---------------------------------------------------------------------------
# Data Exfiltration Detection (volume-based)
# ---------------------------------------------------------------------------


def _exfil_finding(src_ip: str, dst_ip: str, total_bytes: int, start: datetime, end: datetime) -> PcapThreatFinding:
    duration = max((end - start).total_seconds(), 0.0)
    return PcapThreatFinding(
        severity="medium",
        source=src_ip,
        reason="Possible Data Exfiltration",
        evidence=(
            f"{src_ip} sent {total_bytes:,} bytes of payload data to {dst_ip} "
            f"over a {duration:.1f}s episode."
        ),
        recommendation=_recommendation_for("Possible Data Exfiltration"),
    )


def detect_data_exfiltration(packets: list[PacketModel]) -> list[PcapThreatFinding]:
    """One finding per **episode** — a maximal, time-contiguous stretch
    during which a (source IP, destination IP) pair's trailing
    `EXFIL_WINDOW_SECONDS`-second window of payload bytes stays at or
    above `EXFIL_BYTE_THRESHOLD`. Same episode convention as
    `detect_port_scans` — see its docstring for why this isn't simply
    "sum everything and threshold once" the way a live cooldown would.
    Protocol-agnostic: every packet with a `payload_size` counts,
    regardless of `protocol`."""
    by_key: dict[tuple[str, str], list[PacketModel]] = defaultdict(list)
    for p in packets:
        by_key[(p.src_ip, p.dst_ip)].append(p)

    findings: list[PcapThreatFinding] = []

    for (src_ip, dst_ip), pkts in by_key.items():
        pkts.sort(key=lambda p: p.timestamp)
        window: "deque[PacketModel]" = deque()
        running_total = 0
        in_episode = False
        episode_start: Optional[datetime] = None
        episode_end: Optional[datetime] = None
        episode_total = 0

        for p in pkts:
            window.append(p)
            running_total += p.payload_size

            cutoff = p.timestamp - timedelta(seconds=EXFIL_WINDOW_SECONDS)
            while window and window[0].timestamp < cutoff:
                running_total -= window.popleft().payload_size

            if running_total >= EXFIL_BYTE_THRESHOLD:
                if not in_episode:
                    in_episode = True
                    episode_start = window[0].timestamp
                episode_total = running_total
                episode_end = p.timestamp
            elif in_episode:
                findings.append(_exfil_finding(src_ip, dst_ip, episode_total, episode_start, episode_end))
                in_episode = False
                episode_total = 0

        if in_episode:
            findings.append(_exfil_finding(src_ip, dst_ip, episode_total, episode_start, episode_end))

    return findings


# ---------------------------------------------------------------------------
# Combined entry point
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def analyze_threats(packets: list[PacketModel]) -> list[PcapThreatFinding]:
    """Runs both rules and returns findings in a stable, deterministic
    order (highest severity first, then by source) — so repeated calls
    on the same file always render identically instead of depending on
    dict iteration order."""
    findings = (
        detect_port_scans(packets)
        + detect_arp_spoofing(packets)
        + detect_dns_tunneling(packets)
        + detect_syn_floods(packets)
        + detect_beaconing(packets)
        + detect_data_exfiltration(packets)
    )
    findings.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 3), f.source))
    return findings
