"""
Threat Detection Engine.

Owns six independent, intentionally simple detection rules — Port Scan,
ARP Spoofing, DNS Tunneling, SYN Flood, Beaconing, and Data
Exfiltration — plus a bounded ring buffer of resulting alerts, shaped
exactly like PacketStreamEngine: a monotonically increasing sequence
number, `since(last_no)` for delta broadcast, and `backlog(limit)` so a
freshly connected client sees recent alerts immediately. See
docs/contracts/threats.md for the full reasoning behind every threshold,
window, and cooldown constant below, and for the explicit list of what
this v1 does NOT attempt to detect.

Like every other engine, this only ever receives plain Python values
handed in by the capture layer — no Scapy, independently unit-testable
without root privileges or a live capture.

Each rule is fed by its own public method (`record_port_activity`,
`record_arp_sighting`, `record_dns_activity`, `record_syn_activity`,
`record_beacon_activity`, `record_data_transfer`) so any one rule could
be unit-tested, disabled, or extended without touching the others. This
engine also keeps its *own* IP->MAC bookkeeping for Rule 2 rather than
reading `HostDiscoveryEngine`'s internal state — `PacketCapture` calls
both engines' sighting methods independently for the same ARP packet.
Some duplicated ARP-observation logic is the deliberate trade-off this
codebase already makes elsewhere (see `TopTalkersEngine` vs.
`HostDiscoveryEngine`, both fed independently from the same packets) —
it keeps each engine's behavior reasoned about in isolation, instead of
one engine's correctness depending on another's private data shape.
"""

from __future__ import annotations

import re
import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional, Sequence

from app.schemas.threats_live import ThreatAlertRow

DEFAULT_MAX_BUFFER = 500

# ---------------------------------------------------------------------------
# Rule 1 — Port Scan Detection
# ---------------------------------------------------------------------------

# How far back "distinct ports touched" looks. Long enough to catch a
# scan that paces itself slightly, short enough to not need to remember
# minutes of history to decide about "right now".
PORT_SCAN_WINDOW_SECONDS = 10.0

# Distinct (dst_ip, dst_port) pairs from one source within the window
# that counts as a scan. Ordinary browsing realistically stays under 10
# distinct host:port pairs in any 10s window; scanning tools sweep dozens
# to thousands in the same window. 15 sits above normal bursts and below
# even a stealthy scan — see docs/contracts/threats.md for the full case.
PORT_SCAN_DISTINCT_THRESHOLD = 15

# Once a source trips the threshold, suppress further alerts for it for
# this long. A real scan matches on every subsequent packet for as long
# as it runs — without this, one scan floods the table with a
# near-duplicate row per packet. Not optional.
PORT_SCAN_COOLDOWN_SECONDS = 60.0

# ---------------------------------------------------------------------------
# Rule 2 — ARP Spoofing Detection
# ---------------------------------------------------------------------------

# A conflicting MAC must be seen a second time within this many seconds
# of the first conflicting sighting before it's treated as a real claim
# rather than a single stray/retransmitted packet. Real poisoning tools
# repeat forged replies every 1-3s by design, so a genuine attack
# reliably produces the second sighting well inside this window.
ARP_CONFLICT_DEBOUNCE_SECONDS = 2.0

# Once a specific IP has produced a confirmed conflict alert, suppress
# further alerts for that IP for this long. Shorter than the port-scan
# cooldown since ARP conflicts are rarer and more severe.
ARP_CONFLICT_COOLDOWN_SECONDS = 30.0

# ---------------------------------------------------------------------------
# Rule 3 — DNS Tunneling Detection
# ---------------------------------------------------------------------------

# A query's leftmost label ("leaf") at or above this many characters is
# treated as suspicious. Real hostnames people type or that ordinary
# services generate rarely exceed ~20 characters; DNS tunneling tools
# (iodine, dnscat2, dns2tcp) pack encoded payload into the leaf label to
# maximize bytes-per-query and routinely produce labels in the 32-63
# character range — 63 is DNS's own hard per-label limit.
DNS_TUNNEL_LABEL_LENGTH_THRESHOLD = 32

# How far back "oversized-label queries to this parent domain" looks.
# Shorter than the port-scan window — a tunnel is simulating a data
# channel over DNS, so it's chatty by design and reliably produces a
# burst of queries well inside 20 seconds. A longer window would only
# delay detection without meaningfully reducing false positives.
DNS_TUNNEL_WINDOW_SECONDS = 20.0

# Oversized-label queries to the *same* parent domain from one source
# within the window that counts as tunneling. Occasional long subdomains
# happen legitimately (content hashes, some CDN/tracking endpoints) but
# not repeatedly against one domain in a tight burst — 20 sits above what
# a handful of coincidental long hostnames would produce and comfortably
# below what an active tunnel session generates.
DNS_TUNNEL_DISTINCT_THRESHOLD = 20

# Once a source trips this rule for a given parent domain, suppress
# further alerts for that (source, domain) pair for this long. Same
# reasoning as the port-scan cooldown — an open tunnel keeps matching on
# every subsequent query for as long as it stays active.
DNS_TUNNEL_COOLDOWN_SECONDS = 60.0


def dns_tunnel_candidate(dns_query: str) -> Optional[tuple[str, str]]:
    """Given a raw `PacketModel.dns_query` value (e.g.
    `"a1b2c3d4e5f6...z9.evil.example.com (TXT)"`, as formatted by
    `PacketParser._parse_dns`), returns `(leaf_label, parent_domain)` if
    the query's leftmost label is long enough to be an oversized-label
    tunneling candidate, else `None`.

    Module-level and public (not engine-private) so
    `app.engines.pcap_threat_analysis`'s batch analyzer can import it
    directly rather than re-implementing the same parsing — the same
    reason `PORT_SCAN_*`/`ARP_CONFLICT_*` constants are imported there
    instead of redefined. Keeps live and batch detection from silently
    drifting on what counts as a candidate query."""
    idx = dns_query.rfind(" (")
    domain = dns_query[:idx] if idx != -1 else dns_query
    labels = domain.split(".")
    if len(labels) < 3:
        # Need at least leaf.domain.tld — nothing to flag as an
        # oversized leaf sitting in front of a real parent domain.
        return None
    leaf, parent = labels[0], ".".join(labels[1:])
    if len(leaf) < DNS_TUNNEL_LABEL_LENGTH_THRESHOLD:
        return None
    return leaf, parent


# ---------------------------------------------------------------------------
# Rule 4 — SYN Flood Detection
# ---------------------------------------------------------------------------

# How far back "bare SYNs sent to this (dst_ip, dst_port)" looks. A real
# SYN flood is fast by design — the whole point is exhausting a
# listener's half-open backlog before entries can time out — so a short
# window catches the burst without needing to remember much history.
# Ordinary traffic (a browser opening several parallel connections to one
# site) completes its handshakes well inside this window.
SYN_FLOOD_WINDOW_SECONDS = 5.0

# Bare SYNs to the same (dst_ip, dst_port) from one source within the
# window that counts as a flood. A browser opening a handful of parallel
# connections to one host realistically stays under 10 SYNs in 5
# seconds; a flood — even a throttled one — sends dozens to thousands.
# 40 sits comfortably above ordinary concurrent-connection bursts and
# well below what even a modest flood tool generates.
SYN_FLOOD_COUNT_THRESHOLD = 40

# Once a source trips this rule for a given (dst_ip, dst_port), suppress
# further alerts for that pair for this long. Same reasoning as the
# port-scan cooldown — an ongoing flood matches on every subsequent SYN
# for as long as it runs.
SYN_FLOOD_COOLDOWN_SECONDS = 30.0

# Matches PacketParser's own TCP `info` format exactly:
# f"TCP {src_port} \u2192 {dst_port} [{flags}]" — see packet_parser.py.
_TCP_FLAGS_RE = re.compile(r"\[([A-Z]*)\]\s*$")


def is_bare_syn(info: Optional[str]) -> bool:
    """True if `info` (a `PacketModel.info` string) represents a bare
    SYN — a new-connection attempt with only the SYN bit set, not a
    SYN-ACK reply, an ACK, a retransmission, or any other flag
    combination.

    Module-level and public for the same reason `dns_tunnel_candidate`
    is: the live engine and the PCAP batch analyzer both need to answer
    "is this packet a bare SYN?" from the same text, and must not drift
    on the answer. Text-based (parses the trailing `[FLAGS]` PacketParser
    already writes) rather than re-deriving flags from a raw Scapy
    packet, since neither this engine nor the batch analyzer touches
    Scapy directly — see both modules' docstrings."""
    if not info:
        return False
    match = _TCP_FLAGS_RE.search(info)
    if match is None:
        return False
    return match.group(1) == "S"


# ---------------------------------------------------------------------------
# Rule 5 — Beaconing Detection
# ---------------------------------------------------------------------------

# Consecutive connection-timestamp intervals (for one (src_ip, dst_ip,
# dst_port) triple) required before this rule trusts a pattern enough to
# evaluate it at all. Fewer than this and a coincidental run of 2-3
# evenly-spaced connections (a person refreshing a page a couple of
# times) could look "regular" purely by chance. Real C2 frameworks that
# beacon on a fixed sleep timer reliably produce this many observations
# within their first few sleep cycles.
MIN_BEACON_OBSERVATIONS = 8

# Rolling history size — enough connection timestamps to compute exactly
# MIN_BEACON_OBSERVATIONS trailing intervals (one fewer timestamp than
# interval), no more. A fixed-size deque rather than a time window: this
# rule's signal is the *shape* of the gaps between connections, not "how
# many happened in the last N seconds", so a wall-clock window (like
# every other rule here) doesn't fit — see `_BeaconActivity`.
BEACON_HISTORY_SIZE = MIN_BEACON_OBSERVATIONS + 1

# Coefficient of variation (stddev / mean) below which the interval
# pattern is judged "too regular" to be human-driven or bursty machine
# traffic. 0.15 means the gap between check-ins varies by less than a
# seventh of the mean — tighter than almost any legitimate traffic
# pattern, which naturally carries jitter from retries, backoff, or
# queuing delay. Malware timers deliberately hold to a fixed sleep value
# (sometimes with a small jitter percentage, but rarely enough to push
# this above ~0.10-0.15). Set high enough not to dismiss a real,
# slightly-jittered beacon; low enough that ordinary bursty polling
# falls outside it. See docs/contracts/threats.md for the explicit
# false-positive discussion (legitimate periodic polling is real).
BEACON_CV_THRESHOLD = 0.15

# Lower bound of the "suspicious periodicity" range, in seconds. Mean
# intervals faster than this look like an active bulk transfer (or a
# single session's own retries/keepalives being miscounted as separate
# connections), not deliberate periodic beaconing — malware sleep timers
# almost always hold off at least several seconds between check-ins to
# avoid looking exactly like this.
BEACON_MIN_INTERVAL_SECONDS = 5.0

# Upper bound of the "suspicious periodicity" range, in seconds (1 hour).
# Beyond this, reliably accumulating MIN_BEACON_OBSERVATIONS intervals
# would require remembering activity spanning many hours — outside what
# this session-scoped, in-memory engine can reasonably track. Slow
# beacons checking in less often than hourly are covered by the explicit
# non-goal for low-and-slow C2 (see docs/contracts/threats.md).
BEACON_MAX_INTERVAL_SECONDS = 3600.0

# Once a (src_ip, dst_ip, dst_port) triple is confirmed as beaconing,
# suppress further alerts for that triple for this long. Without a
# cooldown, an ongoing beacon keeps re-qualifying on literally every
# subsequent check-in for as long as the malware keeps running. Longer
# than the port-scan/SYN-flood cooldowns because a confirmed beacon is
# an ongoing background condition, not a fast-moving one-off burst —
# there's no urgency to re-alert more often than every 5 minutes once
# the analyst has already been told.
BEACON_COOLDOWN_SECONDS = 300.0


def beacon_pattern_stats(
    timestamps: Sequence[float],
) -> Optional[tuple[float, float, int]]:
    """Given a chronological (oldest-first) sequence of connection
    timestamps (unix seconds) for one (src_ip, dst_ip, dst_port) triple,
    returns `(mean_interval, coefficient_of_variation, interval_count)`
    if the trailing history qualifies as a beaconing candidate — enough
    intervals available, tight enough variation, mean interval inside
    the suspicious periodicity range — else `None`.

    Module-level and public for the same reason `dns_tunnel_candidate`
    and `is_bare_syn` are: the live engine's `record_beacon_activity` and
    the PCAP batch analyzer's `detect_beaconing` both need to answer "is
    this trailing history a beacon?" from the same timestamps, and must
    not drift on the answer."""
    ts = list(timestamps)
    if len(ts) < MIN_BEACON_OBSERVATIONS + 1:
        return None

    intervals = [b - a for a, b in zip(ts, ts[1:])]
    mean = statistics.fmean(intervals)
    if mean <= 0:
        # Duplicate/out-of-order timestamps collapsing to a zero mean —
        # nothing meaningful to divide by, and certainly not a real
        # interval pattern.
        return None

    cv = statistics.pstdev(intervals) / mean
    if cv >= BEACON_CV_THRESHOLD:
        return None
    if not (BEACON_MIN_INTERVAL_SECONDS <= mean <= BEACON_MAX_INTERVAL_SECONDS):
        return None

    return mean, cv, len(intervals)


# ---------------------------------------------------------------------------
# Rule 6 — Data Exfiltration Detection (volume-based)
# ---------------------------------------------------------------------------

# How far back "payload bytes sent to this destination" looks. Long
# enough to catch a sustained bulk transfer while it's happening, short
# enough that stacking several ordinary page loads/API calls back-to-back
# doesn't accidentally accumulate toward a sustained-transfer volume.
EXFIL_WINDOW_SECONDS = 60.0

# Payload bytes from one source to one destination within the window
# that counts as a possible bulk exfiltration. A typical web page load
# transfers on the order of a few hundred KB to a few MB total (even a
# heavy page rarely exceeds 5-10MB); a typical API call moves kilobytes.
# 50MB to one destination inside the same 60-second window is an order
# of magnitude beyond ordinary browsing/API traffic and matches what
# copying a moderately sized file or directory off a host looks like on
# the wire — comfortably above generous legitimate bursts (a software
# update, a large email attachment) while still catching a real bulk
# transfer before it's finished.
EXFIL_BYTE_THRESHOLD = 50_000_000

# Once a (src_ip, dst_ip) pair trips this rule, suppress further alerts
# for that pair for this long. An ongoing transfer keeps the rolling sum
# above threshold for as long as it continues, matching on every
# subsequent packet without a cooldown. Longer than the port-scan
# cooldown since a bulk transfer is a slower-moving, more sustained
# incident than a scan sweep — this collapses one ongoing transfer into
# a small number of alerts instead of one per packet, while still
# re-alerting if the same pair starts a distinct new transfer later.
EXFIL_COOLDOWN_SECONDS = 120.0


@dataclass
class _SourceActivity:
    """Rolling window of (timestamp, dst_ip, dst_port) tuples touched by
    one source IP, plus that source's own cooldown clock."""

    seen: "deque[tuple[float, str, int]]" = field(default_factory=deque)
    last_alert_at: Optional[float] = None


@dataclass
class _ArpBinding:
    """The MAC currently trusted for a given IP."""

    mac: str
    last_seen: float


@dataclass
class _PendingConflict:
    """A candidate new MAC trying to claim an IP that's already bound to
    a different MAC — held here until it either gets confirmed (seen
    again inside the debounce window) or ages out."""

    mac: str
    first_seen: float


@dataclass
class _DnsTunnelActivity:
    """Rolling window of (timestamp, parent_domain) pairs for oversized-
    label DNS queries from one source IP, plus a per-parent-domain
    cooldown clock — a source could plausibly be tunneling over more
    than one domain, so cooldown is tracked per (source, domain) rather
    than per source alone."""

    seen: "deque[tuple[float, str]]" = field(default_factory=deque)
    last_alert_at: dict[str, float] = field(default_factory=dict)


@dataclass
class _SynFloodActivity:
    """Rolling window of (timestamp, dst_ip, dst_port) for bare SYNs sent
    by one source IP, plus a per-(dst_ip, dst_port) cooldown clock — a
    source could plausibly be flooding more than one target at once, so
    cooldown is tracked per destination pair rather than per source
    alone."""

    seen: "deque[tuple[float, str, int]]" = field(default_factory=deque)
    last_alert_at: dict[tuple[str, int], float] = field(default_factory=dict)


@dataclass
class _BeaconActivity:
    """Rolling history of the last `BEACON_HISTORY_SIZE` connection
    timestamps for one (src_ip, dst_ip, dst_port) triple, plus that
    triple's own cooldown clock. Unlike every other rule's rolling
    window (all keyed to wall-clock elapsed seconds), this is a
    fixed-size deque of raw timestamps — beaconing is a decision about
    the *shape* of the gaps between connections, not "how many happened
    in the last N seconds", so a time window doesn't fit the signal the
    way it does for Rules 1/3/4."""

    history: "deque[float]" = field(default_factory=lambda: deque(maxlen=BEACON_HISTORY_SIZE))
    last_alert_at: Optional[float] = None


@dataclass
class _ExfilActivity:
    """Rolling window of (timestamp, payload_size) pairs for one
    (src_ip, dst_ip) pair, plus that pair's own cooldown clock."""

    seen: "deque[tuple[float, int]]" = field(default_factory=deque)
    last_alert_at: Optional[float] = None


class ThreatDetectionEngine:
    def __init__(self, max_buffer: int = DEFAULT_MAX_BUFFER) -> None:
        self._lock = Lock()
        self._buffer: deque[ThreatAlertRow] = deque(maxlen=max_buffer)
        self._seq = 0

        # Rule 1 state — keyed by source IP.
        self._activity: dict[str, _SourceActivity] = {}

        # Rule 2 state — keyed by the contested IP.
        self._bindings: dict[str, _ArpBinding] = {}
        self._pending: dict[str, _PendingConflict] = {}
        self._arp_last_alert_at: dict[str, float] = {}

        # Rule 3 state — keyed by source IP.
        self._dns_activity: dict[str, _DnsTunnelActivity] = {}

        # Rule 4 state — keyed by source IP.
        self._syn_activity: dict[str, _SynFloodActivity] = {}

        # Rule 5 state — keyed by (src_ip, dst_ip, dst_port).
        self._beacon_activity: dict[tuple[str, str, int], _BeaconActivity] = {}

        # Rule 6 state — keyed by (src_ip, dst_ip).
        self._exfil_activity: dict[tuple[str, str], _ExfilActivity] = {}

    # ------------------------------------------------------------------
    # Shared alert plumbing
    # ------------------------------------------------------------------

    def _raise_alert(
        self, severity: str, threat: str, source: str, description: str, now: float
    ) -> ThreatAlertRow:
        """Caller must already hold self._lock."""
        self._seq += 1
        row = ThreatAlertRow(
            no=self._seq,
            id=f"threat-{self._seq}",
            time=now,
            severity=severity,
            threat=threat,
            source=source,
            description=description,
        )
        self._buffer.append(row)
        return row

    # ------------------------------------------------------------------
    # Rule 1 — Port Scan Detection
    # ------------------------------------------------------------------

    def record_port_activity(
        self, src_ip: str, dst_ip: str, dst_port: int, now: Optional[float] = None
    ) -> Optional[ThreatAlertRow]:
        """Called by the capture layer for every TCP/UDP packet. Returns
        the alert if this call is the one that trips the threshold
        (subject to cooldown), else None — the overwhelmingly common
        case for normal traffic.

        `now` defaults to wall-clock time (live capture's behavior,
        unchanged). PCAP Analyzer's batch replay (see
        app/engines/pcap_insights.py) passes each packet's own historical
        timestamp instead — replaying a whole file at wall-clock speed
        would otherwise compress an entire capture's real time span into
        a few milliseconds, making every window/cooldown constant above
        meaningless for static analysis."""
        if now is None:
            now = time.time()
        with self._lock:
            activity = self._activity.setdefault(src_ip, _SourceActivity())
            activity.seen.append((now, dst_ip, dst_port))

            cutoff = now - PORT_SCAN_WINDOW_SECONDS
            while activity.seen and activity.seen[0][0] < cutoff:
                activity.seen.popleft()

            distinct_pairs = {(d_ip, d_port) for _, d_ip, d_port in activity.seen}
            if len(distinct_pairs) < PORT_SCAN_DISTINCT_THRESHOLD:
                return None

            if (
                activity.last_alert_at is not None
                and (now - activity.last_alert_at) < PORT_SCAN_COOLDOWN_SECONDS
            ):
                return None  # still in cooldown for this source

            activity.last_alert_at = now
            distinct_hosts = {d_ip for d_ip, _ in distinct_pairs}
            return self._raise_alert(
                severity="medium",
                threat="Port Scan Detected",
                source=src_ip,
                description=(
                    f"{src_ip} touched {len(distinct_pairs)} distinct host:port pairs "
                    f"across {len(distinct_hosts)} host(s) within {int(PORT_SCAN_WINDOW_SECONDS)}s."
                ),
                now=now,
            )

    # ------------------------------------------------------------------
    # Rule 2 — ARP Spoofing Detection
    # ------------------------------------------------------------------

    def record_arp_sighting(
        self, mac: str, ip: str, now: Optional[float] = None
    ) -> Optional[ThreatAlertRow]:
        """Called by the capture layer for every ARP packet observed —
        independently of HostDiscoveryEngine.record_sighting(mac, ip),
        which is also called for the same packet. See module docstring
        for why the duplication is intentional.

        `now` defaults to wall-clock time (live capture's behavior,
        unchanged) — see record_port_activity's docstring for why PCAP
        Analyzer's batch replay passes each packet's own historical
        timestamp instead."""
        if now is None:
            now = time.time()
        with self._lock:
            binding = self._bindings.get(ip)

            if binding is None:
                # First time ever seeing this IP — nothing to compare
                # against yet, so nothing to flag.
                self._bindings[ip] = _ArpBinding(mac=mac, last_seen=now)
                self._pending.pop(ip, None)
                return None

            if binding.mac == mac:
                # Consistent with what we already trust — the normal
                # case for every subsequent ARP packet for this IP. Any
                # pending conflict for a *different* MAC naturally lapses
                # since it won't be reconfirmed.
                binding.last_seen = now
                self._pending.pop(ip, None)
                return None

            # Conflict: a different MAC is claiming an IP we already
            # have a binding for.
            pending = self._pending.get(ip)
            if (
                pending is not None
                and pending.mac == mac
                and (now - pending.first_seen) <= ARP_CONFLICT_DEBOUNCE_SECONDS
            ):
                # Same conflicting MAC seen a second time within the
                # debounce window — confirmed, not a stray packet.
                old_mac = binding.mac
                self._bindings[ip] = _ArpBinding(mac=mac, last_seen=now)
                del self._pending[ip]

                last_alert = self._arp_last_alert_at.get(ip)
                if last_alert is not None and (now - last_alert) < ARP_CONFLICT_COOLDOWN_SECONDS:
                    return None  # still in cooldown for this IP

                self._arp_last_alert_at[ip] = now
                return self._raise_alert(
                    severity="high",
                    threat="Possible ARP Spoofing",
                    source=ip,
                    description=(
                        f"{ip} was claimed by {old_mac}, then by a different MAC "
                        f"({mac}) shortly after — possible ARP cache poisoning."
                    ),
                    now=now,
                )

            # Either the first sighting of this particular conflicting
            # MAC, or a previous pending conflict aged out before being
            # reconfirmed — either way, record it as pending and wait
            # for a second sighting rather than alerting on one packet.
            self._pending[ip] = _PendingConflict(mac=mac, first_seen=now)
            return None

    # ------------------------------------------------------------------
    # Rule 3 — DNS Tunneling Detection
    # ------------------------------------------------------------------

    def record_dns_activity(
        self, src_ip: str, dns_query: Optional[str], now: Optional[float] = None
    ) -> Optional[ThreatAlertRow]:
        """Called by the capture layer for every DNS packet with a
        parsed query name. Returns the alert if this call is the one
        that trips the threshold for its (source, parent domain) pair
        (subject to cooldown), else None — the overwhelmingly common
        case, since `dns_tunnel_candidate` rejects ordinary queries
        before any window/threshold bookkeeping happens.

        `now` defaults to wall-clock time (live capture's behavior,
        unchanged) — see `record_port_activity`'s docstring for why
        PCAP Analyzer's batch replay passes each packet's own
        historical timestamp instead."""
        if not dns_query:
            return None
        candidate = dns_tunnel_candidate(dns_query)
        if candidate is None:
            return None
        _, parent = candidate

        if now is None:
            now = time.time()
        with self._lock:
            activity = self._dns_activity.setdefault(src_ip, _DnsTunnelActivity())
            activity.seen.append((now, parent))

            cutoff = now - DNS_TUNNEL_WINDOW_SECONDS
            while activity.seen and activity.seen[0][0] < cutoff:
                activity.seen.popleft()

            count_for_parent = sum(1 for _, p in activity.seen if p == parent)
            if count_for_parent < DNS_TUNNEL_DISTINCT_THRESHOLD:
                return None

            last_alert = activity.last_alert_at.get(parent)
            if last_alert is not None and (now - last_alert) < DNS_TUNNEL_COOLDOWN_SECONDS:
                return None  # still in cooldown for this (source, domain) pair

            activity.last_alert_at[parent] = now
            return self._raise_alert(
                severity="medium",
                threat="Possible DNS Tunneling",
                source=src_ip,
                description=(
                    f"{src_ip} sent {count_for_parent} DNS queries with abnormally long "
                    f"subdomain labels (>= {DNS_TUNNEL_LABEL_LENGTH_THRESHOLD} chars) to "
                    f"*.{parent} within {int(DNS_TUNNEL_WINDOW_SECONDS)}s — possible "
                    f"tunneling or data exfiltration over DNS."
                ),
                now=now,
            )

    # ------------------------------------------------------------------
    # Rule 4 — SYN Flood Detection
    # ------------------------------------------------------------------

    def record_syn_activity(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        info: Optional[str],
        now: Optional[float] = None,
    ) -> Optional[ThreatAlertRow]:
        """Called by the capture layer for every TCP packet, once
        PacketParser has built its `info` string — `is_bare_syn` needs
        that text, unlike Rule 1's `record_port_activity`, so this can't
        run from the same pre-parse block the capture layer uses for
        port-scan tracking. Returns the alert if this call is the one
        that trips the threshold for its (dst_ip, dst_port) pair
        (subject to cooldown), else None — the overwhelmingly common
        case, since `is_bare_syn` rejects every non-bare-SYN TCP packet
        (the bulk of TCP traffic: ACKs, data, FINs, SYN-ACK replies)
        before any window/threshold bookkeeping happens.

        `now` defaults to wall-clock time — see `record_port_activity`'s
        docstring for why PCAP Analyzer's batch replay passes each
        packet's own historical timestamp instead."""
        if not is_bare_syn(info):
            return None
        if now is None:
            now = time.time()
        dst_key = (dst_ip, dst_port)
        with self._lock:
            activity = self._syn_activity.setdefault(src_ip, _SynFloodActivity())
            activity.seen.append((now, dst_ip, dst_port))

            cutoff = now - SYN_FLOOD_WINDOW_SECONDS
            while activity.seen and activity.seen[0][0] < cutoff:
                activity.seen.popleft()

            count_for_dst = sum(
                1 for _, d_ip, d_port in activity.seen if (d_ip, d_port) == dst_key
            )
            if count_for_dst < SYN_FLOOD_COUNT_THRESHOLD:
                return None

            last_alert = activity.last_alert_at.get(dst_key)
            if last_alert is not None and (now - last_alert) < SYN_FLOOD_COOLDOWN_SECONDS:
                return None  # still in cooldown for this (source, destination) pair

            activity.last_alert_at[dst_key] = now
            return self._raise_alert(
                severity="medium",
                threat="Possible SYN Flood",
                source=src_ip,
                description=(
                    f"{src_ip} sent {count_for_dst} bare TCP SYN packets to {dst_ip}:{dst_port} "
                    f"within {int(SYN_FLOOD_WINDOW_SECONDS)}s without completing the handshake — "
                    f"possible SYN flood / half-open connection exhaustion."
                ),
                now=now,
            )

    # ------------------------------------------------------------------
    # Rule 5 — Beaconing Detection
    # ------------------------------------------------------------------

    def record_beacon_activity(
        self, src_ip: str, dst_ip: str, dst_port: int, now: Optional[float] = None
    ) -> Optional[ThreatAlertRow]:
        """Called by the capture layer for every TCP/UDP packet with a
        destination port — same raw data `record_port_activity` uses,
        so it doesn't need to wait for PacketParser. Returns the alert
        if this call is the one that confirms a beaconing pattern for
        its (src_ip, dst_ip, dst_port) triple (subject to cooldown),
        else None — the overwhelmingly common case, since
        `beacon_pattern_stats` rejects everything until
        `MIN_BEACON_OBSERVATIONS` intervals have accumulated and the
        pattern is tight and slow enough to look deliberate.

        `now` defaults to wall-clock time — see `record_port_activity`'s
        docstring for why PCAP Analyzer's batch replay passes each
        packet's own historical timestamp instead."""
        if now is None:
            now = time.time()
        key = (src_ip, dst_ip, dst_port)
        with self._lock:
            activity = self._beacon_activity.setdefault(key, _BeaconActivity())
            activity.history.append(now)

            stats = beacon_pattern_stats(activity.history)
            if stats is None:
                return None
            mean, cv, count = stats

            if (
                activity.last_alert_at is not None
                and (now - activity.last_alert_at) < BEACON_COOLDOWN_SECONDS
            ):
                return None  # still in cooldown for this triple

            activity.last_alert_at = now
            return self._raise_alert(
                severity="medium",
                threat="Possible Beaconing Detected",
                source=src_ip,
                description=(
                    f"{src_ip} connected to {dst_ip}:{dst_port} at {count} consecutive "
                    f"~{mean:.1f}s intervals (coefficient of variation {cv:.2f}) — "
                    f"suspiciously regular, possible C2 beaconing."
                ),
                now=now,
            )

    # ------------------------------------------------------------------
    # Rule 6 — Data Exfiltration Detection (volume-based)
    # ------------------------------------------------------------------

    def record_data_transfer(
        self, src_ip: str, dst_ip: str, payload_size: int, now: Optional[float] = None
    ) -> Optional[ThreatAlertRow]:
        """Called by the capture layer for every parsed packet
        (protocol-agnostic — this looks only at payload volume, never
        content). Returns the alert if this call is the one that trips
        the byte-volume threshold for its (src_ip, dst_ip) pair (subject
        to cooldown), else None — the overwhelmingly common case, since
        ordinary traffic never accumulates `EXFIL_BYTE_THRESHOLD` bytes
        to one destination inside `EXFIL_WINDOW_SECONDS`.

        `now` defaults to wall-clock time — see `record_port_activity`'s
        docstring for why PCAP Analyzer's batch replay passes each
        packet's own historical timestamp instead."""
        if now is None:
            now = time.time()
        key = (src_ip, dst_ip)
        with self._lock:
            activity = self._exfil_activity.setdefault(key, _ExfilActivity())
            activity.seen.append((now, payload_size))

            cutoff = now - EXFIL_WINDOW_SECONDS
            while activity.seen and activity.seen[0][0] < cutoff:
                activity.seen.popleft()

            total_bytes = sum(b for _, b in activity.seen)
            if total_bytes < EXFIL_BYTE_THRESHOLD:
                return None

            if (
                activity.last_alert_at is not None
                and (now - activity.last_alert_at) < EXFIL_COOLDOWN_SECONDS
            ):
                return None  # still in cooldown for this (source, destination) pair

            activity.last_alert_at = now
            return self._raise_alert(
                severity="medium",
                threat="Possible Data Exfiltration",
                source=src_ip,
                description=(
                    f"{src_ip} sent {total_bytes:,} bytes of payload data to {dst_ip} "
                    f"within {int(EXFIL_WINDOW_SECONDS)}s — possible bulk data exfiltration."
                ),
                now=now,
            )

    # ------------------------------------------------------------------
    # Delta feed — mirrors PacketStreamEngine exactly, see its docstring
    # in app.engines.packet_stream for the full reasoning.
    # ------------------------------------------------------------------

    def since(self, last_no: int, limit: int = 200) -> list[ThreatAlertRow]:
        """Every buffered alert with `no` greater than `last_no`, oldest
        first, capped at `limit`."""
        with self._lock:
            rows = [r for r in self._buffer if r.no > last_no]
        return rows[-limit:] if len(rows) > limit else rows

    def backlog(self, limit: int = 50) -> list[ThreatAlertRow]:
        """Most recently buffered alerts, oldest first — used to
        populate a newly connected client immediately."""
        with self._lock:
            rows = list(self._buffer)
        return rows[-limit:]

    @property
    def latest_seq(self) -> int:
        with self._lock:
            return self._seq

    @property
    def alert_count(self) -> int:
        """Feeds `threat_alert_count` in stats:update — total alerts
        raised this session (cumulative, not windowed), same convention
        StatisticsEngine already uses for dropped_packets/protocol
        counts. See docs/contracts/threats.md."""
        with self._lock:
            return self._seq
