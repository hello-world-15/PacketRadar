"""
Capture layer.

Wraps Scapy's AsyncSniffer. Scapy objects live only here and in
`app.parser.packet_parser` (the one place we hand a raw Scapy packet to
something else, specifically to build the rich `PacketModel` used by the
Live Packet Stream). Every *engine* downstream of this module (statistics,
host discovery, packet stream, top talkers, threat detection, top
applications) receives plain Python data — ints, strs, dataclasses —
never a Scapy packet object. That's what keeps them independently
unit-testable without a live capture or root privileges.

Known limitation (documented, not hidden): requires elevated/root
privileges to open a raw socket on most platforms. Run the backend with
sudo on macOS/Linux, or as Administrator on Windows.

Two independent lifecycles live here, on purpose (Phase 5, Module 4):

  - Sniffing: the AsyncSniffer itself. Always on — started once at app
    startup (see app.main's lifespan) and left running for the process's
    lifetime, so packets/sec, bandwidth, and the live packet table are
    always populated, the same way Wireshark's capture is "just on"
    while the app is open.
  - Recording: writing sniffed packets to a .pcap file via Scapy's
    PcapWriter. Off by default. `app.api.capture` toggles this
    independently of sniffing — pressing "Record" doesn't start/stop the
    sniffer, it just starts/stops the file write.

`_on_packet` always feeds the in-memory engines; it only *also* writes to
disk while a recording session is active.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import AsyncSniffer, ARP, BOOTP, DHCP, Ether, ICMP, IP, TCP, UDP
from scapy.utils import PcapWriter

from app.cache import packet_cache
from app.capture.active_scan import ActiveScanner
from app.capture.hostname_resolver import HostnameResolver
from app.capture.local_ip import resolve_local_ips
from app.capture.process_resolution import ProcessResolver
from app.engines.host_discovery import HostDiscoveryEngine
from app.engines.packet_stream import ParsedPacket, PacketStreamEngine
from app.engines.statistics import StatisticsEngine
from app.engines.threat_detection import ThreatDetectionEngine
from app.engines.top_applications import TopApplicationsEngine
from app.engines.top_talkers import TopTalkersEngine
from app.parser.packet_parser import PacketParser

# Note: there's deliberately no producer/consumer queue here — _on_packet
# processes each captured packet synchronously and inline (stats, host
# discovery, parsing, caching, and pcap writing all happen on the
# sniffer's own thread before it returns). That means there's nothing
# for a "pending queue depth" to measure; an earlier version of this
# file had a MAX_PENDING check that could never trigger for exactly that
# reason and has been removed. Real packet loss under overload happens
# at the OS/libpcap capture buffer, which isn't reliably visible to us
# cross-platform — see StatisticsEngine's docstring. If capture ever
# needs to survive slow downstream processing (e.g. slow disk writes
# during recording) without stalling the sniffer thread, the right fix
# is a real bounded queue + separate worker thread, not a counter that
# only pretends to track one.

# backend/captures/ — one .pcap per recording session. Gitignored; not
# meant to be a permanent archive, just a handoff point for "Export PCAP".
CAPTURES_DIR = Path(__file__).resolve().parent.parent.parent / "captures"


def _primary_active_scan_ip(local_ips: set[str]) -> str | None:
    """Pick one non-loopback address from the resolved local-IP set for
    ActiveScanner to sweep the subnet from. Which one doesn't matter
    beyond "a real, routable address" — on a typical single-NIC machine
    there's only one candidate anyway, the same single-address
    assumption local_ip.py's own docstring already accepts."""
    for ip in local_ips:
        if ip not in ("127.0.0.1", "::1"):
            return ip
    return None


@dataclass
class RecordingSession:
    """Snapshot of one start_recording()/stop_recording() session, kept
    around after it ends so the export endpoint has something to serve."""

    path: Path
    interface: str | None
    started_at: datetime
    stopped_at: datetime | None
    packet_count: int


def _flow_key(pkt) -> str:
    """Build a direction-agnostic 5-tuple key so A->B and B->A packets
    are counted as the same connection."""
    if IP not in pkt:
        return f"non-ip:{pkt.summary()}"

    proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
    src, dst = pkt[IP].src, pkt[IP].dst
    sport = pkt.sport if hasattr(pkt, "sport") else 0
    dport = pkt.dport if hasattr(pkt, "dport") else 0

    # Sort endpoints so the key is identical regardless of packet direction.
    endpoints = sorted([(src, sport), (dst, dport)])
    return f"{proto}:{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}"


def _dhcp_hostname_and_mac(pkt) -> tuple[str, str] | None:
    """Extract (mac, hostname) from a DHCP packet's Option 12 (Host
    Name) — the same name a router's own DHCP client list/admin page
    shows (e.g. "Johns-iPhone", "DESKTOP-A1B2C3"). Sent by nearly every
    consumer/IoT device as part of its own DISCOVER/REQUEST so the DHCP
    server can log it, regardless of whether that device also has (or
    answers) a reverse-DNS PTR record — the gap this closes; see
    app.capture.hostname_resolver's docstring for why PTR alone misses
    so many devices. Returns None if this isn't a DHCP packet, or it's
    a server->client packet (OFFER/ACK) with no Option 12 of its own —
    only the client names itself, never the server on its behalf."""
    if DHCP not in pkt or BOOTP not in pkt:
        return None

    hostname: str | None = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "hostname":
            raw = opt[1]
            hostname = raw.decode("utf-8", "ignore") if isinstance(raw, bytes) else str(raw)
            break
    if not hostname:
        return None

    if Ether in pkt:
        mac = pkt[Ether].src
    else:
        # No Ethernet layer (unusual, but BOOTP carries the client's own
        # hardware address regardless of what layer-2 wrapped it) — a
        # zeroed chaddr means there's genuinely no client identity in
        # this packet (e.g. Scapy couldn't fully dissect an odd capture
        # frame and chaddr never got populated), so don't fabricate a
        # fake "00:00:00:00:00:00" host out of it; that's not a real
        # device and would collide with every other packet that hits
        # this same fallback, merging unrelated devices into one entry.
        chaddr = pkt[BOOTP].chaddr[:6]
        if chaddr == b"\x00\x00\x00\x00\x00\x00":
            return None
        mac = ":".join(f"{b:02x}" for b in chaddr)
    return mac, hostname


def _dhcp_client_ip(pkt) -> str | None:
    """Best-effort IP for the client that sent this DHCP packet, so a
    host record can be created immediately if this is the first
    sighting of that MAC (see HostDiscoveryEngine.record_dhcp_hostname).
    Tries BOOTP's own `ciaddr` first (set on a renewal, where the client
    already has a lease), then Option 50 "requested_addr" (set on a
    fresh REQUEST for a lease it doesn't have yet) — either is a real,
    already-picked address, never a guess. None if neither is present
    (e.g. a bare DISCOVER with no prior lease), in which case the name
    stays pending until an ARP/active-sweep sighting creates the record."""
    if BOOTP in pkt and pkt[BOOTP].ciaddr not in (None, "0.0.0.0"):
        return pkt[BOOTP].ciaddr
    if DHCP in pkt:
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "requested_addr":
                return opt[1]
    return None


def _dst_port(pkt) -> int | None:
    """Destination port for TCP/UDP packets, used by Port Scan Detection
    (see app.engines.threat_detection) — None for anything else, since
    "distinct ports touched" is only a meaningful signal for transport
    protocols that actually have a port concept."""
    if TCP in pkt:
        return pkt[TCP].dport
    if UDP in pkt:
        return pkt[UDP].dport
    return None


def _local_port(pkt, direction: str | None) -> int | None:
    """The local end's port for a TCP/UDP packet, given the direction
    `_classify_direction` already computed — "upload" means the local
    machine is the source (so its port is `sport`), "download" means
    it's the destination (`dport`). None if direction is unknown (no
    local IP matched, or this isn't a TCP/UDP packet) — matches
    `_classify_direction`'s own "excluded rather than guessed at"
    convention, since guessing which side is local here would credit
    traffic to the wrong process's app entry."""
    if direction not in ("upload", "download"):
        return None
    if TCP in pkt:
        return pkt[TCP].sport if direction == "upload" else pkt[TCP].dport
    if UDP in pkt:
        return pkt[UDP].sport if direction == "upload" else pkt[UDP].dport
    return None


def _protocol_label(pkt) -> str:
    """Classify a packet for the protocol-distribution pie. Deliberately
    separate from PacketParser's own (richer) protocol logic — this only
    needs to run on packets that already got past record_packet's
    try/except, so it stays a small, simple lookup rather than duplicating
    that engine's classification rules.

    Labels must exactly match the frontend's `Protocol` union (see
    src/types/index.ts): 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'ARP' | 'Other'.
    """
    if ARP in pkt:
        return "ARP"
    if UDP in pkt and (pkt[UDP].sport == 53 or pkt[UDP].dport == 53):
        return "DNS"
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    return "Other"


def _classify_direction(pkt, local_ips: set[str]) -> str | None:
    """Classify a packet as "upload" (outbound from this machine),
    "download" (inbound to this machine), or None (neither — excluded
    rather than guessed at) for the bandwidth split. See
    docs/contracts/stats.md's "Upload/download split" for the full
    reasoning, including the loopback tie-break below.

    `local_ips` is resolved once at capture start (see
    app.capture.local_ip) — an empty set here means resolution failed
    or hasn't run yet, so every packet falls through to None, which is
    the documented fallback (bandwidth_mbps stays correct either way;
    only the split is unavailable).
    """
    if not local_ips or IP not in pkt:
        return None

    src, dst = pkt[IP].src, pkt[IP].dst
    if src in local_ips:
        # Also covers the src == dst (loopback) case — arbitrary but
        # harmless tie-break so it doesn't count as both.
        return "upload"
    if dst in local_ips:
        return "download"
    return None


class PacketCapture:
    """One instance for the process's lifetime. `start()`/`stop()`
    control the underlying sniffer (meant to be called once, at app
    startup/shutdown); `start_recording()`/`stop_recording()` control
    pcap export and can be toggled freely while sniffing continues."""

    def __init__(
        self,
        stats_engine: StatisticsEngine,
        host_engine: HostDiscoveryEngine,
        packet_engine: PacketStreamEngine,
        talkers_engine: TopTalkersEngine,
        threat_engine: ThreatDetectionEngine,
        apps_engine: TopApplicationsEngine,
        process_resolver: ProcessResolver,
        hostname_resolver: HostnameResolver,
        active_scanner: ActiveScanner,
        interface: str | None = None,
    ):
        self._stats_engine = stats_engine
        self._host_engine = host_engine
        self._packet_engine = packet_engine
        self._talkers_engine = talkers_engine
        self._threat_engine = threat_engine
        self._apps_engine = apps_engine
        self._process_resolver = process_resolver
        self._hostname_resolver = hostname_resolver
        self._active_scanner = active_scanner
        self._interface = interface
        self._sniffer: AsyncSniffer | None = None
        self._start_error: str | None = None

        # True once start() has succeeded at least once. Distinguishes
        # "never got off the ground" (e.g. missing root — a startup
        # problem, already surfaced via start_error) from "was running,
        # then died" (a watchdog problem) — see needs_restart() in
        # app.capture.watchdog, which uses this to avoid treating a
        # sniffer that never started as something to restart.
        self._ever_started = False

        # Heartbeat: timestamp of the most recently processed packet,
        # updated on every call to _on_packet. This is what actually
        # answers "is capture still working" — a dead sniffer thread
        # (NIC sleep/wake, interface change, an internal Scapy error)
        # can leave `self._sniffer` non-None while producing nothing,
        # so `is_running` alone isn't a reliable signal. Guarded by its
        # own lock since the sniffer thread writes it and the API's
        # request thread (via last_packet_at) reads it concurrently.
        self._heartbeat_lock = threading.Lock()
        self._last_packet_at: float | None = None

        # Resolved once per start() call, not per-packet — this machine's
        # IP address(es) don't change mid-capture. Empty set means
        # resolution hasn't run yet or failed; see local_ip.py and
        # _classify_direction's docstring for the documented fallback.
        self._local_ips: set[str] = set()

        # Recording state. `_pcap_lock` guards all of it since the
        # sniffer thread (via _on_packet) and the API's request thread
        # (via start_recording()/stop_recording()) touch it concurrently.
        self._pcap_lock = threading.Lock()
        self._pcap_writer: PcapWriter | None = None
        self._recording_started_at: datetime | None = None
        self._recording_packet_count = 0
        self._last_session: RecordingSession | None = None

    def _on_packet(self, pkt) -> None:
        with self._heartbeat_lock:
            self._last_packet_at = time.time()
        try:
            length = len(pkt)
            key = _flow_key(pkt)
            protocol = _protocol_label(pkt)
            direction = _classify_direction(pkt, self._local_ips)
            self._stats_engine.record_packet(length, key, protocol, direction)

            if ARP in pkt:
                self._host_engine.record_sighting(mac=pkt[ARP].hwsrc, ip=pkt[ARP].psrc)
                # Best-effort, queued and resolved off this thread — see
                # app.capture.hostname_resolver. Fired for every passive
                # ARP sighting, same as active-sweep hits get from
                # ActiveScanner's own on_sighting callback; the resolver's
                # own per-MAC cooldown keeps this cheap.
                self._hostname_resolver.request(mac=pkt[ARP].hwsrc, ip=pkt[ARP].psrc)
                # Independent of the host_engine call above — see
                # ThreatDetectionEngine's module docstring for why this
                # engine keeps its own ARP bookkeeping rather than
                # reading host_engine's internal state.
                self._threat_engine.record_arp_sighting(mac=pkt[ARP].hwsrc, ip=pkt[ARP].psrc)

            if DHCP in pkt:
                # Router-style device names (see HostDiscoveryEngine's
                # docstring) — cheap, synchronous, no network call
                # needed since the name is already sitting in the
                # packet we just captured, unlike PTR resolution above.
                dhcp_hit = _dhcp_hostname_and_mac(pkt)
                if dhcp_hit is not None:
                    mac, hostname = dhcp_hit
                    self._host_engine.record_dhcp_hostname(mac, hostname)
                    client_ip = _dhcp_client_ip(pkt)
                    if client_ip is not None:
                        self._host_engine.record_sighting(mac=mac, ip=client_ip)

            if IP in pkt:
                self._talkers_engine.record_packet(
                    src_ip=pkt[IP].src, dst_ip=pkt[IP].dst, length=length, flow_key=key
                )
                dport = _dst_port(pkt)
                if dport is not None:
                    self._threat_engine.record_port_activity(
                        src_ip=pkt[IP].src, dst_ip=pkt[IP].dst, dst_port=dport
                    )
        except Exception:
            # A single malformed packet must never crash the capture thread.
            self._stats_engine.record_dropped(1)
            return

        # Beaconing Detection (Rule 5) needs the same raw IP/port data
        # record_port_activity above uses, so it doesn't need to wait
        # for PacketParser. Its own try/except, same reasoning as DNS
        # Tunneling/SYN Flood below — a threat-detection hiccup here
        # must not be miscounted as a capture-layer drop.
        if IP in pkt:
            try:
                beacon_dport = _dst_port(pkt)
                if beacon_dport is not None:
                    self._threat_engine.record_beacon_activity(
                        src_ip=pkt[IP].src, dst_ip=pkt[IP].dst, dst_port=beacon_dport
                    )
            except Exception:
                pass

        # Top Applications: attribute this packet to whichever local
        # process owns the local end of the connection, if any. Its own
        # try/except for the same reason packet-stream parsing and pcap
        # writing get their own blocks below — a ProcessResolver hiccup
        # is an attribution-only problem, not a capture-layer drop, and
        # must not pollute stats_engine's dropped_packets counter (which
        # is specifically queue-overflow, not "some enrichment step
        # failed" — see docs/contracts/stats.md).
        try:
            local_port = _local_port(pkt, direction)
            if local_port is not None and (TCP in pkt or UDP in pkt):
                proto = "tcp" if TCP in pkt else "udp"
                pid, name = self._process_resolver.resolve(proto, local_port)
                if pid is not None:
                    self._apps_engine.record_packet(
                        pid=pid, name=name, length=length, direction=direction, flow_key=key
                    )
        except Exception:
            pass

        # Deliberately outside the block above: a failure here is a
        # packet-stream-only problem, not a capture-layer drop, so it
        # must not double-count against stats_engine's dropped_packets
        # (which is defined as queue-overflow, not parse failures — see
        # docs/contracts/stats.md).
        model = None
        try:
            model = PacketParser.parse(pkt, interface=self._interface or "default")
            if model is None:
                return
            packet_cache.add(model)
            self._packet_engine.record(
                ParsedPacket(
                    source=model.src_ip,
                    destination=model.dst_ip,
                    protocol=model.protocol,
                    length=model.length,
                    info=model.info,
                    process=model.process_name,
                    dns_query=model.dns_query,
                    dns_answer=model.dns_answer,
                )
            )
        except Exception:
            pass

        # DNS Tunneling Detection (Rule 3) needs the query name
        # PacketParser just extracted, and SYN Flood Detection (Rule 4)
        # needs the `info` string PacketParser builds for TCP packets —
        # neither can run in the ARP/port block above. Each gets its own
        # try/except, same reasoning as every other block here — a
        # threat-detection hiccup must not be miscounted as a
        # packet-stream drop.
        if model is not None and model.dns_query:
            try:
                self._threat_engine.record_dns_activity(src_ip=model.src_ip, dns_query=model.dns_query)
            except Exception:
                pass

        if model is not None and model.protocol == "TCP" and model.dst_port is not None:
            try:
                self._threat_engine.record_syn_activity(
                    src_ip=model.src_ip,
                    dst_ip=model.dst_ip,
                    dst_port=model.dst_port,
                    info=model.info,
                )
            except Exception:
                pass

        # Data Exfiltration Detection (Rule 6) needs the payload_size
        # PacketParser computes, and applies to every protocol (not just
        # TCP), so it isn't folded into the SYN Flood block above. Own
        # try/except, same reasoning as every other post-parse
        # threat-detection call here.
        if model is not None:
            try:
                self._threat_engine.record_data_transfer(
                    src_ip=model.src_ip, dst_ip=model.dst_ip, payload_size=model.payload_size
                )
            except Exception:
                pass

        # Recording: stream the raw packet straight to disk, only while
        # a recording session is active. Deliberately its own
        # try/except for the same reason as the block above — a write
        # failure (disk full, permissions) is a recording-only problem
        # and must not get counted as a capture-layer drop.
        with self._pcap_lock:
            writer = self._pcap_writer
        if writer is not None:
            try:
                writer.write(pkt)
                with self._pcap_lock:
                    self._recording_packet_count += 1
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Sniffing lifecycle — call start() once at app boot, stop() at
    # shutdown. Not meant to be toggled per-request.
    # ------------------------------------------------------------------

    def start(self, interface: str | None = None) -> None:
        if self._sniffer is not None:
            return  # already running

        if interface is not None:
            self._interface = interface

        with self._heartbeat_lock:
            self._last_packet_at = None

        # Best-effort — resolve_local_ips() never raises, but wrap it
        # anyway so a truly unexpected failure here can't block the
        # sniffer itself from starting (the upload/download split is a
        # nice-to-have; the sniffer starting is not).
        try:
            self._local_ips = resolve_local_ips()
        except Exception:
            self._local_ips = set()

        try:
            self._sniffer = AsyncSniffer(
                iface=self._interface,
                prn=self._on_packet,
                store=False,  # never buffer full packets in memory here
            )
            self._sniffer.start()
            self._start_error = None
            self._ever_started = True
        except Exception as exc:
            self._sniffer = None
            self._start_error = str(exc)
            raise

        # Hostname resolution and the active ARP sweep are independent
        # of the sniffer thread itself (see their own module docstrings)
        # but tied to the same start()/stop() calls as a matter of
        # convenience — there's no scenario in this app where you'd want
        # one running without the other. HostnameResolver.start() is
        # idempotent; ActiveScanner needs a real local IP to know which
        # subnet to sweep, hence the _primary_active_scan_ip lookup.
        self._hostname_resolver.start()
        self._active_scanner.start(
            interface=self._interface,
            local_ip=_primary_active_scan_ip(self._local_ips),
        )

    def stop(self) -> None:
        # Stop the active sweep even if the sniffer itself was never
        # running (e.g. stop() called after a failed start()) — it's
        # independent state and shouldn't be left dangling. Hostname
        # resolution is deliberately left running: it's cheap, harmless
        # idle when its queue is empty, and restarting its worker
        # threads on every sniffer restart isn't worth the churn.
        self._active_scanner.stop()

        if self._sniffer is None:
            return
        try:
            self._sniffer.stop()
        except Exception:
            # Scapy's AsyncSniffer.stop() raises Scapy_Exception rather
            # than no-op'ing if the thread already exited on its own
            # (`.running` is False) — exactly the dead-thread case
            # is_running exists to detect. Nothing left to clean up on
            # Scapy's side in that case; fall through to clearing our
            # own reference below regardless.
            pass
        self._sniffer = None
        # Sniffing stopping also ends any in-flight recording — there's
        # nothing left to write.
        if self._pcap_writer is not None:
            self.stop_recording()

    def restart(self, interface: str | None = None) -> None:
        """Stop and start the sniffer again — used by the watchdog to
        recover from a dead or stalled thread without restarting the
        whole process. `start()` already re-resolves local IPs and
        resets the packet heartbeat on every call, so a restart gets
        both for free; nothing extra needed here for that.

        Deliberately calls stop() first rather than just start(): start()
        no-ops if `self._sniffer` is already set (see its own guard), and
        a dead thread still leaves that reference set — so skipping the
        stop() step here would make restart() silently do nothing.
        """
        self.stop()
        self.start(interface)

    @property
    def is_running(self) -> bool:
        """True only if the sniffer thread is actually alive.

        `self._sniffer is not None` used to be the whole check, but that
        just means start() succeeded at some point in the past — it says
        nothing about whether the thread behind it is still running.
        Scapy's AsyncSniffer thread can die on its own (NIC sleep/wake,
        an interface dropping, an unhandled exception inside Scapy's own
        recv loop) while leaving `self._sniffer` set, which made the old
        check lie: the API kept reporting `capturing: true` — and the
        frontend kept showing "Live backend data" — long after packets
        had stopped flowing. `AsyncSniffer.thread.is_alive()` reflects
        the real OS thread state, so it can't go stale the same way.
        """
        return (
            self._sniffer is not None
            and self._sniffer.thread is not None
            and self._sniffer.thread.is_alive()
        )

    @property
    def ever_started(self) -> bool:
        """True once start() has succeeded at least once this process
        lifetime. See the field docstring on `self._ever_started`."""
        return self._ever_started

    @property
    def last_packet_at(self) -> float | None:
        """Unix timestamp of the most recently processed packet, or
        None if capture hasn't seen one yet this session. The stronger
        signal for "is capture actually working": a thread can be alive
        (is_running True) while the OS capture buffer has quietly
        stopped delivering anything to it, which this catches and
        `is_running` alone cannot."""
        with self._heartbeat_lock:
            return self._last_packet_at

    @property
    def sniffer_exception(self) -> str | None:
        """If the sniffer thread died from an unhandled exception (as
        opposed to a clean stop() call), Scapy stashes it on the
        AsyncSniffer instance rather than raising it anywhere we'd see.
        Surfacing it here is what lets `capture_error` explain *why*
        `is_running` went False instead of just reporting that it did.
        """
        if self._sniffer is not None and self._sniffer.exception is not None:
            return str(self._sniffer.exception)
        return None

    @property
    def start_error(self) -> str | None:
        """Set if the most recent start() attempt failed (e.g. missing
        root/Administrator privileges). Cleared on a successful start()."""
        return self._start_error

    @property
    def interface(self) -> str | None:
        return self._interface

    @property
    def local_ips(self) -> set[str]:
        """This machine's own IP address(es), resolved at the most
        recent start() — empty until start() has run, or if resolution
        failed. See app.capture.local_ip."""
        return self._local_ips

    # ------------------------------------------------------------------
    # Recording lifecycle — freely toggleable while sniffing continues.
    # ------------------------------------------------------------------

    def start_recording(self) -> None:
        if not self.is_running:
            raise RuntimeError("Cannot start recording: packet capture is not active.")
        with self._pcap_lock:
            if self._pcap_writer is not None:
                return  # already recording

            CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
            started_at = datetime.now(timezone.utc)
            filename = f"capture_{started_at.strftime('%Y%m%dT%H%M%SZ')}.pcap"
            path = CAPTURES_DIR / filename

            self._pcap_writer = PcapWriter(str(path), append=False, sync=True)
            self._recording_started_at = started_at
            self._recording_packet_count = 0

    def stop_recording(self) -> None:
        with self._pcap_lock:
            writer = self._pcap_writer
            started_at = self._recording_started_at
            packet_count = self._recording_packet_count
            self._pcap_writer = None
            self._recording_started_at = None
            self._recording_packet_count = 0

        if writer is None:
            return

        path = Path(writer.filename)
        try:
            writer.close()
        except Exception:
            pass
        self._last_session = RecordingSession(
            path=path,
            interface=self._interface,
            started_at=started_at or datetime.now(timezone.utc),
            stopped_at=datetime.now(timezone.utc),
            packet_count=packet_count,
        )

    @property
    def is_recording(self) -> bool:
        with self._pcap_lock:
            return self._pcap_writer is not None

    @property
    def recording_started_at(self) -> datetime | None:
        with self._pcap_lock:
            return self._recording_started_at

    @property
    def recording_packet_count(self) -> int:
        """Packets written to disk for the *current* recording session,
        or the most recently completed one if idle."""
        with self._pcap_lock:
            if self._pcap_writer is not None:
                return self._recording_packet_count
        return self._last_session.packet_count if self._last_session else 0

    @property
    def last_session(self) -> RecordingSession | None:
        return self._last_session
