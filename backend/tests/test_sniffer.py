"""
Unit tests for app.capture.sniffer's pure-Python packet classification
helpers. Feeds synthetic Scapy packets built in-memory (no live capture,
no root privileges, no actual network I/O) — same pattern as
test_packet_parser.py.
"""

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from app.capture.active_scan import ActiveScanner
from app.capture.hostname_resolver import HostnameResolver
from app.capture.process_resolution import ProcessResolver
from app.capture.sniffer import (
    PacketCapture,
    _classify_direction,
    _dhcp_client_ip,
    _dhcp_hostname_and_mac,
    _dst_port,
)
from app.engines.host_discovery import HostDiscoveryEngine
from app.engines.packet_stream import PacketStreamEngine
from app.engines.statistics import StatisticsEngine
from app.engines.threat_detection import ThreatDetectionEngine
from app.engines.top_applications import TopApplicationsEngine
from app.engines.top_talkers import TopTalkersEngine


def _new_capture() -> PacketCapture:
    """A PacketCapture wired to real (but cheap, I/O-free) engines —
    same construction as app.state, just not the process-wide singleton.
    Never calls .start(), so no root privileges or actual AsyncSniffer
    thread is involved, and neither HostnameResolver's worker threads
    nor ActiveScanner's sweep thread ever spin up either — tests drive
    _on_packet() and the heartbeat/thread-health properties directly
    instead."""
    host_engine = HostDiscoveryEngine()
    hostname_resolver = HostnameResolver(host_engine)
    return PacketCapture(
        StatisticsEngine(),
        host_engine,
        PacketStreamEngine(),
        TopTalkersEngine(),
        ThreatDetectionEngine(),
        TopApplicationsEngine(),
        ProcessResolver(),
        hostname_resolver,
        ActiveScanner(host_engine, on_sighting=hostname_resolver.request),
    )


def _ip_packet(src: str, dst: str):
    return IP(src=src, dst=dst) / TCP(sport=51000, dport=443)


def test_source_match_is_upload():
    pkt = _ip_packet(src="192.168.1.42", dst="93.184.216.34")
    assert _classify_direction(pkt, local_ips={"192.168.1.42"}) == "upload"


def test_destination_match_is_download():
    pkt = _ip_packet(src="93.184.216.34", dst="192.168.1.42")
    assert _classify_direction(pkt, local_ips={"192.168.1.42"}) == "download"


def test_neither_match_is_excluded_not_guessed():
    # Two other LAN devices talking to each other, seen in promiscuous
    # mode — must not be silently attributed to either direction.
    pkt = _ip_packet(src="192.168.1.50", dst="192.168.1.51")
    assert _classify_direction(pkt, local_ips={"192.168.1.42"}) is None


def test_both_match_counts_as_upload_not_both():
    # Loopback traffic — arbitrary but documented tie-break.
    pkt = _ip_packet(src="127.0.0.1", dst="127.0.0.1")
    assert _classify_direction(pkt, local_ips={"127.0.0.1"}) == "upload"


def test_empty_local_ips_is_the_documented_fallback():
    # Resolution failed entirely at capture start — every packet must
    # fall through to None rather than raising or guessing.
    pkt = _ip_packet(src="192.168.1.42", dst="93.184.216.34")
    assert _classify_direction(pkt, local_ips=set()) is None


def test_non_ip_packet_is_excluded():
    arp = ARP(psrc="192.168.1.42", pdst="192.168.1.1")
    assert _classify_direction(arp, local_ips={"192.168.1.42"}) is None


def test_udp_packet_classified_same_as_tcp():
    pkt = IP(src="192.168.1.42", dst="8.8.8.8") / UDP(sport=51000, dport=53)
    assert _classify_direction(pkt, local_ips={"192.168.1.42"}) == "upload"


def test_dst_port_extracted_for_tcp():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000, dport=443)
    assert _dst_port(pkt) == 443


def test_dst_port_extracted_for_udp():
    pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=51000, dport=53)
    assert _dst_port(pkt) == 53


def test_dst_port_is_none_for_non_tcp_udp():
    pkt = ARP(psrc="192.168.1.42", pdst="192.168.1.1")
    assert _dst_port(pkt) is None


def test_is_running_false_before_start():
    # No .start() ever called — self._sniffer is still None.
    capture = _new_capture()
    assert capture.is_running is False


def test_last_packet_at_none_before_any_packet():
    capture = _new_capture()
    assert capture.last_packet_at is None


def test_last_packet_at_updates_on_each_packet():
    capture = _new_capture()
    pkt = _ip_packet(src="192.168.1.42", dst="93.184.216.34")

    capture._on_packet(pkt)
    first = capture.last_packet_at
    assert first is not None

    capture._on_packet(pkt)
    second = capture.last_packet_at
    assert second is not None
    assert second >= first


def test_is_running_reflects_dead_thread_not_just_sniffer_presence():
    # Regression test for the bug this module fixes: is_running used to
    # only check `self._sniffer is not None`, which stays true even
    # after the underlying AsyncSniffer thread has died (NIC sleep/wake,
    # an interface dropping, etc.). A fake sniffer standing in for a
    # dead thread must make is_running report False.
    capture = _new_capture()

    class _DeadThread:
        @staticmethod
        def is_alive():
            return False

    class _FakeDeadSniffer:
        thread = _DeadThread()
        exception = RuntimeError("interface went away")

    capture._sniffer = _FakeDeadSniffer()  # type: ignore[assignment]
    assert capture.is_running is False
    assert capture.sniffer_exception == "interface went away"


def test_is_running_true_for_alive_thread():
    capture = _new_capture()

    class _AliveThread:
        @staticmethod
        def is_alive():
            return True

    class _FakeAliveSniffer:
        thread = _AliveThread()
        exception = None

    capture._sniffer = _FakeAliveSniffer()  # type: ignore[assignment]
    assert capture.is_running is True
    assert capture.sniffer_exception is None


def test_ever_started_false_before_start():
    capture = _new_capture()
    assert capture.ever_started is False


def test_stop_on_dead_thread_does_not_raise():
    # Regression test: Scapy's AsyncSniffer.stop() raises Scapy_Exception
    # rather than no-op'ing when the thread already exited on its own
    # (`.running` is False) — PacketCapture.stop() must absorb that so
    # restart() can rely on stop() always succeeding.
    capture = _new_capture()

    class _DeadThread:
        @staticmethod
        def is_alive():
            return False

    class _FakeDeadSniffer:
        thread = _DeadThread()
        exception = None
        running = False

        @staticmethod
        def stop():
            raise RuntimeError("Not running ! (check .running attr)")

    capture._sniffer = _FakeDeadSniffer()  # type: ignore[assignment]
    capture.stop()  # must not raise
    assert capture._sniffer is None


def test_restart_clears_dead_sniffer_reference_before_starting():
    # Regression test: start() no-ops if self._sniffer is already set,
    # and a dead thread still leaves that reference set — so restart()
    # must call stop() first, or it would silently do nothing.
    capture = _new_capture()

    class _DeadThread:
        @staticmethod
        def is_alive():
            return False

    class _FakeDeadSniffer:
        thread = _DeadThread()
        exception = None
        running = False

        @staticmethod
        def stop():
            raise RuntimeError("Not running ! (check .running attr)")

    capture._sniffer = _FakeDeadSniffer()  # type: ignore[assignment]
    assert capture.is_running is False

    # Real start() would try to open a raw socket (needs root); swap it
    # for a no-op stand-in that just proves restart() reached start()'s
    # body — i.e. that stop() actually cleared _sniffer first.
    started = {"called": False}

    def _fake_start(interface=None):
        started["called"] = True

    capture.start = _fake_start  # type: ignore[assignment]
    capture.restart()
    assert started["called"] is True


def _dhcp_request(hostname: bytes | None = b"Johns-iPhone", requested_addr: str | None = "192.168.1.77", ciaddr: str = "0.0.0.0", mac: str = "aa:bb:cc:dd:ee:ff"):
    options = [("message-type", "request")]
    if hostname is not None:
        options.append(("hostname", hostname))
    if requested_addr is not None:
        options.append(("requested_addr", requested_addr))
    options.append("end")
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), ciaddr=ciaddr)
        / DHCP(options=options)
    )


def test_dhcp_hostname_and_mac_extracts_option_12():
    pkt = _dhcp_request()
    result = _dhcp_hostname_and_mac(pkt)
    assert result == ("aa:bb:cc:dd:ee:ff", "Johns-iPhone")


def test_dhcp_hostname_and_mac_none_without_hostname_option():
    pkt = _dhcp_request(hostname=None)
    assert _dhcp_hostname_and_mac(pkt) is None


def test_dhcp_hostname_and_mac_none_for_non_dhcp_packet():
    pkt = IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=1234, dport=53)
    assert _dhcp_hostname_and_mac(pkt) is None


def test_dhcp_client_ip_prefers_requested_addr_when_ciaddr_unset():
    pkt = _dhcp_request(requested_addr="192.168.1.77", ciaddr="0.0.0.0")
    assert _dhcp_client_ip(pkt) == "192.168.1.77"


def test_dhcp_client_ip_prefers_ciaddr_on_renewal():
    pkt = _dhcp_request(requested_addr="192.168.1.77", ciaddr="192.168.1.99")
    assert _dhcp_client_ip(pkt) == "192.168.1.99"


def test_dhcp_client_ip_none_when_neither_present():
    pkt = _dhcp_request(requested_addr=None, ciaddr="0.0.0.0")
    assert _dhcp_client_ip(pkt) is None


def test_on_packet_attaches_dhcp_hostname_to_new_host():
    capture = _new_capture()
    pkt = _dhcp_request(hostname=b"Kitchen-Chromecast", requested_addr="192.168.1.50")
    capture._on_packet(pkt)

    snap = capture._host_engine.snapshot()
    assert len(snap) == 1
    assert snap[0].mac == "aa:bb:cc:dd:ee:ff"
    assert snap[0].ip == "192.168.1.50"
    assert snap[0].hostname == "Kitchen-Chromecast"


def test_on_packet_dhcp_hostname_pending_until_arp_sighting():
    # No requested_addr/ciaddr on this packet — no IP to create a host
    # record from yet, so the name must be held as a pending hint.
    capture = _new_capture()
    pkt = _dhcp_request(hostname=b"Bedroom-Speaker", requested_addr=None, ciaddr="0.0.0.0")
    capture._on_packet(pkt)
    assert capture._host_engine.snapshot() == []

    arp = ARP(hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.63")
    capture._on_packet(arp)

    snap = capture._host_engine.snapshot()
    assert len(snap) == 1
    assert snap[0].hostname == "Bedroom-Speaker"


def test_dhcp_hostname_and_mac_none_when_ether_missing_and_chaddr_zeroed():
    """Regression test: a DHCP packet with no Ethernet layer captured
    and an all-zero BOOTP chaddr must not be reported as belonging to
    "00:00:00:00:00:00" — that's not a real client identity and would
    create a phantom duplicate host entry (see the fix's changelog:
    a live capture hit exactly this, splitting one real machine into
    two rows sharing the same IP)."""
    pkt = (
        IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=b"\x00\x00\x00\x00\x00\x00", ciaddr="0.0.0.0")
        / DHCP(options=[("message-type", "request"), ("hostname", b"DESKTOP-P1PC1OA"), "end"])
    )
    assert _dhcp_hostname_and_mac(pkt) is None


def test_on_packet_dhcp_with_zeroed_chaddr_does_not_create_phantom_host():
    """End-to-end version of the regression above, through _on_packet:
    the real machine is already known under its real MAC; a DHCP
    packet lacking Ether framing with a zeroed chaddr must be dropped
    silently rather than spawning a second row for the same IP."""
    capture = _new_capture()
    capture._host_engine.record_sighting(mac="48:a4:72:64:ab:b3", ip="192.168.0.103")

    pkt = (
        IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=b"\x00\x00\x00\x00\x00\x00", ciaddr="192.168.0.103")
        / DHCP(options=[("message-type", "request"), ("hostname", b"DESKTOP-P1PC1OA"), "end"])
    )
    capture._on_packet(pkt)

    snap = capture._host_engine.snapshot()
    assert len(snap) == 1
    assert snap[0].mac == "48:a4:72:64:ab:b3"
