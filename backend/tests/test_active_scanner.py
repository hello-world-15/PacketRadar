"""
Unit tests for app.capture.active_scan.

`_sweep_once()` itself needs a real raw socket (via Scapy's srp()) and
isn't exercised here — same boundary test_sniffer.py already draws
around anything requiring root/live capture. What's covered instead is
the pure logic: subnet resolution from psutil's interface data, the
oversized-subnet guard, and that a sweep hit reaches HostDiscoveryEngine
and the on_sighting callback the same way a passive ARP sighting does.
"""

from __future__ import annotations

import ipaddress
from types import SimpleNamespace

from app.capture.active_scan import MAX_SWEEP_HOSTS, ActiveScanner, _subnet_for
from app.engines.host_discovery import HostDiscoveryEngine
from scapy.all import ARP, Ether


def _fake_addr(address: str, netmask: str | None, family: int = 2) -> SimpleNamespace:
    return SimpleNamespace(family=family, address=address, netmask=netmask)


def _no_wifi_gateway(monkeypatch):
    """Most tests below want deterministic "no WiFi adapter found" fallback
    behaviour rather than depending on whatever routing table the machine
    actually running the test suite happens to have."""
    monkeypatch.setattr("app.capture.active_scan.find_wifi_gateway", lambda: None)


def test_subnet_for_finds_matching_interface(monkeypatch):
    fake_if_addrs = {
        "eth0": [_fake_addr("192.168.1.42", "255.255.255.0")],
        "lo": [_fake_addr("127.0.0.1", "255.0.0.0")],
    }
    monkeypatch.setattr(
        "app.capture.active_scan.psutil.net_if_addrs", lambda: fake_if_addrs
    )
    network = _subnet_for("192.168.1.42")
    assert network == ipaddress.IPv4Network("192.168.1.0/24")


def test_subnet_for_returns_none_when_ip_not_found(monkeypatch):
    fake_if_addrs = {"eth0": [_fake_addr("192.168.1.42", "255.255.255.0")]}
    monkeypatch.setattr(
        "app.capture.active_scan.psutil.net_if_addrs", lambda: fake_if_addrs
    )
    assert _subnet_for("10.0.0.5") is None


def test_subnet_for_skips_non_inet_families(monkeypatch):
    fake_if_addrs = {
        "eth0": [_fake_addr("AA:BB:CC:00:00:01", None, family=17)],  # AF_PACKET/link layer
    }
    monkeypatch.setattr(
        "app.capture.active_scan.psutil.net_if_addrs", lambda: fake_if_addrs
    )
    assert _subnet_for("AA:BB:CC:00:00:01") is None


def test_sweep_once_skips_oversized_subnet(monkeypatch):
    _no_wifi_gateway(monkeypatch)
    host_engine = HostDiscoveryEngine()
    scanner = ActiveScanner(host_engine)
    scanner._local_ip = "10.0.0.1"

    huge_network = ipaddress.IPv4Network("10.0.0.0/8")
    assert huge_network.num_addresses > MAX_SWEEP_HOSTS
    monkeypatch.setattr(
        "app.capture.active_scan._subnet_for", lambda ip: huge_network
    )

    scanner._sweep_once()
    assert "too large to sweep" in scanner.last_sweep_error
    assert host_engine.snapshot() == []


def test_sweep_once_records_answered_hosts(monkeypatch):
    _no_wifi_gateway(monkeypatch)
    host_engine = HostDiscoveryEngine()
    sightings: list[tuple[str, str]] = []
    scanner = ActiveScanner(host_engine, on_sighting=lambda mac, ip: sightings.append((mac, ip)))
    scanner._local_ip = "192.168.1.1"

    monkeypatch.setattr(
        "app.capture.active_scan._subnet_for",
        lambda ip: ipaddress.IPv4Network("192.168.1.0/29"),  # small, fast test subnet
    )

    fake_reply = SimpleNamespace(hwsrc="AA:BB:CC:00:00:05", psrc="192.168.1.5")
    fake_answered = [(SimpleNamespace(), fake_reply)]
    monkeypatch.setattr(
        "app.capture.active_scan.srp", lambda *a, **kw: (fake_answered, [])
    )

    scanner._sweep_once()

    snap = host_engine.snapshot()
    assert len(snap) == 1
    assert snap[0].mac == "AA:BB:CC:00:00:05"
    assert snap[0].ip == "192.168.1.5"
    assert sightings == [("AA:BB:CC:00:00:05", "192.168.1.5")]
    assert scanner.last_sweep_error is None


def test_sweep_once_skips_unicast_reprobe_when_broadcast_confirmed_everyone(monkeypatch):
    """A host the broadcast round just answered shouldn't also be
    unicast re-probed the same round — nothing left to confirm."""
    _no_wifi_gateway(monkeypatch)
    host_engine = HostDiscoveryEngine()
    scanner = ActiveScanner(host_engine)
    scanner._local_ip = "192.168.1.1"

    monkeypatch.setattr(
        "app.capture.active_scan._subnet_for",
        lambda ip: ipaddress.IPv4Network("192.168.1.0/29"),
    )

    fake_reply = SimpleNamespace(hwsrc="AA:BB:CC:00:00:05", psrc="192.168.1.5")
    srp_calls: list[object] = []

    def fake_srp(request, timeout, iface, verbose):
        srp_calls.append(request)
        return [(SimpleNamespace(), fake_reply)], []

    monkeypatch.setattr("app.capture.active_scan.srp", fake_srp)

    scanner._sweep_once()

    # Only the broadcast discovery call — the lone known host (the one
    # that broadcast round just answered) needs no unicast re-probe.
    assert len(srp_calls) == 1


def test_sweep_once_unicast_reprobes_known_hosts_broadcast_missed(monkeypatch):
    """A host already known to HostDiscoveryEngine but NOT answered by
    this round's broadcast discovery should get an individual, unicast-
    addressed re-probe — the whole point being resilience against a
    single lost broadcast frame."""
    _no_wifi_gateway(monkeypatch)
    host_engine = HostDiscoveryEngine()
    # Pre-existing host the broadcast sweep below will NOT answer for.
    host_engine.record_sighting(mac="AA:BB:CC:00:00:09", ip="192.168.1.9")

    scanner = ActiveScanner(host_engine)
    scanner._local_ip = "192.168.1.1"

    monkeypatch.setattr(
        "app.capture.active_scan._subnet_for",
        lambda ip: ipaddress.IPv4Network("192.168.1.0/29"),
    )

    reprobe_reply = SimpleNamespace(hwsrc="AA:BB:CC:00:00:09", psrc="192.168.1.9")
    calls: list[object] = []

    def fake_srp(request, timeout, iface, verbose):
        calls.append(request)
        if len(calls) == 1:
            return [], []  # broadcast round: nobody answers
        return [(SimpleNamespace(), reprobe_reply)], []  # unicast re-probe: this host answers

    monkeypatch.setattr("app.capture.active_scan.srp", fake_srp)

    scanner._sweep_once()

    assert len(calls) == 2  # broadcast pass, then the unicast re-probe pass
    unicast_request = calls[1]
    # A real Ether/ARP stack would carry the known MAC as its Ether dst
    # and the known IP as the ARP pdst — verify against a plain list
    # rather than requiring Scapy internals here.
    assert isinstance(unicast_request, list)
    assert len(unicast_request) == 1
    assert unicast_request[0][Ether].dst == "AA:BB:CC:00:00:09"
    assert unicast_request[0][ARP].pdst == "192.168.1.9"


def test_sweep_once_calls_end_sweep_cycle(monkeypatch):
    """Every completed sweep round must advance the engine's cycle
    boundary exactly once, regardless of how many hosts either pass
    reconfirmed — this is what online/offline status is now driven by."""
    _no_wifi_gateway(monkeypatch)
    host_engine = HostDiscoveryEngine()
    scanner = ActiveScanner(host_engine)
    scanner._local_ip = "192.168.1.1"

    monkeypatch.setattr(
        "app.capture.active_scan._subnet_for",
        lambda ip: ipaddress.IPv4Network("192.168.1.0/29"),
    )
    monkeypatch.setattr("app.capture.active_scan.srp", lambda *a, **kw: ([], []))

    calls = {"count": 0}
    original = host_engine.end_sweep_cycle

    def counting_end_sweep_cycle():
        calls["count"] += 1
        original()

    monkeypatch.setattr(host_engine, "end_sweep_cycle", counting_end_sweep_cycle)

    scanner._sweep_once()

    assert calls["count"] == 1


def test_find_wifi_gateway_matches_wireless_adapter_name(monkeypatch):
    from app.capture import active_scan

    # (net, msk, gw, iface, addr, metric) — mirrors Scapy's Route.routes
    # shape. A non-default route and a default route on a wired adapter
    # are both present to prove they're correctly skipped in favour of
    # the wireless one.
    fake_routes = [
        (0x0A000000, 0xFFFFFF00, "10.0.0.1", "eth-iface", "10.0.0.5", 25),
        (0, 0, "192.168.0.1", "wifi-iface", "192.168.0.42", 35),
        (0, 0, "10.0.0.1", "eth-iface", "10.0.0.5", 25),
    ]
    monkeypatch.setattr(active_scan.conf.route, "routes", fake_routes)

    def fake_resolve_iface(iface):
        if iface == "wifi-iface":
            return SimpleNamespace(description="Wireless LAN adapter Wi-Fi", name="Wi-Fi")
        return SimpleNamespace(description="Ethernet adapter Ethernet", name="Ethernet")

    monkeypatch.setattr(active_scan, "resolve_iface", fake_resolve_iface)

    result = active_scan.find_wifi_gateway()
    assert result == ("192.168.0.1", "192.168.0.42", "Wi-Fi")


def test_find_wifi_gateway_returns_none_without_wireless_route(monkeypatch):
    from app.capture import active_scan

    fake_routes = [(0, 0, "10.0.0.1", "eth-iface", "10.0.0.5", 25)]
    monkeypatch.setattr(active_scan.conf.route, "routes", fake_routes)
    monkeypatch.setattr(
        active_scan,
        "resolve_iface",
        lambda iface: SimpleNamespace(description="Ethernet adapter Ethernet", name="Ethernet"),
    )

    assert active_scan.find_wifi_gateway() is None


def test_sweep_once_prefers_wifi_gateway_subnet(monkeypatch):
    """When a WiFi default gateway is found, the sweep should target
    that adapter's subnet (falling back to a /24 around the gateway if
    no netmask is on record yet) rather than whatever local_ip start()
    was given."""
    host_engine = HostDiscoveryEngine()
    scanner = ActiveScanner(host_engine)
    scanner._local_ip = "10.0.0.1"  # deliberately a different subnet

    monkeypatch.setattr(
        "app.capture.active_scan.find_wifi_gateway",
        lambda: ("192.168.0.1", "192.168.0.42", "Wi-Fi"),
    )
    monkeypatch.setattr("app.capture.active_scan._subnet_for", lambda ip: None)

    seen_ifaces: list[str | None] = []

    def fake_srp(request, timeout, iface, verbose):
        seen_ifaces.append(iface)
        return [], []

    monkeypatch.setattr("app.capture.active_scan.srp", fake_srp)

    scanner._sweep_once()

    assert seen_ifaces == ["Wi-Fi"]
    assert scanner.last_gateway == "192.168.0.1"
    assert scanner.last_sweep_error is None
