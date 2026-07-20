"""
Active Host Discovery — periodic ARP sweep of the local subnet.

Replaces the passive-only tradeoff docs/contracts/hosts.md used to
describe: passive ARP sniffing only learns about a device once it
happens to send or receive an ARP packet, which can miss devices with
long-lived, low-churn connections. An active sweep instead asks every
address on the subnet directly ("who has 192.168.1.7?") and records
whoever answers, so the host table reflects a real inventory instead of
whatever incidental ARP traffic happened to cross the wire.

Each sweep round does two passes, not one:

1. **Broadcast discovery** — one ARP request sent to the whole subnet
   (`ff:ff:ff:ff:ff:ff`), to find hosts we don't know about yet.
2. **Unicast re-probe** — an individual ARP request addressed directly
   to each host we already know about, at its last-known MAC. Broadcast
   frames get no MAC-layer retry on WiFi (802.11 doesn't ACK/retransmit
   broadcast or multicast), and devices in power-save mode only wake for
   buffered broadcast traffic at fixed DTIM intervals — so it's common
   for a real, reachable device to simply miss a broadcast probe through
   no fault of its own. A unicast frame to a MAC we already know does
   get real ACK+retry, so re-confirming already-known hosts this way is
   far more reliable than depending on the broadcast round alone. See
   docs/contracts/hosts.md and app.engines.host_discovery for how the
   result of this pass feeds the online/offline decision (a
   consecutive-miss counter, not a raw timer).

Runs as its own background thread — ARP sweeps are blocking I/O
(Scapy's `srp()` waits up to SCAN_REPLY_TIMEOUT_SECONDS for replies) —
independent of the AsyncSniffer capture thread and its watchdog. Same
downstream engine, same `hosts:update` payload: this module only ever
calls `HostDiscoveryEngine.record_sighting()` and, once per completed
round, `end_sweep_cycle()` — nothing downstream (WS broadcast, frontend
table) needed to change to support any of this.

Requires the same elevated/root privileges as the sniffer itself (raw
ARP packets), and, like passive discovery, only covers the local
broadcast domain — devices behind a different subnet/VLAN won't answer.

Every sweep is aimed at the Wireless LAN adapter specifically: it
re-resolves that adapter's own default gateway (`find_wifi_gateway()`
— the same value `ipconfig` shows under "Wireless LAN adapter Wi-Fi:"
-> "Default Gateway", e.g. 192.168.0.1) and ARPs that gateway's subnet,
rather than an arbitrary local IP that might belong to a different
adapter (Ethernet, VPN, etc.) on a multi-NIC machine. Falls back to
whatever interface/local IP `start()` was given if no wireless default
route can be found.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from typing import Callable

import psutil
from scapy.all import ARP, Ether, conf, srp
from scapy.interfaces import resolve_iface

from app.engines.host_discovery import HostDiscoveryEngine

SCAN_INTERVAL_SECONDS = 30.0
SCAN_REPLY_TIMEOUT_SECONDS = 2.0

# Skip absurdly large subnets (e.g. a misconfigured /8) so one sweep
# can't balloon into hundreds of thousands of ARP requests and stall
# the thread for ages. A /16 (65k hosts) is already far more generous
# than any real "local network" segment; anything bigger almost
# certainly isn't the LAN this machine is actually on.
MAX_SWEEP_HOSTS = 65534

# Substrings matched (case-insensitively) against an interface's
# description/name to identify it as a Wireless LAN adapter — covers
# Windows' "Wireless LAN adapter Wi-Fi" naming as well as the more
# generic "wireless"/"wlan" terms other platforms use.
_WIFI_NAME_HINTS = ("wi-fi", "wifi", "wireless", "wlan")


def find_wifi_gateway() -> tuple[str, str, str] | None:
    """Find the Wireless LAN adapter's own default gateway — the same
    value `ipconfig` prints under "Wireless LAN adapter Wi-Fi:" ->
    "Default Gateway" on Windows (e.g. 192.168.0.1).

    Reads Scapy's routing table (already resolved at import time from
    the OS — no new dependency) looking for the default-route entry
    (0.0.0.0/0) whose interface resolves to a Wi-Fi/wireless adapter,
    so the sweep always targets the WiFi subnet specifically rather
    than whichever adapter happened to be picked out of every local IP
    this machine has (Ethernet, VPN, etc. included).

    Returns (gateway_ip, local_ip_on_that_iface, iface_name), or None
    if no wireless default route can be found (e.g. WiFi is off, or
    the platform names its wireless interface in a way none of
    `_WIFI_NAME_HINTS` catches) — callers should fall back to the
    previous "any local IP" behaviour in that case.
    """
    best: tuple[str, str, str, int] | None = None
    for net, msk, gw, iface, addr, metric in conf.route.routes:
        if net != 0 or msk != 0:
            continue  # only interested in default-route entries
        if not gw or gw == "0.0.0.0":
            continue  # route with no real next-hop gateway
        try:
            resolved = resolve_iface(iface)
            label = f"{resolved.description or ''} {resolved.name or ''}".lower()
        except Exception:
            continue
        if not any(hint in label for hint in _WIFI_NAME_HINTS):
            continue
        if best is None or metric < best[3]:
            best = (gw, addr, resolved.name, metric)

    if best is None:
        return None
    gw, addr, iface_name, _metric = best
    return gw, addr, iface_name


def _subnet_for(local_ip: str) -> ipaddress.IPv4Network | None:
    """Find the CIDR network `local_ip` sits on, using its OS-reported
    netmask via psutil — already a hard dependency (see
    requirements.txt), so this needs no new library just for one
    lookup. Returns None if `local_ip` isn't found on any interface or
    has no usable netmask (e.g. resolution ran before the interface was
    fully up)."""
    try:
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family != 2:  # socket.AF_INET, avoided importing socket for one constant
                    continue
                if addr.address != local_ip or not addr.netmask:
                    continue
                iface = ipaddress.IPv4Interface(f"{addr.address}/{addr.netmask}")
                return iface.network
    except Exception:
        pass
    return None


class ActiveScanner:
    """One instance for the process's lifetime, mirroring PacketCapture's
    own start()/stop() shape. Deliberately owns its own thread rather
    than piggybacking on the sniffer's — ARP sweeps and passive capture
    are independent concerns that shouldn't be able to stall each other
    (a slow sweep must never delay packet processing, and vice versa)."""

    def __init__(
        self,
        host_engine: HostDiscoveryEngine,
        on_sighting: Callable[[str, str], None] | None = None,
    ) -> None:
        self._host_engine = host_engine
        # Called for every answered probe, in addition to recording it
        # in host_engine — used to also feed HostnameResolver without
        # this module needing to know that resolver exists.
        self._on_sighting = on_sighting
        self._thread: threading.Thread | None = None
        self._running = False
        self._interface: str | None = None
        self._local_ip: str | None = None
        self._last_sweep_at: float | None = None
        self._last_sweep_error: str | None = None
        self._last_gateway: str | None = None

    def start(self, interface: str | None, local_ip: str | None) -> None:
        if self._thread is not None:
            return  # already running
        self._interface = interface
        self._local_ip = local_ip
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._thread = None

    def _loop(self) -> None:
        while self._running:
            try:
                self._sweep_once()
            except Exception as exc:
                # A single bad sweep (interface hiccup, transient
                # permission issue) must not kill the loop — same
                # tolerance PacketCapture._on_packet gives individual
                # malformed packets.
                self._last_sweep_error = str(exc)

            # Sleep in 1s increments rather than one long sleep so
            # stop() takes effect within ~1s instead of waiting out a
            # full SCAN_INTERVAL_SECONDS.
            for _ in range(int(SCAN_INTERVAL_SECONDS)):
                if not self._running:
                    return
                time.sleep(1)

    def _sweep_once(self) -> None:
        # Re-resolve the Wireless LAN adapter's default gateway on every
        # sweep (not just once at start()) so the scan keeps tracking
        # the WiFi adapter even if it reconnects with a new DHCP lease
        # mid-session. This is the ipconfig "Wireless LAN adapter
        # Wi-Fi: ... Default Gateway" value — falling back to whatever
        # interface/local_ip start() was given only if no wireless
        # default route can be found on this machine.
        wifi = find_wifi_gateway()
        if wifi is not None:
            gateway_ip, local_ip, iface_name = wifi
            interface = iface_name
        else:
            gateway_ip, local_ip, interface = None, self._local_ip, self._interface

        if not local_ip:
            self._last_sweep_error = "no local IP resolved yet — nothing to scan from"
            return

        network = _subnet_for(local_ip)
        if network is None and gateway_ip:
            # No netmask on record (e.g. psutil hasn't caught up with a
            # fresh DHCP lease yet) — fall back to the conventional /24
            # around the gateway rather than giving up the sweep
            # entirely, since a /24 covers the overwhelming majority of
            # home/office WiFi networks (like 192.168.0.0/24 here).
            network = ipaddress.IPv4Network(f"{gateway_ip}/24", strict=False)
        if network is None:
            self._last_sweep_error = "could not determine a scannable local subnet"
            return
        if network.num_addresses > MAX_SWEEP_HOSTS:
            self._last_sweep_error = (
                f"subnet {network} is too large to sweep ({network.num_addresses} addresses)"
            )
            return

        targets = [str(ip) for ip in network.hosts() if str(ip) != local_ip]
        if not targets:
            return

        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)
        answered, _unanswered = srp(
            request,
            timeout=SCAN_REPLY_TIMEOUT_SECONDS,
            iface=interface,
            verbose=False,
        )
        self._last_sweep_at = time.time()
        self._last_sweep_error = None
        self._last_gateway = gateway_ip

        confirmed_macs: set[str] = set()
        for _sent, reply in answered:
            self._host_engine.record_sighting(mac=reply.hwsrc, ip=reply.psrc)
            confirmed_macs.add(reply.hwsrc)
            if self._on_sighting is not None:
                self._on_sighting(reply.hwsrc, reply.psrc)

        # Pass 2 — unicast re-probe every already-known host the
        # broadcast round above didn't just reconfirm, addressed
        # directly to its last-known MAC rather than the subnet
        # broadcast address. See module docstring for why this is far
        # more reliable on WiFi than the broadcast round alone, and
        # HostDiscoveryEngine.end_sweep_cycle() for how a missed reply
        # here actually affects online/offline status.
        known_hosts = self._host_engine.snapshot()
        to_reprobe = [h for h in known_hosts if h.mac not in confirmed_macs]
        if to_reprobe:
            unicast_requests = [Ether(dst=h.mac) / ARP(pdst=h.ip) for h in to_reprobe]
            reprobe_answered, _reprobe_unanswered = srp(
                unicast_requests,
                timeout=SCAN_REPLY_TIMEOUT_SECONDS,
                iface=interface,
                verbose=False,
            )
            for _sent, reply in reprobe_answered:
                self._host_engine.record_sighting(mac=reply.hwsrc, ip=reply.psrc)
                if self._on_sighting is not None:
                    self._on_sighting(reply.hwsrc, reply.psrc)

        # One cycle boundary per completed sweep round, regardless of
        # how many hosts either pass above reconfirmed — this is what
        # advances (or resets) every known host's consecutive-miss count.
        self._host_engine.end_sweep_cycle()

    @property
    def is_running(self) -> bool:
        return (
            self._thread is not None
            and self._thread.is_alive()
        )

    @property
    def last_sweep_at(self) -> float | None:
        """Unix timestamp of the most recently completed sweep, or None
        if none has completed yet this session."""
        return self._last_sweep_at

    @property
    def last_sweep_error(self) -> str | None:
        """Set if the most recent sweep attempt failed or was skipped;
        cleared on the next successful sweep."""
        return self._last_sweep_error

    @property
    def last_gateway(self) -> str | None:
        """The Wireless LAN adapter's default gateway used for the most
        recent sweep (e.g. "192.168.0.1"), or None if no wireless
        default route was found and the sweep fell back to the
        interface/local IP passed to start()."""
        return self._last_gateway
