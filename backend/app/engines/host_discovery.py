"""
Host Discovery Engine.

Owns a table of MAC -> last-known-IP + timing, built from ARP sightings
fed in by the capture layer — both the ones it observes incidentally
(passive sniffing) and the ones it gets by directly asking every address
on the subnet (active sweep, see app.capture.active_scan). Either source
calls the same `record_sighting()` entrypoint below, so this engine
doesn't need to know or care which one produced a given sighting. Like
StatisticsEngine, this class knows nothing about Scapy — it only ever
sees plain (mac, ip) strings, so it's independently unit-testable.

Hostnames come from two independent sources, both best-effort and
non-blocking from this engine's point of view: DHCP Option 12 (see
`record_dhcp_hostname` — the same name a router's own DHCP client list
shows) and reverse-DNS PTR lookups (see `update_hostname`, resolved by
app.capture.hostname_resolver). DHCP takes priority when both are
available — see `update_hostname`'s docstring.

See docs/contracts/hosts.md for the online/offline logic's full rationale
and for the active-vs-passive discussion.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock

from app.schemas.hosts import DiscoveredHost

# A host flips to "offline" only after this many CONSECUTIVE completed
# sweep cycles pass with no confirmation of it by any means — neither a
# passive sighting, nor the sweep's broadcast discovery round, nor (this
# is the important one) its own individual, unicast-addressed re-probe
# (see ActiveScanner._sweep_once). Unicast ARP gets real 802.11 MAC-layer
# ACK+retry, unlike the broadcast frames used to discover brand-new
# hosts, so a missed unicast reply is a much stronger signal than a
# missed broadcast reply — but WiFi is still WiFi (retries can still all
# fail, and power-save devices can still be asleep through an entire
# cycle), so we wait for 2 in a row rather than believing the first one.
# This replaces what used to be a pure last_seen-age cutoff, which had
# no way to distinguish "one unlucky lost packet" from "genuinely gone"
# — see end_sweep_cycle() below for how misses actually gets tracked.
OFFLINE_AFTER_MISSES = 2

# Backstop for when nothing is actively re-confirming hosts at all —
# ActiveScanner disabled, missing the elevated privileges raw ARP needs,
# or no WiFi default route found on this machine — in which case
# end_sweep_cycle() (see below) is never called and `misses` would
# otherwise sit at 0 forever. Without this, a host seen exactly once in
# pure-passive mode would read "online" indefinitely. 5 minutes is
# deliberately generous: passive-only mode has no way to distinguish "a
# device that's idle/asleep and just hasn't sent an incidental ARP
# packet in a while" from "a device that actually left", so this errs
# toward not flapping a real device offline — closing that ambiguity
# faster is exactly what the active sweep (and OFFLINE_AFTER_MISSES
# above) exists to do when it's available.
PASSIVE_ONLY_TTL_SECONDS = 300.0

# Placeholder values that show up on the wire sometimes (a malformed or
# partially-dissected packet, a not-yet-configured virtual adapter, etc.)
# but are never a real device's identity. Guarded here — not just at the
# capture layer — so this table can never end up with a phantom entry
# regardless of which code path a bad MAC slips in through.
_INVALID_MACS = frozenset({"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"})


def _is_valid_mac(mac: str) -> bool:
    return bool(mac) and mac.lower() not in _INVALID_MACS


@dataclass
class HostRecord:
    ip: str
    mac: str
    first_seen: float
    last_seen: float
    hostname: str | None = None
    # Consecutive completed sweep cycles (see end_sweep_cycle()) with no
    # confirmation of this host by any means. Reset to 0 by every
    # record_sighting() call, regardless of source.
    misses: int = 0
    # Internal bookkeeping only — the last_seen value observed at the
    # previous end_sweep_cycle() boundary, used to tell whether this
    # host was reconfirmed at all during the cycle that just ended.
    # Not exposed outside this module.
    _last_seen_at_cycle_start: float = field(default=0.0, repr=False)


class HostDiscoveryEngine:
    def __init__(self) -> None:
        self._lock = Lock()
        self._hosts: dict[str, HostRecord] = {}  # keyed by MAC address
        # Hostnames learned from a DHCP packet (see record_dhcp_hostname)
        # before we've recorded any ARP/active-sweep sighting for that
        # MAC yet — DISCOVER/REQUEST broadcasts routinely arrive before
        # a device's first ARP. Applied the moment record_sighting()
        # creates the host record; cleared once applied.
        self._pending_hostnames: dict[str, str] = {}

    def record_sighting(self, mac: str, ip: str) -> None:
        """Called by the capture layer for every ARP sighting — passive
        (observed in traffic), or active (an answered broadcast-discovery
        probe or a targeted unicast re-probe, see app.capture.active_scan).
        Any of these resets `misses` to 0 — a host is "confirmed" the
        moment we hear from it by any means, not just the sweep's own
        re-probe. A no-op for placeholder MAC values (see _INVALID_MACS)
        — not a real device, never worth a table entry."""
        if not _is_valid_mac(mac):
            return
        now = time.time()
        with self._lock:
            existing = self._hosts.get(mac)
            if existing is not None:
                existing.ip = ip  # IP may have changed (DHCP renewal)
                existing.last_seen = now
                existing.misses = 0
            else:
                hostname = self._pending_hostnames.pop(mac, None)
                self._hosts[mac] = HostRecord(
                    ip=ip, mac=mac, first_seen=now, last_seen=now, hostname=hostname
                )

    def update_hostname(self, mac: str, hostname: str) -> None:
        """Called by app.capture.hostname_resolver once a reverse-DNS
        lookup for this MAC's current IP resolves. A no-op if the host
        has since disappeared from the table (e.g. it aged out between
        the lookup being queued and it completing) — nothing to attach
        the hostname to in that case.

        First name wins and is never overwritten: DHCP-sourced names
        (see record_dhcp_hostname) are both more likely to exist and
        friendlier than a PTR record for most consumer/IoT devices, so
        if one already arrived it takes priority over whatever PTR
        resolves to later. Also avoids the table's hostname column
        flapping between two different names for the same device."""
        with self._lock:
            existing = self._hosts.get(mac)
            if existing is not None and not existing.hostname:
                existing.hostname = hostname

    def record_dhcp_hostname(self, mac: str, hostname: str) -> None:
        """Called by the capture layer when a DHCP packet carries Option
        12 (Host Name) — the same name your router's own DHCP
        client-list page shows (e.g. "Johns-iPhone", "DESKTOP-A1B2C3"),
        sent by nearly every consumer device as part of its own
        DISCOVER/REQUEST. Far more often populated than a reverse-DNS
        PTR record, which is why this is the primary hostname source —
        see update_hostname()'s "first name wins" note for how the two
        interact.

        If this MAC has no host record yet (DHCP broadcasts commonly
        arrive before this device's first ARP sighting), the name is
        stashed in `_pending_hostnames` and applied automatically the
        moment record_sighting() creates the record. Also a no-op for
        placeholder MAC values (see _INVALID_MACS)."""
        if not hostname or not _is_valid_mac(mac):
            return
        with self._lock:
            existing = self._hosts.get(mac)
            if existing is not None:
                if not existing.hostname:
                    existing.hostname = hostname
            else:
                self._pending_hostnames[mac] = hostname

    def ip_hostnames(self) -> dict[str, str]:
        """Current IP -> hostname map for known hosts with a resolved
        name, keyed by IP rather than MAC — lets other engines that
        only ever see IPs (e.g. TopTalkersEngine) borrow this engine's
        resolved names without needing their own resolver or knowing
        about MAC addresses at all."""
        with self._lock:
            return {r.ip: r.hostname for r in self._hosts.values() if r.hostname}

    def end_sweep_cycle(self) -> None:
        """Called once by ActiveScanner after each completed sweep round
        — broadcast discovery plus every per-host unicast re-probe — has
        finished and every resulting record_sighting() call has already
        landed. Any host whose last_seen didn't move since the previous
        cycle boundary got no confirmation at all this round (not
        passively, not via broadcast discovery, not via its own unicast
        re-probe), so its miss count goes up; anything that WAS
        reconfirmed already has misses reset to 0 by record_sighting()
        itself and simply gets its cycle-boundary marker moved forward.

        A no-op with respect to `misses` for any host that never gets a
        sweep cycle at all (ActiveScanner not running) — those hosts
        fall back entirely to PASSIVE_ONLY_TTL_SECONDS in `_status_for`."""
        with self._lock:
            for record in self._hosts.values():
                if record.last_seen <= record._last_seen_at_cycle_start:
                    record.misses += 1
                record._last_seen_at_cycle_start = record.last_seen

    @staticmethod
    def _status_for(record: HostRecord, now: float) -> str:
        # Backstop first: nothing has confirmed this host by any means
        # (passive or active) in a long time, regardless of miss count —
        # covers the pure-passive-mode case where misses never moves.
        if now - record.last_seen > PASSIVE_ONLY_TTL_SECONDS:
            return "offline"
        if record.misses >= OFFLINE_AFTER_MISSES:
            return "offline"
        return "online"

    def snapshot(self) -> list[DiscoveredHost]:
        """Full current host table, most recently seen first."""
        now = time.time()
        with self._lock:
            records = list(self._hosts.values())

        records.sort(key=lambda r: r.last_seen, reverse=True)
        return [
            DiscoveredHost(
                ip=r.ip,
                mac=r.mac,
                hostname=r.hostname,  # None until app.capture.hostname_resolver fills it in
                last_seen=r.last_seen,
                status=self._status_for(r, now),
            )
            for r in records
        ]

    def online_count(self) -> int:
        """Feeds `lan_device_count` in stats:update — see stats.md."""
        now = time.time()
        with self._lock:
            return sum(
                1 for r in self._hosts.values()
                if self._status_for(r, now) == "online"
            )
