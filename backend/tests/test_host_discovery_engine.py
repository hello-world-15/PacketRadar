"""
Unit tests for HostDiscoveryEngine — feeds synthetic (mac, ip) sightings
directly, no Scapy or root privileges required.
"""

import time

from app.engines.host_discovery import (
    OFFLINE_AFTER_MISSES,
    HostDiscoveryEngine,
    HostRecord,
)


def test_empty_engine_has_no_hosts():
    engine = HostDiscoveryEngine()
    assert engine.snapshot() == []
    assert engine.online_count() == 0


def test_new_sighting_is_online():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    snap = engine.snapshot()
    assert len(snap) == 1
    assert snap[0].mac == "AA:BB:CC:00:00:01"
    assert snap[0].ip == "192.168.1.10"
    assert snap[0].status == "online"
    assert snap[0].hostname is None


def test_repeated_sightings_update_not_duplicate():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    assert len(engine.snapshot()) == 1


def test_ip_change_updates_existing_record_by_mac():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.99")  # DHCP renewal
    snap = engine.snapshot()
    assert len(snap) == 1
    assert snap[0].ip == "192.168.1.99"


def test_distinct_macs_are_distinct_hosts():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    engine.record_sighting(mac="AA:BB:CC:00:00:02", ip="192.168.1.11")
    assert len(engine.snapshot()) == 2
    assert engine.online_count() == 2


def test_status_thresholds():
    engine = HostDiscoveryEngine()
    now = time.time()

    engine._hosts["online-host"] = HostRecord(
        ip="192.168.1.1", mac="online-host", first_seen=now, last_seen=now
    )
    engine._hosts["offline-host"] = HostRecord(
        ip="192.168.1.3", mac="offline-host", first_seen=now, last_seen=now - 600
    )

    snap = {h.mac: h for h in engine.snapshot()}
    assert snap["online-host"].status == "online"
    assert snap["offline-host"].status == "offline"  # beyond PASSIVE_ONLY_TTL_SECONDS backstop
    assert engine.online_count() == 1


def test_passive_only_backstop_tolerates_a_quiet_device_for_a_while():
    """With no active sweep running at all (misses never moves), a host
    should stay "online" well past the old 75s window — it has no way
    to know the difference between "asleep/idle" and "gone" without
    active probing, so it should err toward not flapping a real device
    offline. 35s (comfortably under PASSIVE_ONLY_TTL_SECONDS) must still
    read online."""
    engine = HostDiscoveryEngine()
    now = time.time()

    engine._hosts["still-there"] = HostRecord(
        ip="192.168.1.1", mac="still-there", first_seen=now, last_seen=now - 35
    )

    snap = engine.snapshot()
    assert snap[0].status == "online"


def test_snapshot_sorted_most_recent_first():
    engine = HostDiscoveryEngine()
    now = time.time()
    engine._hosts["older"] = HostRecord(ip="192.168.1.1", mac="older", first_seen=now, last_seen=now - 10)
    engine._hosts["newer"] = HostRecord(ip="192.168.1.2", mac="newer", first_seen=now, last_seen=now)

    snap = engine.snapshot()
    assert [h.mac for h in snap] == ["newer", "older"]


def test_update_hostname_attaches_to_existing_host():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    engine.update_hostname("AA:BB:CC:00:00:01", "printer.lan")

    snap = engine.snapshot()
    assert snap[0].hostname == "printer.lan"


def test_update_hostname_is_noop_for_unknown_mac():
    engine = HostDiscoveryEngine()
    # Host aged out / was never seen — resolver result arrives late.
    engine.update_hostname("AA:BB:CC:00:00:99", "ghost.lan")
    assert engine.snapshot() == []


def test_ip_hostnames_only_includes_resolved_hosts():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    engine.record_sighting(mac="AA:BB:CC:00:00:02", ip="192.168.1.11")
    engine.update_hostname("AA:BB:CC:00:00:01", "laptop.lan")

    lookup = engine.ip_hostnames()
    assert lookup == {"192.168.1.10": "laptop.lan"}


def test_ip_hostnames_reflects_ip_change_via_dhcp_renewal():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    engine.update_hostname("AA:BB:CC:00:00:01", "laptop.lan")
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.99")

    assert engine.ip_hostnames() == {"192.168.1.99": "laptop.lan"}


def test_record_dhcp_hostname_sets_name_on_existing_host():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    engine.record_dhcp_hostname("AA:BB:CC:00:00:01", "Johns-iPhone")

    snap = engine.snapshot()
    assert snap[0].hostname == "Johns-iPhone"


def test_record_dhcp_hostname_pending_until_sighting_creates_host():
    engine = HostDiscoveryEngine()
    engine.record_dhcp_hostname("AA:BB:CC:00:00:01", "Kitchen-Chromecast")
    assert engine.snapshot() == []  # nothing to attach it to yet

    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    snap = engine.snapshot()
    assert snap[0].hostname == "Kitchen-Chromecast"


def test_dhcp_hostname_takes_priority_over_later_ptr_result():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    engine.record_dhcp_hostname("AA:BB:CC:00:00:01", "Johns-iPhone")
    engine.update_hostname("AA:BB:CC:00:00:01", "some-ptr-name.isp.example.com")

    snap = engine.snapshot()
    assert snap[0].hostname == "Johns-iPhone"


def test_ptr_result_still_applies_when_no_dhcp_name_arrived():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    engine.update_hostname("AA:BB:CC:00:00:01", "printer.lan")

    snap = engine.snapshot()
    assert snap[0].hostname == "printer.lan"


def test_empty_dhcp_hostname_is_ignored():
    engine = HostDiscoveryEngine()
    engine.record_dhcp_hostname("AA:BB:CC:00:00:01", "")
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    assert engine.snapshot()[0].hostname is None


# ---------------------------------------------------------------------------
# Online/offline via consecutive missed sweep cycles
# ---------------------------------------------------------------------------


def _settle_cycle_baseline(engine: HostDiscoveryEngine) -> None:
    """The first end_sweep_cycle() call after ANY record_sighting() can
    never itself count as a miss — the host was, by definition, just
    confirmed moments before that cycle boundary (see
    HostDiscoveryEngine.end_sweep_cycle()'s docstring: it only adds a
    miss when last_seen didn't move since the PREVIOUS boundary). Tests
    below call this once right after a sighting to consume that
    unavoidable non-miss cycle, so every end_sweep_cycle() call after it
    maps 1:1 onto a real, countable miss."""
    engine.end_sweep_cycle()


def test_one_missed_sweep_cycle_stays_online():
    """A single missed cycle (one lost broadcast/unicast probe) must not
    flip a real device offline — only OFFLINE_AFTER_MISSES consecutive
    misses should."""
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    _settle_cycle_baseline(engine)

    engine.end_sweep_cycle()  # exactly 1 real miss

    assert engine.snapshot()[0].status == "online"


def test_offline_after_threshold_consecutive_misses():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    _settle_cycle_baseline(engine)

    for _ in range(OFFLINE_AFTER_MISSES):
        engine.end_sweep_cycle()

    assert engine.snapshot()[0].status == "offline"


def test_any_sighting_resets_the_miss_counter():
    """A host that's about to go offline (one miss short of the
    threshold) gets fully reset the moment ANY sighting comes in —
    passive, broadcast, or unicast re-probe all call the same
    record_sighting() entrypoint."""
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    _settle_cycle_baseline(engine)

    for _ in range(OFFLINE_AFTER_MISSES - 1):
        engine.end_sweep_cycle()
    assert engine.snapshot()[0].status == "online"  # one miss short of the threshold

    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")  # reconfirmed
    _settle_cycle_baseline(engine)

    # Should now take the FULL threshold again to go offline, not just
    # the one remaining miss it was short by before the reset.
    for _ in range(OFFLINE_AFTER_MISSES - 1):
        engine.end_sweep_cycle()
    assert engine.snapshot()[0].status == "online"

    engine.end_sweep_cycle()
    assert engine.snapshot()[0].status == "offline"


def test_sighting_mid_cycle_prevents_a_miss_being_counted():
    """A sighting that lands between two end_sweep_cycle() calls (e.g. a
    passive ARP packet arriving mid-cycle) should count as that cycle's
    confirmation — the following end_sweep_cycle() must NOT add a miss
    on top of it, and the miss count it had accrued before the sighting
    must not carry forward either."""
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    _settle_cycle_baseline(engine)
    engine.end_sweep_cycle()  # one real, unconfirmed miss
    assert engine.snapshot()[0].status == "online"  # 1 miss, below threshold

    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")  # mid-cycle sighting
    engine.end_sweep_cycle()  # must NOT add a miss — it was just reconfirmed
    assert engine.snapshot()[0].status == "online"

    # From here it should take the full threshold again, not finish off
    # the single miss it had accrued before the reset.
    engine.end_sweep_cycle()
    assert engine.snapshot()[0].status == "online"
    engine.end_sweep_cycle()
    assert engine.snapshot()[0].status == "offline"


def test_end_sweep_cycle_tracks_hosts_independently():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="quiet-host", ip="192.168.1.10")
    engine.record_sighting(mac="active-host", ip="192.168.1.11")
    _settle_cycle_baseline(engine)  # applies to every known host at once

    for _ in range(OFFLINE_AFTER_MISSES):
        engine.record_sighting(mac="active-host", ip="192.168.1.11")  # reconfirmed every cycle
        engine.end_sweep_cycle()

    snap = {h.mac: h.status for h in engine.snapshot()}
    assert snap["quiet-host"] == "offline"
    assert snap["active-host"] == "online"


def test_end_sweep_cycle_alone_never_flips_a_freshly_seen_host():
    """A host that was JUST created by record_sighting() must not
    immediately count as "missed" the first time end_sweep_cycle() runs
    afterward, even though its last_seen and the fresh cycle-start
    baseline are extremely close in time."""
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    engine.end_sweep_cycle()
    assert engine.snapshot()[0].status == "online"


def test_record_sighting_ignores_all_zero_mac():
    """00:00:00:00:00:00 is a placeholder value that shows up on the
    wire sometimes (a malformed/partially-dissected packet, an
    unconfigured virtual adapter, etc.) but is never a real device's
    identity — it must never create a phantom host entry."""
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="00:00:00:00:00:00", ip="192.168.1.10")
    assert engine.snapshot() == []


def test_record_sighting_ignores_broadcast_mac():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="ff:ff:ff:ff:ff:ff", ip="192.168.1.10")
    assert engine.snapshot() == []


def test_record_sighting_ignores_all_zero_mac_case_insensitively():
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="00:00:00:00:00:00".upper(), ip="192.168.1.10")
    assert engine.snapshot() == []


def test_record_dhcp_hostname_ignores_all_zero_mac():
    """Guards the exact bug this was written for: a DHCP packet whose
    MAC couldn't be reliably determined (Ether layer missing, chaddr
    zeroed) must not create a duplicate phantom entry for a device
    that's already correctly recorded under its real MAC."""
    engine = HostDiscoveryEngine()
    engine.record_sighting(mac="48:a4:72:64:ab:b3", ip="192.168.0.103")

    engine.record_dhcp_hostname("00:00:00:00:00:00", "DESKTOP-P1PC1OA")
    engine.record_sighting(mac="00:00:00:00:00:00", ip="192.168.0.103")

    snap = engine.snapshot()
    assert len(snap) == 1
    assert snap[0].mac == "48:a4:72:64:ab:b3"
