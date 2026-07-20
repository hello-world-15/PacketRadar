"""
Unit tests for StatisticsEngine — deliberately does not touch Scapy or a
real capture. Feeds synthetic packet events directly, so this test stays
fast and doesn't need root privileges to run.
"""

import time

from app.engines.statistics import StatisticsEngine


def test_empty_snapshot_is_all_zero():
    engine = StatisticsEngine()
    snap = engine.snapshot()
    assert snap.packets_per_sec == 0
    assert snap.bandwidth_mbps == 0
    assert snap.active_connections == 0
    assert snap.dropped_packets == 0


def test_packets_in_window_are_counted():
    engine = StatisticsEngine()
    for _ in range(10):
        engine.record_packet(length=1000, flow_key="TCP:a:1-b:2")
    snap = engine.snapshot()
    assert snap.packets_per_sec == 10
    # 10 packets * 1000 bytes * 8 bits / 1_000_000 = 0.08 Mbps
    assert snap.bandwidth_mbps == 0.08


def test_distinct_flows_counted_once_each():
    engine = StatisticsEngine()
    engine.record_packet(length=100, flow_key="TCP:a:1-b:2")
    engine.record_packet(length=100, flow_key="TCP:a:1-b:2")  # same flow again
    engine.record_packet(length=100, flow_key="UDP:c:3-d:4")  # different flow
    snap = engine.snapshot()
    assert snap.active_connections == 2
    assert snap.packets_per_sec == 3


def test_old_packets_fall_out_of_the_window():
    engine = StatisticsEngine()
    # Manually inject a packet event timestamped 5 seconds in the past.
    from app.engines.statistics import PacketEvent

    engine._recent.append(PacketEvent(timestamp=time.time() - 5, length=500, flow_key="x"))
    snap = engine.snapshot()
    assert snap.packets_per_sec == 0  # evicted, outside the 1s window


def test_dropped_packets_accumulate():
    engine = StatisticsEngine()
    engine.record_dropped(3)
    engine.record_dropped(2)
    snap = engine.snapshot()
    assert snap.dropped_packets == 5


def test_stub_fields_are_zero_pending_other_engines():
    engine = StatisticsEngine()
    engine.record_packet(length=100, flow_key="TCP:a:1-b:2")
    snap = engine.snapshot()
    assert snap.threat_alert_count == 0
    assert snap.lan_device_count == 0


def test_upload_and_download_are_split_from_the_same_window():
    engine = StatisticsEngine()
    engine.record_packet(length=1000, flow_key="a", direction="upload")
    engine.record_packet(length=1000, flow_key="a", direction="upload")
    engine.record_packet(length=3000, flow_key="b", direction="download")
    snap = engine.snapshot()
    # 2000 bytes * 8 / 1_000_000 = 0.016 Mbps
    assert snap.upload_mbps == 0.02
    # 3000 bytes * 8 / 1_000_000 = 0.024 Mbps
    assert snap.download_mbps == 0.02
    # Combined total is unaffected by direction — same as before Module 6.
    assert snap.bandwidth_mbps == round((1000 + 1000 + 3000) * 8 / 1_000_000, 2)
    assert snap.packets_per_sec == 3


def test_unknown_direction_counts_toward_total_but_not_the_split():
    engine = StatisticsEngine()
    engine.record_packet(length=5000, flow_key="a", direction=None)
    snap = engine.snapshot()
    assert snap.upload_mbps == 0.0
    assert snap.download_mbps == 0.0
    assert snap.bandwidth_mbps == round(5000 * 8 / 1_000_000, 2)


def test_direction_defaults_to_none_for_older_call_sites():
    # record_packet() without a direction arg (e.g. existing tests above,
    # or any call site that predates Module 6) must keep working.
    engine = StatisticsEngine()
    engine.record_packet(length=1000, flow_key="a")
    snap = engine.snapshot()
    assert snap.upload_mbps == 0.0
    assert snap.download_mbps == 0.0
    assert snap.bandwidth_mbps == 0.01
