"""
Unit tests for TopTalkersEngine — feeds synthetic packet events directly,
no Scapy or live capture required.
"""

import time

from app.engines.top_talkers import TopTalkersEngine, ByteEvent, HostRecord


def test_empty_engine_has_no_talkers():
    engine = TopTalkersEngine()
    assert engine.snapshot() == []


def test_both_source_and_destination_are_credited():
    engine = TopTalkersEngine()
    engine.record_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", length=1000, flow_key="f1")
    snap = {t.ip: t for t in engine.snapshot()}
    assert snap["10.0.0.1"].packets == 1
    assert snap["10.0.0.2"].packets == 1


def test_packets_accumulate_per_ip():
    engine = TopTalkersEngine()
    for _ in range(5):
        engine.record_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", length=500, flow_key="f1")
    snap = {t.ip: t for t in engine.snapshot()}
    assert snap["10.0.0.1"].packets == 5
    assert snap["10.0.0.2"].packets == 5


def test_same_ip_as_src_and_dst_credited_once():
    # Shouldn't happen on real traffic, but must not double-count if it does.
    engine = TopTalkersEngine()
    engine.record_packet(src_ip="10.0.0.1", dst_ip="10.0.0.1", length=100, flow_key="f1")
    snap = {t.ip: t for t in engine.snapshot()}
    assert snap["10.0.0.1"].packets == 1


def test_bandwidth_mbps_reflects_windowed_bytes():
    engine = TopTalkersEngine()
    # 10 packets * 1000 bytes = 10000 bytes in the 5s window.
    for _ in range(10):
        engine.record_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", length=1000, flow_key="f1")
    snap = {t.ip: t for t in engine.snapshot()}
    # 10000 bytes * 8 bits / 1_000_000 / 5s window
    expected = round((10000 * 8) / 1_000_000 / 5.0, 3)
    assert snap["10.0.0.1"].bandwidth_mbps == expected


def test_old_bytes_fall_out_of_the_window():
    engine = TopTalkersEngine()
    now = time.time()
    record = HostRecord()
    record.recent_bytes.append(ByteEvent(timestamp=now - 10, length=5000))  # outside 5s window
    engine._hosts["10.0.0.1"] = record
    snap = {t.ip: t for t in engine.snapshot()}
    assert snap["10.0.0.1"].bandwidth_mbps == 0


def test_ranked_by_bandwidth_descending():
    engine = TopTalkersEngine()
    for _ in range(20):
        engine.record_packet(src_ip="10.0.0.1", dst_ip="10.0.0.9", length=1000, flow_key="big")
    for _ in range(2):
        engine.record_packet(src_ip="10.0.0.5", dst_ip="10.0.0.9", length=100, flow_key="small")
    snap = engine.snapshot()
    ips_by_rank = [t.ip for t in snap]
    assert ips_by_rank.index("10.0.0.1") < ips_by_rank.index("10.0.0.5")


def test_top_talker_has_100_percent_bandwidth_pct():
    engine = TopTalkersEngine()
    engine.record_packet(src_ip="10.0.0.1", dst_ip="10.0.0.9", length=5000, flow_key="f1")
    snap = engine.snapshot()
    assert snap[0].bandwidth_pct == 100


def test_limit_caps_returned_talkers():
    engine = TopTalkersEngine()
    for i in range(20):
        engine.record_packet(src_ip=f"10.0.0.{i}", dst_ip="10.0.0.254", length=100, flow_key=f"f{i}")
    snap = engine.snapshot(limit=5)
    assert len(snap) == 5


def test_connections_counts_distinct_active_flows():
    engine = TopTalkersEngine()
    engine.record_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", length=100, flow_key="flow-a")
    engine.record_packet(src_ip="10.0.0.1", dst_ip="10.0.0.3", length=100, flow_key="flow-b")
    engine.record_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", length=100, flow_key="flow-a")  # repeat
    snap = {t.ip: t for t in engine.snapshot()}
    assert snap["10.0.0.1"].connections == 2


def test_stale_connections_are_not_counted():
    engine = TopTalkersEngine()
    now = time.time()
    record = HostRecord(packets=1)
    record.flows["old-flow"] = now - 60  # older than 30s TTL
    engine._hosts["10.0.0.1"] = record
    snap = {t.ip: t for t in engine.snapshot()}
    assert snap["10.0.0.1"].connections == 0


def test_hostname_lookup_fills_in_known_ips():
    engine = TopTalkersEngine()
    engine.record_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", length=100, flow_key="f1")
    snap = {
        t.ip: t
        for t in engine.snapshot(hostname_lookup={"10.0.0.1": "laptop.lan"})
    }
    assert snap["10.0.0.1"].hostname == "laptop.lan"
    assert snap["10.0.0.2"].hostname is None


def test_hostname_lookup_defaults_to_none_when_omitted():
    engine = TopTalkersEngine()
    engine.record_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", length=100, flow_key="f1")
    snap = {t.ip: t for t in engine.snapshot()}
    assert snap["10.0.0.1"].hostname is None
