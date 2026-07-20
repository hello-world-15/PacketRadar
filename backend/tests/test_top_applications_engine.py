"""
Unit tests for TopApplicationsEngine — feeds synthetic packet events
directly, no Scapy, live capture, or psutil required.
"""

import time

from app.engines.top_applications import AppRecord, ByteEvent, TopApplicationsEngine


def test_empty_engine_has_no_applications():
    engine = TopApplicationsEngine()
    assert engine.snapshot() == []


def test_upload_and_download_are_tracked_separately():
    engine = TopApplicationsEngine()
    engine.record_packet(pid=100, name="chrome.exe", length=1000, direction="upload", flow_key="f1")
    engine.record_packet(pid=100, name="chrome.exe", length=4000, direction="download", flow_key="f1")
    snap = {a.pid: a for a in engine.snapshot()}
    expected_upload = round((1000 * 8) / 1000 / 5.0, 2)
    expected_download = round((4000 * 8) / 1000 / 5.0, 2)
    assert snap[100].upload_kbps == expected_upload
    assert snap[100].download_kbps == expected_download


def test_multiple_pids_tracked_independently():
    engine = TopApplicationsEngine()
    engine.record_packet(pid=100, name="chrome.exe", length=500, direction="upload", flow_key="f1")
    engine.record_packet(pid=200, name="slack.exe", length=500, direction="upload", flow_key="f2")
    snap = {a.pid: a for a in engine.snapshot()}
    assert set(snap.keys()) == {100, 200}
    assert snap[100].name == "chrome.exe"
    assert snap[200].name == "slack.exe"


def test_invalid_direction_is_ignored():
    engine = TopApplicationsEngine()
    engine.record_packet(pid=100, name="chrome.exe", length=1000, direction="sideways", flow_key="f1")
    assert engine.snapshot() == []


def test_pid_reuse_starts_a_fresh_record():
    # Same pid, different process name — the OS reused the pid. Must not
    # blend the old process's history into the new one's.
    engine = TopApplicationsEngine()
    engine.record_packet(pid=100, name="chrome.exe", length=5000, direction="upload", flow_key="f1")
    engine.record_packet(pid=100, name="notepad.exe", length=1000, direction="upload", flow_key="f2")
    snap = {a.pid: a for a in engine.snapshot()}
    assert snap[100].name == "notepad.exe"
    expected = round((1000 * 8) / 1000 / 5.0, 2)
    assert snap[100].upload_kbps == expected


def test_connections_counts_distinct_active_flows():
    engine = TopApplicationsEngine()
    engine.record_packet(pid=100, name="chrome.exe", length=100, direction="upload", flow_key="f1")
    engine.record_packet(pid=100, name="chrome.exe", length=100, direction="upload", flow_key="f2")
    engine.record_packet(pid=100, name="chrome.exe", length=100, direction="upload", flow_key="f1")  # dup flow
    snap = {a.pid: a for a in engine.snapshot()}
    assert snap[100].connections == 2


def test_old_bytes_fall_out_of_the_window():
    engine = TopApplicationsEngine()
    now = time.time()
    record = AppRecord(name="chrome.exe")
    record.upload_bytes.append(ByteEvent(timestamp=now - 10, length=5000))  # outside 5s window
    engine._apps[100] = record
    snap = {a.pid: a for a in engine.snapshot()}
    assert snap[100].upload_kbps == 0


def test_snapshot_sorted_by_combined_bandwidth_descending():
    engine = TopApplicationsEngine()
    engine.record_packet(pid=100, name="chrome.exe", length=100, direction="upload", flow_key="f1")
    engine.record_packet(pid=200, name="slack.exe", length=10000, direction="download", flow_key="f2")
    snap = engine.snapshot()
    assert [a.pid for a in snap] == [200, 100]


def test_snapshot_respects_limit():
    engine = TopApplicationsEngine()
    for pid in range(20):
        engine.record_packet(pid=pid, name=f"proc{pid}.exe", length=100, direction="upload", flow_key=f"f{pid}")
    assert len(engine.snapshot(limit=5)) == 5
