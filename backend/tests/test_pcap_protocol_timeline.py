"""
Unit + API tests for Protocol Distribution + Traffic Timeline.

Engine-level tests feed synthetic PacketModel instances directly, no
file I/O or Scapy required — same convention as test_pcap_summary.py.
API-level tests populate PcapAnalysisStore directly (bypassing a real
file upload), same shortcut test_pcap_hosts_conversations_api.py takes,
so they only exercise the route + store lookup, not the parser.
"""

from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from app.cache.pcap_store import pcap_store
from app.engines.pcap_protocol_timeline import (
    compute_protocol_distribution,
    compute_protocol_timeline,
    compute_timeline,
)
from app.engines.pcap_summary import compute_summary
from app.main import app
from app.models.packet import PacketModel

client = TestClient(app)


def _packet(**overrides) -> PacketModel:
    defaults = dict(
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        interface="pcap-upload",
        direction="UNKNOWN",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        length=100,
        payload_size=50,
        flow_key="10.0.0.1:1234-10.0.0.2:80-TCP",
        info="TCP",
    )
    defaults.update(overrides)
    return PacketModel(**defaults)


# ---------------------------------------------------------------------------
# compute_protocol_distribution
# ---------------------------------------------------------------------------


def test_empty_list_returns_empty_distribution():
    assert compute_protocol_distribution([]) == []


def test_protocol_distribution_counts_by_protocol_field():
    packets = [
        _packet(protocol="TCP"),
        _packet(protocol="TCP"),
        _packet(protocol="UDP"),
    ]
    result = {c.label: c.value for c in compute_protocol_distribution(packets)}
    assert result == {"TCP": 2, "UDP": 1}


def test_protocol_distribution_sorted_descending_by_count():
    packets = (
        [_packet(protocol="UDP")]
        + [_packet(protocol="TCP") for _ in range(3)]
        + [_packet(protocol="DNS") for _ in range(2)]
    )
    labels = [c.label for c in compute_protocol_distribution(packets)]
    assert labels == ["TCP", "DNS", "UDP"]


# ---------------------------------------------------------------------------
# compute_timeline
# ---------------------------------------------------------------------------


def test_empty_list_returns_empty_timeline():
    assert compute_timeline([]) == []


def test_single_packet_returns_one_bucket():
    buckets = compute_timeline([_packet(timestamp=datetime(2026, 1, 1, 14, 32, 0))])
    assert len(buckets) == 1
    assert buckets[0].label == "14:32"
    assert buckets[0].value == 1


def test_all_packets_same_timestamp_returns_one_bucket_not_divide_by_zero():
    ts = datetime(2026, 1, 1, 9, 0, 0)
    packets = [_packet(timestamp=ts) for _ in range(5)]
    buckets = compute_timeline(packets)
    assert len(buckets) == 1
    assert buckets[0].value == 5


def test_timeline_buckets_are_evenly_spaced_across_real_duration():
    base = datetime(2026, 1, 1, 12, 0, 0)
    # duration = 180s across 3 buckets -> width = 60s exactly, so labels
    # land on clean minute boundaries and packets fall predictably.
    packets = [
        _packet(timestamp=base),  # offset 0 -> bucket 0
        _packet(timestamp=base + timedelta(seconds=60)),  # offset 60 -> bucket 1
        _packet(timestamp=base + timedelta(seconds=120)),  # offset 120 -> bucket 2
        _packet(timestamp=base + timedelta(seconds=180)),  # offset 180 -> clamped into bucket 2
    ]
    buckets = compute_timeline(packets, bucket_count=3)

    assert len(buckets) == 3
    assert [b.value for b in buckets] == [1, 1, 2]
    assert [b.label for b in buckets] == ["12:00", "12:01", "12:02"]


def test_timeline_respects_default_bucket_count():
    base = datetime(2026, 1, 1, 8, 0, 0)
    packets = [_packet(timestamp=base), _packet(timestamp=base + timedelta(minutes=48))]
    assert len(compute_timeline(packets)) == 24


# ---------------------------------------------------------------------------
# compute_protocol_timeline (combined)
# ---------------------------------------------------------------------------


def test_compute_protocol_timeline_combines_both():
    # Same timestamp on every packet (duration = 0) exercises the
    # single-bucket zero-duration path through the combined function,
    # while still checking protocol counting works alongside it.
    base = datetime(2026, 1, 1, 10, 0, 0)
    packets = [
        _packet(timestamp=base, protocol="TCP"),
        _packet(timestamp=base, protocol="UDP"),
    ]
    result = compute_protocol_timeline(packets)
    assert {c.label for c in result.protocol_distribution} == {"TCP", "UDP"}
    assert len(result.timeline) == 1
    assert result.timeline[0].value == 2


# ---------------------------------------------------------------------------
# GET /api/pcap/{capture_id}/protocol-timeline
# ---------------------------------------------------------------------------


def test_unknown_capture_id_returns_404():
    response = client.get("/api/pcap/does-not-exist/protocol-timeline")
    assert response.status_code == 404
    assert "detail" in response.json()


def test_known_capture_id_returns_protocol_distribution_and_timeline():
    # Same timestamp on every packet keeps the timeline assertion simple
    # (single zero-duration bucket) — real bucket-spacing math is already
    # covered by the compute_timeline unit tests above; this test only
    # needs to confirm the route wires the store's packets through to
    # both fields correctly.
    base = datetime(2026, 1, 1, 14, 32, 0)
    packets = [
        _packet(timestamp=base, protocol="TCP"),
        _packet(timestamp=base, protocol="TCP"),
        _packet(timestamp=base, protocol="DNS"),
    ]
    summary = compute_summary(packets)
    pcap_store.save("test-capture-protocol-timeline", "test.pcap", packets, summary)

    response = client.get("/api/pcap/test-capture-protocol-timeline/protocol-timeline")
    assert response.status_code == 200

    body = response.json()
    dist = {c["label"]: c["value"] for c in body["protocol_distribution"]}
    assert dist == {"TCP": 2, "DNS": 1}
    assert len(body["timeline"]) == 1
    assert body["timeline"][0]["value"] == 3
