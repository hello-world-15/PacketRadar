"""
Unit tests for PacketStreamEngine — feeds synthetic ParsedPacket values
directly, no Scapy or root privileges required.
"""

from app.engines.packet_stream import ParsedPacket, PacketStreamEngine


def _pkt(**overrides):
    defaults = dict(
        source="192.168.1.10",
        destination="93.184.216.34",
        protocol="TCP",
        length=583,
        info="TCP 51372 → 443 [SYN]",
    )
    defaults.update(overrides)
    return ParsedPacket(**defaults)


def test_empty_engine_has_no_backlog_and_zero_seq():
    engine = PacketStreamEngine()
    assert engine.backlog() == []
    assert engine.since(0) == []
    assert engine.latest_seq == 0


def test_record_assigns_increasing_sequence_numbers():
    engine = PacketStreamEngine()
    first = engine.record(_pkt())
    second = engine.record(_pkt(protocol="UDP"))
    assert first.no == 1
    assert second.no == 2
    assert engine.latest_seq == 2


def test_since_only_returns_rows_after_the_given_sequence():
    engine = PacketStreamEngine()
    engine.record(_pkt())
    engine.record(_pkt())
    engine.record(_pkt())
    rows = engine.since(1)
    assert [r.no for r in rows] == [2, 3]


def test_since_with_no_new_rows_is_empty():
    engine = PacketStreamEngine()
    engine.record(_pkt())
    assert engine.since(1) == []


def test_since_caps_at_limit_keeping_the_most_recent():
    engine = PacketStreamEngine()
    for _ in range(10):
        engine.record(_pkt())
    rows = engine.since(0, limit=3)
    assert [r.no for r in rows] == [8, 9, 10]


def test_backlog_returns_most_recent_rows_oldest_first():
    engine = PacketStreamEngine()
    for _ in range(5):
        engine.record(_pkt())
    rows = engine.backlog(limit=2)
    assert [r.no for r in rows] == [4, 5]


def test_ring_buffer_evicts_oldest_when_full():
    engine = PacketStreamEngine(max_buffer=3)
    for _ in range(5):
        engine.record(_pkt())
    # Only the last 3 sequence numbers should still be buffered.
    rows = engine.since(0)
    assert [r.no for r in rows] == [3, 4, 5]
    # But the sequence counter itself keeps counting from the start.
    assert engine.latest_seq == 5


def test_record_preserves_packet_fields():
    engine = PacketStreamEngine()
    row = engine.record(
        _pkt(source="10.0.0.5", destination="10.0.0.1", protocol="ARP", info="who-has")
    )
    assert row.source == "10.0.0.5"
    assert row.destination == "10.0.0.1"
    assert row.protocol == "ARP"
    assert row.info == "who-has"
    assert row.process is None
