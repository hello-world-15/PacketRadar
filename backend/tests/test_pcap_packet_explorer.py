"""
Unit tests for paginate_packets — feeds synthetic PacketModel instances
directly, no file I/O or Scapy required. Matches the style of
test_pcap_summary.py.
"""

from datetime import datetime, timedelta

from app.engines.pcap_packet_explorer import MAX_LIMIT, paginate_packets
from app.models.packet import PacketModel

BASE_TIME = datetime(2026, 1, 1, 12, 0, 0)


def _packet(**overrides) -> PacketModel:
    defaults = dict(
        timestamp=BASE_TIME,
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
        info="TCP 1234 \u2192 80 [SYN]",
        src_mac="AA:AA:AA:AA:AA:AA",
        dst_mac="BB:BB:BB:BB:BB:BB",
    )
    defaults.update(overrides)
    return PacketModel(**defaults)


def _packets(count: int) -> list[PacketModel]:
    return [
        _packet(timestamp=BASE_TIME + timedelta(seconds=i), dst_port=1000 + i)
        for i in range(count)
    ]


def test_empty_capture_returns_empty_page():
    result = paginate_packets([], offset=0, limit=100)
    assert result.packets == []
    assert result.total == 0
    assert result.offset == 0
    assert result.limit == 100


def test_first_page_returns_requested_slice():
    packets = _packets(10)
    result = paginate_packets(packets, offset=0, limit=5)
    assert len(result.packets) == 5
    assert result.total == 10
    assert [r.no for r in result.packets] == [1, 2, 3, 4, 5]


def test_second_page_continues_numbering_from_the_whole_capture():
    packets = _packets(10)
    result = paginate_packets(packets, offset=5, limit=5)
    assert len(result.packets) == 5
    assert [r.no for r in result.packets] == [6, 7, 8, 9, 10]


def test_no_reflects_position_in_whole_capture_not_the_page():
    packets = _packets(20)
    page_one = paginate_packets(packets, offset=0, limit=5)
    page_two = paginate_packets(packets, offset=5, limit=5)
    # Different pages, no overlapping `no` values, and neither page
    # restarts numbering at 1.
    assert page_one.packets[-1].no == 5
    assert page_two.packets[0].no == 6


def test_offset_past_the_end_returns_an_empty_page_not_an_error():
    packets = _packets(10)
    result = paginate_packets(packets, offset=100, limit=10)
    assert result.packets == []
    assert result.total == 10


def test_partial_last_page():
    packets = _packets(13)
    result = paginate_packets(packets, offset=10, limit=5)
    assert len(result.packets) == 3
    assert [r.no for r in result.packets] == [11, 12, 13]


def test_negative_offset_is_clamped_to_zero():
    packets = _packets(5)
    result = paginate_packets(packets, offset=-10, limit=5)
    assert result.offset == 0
    assert [r.no for r in result.packets] == [1, 2, 3, 4, 5]


def test_limit_is_clamped_to_max_limit():
    packets = _packets(5)
    result = paginate_packets(packets, offset=0, limit=MAX_LIMIT + 1000)
    assert result.limit == MAX_LIMIT


def test_limit_of_zero_is_clamped_to_at_least_one():
    packets = _packets(5)
    result = paginate_packets(packets, offset=0, limit=0)
    assert result.limit == 1
    assert len(result.packets) == 1


def test_row_carries_real_mac_and_port_fields():
    packets = [_packet(src_mac="3C:52:82:1A:0F:22", dst_mac="A4:83:E7:2C:9B:11", src_port=51372, dst_port=443)]
    result = paginate_packets(packets, offset=0, limit=10)
    row = result.packets[0]
    assert row.src_mac == "3C:52:82:1A:0F:22"
    assert row.dst_mac == "A4:83:E7:2C:9B:11"
    assert row.src_port == 51372
    assert row.dst_port == 443


def test_row_carries_dns_fields_when_present():
    packets = [
        _packet(
            protocol="DNS",
            dns_query="example.com (A)",
            dns_answer="93.184.216.34",
            info="DNS response: example.com (A) \u2192 93.184.216.34",
        )
    ]
    result = paginate_packets(packets, offset=0, limit=10)
    row = result.packets[0]
    assert row.dns_query == "example.com (A)"
    assert row.dns_answer == "93.184.216.34"


def test_row_dns_fields_are_none_for_non_dns_packets():
    packets = _packets(1)
    result = paginate_packets(packets, offset=0, limit=10)
    assert result.packets[0].dns_query is None
    assert result.packets[0].dns_answer is None


def test_row_time_is_the_packets_own_timestamp():
    ts = BASE_TIME + timedelta(hours=1)
    packets = [_packet(timestamp=ts)]
    result = paginate_packets(packets, offset=0, limit=10)
    assert result.packets[0].time == ts.timestamp()


def test_row_maps_ip_and_length_and_info_correctly():
    packets = [_packet(src_ip="1.2.3.4", dst_ip="5.6.7.8", length=999, info="TCP 1 \u2192 2 [ACK]")]
    result = paginate_packets(packets, offset=0, limit=10)
    row = result.packets[0]
    assert row.source == "1.2.3.4"
    assert row.destination == "5.6.7.8"
    assert row.length == 999
    assert row.info == "TCP 1 \u2192 2 [ACK]"
