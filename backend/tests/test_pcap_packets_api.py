"""
Integration tests for GET /api/pcap/{capture_id}/packets — builds real
synthetic .pcap files with Scapy's wrpcap and queries them through the
real FastAPI endpoints end to end, same pattern as
test_pcap_threats_api.py. No root/elevated privileges needed.
"""

from pathlib import Path

from fastapi.testclient import TestClient
from scapy.all import IP, TCP, Ether, wrpcap

from app.main import app

client = TestClient(app)


def _upload(tmp_path: Path, packets, name: str = "test.pcap") -> str:
    path = tmp_path / name
    wrpcap(str(path), packets)
    with open(path, "rb") as f:
        response = client.post(
            "/api/pcap/upload", files={"file": (name, f, "application/octet-stream")}
        )
    assert response.status_code == 200
    return response.json()["capture_id"]


def test_unknown_capture_id_returns_404():
    response = client.get("/api/pcap/not-a-real-capture-id/packets")
    assert response.status_code == 404


def test_default_pagination_returns_first_page(tmp_path):
    packets = [
        Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=1000 + i, dport=80)
        for i in range(150)
    ]
    capture_id = _upload(tmp_path, packets)

    response = client.get(f"/api/pcap/{capture_id}/packets")
    assert response.status_code == 200
    body = response.json()
    assert len(body["packets"]) == 100  # default limit
    assert body["total"] == 150
    assert body["offset"] == 0
    assert body["limit"] == 100
    assert body["packets"][0]["no"] == 1


def test_explicit_offset_and_limit(tmp_path):
    packets = [
        Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=1000 + i, dport=80)
        for i in range(30)
    ]
    capture_id = _upload(tmp_path, packets)

    response = client.get(f"/api/pcap/{capture_id}/packets", params={"offset": 10, "limit": 5})
    assert response.status_code == 200
    body = response.json()
    assert len(body["packets"]) == 5
    assert [p["no"] for p in body["packets"]] == [11, 12, 13, 14, 15]


def test_packet_rows_carry_real_mac_and_port_data(tmp_path):
    packets = [
        Ether(src="3C:52:82:1A:0F:22", dst="A4:83:E7:2C:9B:11")
        / IP(src="192.168.1.42", dst="142.250.72.14")
        / TCP(sport=51372, dport=443)
    ]
    capture_id = _upload(tmp_path, packets)

    response = client.get(f"/api/pcap/{capture_id}/packets")
    assert response.status_code == 200
    row = response.json()["packets"][0]
    # Scapy normalizes MAC addresses to lowercase once a packet is
    # actually parsed from wire bytes (as every uploaded .pcap is) —
    # this isn't something PacketParser does, it's how Scapy itself
    # represents a dissected Ether layer.
    assert row["src_mac"] == "3c:52:82:1a:0f:22"
    assert row["dst_mac"] == "a4:83:e7:2c:9b:11"
    assert row["src_port"] == 51372
    assert row["dst_port"] == 443
    assert row["source"] == "192.168.1.42"
    assert row["destination"] == "142.250.72.14"


def test_limit_beyond_max_is_rejected_with_422(tmp_path):
    packets = [Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=1000, dport=80)]
    capture_id = _upload(tmp_path, packets)

    response = client.get(f"/api/pcap/{capture_id}/packets", params={"limit": 10_000})
    assert response.status_code == 422


def test_negative_offset_is_rejected_with_422(tmp_path):
    packets = [Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=1000, dport=80)]
    capture_id = _upload(tmp_path, packets)

    response = client.get(f"/api/pcap/{capture_id}/packets", params={"offset": -1})
    assert response.status_code == 422
