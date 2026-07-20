"""
Integration tests for GET /api/pcap/{capture_id}/threats — builds real
synthetic .pcap files with Scapy's wrpcap and uploads them through the
real FastAPI endpoints end to end, same pattern as
test_pcap_upload_api.py. No root/elevated privileges needed.
"""

from datetime import datetime
from pathlib import Path

from fastapi.testclient import TestClient
from scapy.all import ARP, IP, TCP, Ether, wrpcap

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
    response = client.get("/api/pcap/not-a-real-capture-id/threats")
    assert response.status_code == 404
    assert "capture_id" in response.json()["detail"].lower() or "capture" in response.json()["detail"].lower()


def test_clean_capture_returns_empty_threats_list(tmp_path):
    packets = [
        Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=1234, dport=80),
        Ether() / IP(src="10.0.0.5", dst="10.0.0.10") / TCP(sport=1235, dport=443),
    ]
    capture_id = _upload(tmp_path, packets)

    response = client.get(f"/api/pcap/{capture_id}/threats")
    assert response.status_code == 200
    assert response.json() == {"threats": []}


def test_port_scan_pattern_in_real_uploaded_pcap_is_detected(tmp_path):
    packets = [
        Ether() / IP(src="203.0.113.44", dst="10.0.0.9") / TCP(sport=51000, dport=1000 + i)
        for i in range(20)
    ]
    capture_id = _upload(tmp_path, packets)

    response = client.get(f"/api/pcap/{capture_id}/threats")
    assert response.status_code == 200
    threats = response.json()["threats"]
    assert len(threats) == 1
    assert threats[0]["reason"] == "Port Scan Detected"
    assert threats[0]["source"] == "203.0.113.44"
    assert threats[0]["severity"] == "medium"
    assert "distinct host:port pairs" in threats[0]["evidence"]
    assert threats[0]["recommendation"]


def test_arp_conflict_in_real_uploaded_pcap_is_detected(tmp_path):
    packets = [
        Ether() / ARP(psrc="192.168.1.1", pdst="192.168.1.42", hwsrc="AA:AA:AA:AA:AA:AA", op=2),
        Ether() / ARP(psrc="192.168.1.1", pdst="192.168.1.42", hwsrc="BB:BB:BB:BB:BB:BB", op=2),
        Ether() / ARP(psrc="192.168.1.1", pdst="192.168.1.42", hwsrc="BB:BB:BB:BB:BB:BB", op=2),
    ]
    capture_id = _upload(tmp_path, packets)

    response = client.get(f"/api/pcap/{capture_id}/threats")
    assert response.status_code == 200
    threats = response.json()["threats"]
    assert len(threats) == 1
    assert threats[0]["reason"] == "Possible ARP Spoofing"
    assert threats[0]["source"] == "192.168.1.1"
    assert threats[0]["severity"] == "high"
