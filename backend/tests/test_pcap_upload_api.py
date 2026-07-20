"""
Integration test for POST /api/pcap/upload — unlike every other test in
this suite, this one deliberately DOES touch Scapy and real file I/O: it
writes a small synthetic .pcap to a temp file with Scapy's own wrpcap,
then uploads it through the real FastAPI endpoint. This is the one place
worth testing the actual parse-a-real-file path end to end, since
`test_pcap_summary.py` already covers the aggregation logic in isolation.

No root/elevated privileges needed — writing/reading a .pcap file doesn't
require raw-socket access, only live capture does.
"""

from pathlib import Path

from fastapi.testclient import TestClient
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap

from app.main import app

client = TestClient(app)


def _build_test_pcap(tmp_path: Path) -> Path:
    packets = [
        Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=1234, dport=80),
        Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=5000, dport=53)
        / DNS(qd=DNSQR(qname="example.com")),
    ]
    path = tmp_path / "test.pcap"
    wrpcap(str(path), packets)
    return path


def test_upload_rejects_unsupported_extension(tmp_path):
    bad_file = tmp_path / "not-a-pcap.txt"
    bad_file.write_text("hello")
    with open(bad_file, "rb") as f:
        response = client.post(
            "/api/pcap/upload", files={"file": ("not-a-pcap.txt", f, "text/plain")}
        )
    assert response.status_code == 400


def test_upload_parses_real_pcap_and_returns_summary(tmp_path):
    pcap_path = _build_test_pcap(tmp_path)
    with open(pcap_path, "rb") as f:
        response = client.post(
            "/api/pcap/upload", files={"file": ("test.pcap", f, "application/octet-stream")}
        )
    assert response.status_code == 200

    body = response.json()
    assert body["filename"] == "test.pcap"
    assert isinstance(body["capture_id"], str) and len(body["capture_id"]) > 0

    summary = body["summary"]
    assert summary["packet_count"] == 2
    assert summary["dns_request_count"] == 1
    assert summary["connection_count"] == 2
    assert summary["unique_hosts"] == 3  # 10.0.0.5, 10.0.0.9, 8.8.8.8


def test_list_recorded_captures_empty_when_dir_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api.pcap.CAPTURES_DIR", tmp_path / "does-not-exist")
    response = client.get("/api/pcap/captures")
    assert response.status_code == 200
    assert response.json() == []


def test_list_recorded_captures_returns_pcap_files_newest_first(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api.pcap.CAPTURES_DIR", tmp_path)

    older = _build_test_pcap(tmp_path)
    older.rename(tmp_path / "capture_20260101T000000Z.pcap")
    newer = tmp_path / "capture_20260102T000000Z.pcap"
    _build_test_pcap(tmp_path).rename(newer)
    # A non-pcap file in the same directory should be ignored.
    (tmp_path / "notes.txt").write_text("hello")

    import os
    import time

    os.utime(tmp_path / "capture_20260101T000000Z.pcap", (time.time() - 100, time.time() - 100))

    response = client.get("/api/pcap/captures")
    assert response.status_code == 200
    body = response.json()
    filenames = [c["filename"] for c in body]
    assert filenames == ["capture_20260102T000000Z.pcap", "capture_20260101T000000Z.pcap"]
    assert all("size_bytes" in c and "captured_at" in c for c in body)


def test_analyze_recorded_capture_parses_file_from_captures_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api.pcap.CAPTURES_DIR", tmp_path)
    pcap_path = _build_test_pcap(tmp_path)
    recorded_name = "capture_20260103T000000Z.pcap"
    pcap_path.rename(tmp_path / recorded_name)

    response = client.post(f"/api/pcap/captures/{recorded_name}/analyze")
    assert response.status_code == 200

    body = response.json()
    assert body["filename"] == recorded_name
    assert body["summary"]["packet_count"] == 2


def test_analyze_recorded_capture_404s_for_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api.pcap.CAPTURES_DIR", tmp_path)
    response = client.post("/api/pcap/captures/does-not-exist.pcap/analyze")
    assert response.status_code == 404


def test_analyze_recorded_capture_rejects_path_traversal(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api.pcap.CAPTURES_DIR", tmp_path)
    response = client.post("/api/pcap/captures/..%2F..%2Fetc%2Fpasswd/analyze")
    assert response.status_code in (400, 404)


def test_repeated_uploads_get_distinct_capture_ids(tmp_path):
    pcap_path = _build_test_pcap(tmp_path)

    with open(pcap_path, "rb") as f:
        first = client.post(
            "/api/pcap/upload", files={"file": ("a.pcap", f, "application/octet-stream")}
        ).json()

    with open(pcap_path, "rb") as f:
        second = client.post(
            "/api/pcap/upload", files={"file": ("b.pcap", f, "application/octet-stream")}
        ).json()

    assert first["capture_id"] != second["capture_id"]


def test_insights_returns_404_for_unknown_capture_id():
    response = client.get("/api/pcap/does-not-exist/insights")
    assert response.status_code == 404


def test_insights_returns_real_data_for_uploaded_capture(tmp_path):
    pcap_path = _build_test_pcap(tmp_path)
    with open(pcap_path, "rb") as f:
        upload = client.post(
            "/api/pcap/upload", files={"file": ("test.pcap", f, "application/octet-stream")}
        ).json()

    response = client.get(f"/api/pcap/{upload['capture_id']}/insights")
    assert response.status_code == 200

    body = response.json()
    assert "dns" in body and "threats" in body and "health" in body
    assert 0 <= body["health"]["score"] <= 100
    assert isinstance(body["threats"], list)
    assert isinstance(body["dns"]["top_domains"], list)
