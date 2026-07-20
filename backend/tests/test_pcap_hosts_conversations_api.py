"""
Integration tests for GET /api/pcap/{capture_id}/hosts-conversations.
Populates PcapAnalysisStore directly (bypassing a real file upload,
same shortcut test_pcap_summary.py's unit tests take at the engine
level) so this only exercises the route + store lookup, not the parser.
"""

from datetime import datetime

from fastapi.testclient import TestClient

from app.cache.pcap_store import pcap_store
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
        dst_port=443,
        protocol="TCP",
        length=1000,
        payload_size=950,
        flow_key="10.0.0.1:1234-10.0.0.2:443-TCP",
        info="TCP",
    )
    defaults.update(overrides)
    return PacketModel(**defaults)


def test_unknown_capture_id_returns_404():
    response = client.get("/api/pcap/does-not-exist/hosts-conversations")
    assert response.status_code == 404
    assert "detail" in response.json()


def test_known_capture_id_returns_hosts_and_conversations():
    packets = [_packet(), _packet(src_ip="10.0.0.2", dst_ip="10.0.0.1")]
    summary = compute_summary(packets)
    pcap_store.save("test-capture-1", "test.pcap", packets, summary)

    response = client.get("/api/pcap/test-capture-1/hosts-conversations")
    assert response.status_code == 200

    body = response.json()
    ips = {h["ip"] for h in body["top_hosts"]}
    assert ips == {"10.0.0.1", "10.0.0.2"}
    assert len(body["conversations"]) == 1
    assert body["conversations"][0]["packets"] == 2
