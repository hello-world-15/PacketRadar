"""
Unit tests for app.cache.hostname_store.HostnameStore — all against a
temp file (pytest's tmp_path), never the real backend/data/known_hosts.json.
"""

from __future__ import annotations

from app.cache.hostname_store import HostnameStore


def test_get_returns_none_for_unknown_mac(tmp_path):
    store = HostnameStore(path=tmp_path / "known_hosts.json")
    assert store.get("AA:BB:CC:00:00:01") is None


def test_set_then_get_round_trips(tmp_path):
    store = HostnameStore(path=tmp_path / "known_hosts.json")
    store.set("AA:BB:CC:00:00:01", "Johns-iPhone")
    assert store.get("AA:BB:CC:00:00:01") == "Johns-iPhone"


def test_set_ignores_empty_hostname(tmp_path):
    store = HostnameStore(path=tmp_path / "known_hosts.json")
    store.set("AA:BB:CC:00:00:01", "")
    assert store.get("AA:BB:CC:00:00:01") is None


def test_persists_across_new_instances(tmp_path):
    path = tmp_path / "known_hosts.json"
    HostnameStore(path=path).set("AA:BB:CC:00:00:01", "Kitchen-Chromecast")

    # Fresh instance, same file — simulates a backend restart.
    reloaded = HostnameStore(path=path)
    assert reloaded.get("AA:BB:CC:00:00:01") == "Kitchen-Chromecast"


def test_missing_file_starts_empty_not_an_error(tmp_path):
    store = HostnameStore(path=tmp_path / "does-not-exist" / "known_hosts.json")
    assert store.all() == {}


def test_corrupt_file_starts_empty_not_an_error(tmp_path):
    path = tmp_path / "known_hosts.json"
    path.write_text("{not valid json", encoding="utf-8")
    store = HostnameStore(path=path)
    assert store.all() == {}


def test_all_returns_full_snapshot(tmp_path):
    store = HostnameStore(path=tmp_path / "known_hosts.json")
    store.set("AA:BB:CC:00:00:01", "Johns-iPhone")
    store.set("AA:BB:CC:00:00:02", "Kitchen-Chromecast")
    assert store.all() == {
        "AA:BB:CC:00:00:01": "Johns-iPhone",
        "AA:BB:CC:00:00:02": "Kitchen-Chromecast",
    }


def test_creates_parent_directory_if_missing(tmp_path):
    path = tmp_path / "nested" / "data" / "known_hosts.json"
    store = HostnameStore(path=path)
    store.set("AA:BB:CC:00:00:01", "Johns-iPhone")
    assert path.exists()
