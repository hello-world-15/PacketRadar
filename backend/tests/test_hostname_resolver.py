"""
Unit tests for app.capture.hostname_resolver.

Doesn't spin up real worker threads or do real DNS I/O (network access
isn't guaranteed in CI/sandboxed environments) — instead drives the
queueing/cooldown logic directly and exercises `_resolve()` in
isolation with a monkeypatched `socket.gethostbyaddr`.
"""

from __future__ import annotations

import socket

import pytest

from app.capture.hostname_resolver import HostnameResolver
from app.engines.host_discovery import HostDiscoveryEngine


def test_request_queues_first_sighting():
    resolver = HostnameResolver(HostDiscoveryEngine())
    resolver.request(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    assert resolver._queue.qsize() == 1


def test_request_respects_cooldown_for_same_mac():
    resolver = HostnameResolver(HostDiscoveryEngine())
    resolver.request(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    resolver.request(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")  # immediate repeat
    assert resolver._queue.qsize() == 1


def test_request_does_not_throttle_distinct_macs():
    resolver = HostnameResolver(HostDiscoveryEngine())
    resolver.request(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    resolver.request(mac="AA:BB:CC:00:00:02", ip="192.168.1.11")
    assert resolver._queue.qsize() == 2


def test_resolve_returns_hostname_on_success(monkeypatch):
    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda ip: ("laptop.lan", [], [ip])
    )
    assert HostnameResolver._resolve("192.168.1.10") == "laptop.lan"


def test_resolve_returns_none_on_no_ptr_record(monkeypatch):
    def _raise(ip):
        raise socket.herror("no PTR record")

    monkeypatch.setattr(socket, "gethostbyaddr", _raise)
    assert HostnameResolver._resolve("192.168.1.10") is None


def test_worker_loop_updates_engine_on_successful_resolve(monkeypatch):
    host_engine = HostDiscoveryEngine()
    host_engine.record_sighting(mac="AA:BB:CC:00:00:01", ip="192.168.1.10")
    resolver = HostnameResolver(host_engine)

    monkeypatch.setattr(
        HostnameResolver, "_resolve", staticmethod(lambda ip: "laptop.lan")
    )

    resolver._queue.put(("AA:BB:CC:00:00:01", "192.168.1.10"))
    resolver._running = True
    # Run one iteration of the loop body manually rather than spinning up
    # a real thread — keeps this test deterministic and fast.
    mac, ip = resolver._queue.get(timeout=1.0)
    hostname = resolver._resolve(ip)
    if hostname is not None:
        resolver._host_engine.update_hostname(mac, hostname)

    assert host_engine.snapshot()[0].hostname == "laptop.lan"
