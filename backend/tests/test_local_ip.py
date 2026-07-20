"""
Unit tests for app.capture.local_ip. No Scapy, no live capture, no root
required — this module only ever touches stdlib `socket`.
"""

import socket

from app.capture import local_ip


def test_resolve_local_ips_returns_a_set_of_strings():
    ips = local_ip.resolve_local_ips()
    assert isinstance(ips, set)
    assert all(isinstance(ip, str) for ip in ips)


def test_resolve_local_ips_always_includes_loopback():
    # Loopback capture should always classify as local, regardless of
    # whether the machine has any other network configured.
    ips = local_ip.resolve_local_ips()
    assert "127.0.0.1" in ips


def test_resolve_local_ips_never_raises_when_hostname_lookup_fails(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("no such host")

    monkeypatch.setattr(socket, "gethostbyname_ex", boom)
    # Should fall through to the route-probe method (or just loopback)
    # instead of propagating the exception.
    ips = local_ip.resolve_local_ips()
    assert "127.0.0.1" in ips


def test_resolve_local_ips_never_raises_when_route_probe_fails(monkeypatch):
    class ExplodingSocket:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def connect(self, *args, **kwargs):
            raise OSError("network is unreachable")

    monkeypatch.setattr(socket, "socket", lambda *a, **k: ExplodingSocket())
    ips = local_ip.resolve_local_ips()
    # Total network failure — should degrade to just the always-local set
    # rather than raising and blocking capture startup.
    assert "127.0.0.1" in ips


def test_resolve_local_ips_never_raises_when_everything_fails(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("nope")

    monkeypatch.setattr(socket, "gethostbyname_ex", boom)
    monkeypatch.setattr(socket, "gethostname", boom)

    class ExplodingSocket:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def connect(self, *args, **kwargs):
            raise OSError("nope")

    monkeypatch.setattr(socket, "socket", lambda *a, **k: ExplodingSocket())

    ips = local_ip.resolve_local_ips()
    assert ips == {"127.0.0.1", "::1"}
