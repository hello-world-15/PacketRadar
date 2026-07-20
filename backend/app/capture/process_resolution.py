"""
Local port -> PID/process name resolution, for Top Applications.

Unlike `local_ip.py`'s "which IP is this machine" question, "which
process owns local port N" has no reasonable stdlib answer on any of
the three platforms this app targets — it's a real OS-level
connection table lookup (`/proc/net/tcp` parsing on Linux,
`GetExtendedTcpTable`/`GetExtendedUdpTable` on Windows, `lsof`-style
APIs on macOS). `psutil` wraps all three behind one call
(`psutil.net_connections`) and is the standard, well-maintained way to
do this — the "just use stdlib" pragmatism that keeps local_ip.py
dependency-free doesn't apply here, since there's no equivalent trick
available. Added to requirements.txt for this reason.

Same privilege requirement as packet capture itself: seeing *other*
users' processes (not just your own) typically needs the same
root/Administrator elevation the sniffer already requires, so this
doesn't add a new permissions ask beyond what the app already needs to
run at all.

Design: resolving on every packet would mean an OS-wide connection-table
scan per packet, which is far too expensive to sit in the sniffer's
hot path. Instead this keeps a small TTL-cached snapshot, refreshed at
most once every REFRESH_INTERVAL_SECONDS, and _on_packet just does a
dict lookup against whatever snapshot is current. The trade-off: a
process that opens and closes a connection entirely between two refresh
ticks can be missed. Acceptable for a "what's using my bandwidth right
now" dashboard — see docs/contracts/applications.md.
"""

from __future__ import annotations

import socket
import time
from threading import Lock
from typing import Optional

import psutil

REFRESH_INTERVAL_SECONDS = 2.0


class ProcessResolver:
    """One instance for the process's lifetime, shared across packets.
    `resolve()` is what the capture layer calls; it transparently
    refreshes the underlying snapshot when it's gone stale."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._last_refresh = 0.0
        # (proto, local_port) -> (pid, process_name). Two separate port
        # spaces (TCP vs UDP) are kept in one dict keyed by proto so a
        # TCP port N and a UDP port N — a common, legal overlap — don't
        # collide.
        self._table: dict[tuple[str, int], tuple[int, str]] = {}
        # pid -> name, built fresh each refresh so a reused pid from an
        # exited process can never leak a stale name into the next scan.
        self._names: dict[int, str] = {}

    def _refresh(self, now: float) -> None:
        """Caller must already hold self._lock."""
        table: dict[tuple[str, int], tuple[int, str]] = {}
        names: dict[int, str] = {}

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Not running elevated — leave the table empty rather than
            # raising; process attribution is a nice-to-have on top of
            # capture, not a reason to break it. Same "documented
            # limitation, not hidden" convention as elsewhere in this
            # codebase (see StatisticsEngine's dropped_packets).
            self._table = {}
            self._names = {}
            self._last_refresh = now
            return
        except Exception:
            # Leave the previous (stale but plausible) table in place
            # rather than blanking it on a transient failure.
            self._last_refresh = now
            return

        for conn in connections:
            if conn.pid is None or conn.laddr is None or not conn.laddr.port:
                continue

            name = names.get(conn.pid)
            if name is None:
                try:
                    name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                names[conn.pid] = name

            proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
            table[(proto, conn.laddr.port)] = (conn.pid, name)

        self._table = table
        self._names = names
        self._last_refresh = now

    def resolve(self, proto: str, local_port: int) -> tuple[Optional[int], Optional[str]]:
        """Returns (pid, process_name) for a local (proto, port), or
        (None, None) if unmapped (e.g. traffic for a connection that
        closed since the last refresh, or resolution isn't available on
        this platform/permission level)."""
        now = time.time()
        with self._lock:
            if now - self._last_refresh >= REFRESH_INTERVAL_SECONDS:
                self._refresh(now)
            return self._table.get((proto, local_port), (None, None))
