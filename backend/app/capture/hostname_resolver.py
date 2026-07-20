"""
Hostname resolution for discovered hosts.

Reverse DNS (PTR) lookups are a blocking network call, so they must
never happen inline on the sniffer thread or the active-scan thread —
see docs/contracts/hosts.md. Instead this module owns a small pool of
background worker threads: resolution requests get queued by whichever
capture path (passive sniffing or active sweep) sees a MAC/IP pairing,
resolved off the hot path, and pushed back into HostDiscoveryEngine via
`update_hostname()` once done.

Deliberately best-effort, matching the same pragmatism the rest of the
capture layer already accepts elsewhere in this codebase:
  - Failures (NXDOMAIN, no PTR record, timeout) leave hostname as None
    — most consumer/IoT devices on a LAN simply don't have one, and
    that's a legitimate result, not an error worth retrying aggressively.
  - Each MAC is only re-resolved on a cooldown, not on every single
    sighting — DHCP renewals and active-sweep hits fire far more often
    than a hostname could plausibly change.
  - A handful of daemon worker threads (not one-shot threads per
    lookup) so a slow/unreachable DNS server can only ever stall a
    fraction of the queue, never all of it, and never blocks process
    shutdown.

Known limitation: `socket.gethostbyaddr()` doesn't accept a per-call
timeout (it goes through the OS resolver, not a socket object, so
`socket.setdefaulttimeout()` has no effect on it). A single lookup can
therefore occasionally run long. Accepted rather than worked around —
this is the same stdlib-only, no-new-dependency trade-off local_ip.py
already documents, and WORKER_COUNT > 1 keeps one slow lookup from
starving the others.
"""

from __future__ import annotations

import socket
import threading
import time
from queue import Empty, Queue

from app.engines.host_discovery import HostDiscoveryEngine

RESOLVE_COOLDOWN_SECONDS = 600.0  # don't re-resolve the same MAC more than once per 10 min
WORKER_COUNT = 4


class HostnameResolver:
    def __init__(self, host_engine: HostDiscoveryEngine) -> None:
        self._host_engine = host_engine
        self._queue: "Queue[tuple[str, str]]" = Queue()
        self._cooldown_lock = threading.Lock()
        self._last_attempt: dict[str, float] = {}  # mac -> unix ts
        self._workers: list[threading.Thread] = []
        self._running = False

    def start(self) -> None:
        """Idempotent — safe to call multiple times (e.g. if capture
        restarts); only spins up workers once."""
        if self._running:
            return
        self._running = True
        for _ in range(WORKER_COUNT):
            t = threading.Thread(target=self._worker_loop, daemon=True)
            t.start()
            self._workers.append(t)

    def stop(self) -> None:
        """Signals workers to exit after their current lookup (if any).
        Not awaited/joined — these are daemon threads and a lookup in
        flight is allowed to finish naturally rather than being killed,
        same tolerance the rest of the capture layer gives in-flight
        work during shutdown."""
        self._running = False

    def request(self, mac: str, ip: str) -> None:
        """Queue a (mac, ip) pair for resolution, subject to the
        per-MAC cooldown. Cheap and safe to call on every passive ARP
        sighting and every active-sweep hit — most calls are a no-op
        dict lookup that returns immediately."""
        now = time.time()
        with self._cooldown_lock:
            last = self._last_attempt.get(mac)
            if last is not None and (now - last) < RESOLVE_COOLDOWN_SECONDS:
                return
            self._last_attempt[mac] = now
        self._queue.put((mac, ip))

    def _worker_loop(self) -> None:
        while self._running:
            try:
                mac, ip = self._queue.get(timeout=1.0)
            except Empty:
                continue
            hostname = self._resolve(ip)
            if hostname is not None:
                self._host_engine.update_hostname(mac, hostname)

    @staticmethod
    def _resolve(ip: str) -> str | None:
        try:
            name, _aliases, _addrs = socket.gethostbyaddr(ip)
            return name
        except (socket.herror, socket.gaierror, OSError):
            # No PTR record, malformed address, or resolver error —
            # all just mean "no hostname available," not a bug.
            return None
