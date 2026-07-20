"""
Persistent MAC -> hostname store.

Device names (see app.engines.host_discovery — DHCP Option 12
primarily, reverse-DNS PTR as a fallback) previously only lived in
memory: a name learned during one capture session was forgotten the
moment the backend restarted, and the host table would show "Unknown
Device" for that device all over again until it happened to send
another DHCP broadcast or a fresh PTR lookup resolved. This module
persists the mapping to a small JSON file on disk so a name, once
learned, survives restarts.

Keyed by MAC rather than IP: a MAC address is the stable identity for
a physical device on the LAN, while its IP can (and often does) change
on every DHCP renewal. Looking a device up by "whatever IP it has right
now" would lose the name the moment its lease changed — MAC doesn't
have that problem, which is also why HostDiscoveryEngine's own live
table is keyed by MAC internally.

Known limitation, accepted rather than worked around: once a name is
persisted for a MAC, it's never overwritten by a later resolution for
that same MAC — same "first name wins, no flapping" policy
HostDiscoveryEngine already applies in-memory between its own DHCP and
PTR sources (see that module's docstring), just extended to survive
across restarts too. A device that gets renamed later (rare, but
possible — a phone's DHCP hostname can change after a factory reset,
for instance) will keep showing its old stored name rather than
picking up the new one automatically; clearing that one entry (or the
whole file) is the escape hatch, since nothing here treats this as
permanent, authoritative data.

Deliberately simple: this is a small (one row per device ever seen on
the LAN — realistically dozens to low hundreds of entries) dict written
as plain JSON, not a database — matching the same proportionate-
complexity choices the rest of the capture layer makes (see
local_ip.py's docstring for the same reasoning applied elsewhere).
"""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock

# backend/data/known_hosts.json — sits next to captures/ and
# pcap_uploads/ as another piece of on-disk, gitignored runtime state,
# specific to whatever LAN this machine happens to be capturing on.
DEFAULT_STORE_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "known_hosts.json"


class HostnameStore:
    """Thread-safe MAC -> hostname persistence, backed by a JSON file.

    Every write is flushed to disk immediately rather than
    batched/debounced: hostname updates are rare (once per newly-seen
    device, occasionally refreshed) rather than a per-packet operation,
    so there's no meaningful performance cost to keeping the on-disk
    copy always current — and it means a crash or `kill -9` right after
    a name is learned still keeps it.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or DEFAULT_STORE_PATH
        self._lock = Lock()
        self._entries: dict[str, str] = self._load()

    def _load(self) -> dict[str, str]:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError:
            return {}  # no file yet — first run, or a fresh data/ dir
        try:
            data = json.loads(raw)
        except ValueError:
            # Corrupt/partial file (e.g. process killed mid-write on an
            # unusual filesystem) — start fresh rather than crashing
            # capture startup over a cache file.
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items() if v}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Write to a temp file then rename — rename is atomic on
            # both POSIX and Windows, so a crash mid-write can never
            # leave known_hosts.json half-written/corrupt for the next
            # startup's _load() to trip over.
            tmp_path = self._path.with_suffix(".json.tmp")
            tmp_path.write_text(
                json.dumps(self._entries, indent=2, sort_keys=True), encoding="utf-8"
            )
            tmp_path.replace(self._path)
        except OSError:
            # Persistence is a nice-to-have, not load-bearing — a full
            # disk or permissions issue must not take capture down.
            pass

    def get(self, mac: str) -> str | None:
        """The previously-learned name for this MAC, if any — checked
        by HostDiscoveryEngine.record_sighting() when a host record is
        first created this session, so a device already known from a
        prior run shows its real name immediately instead of "Unknown
        Device" until it's rediscovered from scratch."""
        with self._lock:
            return self._entries.get(mac)

    def set(self, mac: str, hostname: str) -> None:
        """Persist a newly-learned name. Called by HostDiscoveryEngine
        only the first time a MAC gets a name in a given process
        (either from DHCP or PTR) — see this module's docstring for why
        later resolutions for an already-named MAC don't reach here."""
        if not hostname:
            return
        with self._lock:
            if self._entries.get(mac) == hostname:
                return  # already stored — skip the disk write
            self._entries[mac] = hostname
            self._save()

    def all(self) -> dict[str, str]:
        """Full MAC -> hostname snapshot, mainly for debugging/tests."""
        with self._lock:
            return dict(self._entries)
