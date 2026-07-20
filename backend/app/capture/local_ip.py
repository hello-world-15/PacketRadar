"""
Local IP resolution.

Module 6 (Real Bandwidth Chart) needs to know which side of a captured
packet is "this machine" so it can split total bandwidth into upload vs.
download. That means knowing this machine's own IP address(es).

Deliberately uses only the stdlib `socket` module rather than pulling in
a new dependency (e.g. psutil) for a single utility function — the
project's `requirements.txt` doesn't already carry it, and one small
function isn't a reason to add one. See docs/contracts/stats.md's
"Upload/download split" section for the full reasoning.

Two independent sources are combined into one set, since either can miss
addresses on its own:

  - `socket.gethostbyname_ex(hostname)`: resolves every address the OS
    associates with this machine's own hostname. Works offline, but on
    some systems (especially misconfigured /etc/hosts, or machines with
    no forward DNS entry for themselves) it can return nothing useful,
    or just 127.0.0.1.
  - The "UDP connect" trick: opening a UDP socket and calling connect()
    to a public address doesn't actually send any packets (UDP is
    connectionless — connect() here only tells the OS which local
    interface/address it *would* use to route there), then reading back
    the local address the OS picked via getsockname(). This reliably
    finds the primary outbound-facing address even when the hostname
    trick fails, but requires *some* route to exist (fails on a fully
    offline machine with no configured route at all).

Deliberately interface-agnostic — this asks "what IP does this machine
appear as", not "what IP is bound to the specific interface Scapy is
capturing on". On a typical single-NIC machine those are the same
address; see the known-limitation note in docs/contracts/stats.md for
where that assumption breaks down. Chasing full per-interface accuracy
across macOS/Linux/Windows would mean either shelling out to
platform-specific tools or adding psutil — more machinery than a
"split bandwidth in two" feature justifies, matching the same pragmatism
Host Discovery's ARP-only approach already accepts elsewhere in this
codebase.
"""

from __future__ import annotations

import socket

# Any machine can always reach itself — always include this so loopback
# traffic (captured on the loopback interface) still classifies as local.
_ALWAYS_LOCAL = {"127.0.0.1", "::1"}

# Public, always-routable address used only to ask the OS "which local
# address would you use to reach the internet" — see module docstring.
# No packet is actually sent; UDP connect() is purely local kernel state.
_ROUTE_PROBE_ADDR = ("8.8.8.8", 80)


def resolve_local_ips() -> set[str]:
    """Best-effort resolution of this machine's own IP address(es).

    Never raises — capture startup must not fail just because IP
    resolution didn't work in some environment (offline machine,
    sandboxed/CI container with no configured route, unusual DNS setup).
    Returns an empty set on total failure; callers must treat that as
    "direction unknown for every packet" rather than crashing. See
    docs/contracts/stats.md's "Fallback if local IP resolution fails".
    """
    ips: set[str] = set(_ALWAYS_LOCAL)

    try:
        hostname = socket.gethostname()
        _, _, addrs = socket.gethostbyname_ex(hostname)
        ips.update(addrs)
    except Exception:
        # No forward DNS/hosts entry for our own hostname, or no
        # hostname configured at all — fall through to the route-probe
        # method below rather than giving up.
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(_ROUTE_PROBE_ADDR)
            ips.add(probe.getsockname()[0])
    except Exception:
        # No route to the outside world (offline, sandboxed environment)
        # — leave whatever the hostname lookup above found, if anything.
        pass

    return ips
