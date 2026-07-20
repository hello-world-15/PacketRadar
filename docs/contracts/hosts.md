# Data Contracts — Hosts

Covers the Active Host Discovery table on Live Monitor. Also the source
of truth for `lan_device_count` in `stats:update` (see `stats.md`) —
that field was stubbed at 0 in Module 1 pending this engine.

---

## Active Host Discovery Table

**Frontend location:** `src/components/HostTable.tsx`, fed from `src/pages/LiveMonitor.tsx`.
**Type:** `DiscoveredHost` in `src/types/index.ts`.

**Push or pull:** Push — the table should reflect newly-seen devices without a manual refresh.

**Transport:** WebSocket event `hosts:update`, on the same `/ws/live` socket as `stats:update` (see "Why one socket" below) — not a separate connection.

**Payload:**
```json
{
  "type": "hosts:update",
  "data": [
    {
      "ip": "192.168.1.42",
      "mac": "3C:52:82:1A:0F:22",
      "hostname": null,
      "last_seen": 1752345212.481,
      "status": "online"
    }
  ]
}
```

**Field notes:**
| Field | Type | Source |
|---|---|---|
| `ip` | `str` | ARP packet's sender protocol address (`psrc`) |
| `mac` | `str` | ARP packet's sender hardware address (`hwsrc`) |
| `hostname` | `str \| null` | Reverse-DNS name, resolved asynchronously off the capture thread. `null` until resolved, and stays `null` for hosts with no PTR record — see "hostname resolution" below. |
| `last_seen` | `float` (unix seconds) | Timestamp of the most recent ARP packet seen from this MAC. Sent as a raw timestamp, not a pre-formatted string — formatting is a frontend concern. |
| `status` | `"online" \| "offline"` | Derived from a consecutive-missed-sweep-cycle counter, not a raw age cutoff — see "Online/offline logic" below. |

**Cadence:** Every 3 seconds. Slower than `stats:update` (1s) deliberately — host presence doesn't need to update at the same resolution as bandwidth, and a full-table push every second would be wasted re-renders for data that rarely changes second-to-second.

**Why ARP and not just "any packet with an IP + MAC"?** Regular IP traffic captured on your NIC often only shows your *router's* MAC address as the layer-2 source (everything past your router got there through it), not the actual originating device. ARP is link-local by nature — it's never routed — so an ARP packet's hardware address reliably belongs to a real device on your segment. That's true whether the ARP traffic is *observed* (passive sniffing) or *solicited* (the active sweep below) — either way, this table only ever calls `HostDiscoveryEngine.record_sighting(mac, ip)`.

**Active sweep, not passive-only.** `app.capture.active_scan.ActiveScanner` runs on its own background thread and, every 30s, ARP-requests every address on the Wireless LAN adapter's subnet (resolved from that adapter's own default gateway — the same value `ipconfig` shows under "Wireless LAN adapter Wi-Fi:" -> "Default Gateway" — via Scapy's routing table, netmask via `psutil`, the actual sweep via Scapy's `srp()`), feeding replies into the same `record_sighting()` entrypoint passive sniffing uses. This closes the original passive-only gap: a device that's active on the network but hasn't sent/received ARP recently (long-lived TCP connections, low ARP-cache churn) would previously not show up until it happened to. The sweep still only covers the local broadcast domain — devices behind a different subnet/VLAN won't answer — and skips subnets larger than 65,534 addresses as a safety guard against a misconfigured route turning into an enormous sweep. Each cycle also individually unicast-re-probes every already-known host in addition to this broadcast round — see "Online/offline logic" below for why.

**Hostname resolution.** Two independent sources feed `hostname`, both best-effort:

- **DHCP Option 12 (primary).** `app.capture.sniffer` reads the "Host Name" option directly off DHCP DISCOVER/REQUEST packets the device itself broadcasts — the same name shown on a router's own DHCP client-list page (e.g. "Johns-iPhone", "DESKTOP-A1B2C3"). No network call needed; it's parsed synchronously from a packet already captured. If a DHCP packet with a hostname arrives before this MAC has any ARP/sweep sighting yet (common — DISCOVER/REQUEST routinely precede the client's first ARP), the name is held as a pending hint and attached automatically the moment the host record is created.
- **Reverse-DNS PTR (fallback).** `app.capture.hostname_resolver.HostnameResolver` owns a small pool of background worker threads doing `socket.gethostbyaddr()` off the capture/sweep threads, triggered by both passive ARP sightings and active-sweep hits, subject to a 10-minute per-MAC cooldown.

Whichever source resolves a name first wins and is never overwritten by the other — DHCP names are both more commonly available and friendlier than PTR results for most consumer/IoT gear, so if DHCP already supplied a name, a later PTR result is ignored rather than replacing it. `hostname` stays `null` for any host neither source produced a name for (no DHCP broadcast observed and no PTR record) — a normal, expected outcome for plenty of devices, not an error — which is why the frontend still falls back to displaying "Unknown Device" for those.

**Online/offline logic.** Status used to be a pure `last_seen` age cutoff (≤75s = online). That had a real failure mode: the active sweep's discovery round is a single *broadcast* ARP request per cycle, and 802.11 doesn't retransmit or ACK broadcast/multicast frames the way it does unicast — and a device in WiFi power-save mode only wakes for buffered broadcast traffic at fixed DTIM intervals. So it was common for a genuinely present, reachable device to simply miss one broadcast probe through no fault of its own and get shown as "offline" despite being online the whole time.

The fix is two changes working together, both in `app.engines.host_discovery` and `app.capture.active_scan`:

1. **Targeted unicast re-probe.** Each sweep cycle now does two passes: the existing subnet-wide broadcast round (still needed to discover brand-new hosts), followed by an individual, unicast-addressed ARP request to every host already known, sent directly to its last-known MAC. Unicast frames DO get real 802.11 MAC-layer ACK+retry, so re-confirming an already-known host this way is far more reliable than depending on the broadcast round alone.
2. **Consecutive-miss counter instead of a raw timer.** `HostRecord.misses` counts consecutive completed sweep cycles (`HostDiscoveryEngine.end_sweep_cycle()`, called once per cycle by `ActiveScanner`) in which a host wasn't reconfirmed by *any* means — passive sighting, broadcast discovery, or its own unicast re-probe. `record_sighting()` resets `misses` to 0 on every call, regardless of source. A host only flips to `"offline"` once `misses >= OFFLINE_AFTER_MISSES` (2) — one lost frame, broadcast or unicast, is no longer enough on its own.

A `PASSIVE_ONLY_TTL_SECONDS` (300s) age backstop still exists underneath this, for the case where `ActiveScanner` isn't running at all (disabled, missing the elevated privileges raw ARP needs, or no WiFi default route found) — in that situation `end_sweep_cycle()` is never called, `misses` never moves, and without a backstop a host seen exactly once would read "online" forever. 5 minutes is deliberately generous, since pure-passive mode has no way to distinguish "idle" from "gone."

`last_seen` itself is unaffected by any of this — it's still just "the most recent timestamp any sighting arrived," used for both display and the passive-only backstop; `misses` is a separate, independent counter that's what actually drives status when the active sweep is running normally.

---

## Why one shared WebSocket instead of a second connection

Module 1 built `/ws/stats`. Rather than open a second `/ws/hosts` connection, this module renames it to `/ws/live` and multiplexes both event types over one socket, dispatched by the existing `type` field. Two sockets would mean duplicating capture-lifecycle management (start-on-connect/stop-on-disconnect) for no real benefit, and `ws/manager.py` already left a comment anticipating this. One connection, two event types, two independent broadcast intervals.

---

*Next candidate: **Bandwidth Chart** (needs a time-series buffer instead of a single snapshot), or **Threat Detection Engine** (would unblock the `threat_alert_count` stub the same way this unblocks `lan_device_count`).*
