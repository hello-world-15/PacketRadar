# Data Contracts — Top Talkers

Covers the Top Talkers table on Live Monitor.

---

## Top Talkers Table

**Frontend location:** `src/components/TopTalkersTable.tsx`, fed from `src/pages/LiveMonitor.tsx`.
**Type:** `TopTalker` in `src/types/index.ts` — already exists (mock data used this shape from day one), no frontend type changes needed.

**Push or pull:** Push — a SOC dashboard shouldn't require a manual refresh to see who's currently dominating bandwidth.

**Transport:** WebSocket event `talkers:update`, on the same `/ws/live` socket as everything else.

**Payload:**
```json
{
  "type": "talkers:update",
  "data": [
    {
      "ip": "192.168.1.42",
      "hostname": null,
      "packets": 48213,
      "bandwidth_mbps": 4.821,
      "bandwidth_pct": 100,
      "connections": 6
    }
  ]
}
```

**Field notes:**
| Field | Type | Source |
|---|---|---|
| `ip` | `str` | Either the source or destination IP of a captured packet — a host is a "talker" whether it's sending or receiving |
| `hostname` | `str \| null` | Borrowed from `HostDiscoveryEngine.ip_hostnames()` (same resolver, same cache) when this IP matches a known host's current IP. `null` if unresolved or if this IP was never seen via ARP. |
| `packets` | `int` | Cumulative count for this IP since the capture session started — not windowed, matches how `protocol_distribution` already accumulates in `stats.md` |
| `bandwidth_mbps` | `float` | **Smoothed over a 5-second rolling window**, not the 1-second window `stats:update` uses for the overall KPI number — see "why 5s" below |
| `bandwidth_pct` | `float` (0–100) | This host's `bandwidth_mbps` relative to the single highest talker *in this snapshot* — recomputed every broadcast, not a fixed scale. Powers the progress bar. |
| `connections` | `int` | Distinct flows (5-tuples) touching this IP within the last 30s — same TTL concept `active_connections` already uses in `stats.md` |

**Cadence:** Every 2 seconds. Sends the top 12 talkers by bandwidth, not the full host table.

**Why a 5s window for bandwidth instead of reusing the 1s window `stats:update` already computes?** A single aggregate number (total bandwidth) is fine to show at 1s resolution — it's one number, jitter there just looks "live." A 12-row table with progress bars re-ranking and bouncing every second reads as noisy, not live. 5 seconds is long enough to smooth a network's natural burstiness without feeling stale for a page that's meant to feel real-time.

**Hostname resolution.** Same resolver as `hosts.md`, not a separate one — `TopTalkersEngine` stays IP-only and has no resolver of its own; `app.ws.live_socket._talkers_loop` passes `host_engine.ip_hostnames()` into `snapshot(hostname_lookup=...)` on every tick, so a talker gets a hostname exactly when `HostDiscoveryEngine` has already resolved one for that IP. `hostname` stays `null` for talkers whose IP hasn't been seen via ARP (e.g. purely off-subnet traffic) or has no PTR record. Frontend still handles `hostname: null` → "Unknown Device" for `TopTalkersTable.tsx`.

**Note on counting both directions:** a single packet from A to B increments *both* A's and B's packet/byte counters. This is intentional — "how much of the network is this host responsible for" should count traffic whether the host is the sender or the receiver. It does mean the sum of all talkers' bandwidth will exceed total network bandwidth (each packet counted twice) — acceptable for a ranking table, not something this contract claims to be a partition of total traffic.
