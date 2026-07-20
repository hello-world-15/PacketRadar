# Data Contracts — Top Applications

Covers the Top Applications table on Live Monitor.

---

## Top Applications Table

**Frontend location:** `src/components/ProcessTable.tsx`, fed from `src/pages/LiveMonitor.tsx`.
**Type:** `TopApplication` in `src/types/index.ts` — already exists (mock data used this shape from day one), no frontend type changes needed. Its `icon` field is filled client-side (see "Icons are frontend-only" below); the backend payload doesn't have one.

**Push or pull:** Push — same reasoning as Top Talkers.

**Transport:** WebSocket event `applications:update`, on the same `/ws/live` socket as everything else.

**Payload:**
```json
{
  "type": "applications:update",
  "data": [
    {
      "pid": 8420,
      "name": "chrome.exe",
      "upload_kbps": 128.4,
      "download_kbps": 942.1,
      "connections": 6
    }
  ]
}
```

**Field notes:**
| Field | Type | Source |
|---|---|---|
| `pid` | `int` | OS process id at the time of the most recent packet credited to it — see "PID reuse" below |
| `name` | `str` | Process name as reported by the OS via `psutil.Process(pid).name()` — `"chrome.exe"` on Windows, `"chrome"` on Linux/macOS (no extension) |
| `upload_kbps` | `float` | Smoothed over a 5s rolling window, same convention as `talkers.md`'s `bandwidth_mbps` |
| `download_kbps` | `float` | Same, separate window — see "why two windows" below |
| `connections` | `int` | Distinct flows attributed to this pid within the last 30s, same TTL concept as `talkers.md` |

**Cadence:** Every 2 seconds. Sends the top 12 applications by combined upload+download, same limit/ranking pattern as Top Talkers.

**How a packet gets attributed to a process.** Unlike every other engine in this codebase, this is the one place capture needs OS-level state beyond the packet itself: `app.capture.process_resolution.ProcessResolver` wraps `psutil.net_connections()` to build a `(proto, local_port) -> (pid, name)` table. `PacketCapture._on_packet` figures out which side of a TCP/UDP packet is *this machine* (reusing the same `_classify_direction`/`local_ips` logic `stats.md`'s upload/download split already established), looks up that local port, and — if it resolves — credits the packet to that pid in both directions (upload if this machine is the source, download if it's the destination).

**Why polled, not per-packet.** `psutil.net_connections()` is a full OS connection-table scan — far too expensive to run for every captured packet. `ProcessResolver` keeps a snapshot refreshed at most once every 2 seconds; packets between refreshes look up against whatever snapshot is current. Trade-off: a connection that opens and fully closes between two refreshes can be missed entirely. Accepted for the same reason `stats.md` accepts windowed rather than instantaneous numbers — this is a "what's using my bandwidth right now" dashboard, not a packet-perfect audit log.

**Why two separate smoothing windows instead of one.** Top Talkers has one `bandwidth_mbps` because "how much is this IP talking" has no inherent direction. This widget's whole purpose is showing the up/down split per app (`ProcessTable` has separate Upload/Download columns), so `TopApplicationsEngine` keeps upload and download as two independent rolling windows rather than one combined number it would then have to split back apart.

**PID reuse.** If the OS reuses a pid for a different process between snapshots, `TopApplicationsEngine.record_packet` detects the name mismatch and starts a fresh record rather than blending the old process's history into the new one's — same principle `ProcessResolver` already follows by rebuilding its pid→name cache from scratch on every refresh instead of patching the old one.

**Known limitation — same privilege requirement as capture itself.** Seeing other users' processes (not just your own) via `psutil.net_connections()` typically needs the same root/Administrator elevation packet capture already requires — this doesn't add a new permissions ask. If resolution fails for permission reasons, `ProcessResolver` returns nothing rather than raising; the table will simply stay empty rather than the app failing to start. Traffic that can't be attributed to a local process (e.g. this machine is a router/promiscuous-mode observer, not the connection's actual endpoint) is silently excluded from this widget — it's still fully counted everywhere else (`stats:update`, Top Talkers, Live Packet Stream).

**Icons are frontend-only.** Which emoji represents `"chrome.exe"` is presentation, not data — `src/data/mockData.ts`'s `appIcons` map (already built for the mock version of this table) is reused for real data too, in `useLiveSocket.ts`'s `toApplication()` converter. A process name with no entry in that map falls back to a generic icon, same as the mock data always did.
