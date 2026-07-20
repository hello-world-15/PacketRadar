# Data Contracts — Packets

Covers the Live Packet Stream table on Live Monitor. This is **Module 3**,
following Module 1 (Stats) and Module 2 (Hosts) — see their contracts for
why capture lifecycle and socket-sharing work the way they do.

---

## Live Packet Stream Table

**Frontend location:** `src/components/PacketTable.tsx`, fed from `src/pages/LiveMonitor.tsx`.
**Type:** `PacketRow` in `src/types/index.ts` (existed for the mock generator; gained two optional fields, `dnsQuery`/`dnsAnswer`, for the DNS detail below).

**Push or pull:** Push, but **delta**, not snapshot — unlike `hosts:update`.
Host Discovery re-sends the *whole* table every 3s because it's small and
rarely changes. A packet stream is neither: resending a 2,000-row buffer
every tick just to deliver the one new row would be wasted bandwidth and
wasted re-renders. So this event only ever carries packets the client
hasn't seen yet.

**Transport:** WebSocket event `packets:update`, on the same `/ws/live`
socket as `stats:update` and `hosts:update` — same reasoning as
`hosts.md`'s "why one shared socket" section: one capture lifecycle, one
connection, multiple event types dispatched by `type`.

**Payload:**
```json
{
  "type": "packets:update",
  "data": [
    {
      "no": 10432,
      "time": 1752345212.481,
      "source": "192.168.1.42",
      "destination": "142.250.72.14",
      "protocol": "TCP",
      "length": 583,
      "process": null,
      "info": "TCP 51372 → 443 [PSH, ACK]"
    },
    {
      "no": 10433,
      "time": 1752345212.981,
      "source": "192.168.1.42",
      "destination": "8.8.8.8",
      "protocol": "DNS",
      "length": 71,
      "process": null,
      "info": "DNS response: example.com (A) → 93.184.216.34",
      "dns_query": "example.com (A)",
      "dns_answer": "93.184.216.34"
    }
  ]
}
```

**Field notes:**
| Field | Type | Source |
|---|---|---|
| `no` | `int` | Monotonically increasing sequence number assigned by the Packet Stream Engine, per capture session (not per-packet-on-the-wire — it's our own counter) |
| `time` | `float` (unix seconds) | Timestamp when we parsed the packet. Sent raw, same as `hosts.md`'s `last_seen` — formatting is a frontend concern |
| `source` / `destination` | `str` | IP address only (Wireshark convention) — ports live in `info`, not their own columns, matching the existing `PacketRow` shape |
| `protocol` | `str` | One of `TCP \| UDP \| ICMP \| DNS \| ARP \| Other`. DNS is detected as UDP on port 53, not its own transport |
| `length` | `int` | Total packet length in bytes, `len(packet)` |
| `process` | `str \| null` | **Stubbed at `null`** — see known limitation below |
| `info` | `str` | Human-readable summary line — TCP flags with ports, ICMP type, ARP who-has/is-at, or the DNS query/response summary described below |
| `dns_query` | `str \| null` | **Only present when `protocol == "DNS"`.** The domain and record type asked about, e.g. `"example.com (A)"` — set on both the query and the response (a response echoes the question it's answering) |
| `dns_answer` | `str \| null` | **Only present when `protocol == "DNS"`.** Comma-joined resolved values (IPs for A/AAAA, hostnames for CNAME/NS/PTR/MX, etc.). `null` on the query half, and also `null` on a response with no answer records (NXDOMAIN, SERVFAIL) — check `info` for the response code in that case |

**DNS detail, since it's the richest single protocol here:** DNS is
identified as UDP traffic on port 53 in either direction — not a
separate Scapy transport layer. Once flagged as DNS, the packet's
question/answer sections are parsed for the actual domain name and
resolved value(s), not just labeled "DNS query"/"DNS response" the way
a bare port-number heuristic would. A handful of common record types
(A, AAAA, CNAME, NS, PTR, MX, TXT, SRV, SOA, ANY) get friendly names;
anything else falls back to its raw numeric QTYPE. A response with no
answer records (NXDOMAIN, SERVFAIL, etc.) surfaces the actual DNS
response code in `info` instead of silently looking like an unresolved
query.

**Cadence:** Every 0.5s, and **only rows recorded since the last tick**,
capped at 500 rows per frame so a client that stalls for a few ticks
can't be handed a multi-thousand-row frame in one go. Faster than
`stats:update` (1s) because a stalled-out packet table reads as broken
in a way a one-second-late KPI number doesn't.

**New connection backlog:** A client that connects mid-session would
otherwise stare at a blank table until the next tick. To match the
project's "never show a broken/blank state" rule (see backend README),
the server sends one immediate `packets:update` frame containing the
most recent buffered rows (up to 100) right after the socket accepts,
before the regular tick loop starts. The frontend doesn't need to treat
this differently — it dedupes/merges by `no` the same way it does for
every other frame.

**Known limitation — no process attribution.** Real per-packet process
names require correlating the 5-tuple against the OS's live socket table
(e.g. `psutil.net_connections()` on a poll loop, joined by port). That's
a real feature with real cross-platform quirks (needs elevated
permissions on some OSes, races with short-lived connections) — it's a
separate module, not attempted here. `process` is always `null` in v1;
the frontend already renders that as an em dash, same pattern as
`hostname: null` in the Hosts contract.

**Known limitation — client-side filtering only.** The search box and
protocol/port/process filters in `FilterBar` filter the client's already-
buffered rows, not a real BPF capture filter applied at the sniffer. A
device generating enough traffic to blow past the buffer before you find
what you're looking for won't be helped by this. Real capture-side
filtering (passing a BPF string into `AsyncSniffer(filter=...)`) is a
reasonable v2 addition, flagged as a decision to make, not solved here.

---

## Why a ring buffer instead of unbounded storage

The Packet Stream Engine keeps a bounded `deque` (default 2,000 packets)
the same way `StatisticsEngine` keeps a bounded rolling window — memory
must stay flat regardless of how long a capture runs. Older packets are
silently evicted. Full-capture persistence (so you could scroll back
further than the buffer, or re-open a past session) is a separate Export
module, not this one.

---

*Next candidate: **Threat Detection Engine** (would unblock the
`threat_alert_count` stub the same way Module 2 unblocked
`lan_device_count`), or **Process Attribution** (would unblock the
`process` field stubbed here).*
