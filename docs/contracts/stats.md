# Data Contracts — Stats

Covers every widget that is "a number in a card": the six Live Monitor KPI
cards, the six PCAP Analyzer summary cards, and the Network Health Score.
These are the simplest contracts in the app — no pagination, no filtering,
just current values.

---

## 1. Live Monitor — KPI Cards

**Frontend location:** `src/pages/LiveMonitor.tsx`, the `<StatCard>` grid at the top.
**Type:** `src/types/index.ts` has no dedicated type for this yet — it's six scalars, not worth a shared interface until the backend defines it. Suggest adding a `LiveStats` type once this contract is implemented.

**Push or pull:** Push. These change continuously while a capture is running.

**Transport:** WebSocket event `stats:update`, sent on the same connection as the packet stream (see Packets contract) but as a distinct event type/channel so the frontend can subscribe to just this one if a widget doesn't need packet-level data.

**Payload:**
```json
{
  "type": "stats:update",
  "data": {
    "packets_per_sec": 4218,
    "bandwidth_mbps": 38.4,
    "upload_mbps": 6.1,
    "download_mbps": 31.9,
    "active_connections": 214,
    "threat_alert_count": 6,
    "lan_device_count": 14,
    "dropped_packets": 132,
    "protocol_distribution": [
      { "label": "TCP", "value": 18420 },
      { "label": "UDP", "value": 3110 },
      { "label": "DNS", "value": 980 },
      { "label": "ICMP", "value": 44 },
      { "label": "ARP", "value": 12 },
      { "label": "Other", "value": 6 }
    ]
  }
}
```

**Field notes:**
| Field | Type | Source |
|---|---|---|
| `packets_per_sec` | `int` | Statistics Engine — count in rolling 1s window |
| `bandwidth_mbps` | `float` | Statistics Engine — bytes in rolling 1s window × 8 / 1e6, **all** captured traffic regardless of direction |
| `upload_mbps` | `float` | Statistics Engine — same rolling 1s window, restricted to packets whose *source* IP matched a local IP at capture start (see "Upload/download split" below) |
| `download_mbps` | `float` | Statistics Engine — same window, restricted to packets whose *destination* IP matched a local IP |
| `active_connections` | `int` | Statistics Engine — count of tracked flows with recent activity (needs a TTL, e.g. no packets seen in 30s = connection closed) |
| `threat_alert_count` | `int` | Running total of alerts raised by the Threat Detection Engine for the current capture session |
| `lan_device_count` | `int` | Count of hosts currently `online` from Host Discovery |
| `dropped_packets` | `int` | Cumulative, reported by the capture layer (e.g. Scapy/libpcap buffer drops) |
| `protocol_distribution` | `{label: string, value: int}[]` | Statistics Engine — **cumulative** count per protocol label since the capture started (unlike the fields above, this is *not* windowed — a distribution pie that reset every second would be useless). Raw counts, not percentages; the frontend computes percentages itself. Labels: `TCP \| UDP \| ICMP \| DNS \| ARP \| Other`, classified by the capture layer (`app.capture.sniffer._protocol_label`) — ARP frames first, then UDP on port 53 as DNS, then TCP, remaining UDP, then ICMP, else Other. |

### Upload/download split (Module 6)

`upload_mbps` and `download_mbps` land directly on `LiveStats` rather than
in a separate `bandwidth.md` contract or a new engine file. `StatisticsEngine`
already owns the single rolling 1s window and the combined `bandwidth_mbps`
number computed from it — direction is just another dimension of the same
per-packet event, not a different data source or a different cadence. A
new engine would mean re-deriving the same window twice for no benefit;
splitting it into its own doc would mean cross-referencing two files to
understand one number. Matches the project's stated bias against
over-engineering.

**How direction is determined:** at capture start, `app.capture.local_ip`
resolves the set of IP address(es) belonging to the machine running the
capture (see its docstring for the exact method — a UDP-connect trick plus
`gethostbyname_ex`, no new dependency). Each packet's source and
destination IP are checked against that set:
- source matches a local IP → **upload** (outbound)
- destination matches a local IP (and source didn't already match) →
  **download** (inbound)
- neither matches → **excluded from both** — this happens for LAN-to-LAN
  traffic between two other devices that this machine happens to see in
  promiscuous/monitor mode. It's still counted in the combined
  `bandwidth_mbps` total, just not attributable to "this machine's"
  upload or download. **Named limitation, not silently guessed at** — see
  README's "Known limitations".
- if *both* source and destination match a local IP (e.g. loopback
  traffic), it's counted as upload only, not both — arbitrary but
  harmless tie-break so loopback traffic doesn't double-count against the
  combined total.

**Fallback if local IP resolution fails** (e.g. no network interface up,
sandboxed/CI environment): `app.capture.local_ip` returns an empty set
rather than raising. Every packet then falls into "neither matches", so
`upload_mbps`/`download_mbps` stay at `0.0` while `bandwidth_mbps` (the
pre-existing combined total) is completely unaffected — capture startup
never fails because of this. Documented in `local_ip.py`'s docstring and
the README, not silently swallowed.

**Known limitation:** local IP resolution is interface-agnostic — it asks
the OS which address it would use to reach the internet and which
address(es) resolve for the machine's hostname, rather than specifically
querying the interface Scapy is capturing on. On a typical single-NIC
machine these are the same address. On a machine actively capturing on a
*different* interface than its default route (e.g. a secondary NIC, a VPN
tunnel), upload/download may misclassify. Same level of pragmatism as Host
Discovery's ARP-only approach — accepting incompleteness over chasing full
cross-platform per-interface correctness.

**Cadence:** Emitted once per second on a server-side timer. Do **not** emit per-packet — the frontend just re-renders the animated number on each tick, sub-second updates would be wasted work and visually jittery.

**Trend arrows** (the "↑ 12% vs last min" text under some cards): out of scope for v1 — the frontend currently hardcodes these. If we want them live, the backend would need to keep the previous minute's snapshot and diff it. Flagging this as a **decision to make, not assumed** — see open questions below.

**Idle/no-capture state:** when capture is stopped, the endpoint that starts a WS connection should either not emit `stats:update` at all, or emit one final `{ ...zeros, dropped_packets: <last known> }` frame so cards visibly reset instead of freezing on stale numbers.

---

## 2. PCAP Analyzer — Capture Summary Cards

**Frontend location:** `src/pages/PcapAnalyzer.tsx`, the `<StatCard>` grid rendered after `analyzed` becomes true.

**Push or pull:** Pull. One-shot — computed once when analysis finishes, never updates again for that capture.

**Transport:** REST. Part of the response from the "analyze this upload" endpoint (see Packets/Upload contract for the full response shape) — **not** a separate call. Splitting summary stats into their own endpoint would mean re-parsing the file twice for no reason.

**Endpoint:** `POST /api/pcap/analyze` (defined fully in the packets contract) — this section only documents the `summary` slice of that response.

**Payload slice:**
```json
{
  "summary": {
    "packet_count": 128430,
    "duration_seconds": 1080,
    "avg_packet_size_bytes": 612,
    "unique_hosts": 47,
    "connection_count": 892,
    "dns_request_count": 3120
  }
}
```

**Field notes:**
| Field | Type | Source |
|---|---|---|
| `packet_count` | `int` | `len(packets)` after parse |
| `duration_seconds` | `int` | `last_packet.time - first_packet.time` |
| `avg_packet_size_bytes` | `int` | `total_bytes / packet_count` |
| `unique_hosts` | `int` | Distinct source+destination IPs seen |
| `connection_count` | `int` | Distinct 5-tuples (src IP, dst IP, src port, dst port, protocol) |
| `dns_request_count` | `int` | Count of packets where `protocol == "DNS"` and it's a query (not response) |

Frontend displays `duration_seconds` as minutes — conversion happens client-side, backend sends raw seconds so the frontend controls formatting.

---

## 3. PCAP Analyzer — Network Health Score

**Frontend location:** `src/pages/PcapAnalyzer.tsx` → `<HealthGauge score={87} />` from `src/components/Charts.tsx`.

**Push or pull:** Pull, same response as the summary cards above — not a separate call.

**Payload slice:**
```json
{
  "health_score": {
    "score": 87,
    "label": "SAFE"
  }
}
```

**Field notes:**
- `score`: `int`, 0–100.
- `label`: one of `"SAFE" | "WARNING" | "HIGH_RISK"`. **Decision needed:** should the frontend derive the label from the score (it already does — see the `>= 80 / >= 50` thresholds baked into `HealthGauge`), or should the backend own the thresholds and send the label explicitly so the logic lives in one place? Recommend: **backend sends both**, frontend's local thresholds become a fallback/default only. Otherwise you have the scoring rule duplicated in two languages.
- **Not yet defined:** the actual scoring formula (how threat count/severity, encryption ratio, anomaly volume combine into 0–100). That belongs in the Threat Detection Engine design, not this contract — flagging it as a dependency, not solving it here.

---

## Open questions from this group

1. Do KPI card trend arrows ("↑ 12%") ship in v1, or do we drop them from the UI until there's a real diffing mechanism?
2. Where does `health_score` get computed — as part of the same analysis pass as the threat report, or a separate post-processing step? (Affects whether Phase 5 can build it standalone or needs the Threat Engine first.)

---

*Next group: **Tables** (Top Talkers, Top Applications, Top Hosts, Conversations).*
