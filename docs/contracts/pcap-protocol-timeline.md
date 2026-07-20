# Data Contracts — PCAP Analyzer: Protocol Distribution + Traffic Timeline

Reads from the same `PcapAnalysisStore` entry `pcap-upload.md`'s
`POST /api/pcap/upload` populates — no re-parsing. Named as a candidate
in that contract's "Next candidates" list.

---

## Why this is REST, not WebSocket

Same reasoning as every other PCAP Analyzer module: an uploaded capture
is a static, finite dataset once parsed. There's no "live" concept to
justify a socket — one `GET`, one snapshot.

## Endpoint

**Frontend location:** `src/pages/PcapAnalyzer.tsx`'s Protocol
Distribution and Traffic Timeline chart cards.

`GET /api/pcap/{capture_id}/protocol-timeline`

**Response:**
```json
{
  "protocol_distribution": [
    { "label": "TCP", "value": 812 },
    { "label": "UDP", "value": 340 },
    { "label": "DNS", "value": 96 }
  ],
  "timeline": [
    { "label": "14:32", "value": 44 },
    { "label": "14:33", "value": 61 }
  ]
}
```

`404` (same error body shape as `get_hosts_conversations` in
`app/api/pcap.py`) if `capture_id` isn't in the store — either it never
existed or it aged out (`PcapAnalysisStore` only keeps the 5 most recent
uploads).

## Protocol Distribution

Counts every stored packet by its already-classified `protocol` field.
`PacketParser` (shared with live capture) already assigned this label at
parse time — this module does no reclassification of its own, it only
tallies what's already there. Sorted descending by count, matching this
codebase's existing convention for ranked lists (e.g. `pcap_insights.py`'s
Top Domains) so the largest slice of the pie always renders first.

| Field | Type | Source |
|---|---|---|
| `label` | `string` | `PacketModel.protocol`, verbatim |
| `value` | `int` | Count of packets with that protocol, across the whole capture |

## Traffic Timeline

**The old mock faked 24 fixed hourly buckets (`"0:00"` .. `"23:00"`) —
meaningless for a capture of any length other than exactly a day.**
Replaced with real, evenly-spaced buckets across the capture's *own*
actual duration:

- **Bucket count:** fixed at 24, matching the mock's original visual
  density (the `TimelineChart` line component reads fine at that
  resolution regardless of what real span it now represents).
- **Bucket width:** `duration_seconds / 24`, where `duration_seconds` is
  the same `max(timestamp) - min(timestamp)` definition `pcap_summary.md`
  already uses for the Capture Summary's `duration_seconds` field — not
  recomputed differently here.
- **Bucket label — real clock time (e.g. `"14:32"`), not a relative
  offset (`"+0:07"`).** A relative-offset axis needs its own unit choice
  that changes with capture length (seconds for a 3-minute capture,
  minutes for a 3-hour one) and doesn't answer the question a person
  reading a report actually has — "what time did this happen" — the way
  a wall-clock label does. This does mean two different captures analyzed
  side by side won't visually "line up" on a shared relative timeline,
  but nothing in this app compares two captures at once, so that
  trade-off costs nothing today.
- **Bucket value: packet count**, not bytes/bandwidth. Simplest, and
  conceptually the offline counterpart of the Live Monitor's own "Live
  Traffic (Packets/sec)" line — same unit family, just totals instead of
  a rate. Switching to bytes would need a separate design decision this
  module doesn't need to make yet; not attempted here.
- **Zero-duration handling:** a capture with exactly one packet, or where
  every packet happens to share the same timestamp, has a real duration
  of `0.0` — there is no time axis to spread 24 buckets across. Rather
  than divide by zero (or silently produce 24 buckets, 23 of them empty
  and meaningless), this case returns a **single** bucket holding every
  packet, labeled at that shared timestamp. The frontend's existing
  `TimelineChart` renders a 1-point line fine; no special-casing needed
  there.
- **Boundary packet:** the packet at the exact maximum timestamp
  computes to bucket index `bucket_count` (one past the end) under plain
  `offset / bucket_width` division — it's clamped into the last bucket
  (`bucket_count - 1`) rather than dropped or raising an index error.

| Field | Type | Source |
|---|---|---|
| `label` | `string` | Each bucket's start time, `strftime("%H:%M")` |
| `value` | `int` | Packet count falling in that bucket's `[start, start + width)` window (last bucket is closed on both ends, see "Boundary packet" above) |

## Known limitations

- **Minute-granularity labels can repeat** for a very short capture
  (bucket width under 60s) — e.g. two adjacent buckets both starting
  within the same clock minute both render `"14:32"`. The x-axis order
  is still correct (buckets are emitted start-to-end), only the *label
  text* can be ambiguous at a glance for sub-minute-wide buckets. Not
  fixed here — a capture that short is an edge case this v1 accepts
  rather than adding sub-minute label formatting for.
- **No timezone handling beyond whatever `PacketModel.timestamp` already
  carries** (naive datetimes, same as every other PCAP Analyzer module —
  see `pcap-upload.md`'s reuse of `PacketParser`). Labels reflect
  whatever timezone the parsed timestamps are already in, not
  necessarily the viewer's local time.
- **Protocol labels are exactly whatever `PacketParser` already
  produced** — this module does not know or care about the live
  classification order `stats.md` documents (ARP → DNS → TCP → UDP →
  ICMP → Other); it just groups by the string that's already on each
  `PacketModel`. If that live classification ever changes, this module's
  output changes with it for free, with no changes needed here.
