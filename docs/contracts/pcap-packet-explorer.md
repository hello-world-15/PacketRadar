# Data Contracts — PCAP Analyzer: Packet Explorer

Fourth backend module for the PCAP Analyzer page, building on
`pcap-upload.md` (Capture Summary + `PcapAnalysisStore`). Read that first
— this module reads from the same store, doesn't re-parse the file.

---

## REST, paginated, not a full dump

Like every other PCAP Analyzer endpoint, this is REST, not WebSocket — a
finished upload is a closed dataset, there's nothing to push. But unlike
Capture Summary or DNS Analysis (small, fixed-size aggregates), the raw
packet list itself can be up to `MAX_PACKETS` (200,000, see
`pcap-upload.md`) rows. Returning all of them in one response would mean
serializing/transferring/rendering 200k rows just to look at the first
page — a real cost for zero benefit, the same reasoning `packets.md`
already used to justify a delta feed over a full-snapshot broadcast for
live capture, just applied to pagination instead of streaming.

**Endpoint:** `GET /api/pcap/{capture_id}/packets?offset=0&limit=100`

- `offset` — 0-based, default `0`.
- `limit` — default `100`, clamped to a max of `500` per request (both
  enforced at the FastAPI parameter level, so an out-of-range request
  gets a clean `422` rather than reaching application code).

**Response:**
```json
{
  "packets": [
    {
      "no": 1,
      "time": 1752345212.481,
      "source": "192.168.1.42",
      "destination": "142.250.72.14",
      "protocol": "TCP",
      "length": 583,
      "info": "TCP 51372 \u2192 443 [PSH, ACK]",
      "src_mac": "3C:52:82:1A:0F:22",
      "dst_mac": "A4:83:E7:2C:9B:11",
      "src_port": 51372,
      "dst_port": 443,
      "dns_query": null,
      "dns_answer": null
    }
  ],
  "total": 48213,
  "offset": 0,
  "limit": 100
}
```

**`no` is the packet's position in the *whole capture*, not the page** —
`offset + index_in_page + 1`. So packet `#4,102` means the same thing
regardless of what page you fetched it on, matching the existing "Packet
#N" convention `packets.md`'s live stream and the drawer subtitle already
use. Renumbering per-page (`1, 2, 3...` on every page) would make that
label meaningless.

**`404`** if `capture_id` doesn't exist or has aged out of
`PcapAnalysisStore` (same 5-most-recent-uploads limitation as every other
PCAP Analyzer endpoint).

---

## Why this response carries more fields than the live `PacketRow`

Live capture's `packets:update` (`packets.md`) deliberately keeps its
per-packet payload small — it's rebroadcast every 0.5s to every connected
client, so extra fields are a recurring bandwidth cost. A finished
upload's packet list is the opposite: it's fetched once per page, on
demand, only when the analyst actually opens the drawer for a specific
row. That budget difference is why this endpoint includes `src_mac`,
`dst_mac`, `src_port`, and `dst_port` — real values needed to make the
Packet Details drawer's "Ethernet II" and per-protocol port fields
genuine instead of the hardcoded placeholders they used to be — where the
live version doesn't bother.

---

## What the drawer can — and can't — honestly show

The existing Packet Details drawer UI (built before any backend existed
for it) had **six** hardcoded fields: Src/Dst MAC, Source, Destination,
TTL, Src/Dst Port, Flags, Length, plus a hex dump and an ASCII view.
Once wired to `PacketModel`, most of these become real. Two don't, and
this module does **not** fake them to preserve the UI's old look:

- **TTL is dropped.** `PacketParser` never extracts or stores a TTL
  value anywhere in `PacketModel` — it was never part of the "parse
  once, reuse everywhere" internal representation any other module
  reads. Adding it now, only for this one drawer field, would mean
  either re-parsing the file a second time (against this codebase's
  explicit "never duplicate packet parsing logic" rule) or extending
  `PacketModel` for a field literally nothing else uses. Named here as a
  legitimate future addition to `PacketParser`, not silently dropped —
  the drawer simply omits the row rather than showing a fabricated
  number.
- **Hex View / ASCII View are replaced with an honest note.**
  `PacketModel` stores `payload_size` (an int) but never the actual
  payload bytes — by design: retaining raw bytes for every packet in a
  200,000-packet capture is a real memory cost this codebase has never
  needed to pay for anything else it does (stats, DNS, threats, hosts —
  none of them need the actual bytes, only structured fields parsed out
  of them). Making the hex/ASCII views real would mean either storing
  every packet's full payload in memory for the life of the upload, or
  re-reading the original `.pcap` file from disk on every drawer open —
  a real architectural decision, not a one-line fix, so it's surfaced
  honestly as a known limitation rather than resolved by continuing to
  show three lines of hex that have nothing to do with the packet you
  clicked.

Also changed: **Flags** is no longer its own field — `PacketParser`
never stores TCP flags separately either, only folded into the existing
`info` string (e.g. `"TCP 51372 → 443 [PSH, ACK]"`). Rather than parse
that string back apart client-side (fragile, and duplicating logic that
belongs in the parser if it's ever needed as a first-class field), the
drawer shows `info` directly as one line — it already contains the flags
for TCP, the ICMP type label, or the DNS query/response summary,
whichever applies.

---

## Filtering stays client-side, same limitation as `packets.md`

`FilterBar`'s search/protocol filters still only filter whatever page(s)
have actually been fetched into the browser — not a server-side query
across the full capture. A "Load More" button grows the loaded set by
fetching the next page and appending it, rather than a traditional
page-number pager, so filtering feels continuous as more of the capture
loads. Exactly the same trade-off `packets.md` already names for the
live table, just extended to pagination instead of a live buffer cap.

---

## Known limitations

- No server-side search — see "Filtering stays client-side" above.
- No TTL, no raw hex/ASCII payload — see "What the drawer can — and
  can't — honestly show" above. Both are legitimate future additions to
  `PacketParser`/`PacketModel`, not bugs in this module.
- Bounded by the same `MAX_PACKETS` (200,000) parse cap as every other
  PCAP Analyzer module — a larger capture is only ever explorable up to
  whatever was actually parsed and stored.
- `total` reflects however many packets were actually stored (post
  `MAX_PACKETS` cap), not the original file's true packet count if it
  was truncated.

---

*Next candidates: Protocol Distribution + Traffic Timeline are the only
PCAP Analyzer widgets still on mock data after this module.*
