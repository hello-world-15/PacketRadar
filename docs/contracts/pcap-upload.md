# Data Contracts — PCAP Analyzer: Upload & Capture Summary

First module of the PCAP Analyzer page's backend (previously 100% mock).
Covers the upload flow and the six Capture Summary cards. Everything else
on this page — Protocol Distribution, Timeline, Top Hosts, Conversations,
DNS Analysis, Threat Analysis, Health Score, Packet Explorer — is a
separate, later module that reads from the same stored analysis this one
produces. Nothing else on the page is touched by this task.

---

## Why this is REST, not WebSocket

Every Live Monitor module so far has been push/streaming, because live
capture is continuous. PCAP analysis is the opposite: a single file comes
in, gets parsed once, and the result doesn't change again. A one-shot
`POST` that returns the summary is the right shape — there's no "live"
concept here to justify a socket.

## Upload & Analyze

**Frontend location:** `src/components/UploadZone.tsx` (the "Analyze
Capture" button) and `src/pages/PcapAnalyzer.tsx`.

**Endpoint:** `POST /api/pcap/upload`, multipart form body, field name
`file`. Accepts `.pcap` / `.pcapng` only — anything else is rejected with
`400` before any parsing is attempted.

**Response:**
```json
{
  "capture_id": "a3f9c2e1b7d44f0a9c8e1b2d3f4a5b6c",
  "filename": "office-capture.pcapng",
  "summary": {
    "packet_count": 128430,
    "duration_seconds": 1080.442,
    "avg_packet_size_bytes": 612,
    "unique_hosts": 47,
    "connection_count": 892,
    "dns_request_count": 3120
  }
}
```

**`capture_id`** is the handle every later module (Protocol Distribution,
Timeline, Top Hosts, etc.) will use to fetch more views of the *same*
already-parsed capture without re-uploading or re-parsing the file. This
is the whole reason this module exists as its own foundational piece
before anything else on the page.

**Field notes (Capture Summary):**
| Field | Type | Source |
|---|---|---|
| `packet_count` | `int` | `len(packets)` after parsing |
| `duration_seconds` | `float` | `max(timestamp) - min(timestamp)` across all parsed packets — real capture timestamps from the file, not "time we happened to parse it" (see "The timestamp bug" below) |
| `avg_packet_size_bytes` | `int` | `total_length / packet_count`, rounded |
| `unique_hosts` | `int` | Distinct `src_ip`/`dst_ip` values across all packets, excluding the parser's `"Unknown"` placeholder |
| `connection_count` | `int` | Distinct `flow_key` values (same 5-tuple-ish key the live parser already computes per packet) |
| `dns_request_count` | `int` | Count of packets where `protocol == "DNS"` and `dst_port == 53` — the same condition `PacketParser` uses internally to distinguish a query from a response, recomputed here from the already-parsed `PacketModel` rather than re-inspecting the raw packet |

## Reusing `PacketParser` — and the timestamp bug it required fixing

The architecture mandates uploaded files reuse the exact same parser live
capture uses — no duplicate parsing logic. `PacketParser.parse()` already
did this cleanly for every field **except one**: it hardcoded
`timestamp=datetime.now()` inside itself. That's correct for live capture
(a packet really was just seen "now"), but wrong for an uploaded file,
where every packet has its own real capture timestamp already embedded in
the `.pcap` (Scapy exposes it as `packet.time`). Parsing an uploaded file
through the unmodified parser would have given every packet in the file
the same "right now" timestamp — silently breaking `duration_seconds`
(would read ~0) and any future Traffic Timeline module before it's even
built.

**Fix:** `PacketParser.parse()` now takes an optional `timestamp:
datetime | None = None` keyword argument. When omitted, behavior is
byte-for-byte identical to before (`datetime.now()`), so the one existing
live-capture call site (`sniffer.py`) needed no changes. The PCAP upload
path passes `datetime.fromtimestamp(float(pkt.time))` explicitly. This is
a genuine bug fix surfaced by the "reuse, don't duplicate" mandate doing
its job — the parser was never exercised with real historical timestamps
before this task.

## Where parsed results live: `PcapAnalysisStore`

`app/cache/pcap_store.py` — an in-memory dict keyed by `capture_id`,
holding the full list of parsed `PacketModel`s plus the computed summary.
Bounded to the 5 most recent uploads (simple oldest-evicted-first), so
repeated uploads in one session can't grow memory without bound. This is
a single-user local app with no requirement to survive a server restart —
an in-memory store is the right scope here, not a database. Every later
PCAP Analyzer module reads from this same store via `capture_id` instead
of re-parsing.

## Known limitations

- **File size / packet count isn't streamed to the client during
  parsing** — a very large file makes the upload request take longer with
  no progress feedback beyond the existing spinner. A `MAX_PACKETS` safety
  cap (200,000) prevents an enormous file from parsing indefinitely or
  exhausting memory; parsing stops at that cap rather than failing, and
  the summary reflects only the packets actually parsed. Named as a
  scope cut, not silently truncating without limit.
- **No background/async job queue.** Parsing happens synchronously inside
  the request handler. Fine at portfolio-project scale; a genuinely huge
  file or a multi-user deployment would need this to become a background
  task with polling/webhook completion instead. Not attempted here.
- **Uploaded `.pcap` files are written to disk** (`backend/pcap_uploads/`,
  gitignored) so Scapy's `PcapReader` can stream-parse without holding the
  whole file in memory twice. They are never deleted automatically after
  parsing — acceptable for local single-user use, but a real cleanup
  policy (TTL, explicit delete endpoint) is a legitimate future addition,
  not implemented here.
- **`unique_hosts` counts ARP participants too** (ARP's `psrc`/`pdst` are
  real IPs) — not just IP/TCP/UDP endpoints. This matches what a human
  would consider "a host on this network," not a strict Layer 3 traffic
  count.

---

## Analyzing an already-recorded capture

`UploadZone` also offers a dropdown alongside "Browse Files" that lists
files Live Monitor's Start/Stop Recording has already saved to
`backend/captures/` (see `app.capture.sniffer.CAPTURES_DIR`), so a
capture recorded earlier doesn't have to be exported and re-uploaded by
hand to analyze it.

**`GET /api/pcap/captures`** — lists those files, newest first (by file
mtime, not by parsing the `capture_YYYYMMDDTHHMMSSZ.pcap` filename
convention, so it stays correct even if that naming ever changes):
```json
[
  { "filename": "capture_20260717T133932Z.pcap", "size_bytes": 483920, "captured_at": "2026-07-17T13:39:32+00:00" }
]
```

**`POST /api/pcap/captures/{filename}/analyze`** — runs the exact same
parse-and-store flow as `/upload` above, just reading the bytes from
`backend/captures/{filename}` instead of a multipart body. Returns the
identical `PcapUploadResponse` shape (`capture_id`, `filename`,
`summary`), so the frontend's `capture_id`-based modules downstream of
this don't need to know or care which entry point produced it. Rejects
any `filename` containing a path separator (`400`) so this can't be used
to read arbitrary files off disk, and `404`s if the named file isn't
actually sitting in `backend/captures/`.

*Everything named above as a "next candidate" has since been built —
Protocol Distribution + Traffic Timeline (`pcap-protocol-timeline.md`),
Top Hosts + Conversations (`pcap-hosts-conversations.md`), DNS Analysis
+ Threat Analysis + Network Health Score (`pcap-analysis.md`, plus a
dedicated, better Threat Analysis in `pcap-threat-analysis.md`), and
Packet Explorer (`pcap-packet-explorer.md`). See `backend/README.md`'s
PCAP Analyzer status table for the current list of what's real. Only
Export PDF Report remains mock.*
