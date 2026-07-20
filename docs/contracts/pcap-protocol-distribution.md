# Data Contract — PCAP Analyzer: Protocol Distribution

Fourth module on the PCAP Analyzer page's backend, alongside Capture
Summary (`pcap-upload.md`), Top Hosts + Conversations
(`pcap-hosts-conversations.md`), and DNS Analysis (`pcap-dns-analysis.md`).
Read `pcap-upload.md` first — this reuses the same `PcapAnalysisStore`
entry every other module reads from.

Originally scoped together with Traffic Timeline as one candidate
("Protocol Distribution + Traffic Timeline" in `pcap-upload.md`'s "Next
candidates"). Split the same way Top Hosts+Conversations and DNS
Analysis were split out of their own original groupings — Protocol
Distribution and Traffic Timeline answer different questions ("what kind
of traffic" vs. "when did it happen") and don't share a computation.
**Traffic Timeline is out of scope here and still mock** — named
explicitly rather than silently left half-done.

---

## Why this is the simplest PCAP Analyzer module so far

Every other module has needed its own aggregation logic — Top Hosts
needed a bandwidth average, DNS Analysis needed to walk query/answer
pairs. Protocol Distribution needs none of that: `PacketParser.parse()`
(the same parser both live capture and this upload endpoint already call
— see `pcap-upload.md`'s "never duplicate packet parsing logic" mandate)
has *already* classified every packet's `protocol` field to one of
exactly six values (`TCP`, `UDP`, `ICMP`, `DNS`, `ARP`, `OTHER`) by the
time it lands in `PcapAnalysisStore`. This module is a `Counter` over a
field that already exists — nothing to classify, nothing to re-parse.

**Why not reuse `app.capture.sniffer._protocol_label`?** That live-capture
classifier exists *only* because live packets flow through a fast,
minimal path (`record_packet` in `statistics.py`) that intentionally
skips `PacketParser`'s full parse for performance — see that module's
own docstring. An uploaded file has no such constraint: every packet
already went through the full parser once at upload time, so there's a
second, richer classification sitting right there (`PacketModel.protocol`)
that the live path simply doesn't have. Re-deriving a label from raw
Scapy layers here would be strictly worse than reading the one the
parser already computed — a second classifier would even risk *drifting*
from the parser's own logic over time.

**One naming reconciliation:** the parser's fallback label is `"OTHER"`
(matching its own internal convention), but the frontend's `Protocol`
union (`src/types/index.ts`) and the existing live-stats contract
(`stats.md`) both use `"Other"`. This module normalizes that one label
on the way out (`"OTHER" -> "Other"`); the other five values already
match the union exactly and pass through unchanged.

---

## Endpoint

`GET /api/pcap/{capture_id}/protocol-distribution`

**Response**, matching `stats.md`'s existing `protocol_distribution`
field shape exactly (same `ProtocolCount` schema, reused from
`app.schemas.stats` rather than redefined — see below):
```json
{
  "protocol_distribution": [
    { "label": "TCP", "value": 340 },
    { "label": "UDP", "value": 58 },
    { "label": "DNS", "value": 22 },
    { "label": "ARP", "value": 4 },
    { "label": "ICMP", "value": 1 }
  ]
}
```

- Raw counts, not percentages — the frontend already computes
  percentages itself for the live version's identical shape
  (`ProtocolPieChart`), so this deliberately doesn't duplicate that math
  server-side.
- **Only protocols actually present appear** — a capture with no ICMP
  traffic simply omits `"ICMP"` rather than sending `{"label": "ICMP",
  "value": 0}`. Matches the live version's behavior
  (`StatisticsEngine._protocol_counts` is a `Counter`, which never
  reports a key it hasn't seen).
- **Sorted by count, descending.** Unlike the live version (which sends
  `Counter.items()` in whatever insertion order protocols were first
  seen, fine for a pie chart nobody reads top-to-bottom), a static
  capture's distribution is worth showing busiest-first for anyone
  scanning the raw numbers, and a fixed dataset can afford to be
  deterministic about it. Ties broken by a fixed canonical order (`TCP,
  UDP, DNS, ICMP, ARP, Other`) so the response is byte-identical across
  repeated requests for the same capture.
- `404` with a clear error body if `capture_id` isn't in the store — same
  as every other module reading from `PcapAnalysisStore`.

**Schema reuse, not duplication:** `ProtocolCount` (`{label: str, value:
int}`) already exists in `app.schemas.stats` for the live version. This
module imports it directly rather than defining an identical class in a
`pcap_protocol.py` — the two schemas are the same *shape by definition*
(same frontend `Protocol` union backs both), so a second class would be
either a copy that must be kept in sync forever or an invitation for the
two to quietly drift. `ProtocolDistributionResponse` (the one new class
this module adds, in `app.schemas.pcap_protocol`) just wraps a
`list[ProtocolCount]`.

---

## Known limitations

- Traffic Timeline (the other half of the originally-grouped candidate)
  is still mock — a separate future module, not attempted here.
- No hostname/IP dimension here at all — this is purely "what protocols
  appeared and how often," unrelated to Top Hosts/Conversations' per-IP
  breakdown. Cross-referencing "which hosts sent the ICMP traffic" isn't
  something this endpoint answers; Packet Explorer (future module, with
  a protocol filter) is the right place for that drill-down.
