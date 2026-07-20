# Data Contracts — PCAP Analyzer: Top Hosts + Conversations

Third module of the PCAP Analyzer page's backend. Builds on
`pcap-upload.md` (Capture Summary + `PcapAnalysisStore`) — read that
first. Reuses `talkers.md`'s reasoning for *why* both source and
destination IP get credited on a packet — this is conceptually the
offline version of Top Talkers, just with a fixed dataset instead of a
live rolling window. Protocol Distribution, Traffic Timeline, DNS
Analysis, Threat Analysis, Network Health Score, and Packet Explorer
remain separate modules, untouched here.

---

## Why REST, not WebSocket

Same reasoning as every PCAP Analyzer module so far: the file is parsed
once and the result doesn't change. `GET /api/pcap/{capture_id}/hosts-conversations`
reads from the same already-parsed `PcapAnalysisStore` entry every other
module reads from — no re-parsing, no new upload.

**Endpoint:** `GET /api/pcap/{capture_id}/hosts-conversations`

**Response:**
```json
{
  "top_hosts": [
    { "ip": "192.168.1.42", "hostname": null, "packets": 4821, "bandwidth_mbps": 2.4, "bandwidth_pct": 100, "connections": 6 }
  ],
  "conversations": [
    { "a": "192.168.1.42", "b": "8.8.8.8", "packets": 340, "bytes": "1.2 MB", "duration": "4m 12s" }
  ]
}
```

`404` with a clear error body if `capture_id` doesn't exist or has aged
out of `PcapAnalysisStore` (only the 5 most recent uploads are kept —
same limitation as every other module reading from this store).

---

## Top Hosts

**Why this reuses Top Talkers' reasoning, not its mechanism.** Both
source and destination IP of every packet get credited — "how much of
this capture is this host responsible for" should count traffic whether
the host sent or received it, exactly the case `talkers.md` already
makes. What doesn't carry over is the *windowing*: `TopTalkersEngine`
smooths bandwidth over a live 5-second rolling window because packets
keep arriving and "current rate" is a meaningful, ever-changing number.
An uploaded file is finite — there's no "current rate" to smooth, only
one honest number: **average Mbps across the whole capture**
(`host_total_bytes * 8 / capture_duration_seconds / 1_000_000`). Copying
the rolling-window deque/eviction logic here would compute something
that looks like a rate but means nothing for a file that already
finished.

**`duration_seconds` reuse, not recomputation.** The denominator above is
the *whole capture's* duration — the same number `pcap_summary.py`
already computed as part of Capture Summary and that's sitting in
`PcapAnalysis.summary.duration_seconds` in the store. This module reads
that stored value rather than recomputing `max(ts) - min(ts)` over all
packets a second time — one already-parsed capture, one duration,
computed once. (Per-*conversation* duration below is a different, smaller
number — see that section.)

**`duration_seconds == 0` edge case.** A capture where every packet
shares one timestamp (a very short capture, or a file where Scapy only
retained one distinct timestamp) has nothing to divide by.
`bandwidth_mbps` is `0.0` for every host in that case rather than
raising — an average rate genuinely isn't defined over zero elapsed
time, so `0.0` communicates "not meaningful" without crashing the
endpoint. Documented, not silently guessed at.

**Fields, matching `TopTalker` in `src/types/index.ts` exactly** (same
shape as live Top Talkers, so `TopTalkersTable`-style rendering carries
over conceptually even though this page doesn't literally reuse that
component):

| Field | Type | Source |
|---|---|---|
| `ip` | `str` | Either the source or destination IP of a packet in this capture |
| `hostname` | `str \| null` | **Not resolved** — same documented limitation as `hosts.md`/`talkers.md`, always `null` |
| `packets` | `int` | Count of packets in this capture where this IP was source or destination |
| `bandwidth_mbps` | `float` | `host_total_bytes * 8 / capture_duration_seconds / 1_000_000`, `0.0` if `duration_seconds == 0` |
| `bandwidth_pct` | `float` (0–100) | This host's `bandwidth_mbps` relative to the single highest host **in this top-N list** — recomputed after ranking, same convention `talkers.md` uses |
| `connections` | `int` | Distinct `flow_key` values touching this IP **anywhere in the capture** — no 30s TTL here (unlike live Top Talkers' `active_connections`), because the whole file is already a bounded, finished dataset; "connections" for a static capture just means "how many distinct flows did this host appear in", full stop |

**Top-N count: 8.** Matches what the frontend mock (`topTalkers.slice(0, 8)`)
already showed — a capture summary panel is meant to be a scannable
top-of-list view, not a full host inventory. `TOP_HOSTS_LIMIT = 8` is a
module constant, not hardcoded inline, so it's one place to change if
that number ever needs revisiting.

**`Unknown` placeholder IPs excluded**, same as `pcap_summary.py`'s
`unique_hosts` — a packet the parser couldn't resolve an endpoint for
isn't a real host to rank.

---

## Conversations

A conversation is a **direction-agnostic pair of hosts**: A→B and B→A
packets collapse into the same entry, the same idea `_flow_key` already
uses for a full 5-tuple, applied here at host-pair granularity instead
(a "conversation" is host-level — TCP:A:51000-B:443 and TCP:A:51000-B:80
are the same *conversation* between A and B even though they're
different *connections*/`flow_key`s). The pair key is
`tuple(sorted([src_ip, dst_ip]))` so ordering never matters.

**Fields, matching `Conversation` in `src/types/index.ts`:**

| Field | Type | Source |
|---|---|---|
| `a`, `b` | `str` | The two IPs in the pair, in sorted order (arbitrary but deterministic — not "who spoke first") |
| `packets` | `int` | Count of packets between this pair, either direction |
| `bytes` | `str` | Total bytes exchanged between this pair, **pre-formatted** — see "Format decision" below |
| `duration` | `str` | This *pair's own* first-to-last timestamp span — **not** the whole capture's duration. Two hosts that only talked for 40 seconds near the start of a 20-minute capture have a 40s conversation, not a 20-minute one. Pre-formatted, same as `bytes` |

Same `Unknown`-IP exclusion as Top Hosts — a pair involving the parser's
placeholder isn't a real conversation between two hosts.

**Ranking:** by total bytes, descending — the busiest conversations
first, matching how Top Hosts is ranked and how a human scanning this
table would expect the most significant pairs to surface at the top. No
separate top-N cap is applied here (unlike Top Hosts' explicit 8) — a
capture's conversation count is naturally bounded by its host count
(`unique_hosts` choose 2, in the worst case), and the frontend table is
already a scrollable, fixed-height panel, same as it already handles the
uncapped mock `conversations` list today.

### Format decision: pre-formatted strings, not raw numbers

`Conversation.bytes` and `Conversation.duration` are typed as `string` in
the frontend today (`"42.1 MB"`, `"3m 12s"`), not raw numbers — this
predates this module (the original mock data already used display
strings). **Formatting happens on the backend**, matching that existing
type exactly:

- Less frontend churn — no new formatting utility needs to be written or
  imported into `PcapAnalyzer.tsx` just for this one table.
- Keeps byte/duration formatting logic in one place. If a second surface
  ever needs to show "bytes exchanged" as a human string, it has one
  function to call (`_format_bytes`) instead of two independent
  implementations drifting apart (one per language).
- The type already promises a display string, not a number — sending a
  raw number and reformatting client-side would mean either changing the
  type (churn for every other consumer of `Conversation`) or having the
  frontend re-derive a string that means "already formatted for display"
  from a field that no longer is. Matching the existing contract's
  meaning was the deciding factor, not just convenience.

`_format_bytes` uses binary units (1024-based: B / KB / MB / GB / TB),
one decimal place above B (`"1.2 MB"`, matching the pre-existing mock
data's own formatting style). `_format_duration` renders `"0s"` up to
`"59s"`, then `"Xm Ys"` (omitting `Ys` if it's exactly zero), then
`"Xh Ym"` past an hour, omitting the minutes if exactly zero — plain,
human-scannable, no fractional units mixed together.

---

## Known limitations

- No hostname resolution — identical situation and identical reasoning
  to `hosts.md` and `talkers.md`.
- Top Hosts' `bandwidth_mbps` is a **whole-capture average**, not a rate
  at any specific moment — a host that sent one huge burst in the first
  10 seconds of a 10-minute capture shows the same averaged-down number
  as one that sent the same total bytes steadily throughout. This is the
  necessary consequence of "no live window to smooth over" stated above,
  not an oversight — a Traffic Timeline (separate future module) is
  the right place to see *when* traffic happened, not this table.
- `connections` counts distinct flow_keys with no TTL/activity-recency
  concept, unlike live Top Talkers — for a finished, static file "was
  this flow ever active" is the only meaningful question; "was it active
  *recently*" doesn't apply to something that already ended.
- Conversations has no top-N cap — a capture with an unusually large
  number of distinct host pairs (e.g. one host that briefly touched
  hundreds of others, like during a port scan) returns every pair. Not
  expected to be a practical problem at this app's scale (a capture
  already capped at 200,000 packets per `pcap-upload.md`), but named as
  a real possible edge case rather than asserted away.
