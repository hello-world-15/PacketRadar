# Data Contracts — PCAP Analyzer: DNS Analysis

Builds on `docs/contracts/pcap-upload.md` (Capture Summary +
`PcapAnalysisStore`) — read that first. Covers the three DNS Analysis
panels on the PCAP Analyzer page: **Top Domains**, **Repeated Queries**,
**Failed Queries**. Protocol Distribution, Traffic Timeline, Top Hosts,
Conversations, Threat Analysis, Network Health Score, and Packet Explorer
remain separate, untouched by this task.

---

## A note on a second, older DNS Analysis in this codebase

`app/engines/pcap_insights.py` and `docs/contracts/pcap-analysis.md`
already contain a *different* DNS Analysis implementation, bundled
together with Threat Analysis and a Network Health Score under a
still-unwired `GET /api/pcap/{capture_id}/insights` endpoint. That module
was written and unit-tested but never actually finished being
integrated — the schema classes it imports didn't exist until this task
also patched them (a required fix just to stop `pytest` from failing to
collect at all), and its route was never added to `app/api/pcap.py`. It
remains dormant: no route, no frontend consumer.

This endpoint is the one that's actually live. It intentionally does
**not** reuse that module's schema or engine, for two reasons:

1. Its `top_domains` rows use `count` as the field name; this endpoint's
   need `queries` to match `src/data/mockData.ts`'s existing shape
   exactly (`{ domain, queries }` for Top Domains vs. `{ domain, count }`
   for the other two lists) — genuinely incompatible shapes, not just a
   style choice.
2. It computes Failed Queries via `dns_answer is None` — a proxy for
   failure that predates `dns_rcode` existing as a field at all (see
   below). This endpoint uses the more precise signal directly.

Both modules keep the same `TOP_DOMAINS_LIMIT = 8` and
`REPEATED_QUERY_MIN_COUNT = 40` constants, duplicated rather than shared,
so the two don't silently drift apart if one is tuned later without
noticing the other exists. If `pcap-analysis.md`'s module is ever
actually wired up, reconciling the two DNS analyses into one is a
reasonable follow-up — not attempted here, since this task's scope is
this endpoint only.

---

## The `dns_rcode` fix this endpoint required

Whether a DNS response actually *failed* (NXDOMAIN, SERVFAIL, etc.) was,
before this task, only ever computed transiently inside
`PacketParser.parse()` and embedded into the human-readable `info`
string — e.g. `"DNS response: example.com → NXDOMAIN"`. It was never its
own field on `PacketModel`. Building Failed Queries by substring-matching
`info` would have been fragile (breaks the moment that wording changes)
— and this codebase has already hit this exact class of problem once:
`PacketParser` originally hardcoded `datetime.now()` instead of a real
timestamp parameter, silently breaking `duration_seconds` for uploaded
files (see `pcap-upload.md`). The fix there, and the fix here, is the
same principle: extend the parser with a proper field instead of working
around the gap downstream.

**Fix:** `PacketModel.dns_rcode: Optional[str] = None` — set by
`PacketParser.parse()` whenever a DNS *response* is parsed (never on the
query half, which has no response code to report): `"NOERROR"` when the
response actually resolved, or the real rcode name (`"NXDOMAIN"`,
`"SERVFAIL"`, etc., reusing the existing `_dns_rcode_name` helper) when
it didn't. The `info` string now reads from this same field instead of
calling `_dns_rcode_name` a second time — one source of truth, not two
call sites that could theoretically disagree.

This is a small, backward-compatible model extension (a new optional
field defaulting to `None`) — every existing call site and test that
doesn't care about DNS failure detail is unaffected.

---

## `GET /api/pcap/{capture_id}/dns`

**Frontend location:** `src/pages/PcapAnalyzer.tsx`'s "DNS Analysis"
section, client function in `src/lib/pcapApi.ts`.

**Response:**
```json
{
  "top_domains": [{ "domain": "googleapis.com", "queries": 1842 }],
  "repeated_queries": [{ "domain": "telemetry.example.net", "count": 214 }],
  "failed_queries": [{ "domain": "xj4k9z-c2.top", "count": 41 }]
}
```
Matches `src/data/mockData.ts`'s existing `topDomains`/`repeatedQueries`/
`failedQueries` shapes exactly.

`404` if `capture_id` isn't in `PcapAnalysisStore` — either it was never
valid, or it aged out (only the 5 most recent uploads are kept, same
limitation as `pcap-upload.md`).

### Top Domains

Every distinct `dns_query` domain in the **question direction**
(`protocol == "DNS" and dst_port == 53` — the exact condition
`app/engines/pcap_summary.py`'s `dns_request_count` already uses, reused
here rather than reinvented), ranked by query count descending, **top 8**.

**Why 8, not the mock's 6:** picked to match
`app.engines.pcap_insights`'s own already-established `TOP_DOMAINS_LIMIT`
for the same underlying concept (see the note above) rather than
introduce a third arbitrary cutoff for "how many domains is enough to
show" in the same codebase. The mock's 6 was simply whatever fit the
placeholder list, not a considered decision.

### Repeated Queries

**Not** a lower-ceiling rerun of Top Domains — that would just show the
same list twice with less of it. This list answers a different question:
"which domain was queried an *unusually* high number of times", a crude
frequency-based proxy for behavior that might be automated (beaconing,
DNS tunneling, some malware C2 patterns look like this) — genuinely
weaker and less specific than a real anomaly/behavioral detector would
be, and **explicitly named as such**, the same honesty standard
`threats.md`'s "Explicit non-goals" section already holds this codebase
to.

**Threshold: 40 or more queries**, ranked by count, top 8. A busy
capture's single most-queried domain from perfectly ordinary CDN/API
chatter often already sits around 20-50 — so 40 is deliberately not "the
next tier down from Top Domains's #1", it's set high enough that a
domain crossing it looks meaningfully different from ordinary popular
traffic, not just "somewhat popular." A capture with nothing this
repetitive correctly returns an empty list, not a padded one.

**Deliberately allowed to overlap with Top Domains** rather than
excluding whatever's already in that list: a domain can legitimately be
both genuinely popular *and* cross the repetition threshold, and that's
a meaningfully different fact from "this domain happens to be ranked
highly" — the two lists use different criteria (rank vs. absolute
threshold), so showing the same domain in both isn't redundant the way
using the identical ranking twice would be.

### Failed Queries

Domains whose response (`dns_rcode not in (None, "NOERROR")`) reflects
an actual failure — NXDOMAIN, SERVFAIL, REFUSED, etc. — grouped and
counted per domain, ranked by failure count descending, top 8.

---

## Domain extraction

Same convention as `pcap-analysis.md`'s DNS Analysis: strip the trailing
`" (TYPE)"` Q-type suffix `PacketParser` already appends (e.g.
`"example.com (A)"` → `"example.com"`). No case normalization or
subdomain grouping — `www.example.com` and `example.com` count
separately, matching what a human scanning the raw capture would
actually see.

---

## Known limitations

- A capture with zero DNS traffic returns all three lists empty, not an
  error — an empty result is a legitimate, common outcome, not a
  failure case.
- Repeated Queries is a crude frequency heuristic, explicitly not real
  anomaly or behavioral detection — see above.
- No case normalization or subdomain grouping (see above) — inherited
  from `pcap-analysis.md`'s established convention for the same reason.
- This endpoint reads only the already-parsed `PacketModel` list stored
  at upload time — it never re-opens or re-parses the `.pcap` file.
