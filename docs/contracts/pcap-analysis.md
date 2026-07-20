# Data Contracts — PCAP Analyzer: DNS Analysis, Threat Analysis, Network Health Score

Second module of the PCAP Analyzer page's backend. Builds on
`pcap-upload.md` (Capture Summary + `PcapAnalysisStore`) — read that
first. This module covers three panels that are bundled into one
endpoint because they're always displayed together, on the same
already-parsed capture, computed in a single pass: **DNS Analysis**,
**Threat Analysis**, and the **Network Health Score** gauge. Protocol
Distribution, Traffic Timeline, Top Hosts, Conversations, and Packet
Explorer remain separate future modules, untouched here.

---

## Why one bundled endpoint, not three

Every Live Monitor module got its own contract and its own event,
because each was independently useful and independently timed. These
three are different: they're always requested together (right after
upload finishes), always computed from the same packet list, and the
health score's own formula *depends on* the other two's output (see
below). Three separate round-trips would triple the "did this load yet"
bookkeeping on the frontend for zero benefit — one response is the
honest shape here.

**Endpoint:** `GET /api/pcap/{capture_id}/insights`

**Response:**
```json
{
  "capture_id": "a3f9c2e1b7d44f0a9c8e1b2d3f4a5b6c",
  "dns": {
    "top_domains": [{ "domain": "googleapis.com", "count": 214 }],
    "repeated_queries": [{ "domain": "telemetry.example-cdn.net", "count": 63 }],
    "failed_queries": [{ "domain": "nonexistent-host.local", "count": 12 }]
  },
  "threats": [
    {
      "severity": "medium",
      "reason": "Port Scan Detected",
      "evidence": "203.0.113.44 touched 18 distinct host:port pairs across 6 host(s) within 10s.",
      "recommendation": "Review firewall rules and consider rate-limiting or blocking this source if the scan wasn't an authorized security assessment."
    }
  ],
  "health": {
    "score": 78,
    "factors": [
      "-10 for 1 threat finding(s)",
      "-12 for 40 failed DNS lookup(s) (80% of 50 response(s))"
    ]
  }
}
```

`404` if `capture_id` doesn't exist or has aged out of `PcapAnalysisStore`
(only the 5 most recent uploads are kept — same limitation as
`pcap-upload.md`).

---

## DNS Analysis

Built from `PacketModel.dns_query`/`dns_answer` (already populated by
`PacketParser` for every `protocol == "DNS"` packet) — no new parsing.

- **Top Domains** — every distinct queried domain (question direction,
  `dst_port == 53`), ranked by query count, top 8.
- **Repeated Queries** — domains queried **40 or more times**, ranked by
  count, top 8. Deliberately a much higher bar than a typical #1 entry in
  Top Domains (a busy capture's most-queried domain might sit around
  20-50 from ordinary CDN/API chatter) — this list exists to flag
  outliers that look like beaconing or tunneling, not to duplicate Top
  Domains with a lower ceiling. A capture with nothing this repetitive
  correctly returns an empty list rather than padding it with the
  merely-popular.
- **Failed Queries** — domains whose response (`src_port == 53`) had a
  question but no resolved answer (`dns_answer is None`) — NXDOMAIN,
  SERVFAIL, REFUSED, etc. — ranked by failure count, top 8.

Domain names are extracted by stripping the trailing `" (TYPE)"` Q-type
suffix `PacketParser` already appends (e.g. `"example.com (A)"` →
`"example.com"`). No case normalization or subdomain grouping is
attempted — `www.example.com` and `example.com` are counted separately,
matching what a human scanning the raw capture would actually see.

---

## Threat Analysis

**Reuses `ThreatDetectionEngine`'s two live rules** (Port Scan Detection,
ARP Spoofing Detection) rather than re-implementing detection logic for
static files — same rules, same thresholds, same severities, documented
once in `threats.md`. A **fresh** `ThreatDetectionEngine` instance is
created per analysis call (this is a one-shot batch computation, not the
shared live singleton in `app.state`), fed every packet in the capture
**in chronological order**.

### The correctness problem this reuse required solving

`ThreatDetectionEngine`'s windows, debounce, and cooldowns are all
defined in real elapsed seconds, and the live engine reads `time.time()`
internally to get "now". Naively replaying a stored capture's packets
through the unmodified engine — one Python call per packet, back to back
— would feed every packet the *wall-clock* time the replay loop happens
to run at, not the time the packet actually occurred. Two concrete ways
that breaks detection:

1. A real scan that unfolded over several real seconds in the capture
   would still window correctly (replay is faster than the 10s window,
   so packets still land in the same bucket) — but a **second, genuinely
   separate** scan that happened 5 real minutes later in the same file
   would get wrongly swallowed by the first scan's 60s cooldown, because
   wall-clock replay compresses that 5-minute gap into milliseconds.
2. Two ARP packets that were actually minutes apart in the real capture
   would look like they arrived within the 2-second spoofing debounce
   window during replay — a false positive from timing compression, not
   a real attack pattern.

**Fix:** both `record_port_activity` and `record_arp_sighting` on
`ThreatDetectionEngine` now take an optional `now: float | None = None`
keyword argument. Live capture's existing call sites in `sniffer.py`
pass nothing and get byte-for-byte identical behavior (`time.time()`).
The PCAP batch path explicitly passes `packet.timestamp.timestamp()` —
the packet's own real historical capture time — so every window,
debounce, and cooldown decision is evaluated against real elapsed time
between events in the file, exactly as it would have been observed live.
Same "optional kwarg, default preserves prior behavior" pattern already
used to fix the parser's timestamp bug in `pcap-upload.md`.

### A field this required adding: `PacketModel.src_mac`

ARP Spoofing Detection needs the claimed MAC address, not just the IP —
but `PacketModel` had no MAC field at all (the live packet table doesn't
display one). `src_mac: Optional[str] = None` was added, populated by
`PacketParser` from `packet[ARP].hwsrc` for ARP packets only (`None` for
everything else — this isn't a general Ethernet-layer field, just enough
to support this one rule). Same incremental "add the field exactly when
a real feature needs it" pattern already used for `dns_query`/`dns_answer`.

### Output shape

Each `ThreatAlertRow` the batch run produces is mapped to:
```
{ severity, reason: threat, evidence: description, recommendation }
```
`recommendation` comes from a small static lookup keyed on the alert's
`threat` label (`"Port Scan Detected"` → ..., `"Possible ARP Spoofing"` →
...), with a generic fallback string if `ThreatDetectionEngine` ever
grows a third rule without a matching entry here — a deliberate,
documented coupling rather than a silent crash risk.

**Only two severities ever appear in practice** (`high` for ARP
Spoofing, `medium` for Port Scan) — there is no `low`-severity rule
implemented. The frontend's `Severity` type still allows `'low'` for
forward compatibility, but nothing here produces it today.

---

## Network Health Score

**An explicitly heuristic, relative indicator — not a security audit.**
No real TLS/protocol inspection, no CVE or malware-signature matching, no
ground truth to calibrate against. Named as a limitation, not implied to
be more rigorous than it is.

Starts at 100, three factors subtract from it:

1. **Threat signatures** — `-20` per `high` severity finding, `-10` per
   `medium`. (No rule currently produces `low`.)
2. **DNS anomaly volume** — combines two things:
   - Failed-lookup ratio (failed DNS responses ÷ total DNS responses)
     scaled up to `-15`, so a capture with a handful of failures out of
     thousands of lookups barely moves the score, while a capture where
     most DNS lookups fail is penalized close to the full amount.
   - `-3` per domain flagged in Repeated Queries, capped at `-10` total
     — this is about *how many distinct domains* look like beaconing,
     not how loud any single one is (a single very loud domain's
     contribution is already partly reflected in the failure ratio if
     it's also failing).
3. **Encryption posture** — a coarse heuristic: the fraction of TCP
   traffic on well-known plaintext ports (21 FTP, 23 Telnet, 80 HTTP,
   110 POP3, 143 IMAP) scaled up to `-15`. This is a **port-number proxy,
   not real inspection** — traffic on port 80 that's actually a
   misconfigured redirect-only server is treated the same as one
   serving real cleartext content, since nothing here decodes payloads
   to check.

Final score is clamped to `[0, 100]` and rounded to the nearest integer.
`factors` is a list of plain-English strings for each deduction that
actually applied (empty deductions are omitted, not shown as `-0`) — if
none apply at all, `factors` contains a single explicit
"no anomalies found" string rather than an empty array a UI would have
to special-case.

**Why these specific weights:** chosen so no single factor can zero out
the score by itself (max single-factor deduction is well under 100), and
so a capture with just one medium-severity finding and nothing else
still reads as "mostly healthy" rather than tanking the gauge into
`HIGH RISK` — matching the existing `HealthGauge` component's own
`>= 80 SAFE / >= 50 WARNING / else HIGH RISK` bands, which this contract
did not change.

---

## Known limitations

- Health Score weights above are a considered starting point, not
  empirically validated against real incident data — a legitimate future
  enhancement is calibrating them against labeled captures, not attempted
  here.
- DNS domain matching does no normalization (case, trailing dot,
  subdomain grouping) — `Example.com` and `example.com` count separately.
- Threat Analysis inherits every limitation already named in
  `threats.md` (no DNS tunneling/C2/exfiltration detection, no
  signature/known-bad-IP matching, no tuning UI) — running the same two
  rules once instead of continuously doesn't add coverage beyond what
  live detection already doesn't cover.
- Encryption posture is a port-number heuristic, not protocol/TLS
  inspection — deliberately named above, not hidden.
- `PacketModel.src_mac` is populated for ARP packets only; it is not a
  general per-packet Ethernet-layer field and nothing else reads it.

---

*Next candidates, each still reading from `PcapAnalysisStore` via
`capture_id`: Protocol Distribution + Traffic Timeline, Top Hosts +
Conversations, Packet Explorer (showing this capture's real packets
instead of the current unrelated mock stream).*
