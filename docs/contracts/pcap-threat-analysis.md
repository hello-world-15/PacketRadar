# Data Contracts — PCAP Analyzer: Threat Analysis

Third backend module for the PCAP Analyzer page, building on
`pcap-upload.md` (Capture Summary + `PcapAnalysisStore`) — read that
first. Also read `threats.md` in full: this module reuses its six
detection **rules** (Port Scan Detection, ARP Spoofing Detection, DNS
Tunneling Detection, SYN Flood Detection, Beaconing Detection, Data
Exfiltration Detection) and their documented thresholds, but not its
**engine** — see below for why that distinction matters.

---

## REST, not WebSocket, and why that's not just "because it's a file"

Every Live Monitor module is push/WebSocket because the underlying data
keeps changing for as long as the socket is open. An uploaded capture is
the opposite: it's a fixed, closed dataset the moment the upload
finishes. There's nothing to push updates about — a single `GET` that
computes and returns the complete answer is the honest shape, same
reasoning already established by `pcap-upload.md` for the Capture
Summary endpoint.

**Endpoint:** `GET /api/pcap/{capture_id}/threats`

**Response:**
```json
{
  "threats": [
    {
      "severity": "medium",
      "source": "192.168.1.44",
      "reason": "Port Scan Detected",
      "evidence": "192.168.1.44 touched 38 distinct host:port pairs across 6 host(s) over a 6.2s episode.",
      "recommendation": "Investigate host 192.168.1.44 for scanning tools or malware; review firewall rules and consider rate-limiting or blocking this source if the scan wasn't an authorized security assessment."
    },
    {
      "severity": "high",
      "source": "192.168.1.1",
      "reason": "Possible ARP Spoofing",
      "evidence": "192.168.1.1 was claimed by 2 different MAC addresses (AA:AA:AA:AA:AA:AA, BB:BB:BB:BB:BB:BB) across 1 confirmed conflict.",
      "recommendation": "Confirm which device legitimately owns the claimed MAC address. Consider static ARP entries or dynamic ARP inspection for critical hosts such as the gateway."
    },
    {
      "severity": "medium",
      "source": "172.16.0.50",
      "reason": "Possible DNS Tunneling",
      "evidence": "172.16.0.50 sent 24 DNS queries with abnormally long subdomain labels (>= 32 chars) to *.evil.example.com over a 4.8s episode.",
      "recommendation": "Investigate this source for DNS tunneling or exfiltration tools (iodine, dnscat2, dns2tcp). Check what process on this host is generating the queries, and consider blocking or rate-limiting DNS to the named parent domain if it isn't a known service."
    },
    {
      "severity": "medium",
      "source": "198.51.100.7",
      "reason": "Possible SYN Flood",
      "evidence": "198.51.100.7 sent 47 bare TCP SYN packets to 10.0.0.20:80 without completing the handshake, over a 2.3s episode.",
      "recommendation": "Check the targeted host's connection backlog and firewall/rate-limiting rules. If this traffic isn't a known load test or monitoring tool, consider blocking or throttling the source IP and enabling SYN cookies on the target if not already in place."
    },
    {
      "severity": "medium",
      "source": "10.0.0.42",
      "reason": "Possible Beaconing Detected",
      "evidence": "10.0.0.42 connected to 203.0.113.9:443 at 8 consecutive ~30.0s intervals (coefficient of variation 0.03) over a 240.0s span — suspiciously regular, possible C2 beaconing.",
      "recommendation": "Investigate the process on this host making these regular connections for C2/malware behavior. Check the destination's reputation, and rule out known legitimate periodic clients (health checks, chat apps, telemetry) before escalating."
    },
    {
      "severity": "medium",
      "source": "10.0.0.51",
      "reason": "Possible Data Exfiltration",
      "evidence": "10.0.0.51 sent 62,914,560 bytes of payload data to 198.51.100.200 over a 12.4s episode.",
      "recommendation": "Determine what process and data are behind this transfer. If it isn't a known backup, sync, or file-transfer job, treat this as a potential data-loss incident and consider blocking or rate-limiting traffic to this destination pending investigation."
    }
  ]
}
```

`404` if `capture_id` doesn't exist or has aged out of `PcapAnalysisStore`
(only the 5 most recent uploads are kept — same limitation as
`pcap-upload.md`).

---

## Why this reuses the live rules but NOT the live engine

`ThreatDetectionEngine` (`app/engines/threat_detection.py`) is built for
one job: deciding, packet by packet, in real time, whether *right now* is
worth alerting on. Every piece of its state exists to serve that job —
a rolling window keyed to wall-clock `time.time()`, and a **cooldown**
that exists specifically to stop one ongoing live incident from flooding
the alert panel with a near-duplicate row per packet for as long as it
continues.

None of that fits analyzing a file you already have in full:

- **"Now" is meaningless.** The live engine asks "is this happening at
  this instant." A batch report asks "did this happen anywhere in this
  file's timeline" — a fundamentally different question that doesn't
  need (and would be actively wrong to answer using) the wall-clock.
- **A cooldown is the wrong tool for "report every genuine finding."**
  The live engine's cooldown answers "don't tell me about the same
  ongoing thing again for N seconds." A batch report doesn't want a
  time-based throttle at all — it wants to know about every genuinely
  distinct incident in the file, however many there were, whenever they
  occurred. Reusing the live engine instance (pointing this endpoint at
  the shared singleton in `app.state`) would also be wrong for a more
  basic reason: it would mix an uploaded file's findings into the *live
  capture's own* alert history, which is a correctness bug, not just an
  awkward reuse.

So this module **reimplements all six rules as pure functions** over a
`list[PacketModel]` — no engine class, no mutable session state, nothing
that outlives a single function call. It imports `PORT_SCAN_WINDOW_SECONDS`,
`PORT_SCAN_DISTINCT_THRESHOLD`, `ARP_CONFLICT_DEBOUNCE_SECONDS`,
`DNS_TUNNEL_WINDOW_SECONDS`, `DNS_TUNNEL_DISTINCT_THRESHOLD`,
`DNS_TUNNEL_LABEL_LENGTH_THRESHOLD`, `SYN_FLOOD_WINDOW_SECONDS`,
`SYN_FLOOD_COUNT_THRESHOLD`, `MIN_BEACON_OBSERVATIONS`,
`BEACON_HISTORY_SIZE`, `EXFIL_WINDOW_SECONDS`, `EXFIL_BYTE_THRESHOLD`, and
the `dns_tunnel_candidate()`/`is_bare_syn()`/`beacon_pattern_stats()`
helpers directly from `threat_detection.py` (not re-typed as separate
constants/logic) so the two detection surfaces can never silently drift
apart on what counts as a scan, a confirmed conflict, a tunneling
candidate, a bare SYN, or a beacon — only the *cooldown* concept is
deliberately left behind, replaced by something that fits batch analysis
better:

### Port Scan Detection — from cooldown to "episodes"

Instead of guessing how long to suppress duplicate alerts, batch mode can
just look at when the signal itself actually stops: a **scan episode**
is the maximal, time-contiguous stretch during which a source IP's
trailing `PORT_SCAN_WINDOW_SECONDS`-second window of distinct
`(dst_ip, dst_port)` pairs stays at or above `PORT_SCAN_DISTINCT_THRESHOLD`.
The episode starts the moment the window first crosses the threshold and
ends the moment it drops back below it. One finding is reported per
episode — not per packet, and not artificially split or merged by a
fixed cooldown duration. If the same source IP has two genuinely separate
scanning episodes hours apart in the same file, that's correctly two
findings, not one suppressed by an arbitrary timer. `evidence` reports
the real, computed totals for that specific episode: how many distinct
host:port pairs, across how many hosts, over what actual duration.

### ARP Spoofing Detection — from cooldown to "aggregate per contested IP"

The debounce concept survives unchanged: a conflicting MAC must be
confirmed by a second sighting within `ARP_CONFLICT_DEBOUNCE_SECONDS` of
the first, same as `threats.md`, so a single stray or retransmitted
packet still can't trigger a finding by itself. But instead of alerting
on each confirmed conflict and then cooling down, batch mode walks the
*entire* ordered history of sightings for a given IP once, and if **any**
conflict gets confirmed anywhere in that history, all of that IP's
confirmed conflicting MACs are rolled into **one finding** — the natural
"distinct finding" unit for a report is "this IP was involved in ARP
spoofing," not "this IP flipped MACs N separate times." `evidence` names
every MAC involved and how many confirmed conflicts occurred.

### DNS Tunneling Detection — from cooldown to "episodes"

Same episode conversion as Port Scan, applied per **(source IP, parent
domain)** pair instead of per source IP alone — a tunnel over
`evil.example.com` and a separate, unrelated tunnel-shaped burst over
`another.example.com` from the same host are genuinely distinct
incidents, not one finding. An episode is the maximal, time-contiguous
stretch during which that pair's trailing `DNS_TUNNEL_WINDOW_SECONDS`-
second window of oversized-label queries (`dns_tunnel_candidate()`
decides "oversized-label," same helper the live engine uses) stays at or
above `DNS_TUNNEL_DISTINCT_THRESHOLD`. `evidence` reports the real,
computed query count and episode duration, not a generic template.

### SYN Flood Detection — from cooldown to "episodes"

Same episode conversion again, applied per **(source IP, destination IP,
destination port)** triple — a flood against port 80 and a separate
flood against port 443 on the same target from the same source are
genuinely distinct incidents. An episode is the maximal, time-contiguous
stretch during which that triple's trailing `SYN_FLOOD_WINDOW_SECONDS`-
second window of bare SYNs (`is_bare_syn()` decides "bare," same helper
the live engine uses, parsing the same `info` text) stays at or above
`SYN_FLOOD_COUNT_THRESHOLD`. `evidence` reports the real, computed SYN
count and episode duration, not a generic template.

### Beaconing Detection — from cooldown to "episodes"

Rule 5 isn't a rolling-time-window rule to begin with — the live engine
tracks a fixed-size deque of the last `BEACON_HISTORY_SIZE` connection
timestamps per **(source IP, destination IP, destination port)** triple
and recomputes on every new connection whether that trailing history
looks like a beacon (`beacon_pattern_stats()` — same shared helper the
live engine's `record_beacon_activity` uses). The episode concept still
applies cleanly on top of that: at each new connection, the trailing
history either currently qualifies as a beacon or it doesn't, and a
maximal contiguous run of "yes" is one distinct incident, closed the
moment a connection's trailing history stops qualifying (an irregular
gap, a burst that's suddenly too fast, etc.). `evidence` reports the
real, computed interval count, mean interval, and coefficient of
variation for that episode, not a generic template.

### Data Exfiltration Detection — from cooldown to "episodes"

Same episode conversion as Port Scan and SYN Flood, applied per
**(source IP, destination IP)** pair. An episode is the maximal,
time-contiguous stretch during which that pair's trailing
`EXFIL_WINDOW_SECONDS`-second window of summed `payload_size` stays at or
above `EXFIL_BYTE_THRESHOLD`. Protocol-agnostic, same as the live rule:
every packet with a payload counts, regardless of `protocol`. `evidence`
reports the real, computed byte total and episode duration, not a
generic template.

---

## The MAC data gap

ARP Spoofing Detection needs MAC addresses to detect one IP being claimed
by two different MACs. `PacketModel` had no MAC field at all before this
module — live capture gets MACs directly off the raw Scapy packet in
`sniffer.py`, a data path `PacketModel` was never part of.

**Chosen fix: extend `PacketModel` with `src_mac: Optional[str] = None`**,
populated by `PacketParser.parse()` from `packet[ARP].hwsrc` — **for ARP
packets only**, exactly matching what `sniffer.py` already extracts for
the live path (it never reads a MAC off any other protocol either). This
keeps the "parse once, reuse everywhere" principle intact: the file is
still only opened and parsed a single time in `POST /api/pcap/upload`,
and this endpoint reads the same already-parsed `packets: list[PacketModel]`
sitting in `pcap_store` that every other PCAP Analyzer module reads.

**Only `src_mac`, not also `dst_mac`.** ARP Spoofing Detection only cares
about *who is claiming to own an IP* — that's the sender's own hardware
address (`hwsrc`), which is exactly `src_mac`. Nothing in this module (or
anywhere else in the codebase) reads a destination MAC, and Ethernet's
destination address for an ARP request is conventionally a broadcast
address anyway (not meaningful signal here). Adding an unused `dst_mac`
field would be speculative scope creep against this codebase's own
"add a field exactly when a real feature needs it" pattern (the same
reasoning that already governed adding `dns_query`/`dns_answer` only when
DNS detail was actually needed).

**Backward compatibility:** `src_mac` is optional and defaults to `None`,
so every existing caller of `PacketModel` (live capture's packet stream,
cache, stats) is unaffected. Verified by running the full backend test
suite after the change, not assumed.

---

## Output shape — deliberately different from live `ThreatAlert`

Live `ThreatAlert` (`{ id, time, severity, threat, source, description }`)
reads as "here's what's happening right now." This endpoint's shape —
`{ severity, source, reason, evidence, recommendation }` — reads as "here's
what we found in this file and what to do about it," matching the
existing PCAP Analyzer UI's card layout (an "Evidence:" line and a
"Recommendation:" line) that was already built around this exact shape
for its mock data. These are two different *kinds* of communication, not
the same data reformatted twice, so they are intentionally not unified
into one shared type. `time`/`id` (meaningful for a live, ordered feed)
and `threat` (renamed `reason` here, since "the reason this was flagged"
reads more naturally in a report than "the alert's category") don't
carry over; `source` is included since grounding a finding in a concrete
IP is what makes it actionable.

`recommendation` comes from the same kind of small static lookup keyed on
the `reason` label that a live-alert-to-report mapping would use, with a
generic fallback string if a future rule is ever added without a matching
entry — a deliberate, documented coupling rather than a silent crash
risk, same pattern this codebase already uses elsewhere for canned
guidance text.

---

## Known limitations

- Inherits every limitation already named in `threats.md` — no
  signature/known-bad-IP matching, no automatic blocking, no tuning UI
  (thresholds are hardcoded constants, imported from
  `threat_detection.py`), and DNS Tunneling Detection is label-length-
  based rather than entropy-based, so a tunnel that deliberately keeps
  each query's leaf under `DNS_TUNNEL_LABEL_LENGTH_THRESHOLD` won't trip
  it — same gap as the live rule, not newly introduced here.
- A scan paced slower than `PORT_SCAN_DISTINCT_THRESHOLD` within any
  `PORT_SCAN_WINDOW_SECONDS`-second stretch, or spread across multiple
  source IPs (a distributed scan), won't be detected — same gap as the
  live rule, not newly introduced here.
- A SYN flood spread thin across many source IPs (each individually
  under `SYN_FLOOD_COUNT_THRESHOLD` against the same target) won't be
  detected either — Rule 4 tracks bare SYNs per source IP, not per
  destination in aggregate — same cross-source correlation gap as the
  live rule and as Port Scan above, not newly introduced here.
- Beaconing Detection assumes a roughly fixed interval — a beacon that
  deliberately randomizes its sleep interval by more than
  `BEACON_CV_THRESHOLD` (jittered C2) won't trip Rule 5 as written, and
  legitimate periodic polling (health checks, chat clients, telemetry)
  can look identical to a timer-based beacon from a pure timing signal
  alone — same false-positive source and same gap as the live rule.
- Data Exfiltration Detection only catches one specific shape: a burst
  to a single destination within one `EXFIL_WINDOW_SECONDS`-second
  window. Slow/low-and-slow exfiltration spread across time, or split
  across multiple destinations, won't trip Rule 6 — same honest gap as
  the live rule.
- Bounded by the same `MAX_PACKETS` parse cap documented in
  `pcap-upload.md` — a capture larger than that cap is only analyzed up
  to whatever was actually parsed and stored.
- `src_mac` is populated for ARP packets only; it is not a general
  per-packet Ethernet-layer field and nothing else reads it.
- This endpoint is independent of the Network Health Score (a separate,
  not-yet-built module per `pcap-upload.md`'s "Next candidates") — it
  does not currently feed into any composite score.

---

*Next candidates, each still reading from `PcapAnalysisStore` via
`capture_id`: Protocol Distribution + Traffic Timeline, Top Hosts +
Conversations, DNS Analysis, Network Health Score, Packet Explorer.*
