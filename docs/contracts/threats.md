# Data Contracts — Threats (Live Detection)

Covers the Threat Detection panel on Live Monitor. This is **Module 7**.
Closer in shape to `packets.md` (delta feed + backlog) than to the
snapshot-style `stats.md` or `hosts.md` — alerts are sparse, discrete
events, not something to re-send in full on a timer.

---

## Threat Detection Panel

**Frontend location:** `src/components/ThreatTable.tsx`, fed from `src/pages/LiveMonitor.tsx`.
**Type:** `ThreatAlert` in `src/types/index.ts` — already exists (`{ id, time, severity, threat, source, description }`), unchanged by this task.

**Push or pull:** Push, delta — same reasoning as `packets.md`. Alerts are
rare relative to packets, but re-sending the *whole* alert history every
tick doesn't scale any better here than it would for the packet table, and
for the same reason: growing cost for zero benefit once the buffer has
more than a handful of rows.

**Transport:** WebSocket event `threats:update`, on the same `/ws/live`
socket as everything else.

**Payload:**
```json
{
  "type": "threats:update",
  "data": [
    {
      "no": 12,
      "id": "threat-12",
      "time": 1752345212.481,
      "severity": "medium",
      "threat": "Port Scan Detected",
      "source": "203.0.113.44",
      "description": "203.0.113.44 touched 18 distinct host:port pairs across 6 host(s) within 10s."
    },
    {
      "no": 13,
      "id": "threat-13",
      "time": 1752345260.112,
      "severity": "high",
      "threat": "Possible ARP Spoofing",
      "source": "192.168.1.1",
      "description": "192.168.1.1 was claimed by AA:BB:CC:11:22:33, then by a different MAC (DE:AD:BE:EF:00:01) shortly after — possible ARP cache poisoning."
    },
    {
      "no": 14,
      "id": "threat-14",
      "time": 1752345301.774,
      "severity": "medium",
      "threat": "Possible DNS Tunneling",
      "source": "172.16.0.50",
      "description": "172.16.0.50 sent 24 DNS queries with abnormally long subdomain labels (>= 32 chars) to *.evil.example.com within 20s — possible tunneling or data exfiltration over DNS."
    },
    {
      "no": 15,
      "id": "threat-15",
      "time": 1752345340.006,
      "severity": "medium",
      "threat": "Possible SYN Flood",
      "source": "198.51.100.7",
      "description": "198.51.100.7 sent 47 bare TCP SYN packets to 10.0.0.20:80 within 5s without completing the handshake — possible SYN flood / half-open connection exhaustion."
    },
    {
      "no": 16,
      "id": "threat-16",
      "time": 1752345412.330,
      "severity": "medium",
      "threat": "Possible Beaconing Detected",
      "source": "10.0.0.42",
      "description": "10.0.0.42 connected to 203.0.113.9:443 at 8 consecutive ~30.0s intervals (coefficient of variation 0.03) — suspiciously regular, possible C2 beaconing."
    },
    {
      "no": 17,
      "id": "threat-17",
      "time": 1752345470.918,
      "severity": "medium",
      "threat": "Possible Data Exfiltration",
      "source": "10.0.0.51",
      "description": "10.0.0.51 sent 62,914,560 bytes of payload data to 198.51.100.200 within 60s — possible bulk data exfiltration."
    }
  ]
}
```

**Field notes:**
| Field | Type | Source |
|---|---|---|
| `no` | `int` | Monotonically increasing sequence number, engine-internal (mirrors `PacketStreamRow.no`) — used by the broadcast loop's delta cursor, **not surfaced on the frontend's `ThreatAlert` type**, which has no `no` field. The hook drops it after using it to dedupe. |
| `id` | `str` | `f"threat-{no}"` — stable, unique, and doubles as the frontend's list/merge key so the hook doesn't need `no` for anything the UI touches |
| `time` | `float` (unix seconds) | When the alert was raised. Sent raw, same convention as every other live event — formatting is a frontend concern |
| `severity` | `str` | `"high"` for ARP Spoofing, `"medium"` for Port Scan, DNS Tunneling, SYN Flood, Beaconing, and Data Exfiltration — see each rule's "Severity" note below |
| `threat` | `str` | Fixed label per rule: `"Port Scan Detected"`, `"Possible ARP Spoofing"`, `"Possible DNS Tunneling"`, `"Possible SYN Flood"`, `"Possible Beaconing Detected"`, or `"Possible Data Exfiltration"` |
| `source` | `str` | The IP responsible — the scanning source for Rule 1, the contested IP for Rule 2 |
| `description` | `str` | One human-readable sentence with the concrete numbers that tripped the rule — not a generic template, so an analyst doesn't have to click into "Investigate" just to see what triggered it |

**Cadence:** Every 1 second — faster than `hosts:update` (3s) because an
alert panel that lags behind an active incident by several seconds
undermines the point of a *live* threat feed, but not as fast as
`packets:update` (0.5s), since alerts are by design far less frequent
than raw packets and don't need sub-second delivery.

**New connection backlog:** Same pattern as `packets.md` — a client that
connects mid-session gets one immediate `threats:update` frame with the
most recent buffered alerts (up to 50) right after the socket accepts,
so a fresh page load doesn't show an empty panel until something *new*
happens to trip a rule.

**Wiring `threat_alert_count`:** `stats:update`'s `threat_alert_count`
(stubbed at 0 since Module 1) now reads `ThreatDetectionEngine.alert_count`
in `live_socket.py`'s `_stats_loop`, the exact same pattern Module 2 used
to make `lan_device_count` real from `host_engine.online_count()`. This
is a *cumulative* count (total alerts raised this session), not a
current/active count — there's no real "active threat" concept once an
alert has been raised; it's a log entry, not a gauge.

---

## Rule 1 — Port Scan Detection

**Signal:** one source IP touching an unusually high number of distinct
`(destination IP, destination port)` pairs within a short rolling window.

**Window — 10 seconds.** Long enough to catch a scan that paces itself
slightly to avoid looking like a burst, short enough that the engine
doesn't have to remember activity from minutes ago to make a decision
about "right now."

**Threshold — 15 distinct (dst_ip, dst_port) pairs within the window.**
Ordinary browsing opens a handful of parallel connections to a handful of
CDN/ad-tech/analytics hosts in a burst — realistically fewer than 10
distinct host:port pairs in any 10-second window, even on a busy page
load. Scanning tools (nmap, masscan, etc.) sweep dozens to thousands of
ports/hosts in the same window. 15 sits comfortably above normal browser
bursts and comfortably below even a deliberately slow/stealthy scan —
picked to bias toward not crying wolf on ordinary traffic, at the cost of
missing an extremely slow, low-and-slow scan spread across many separate
10s windows (see non-goals).

**Cooldown — 60 seconds per source IP.** Once a source trips the
threshold, it will keep matching on literally every subsequent packet for
as long as the scan continues (a scan can run for minutes). Without a
cooldown, one real scan would flood the table with a near-duplicate row
per packet. 60 seconds means one ongoing incident reads as one alert (or
a handful, if it's a long scan), while still re-alerting reasonably
promptly if the same host starts a distinct new scan later. This is not
optional — it's the difference between a usable alert panel and a
scrolling wall of duplicates.

**Severity — `medium`.** Port scanning has real benign explanations
(internal vulnerability scanners, monitoring tools, even some antivirus
and asset-inventory software probe multiple ports as part of normal
operation) — it's a strong reconnaissance signal, not proof of hostile
intent by itself. Reported for visibility, not treated as confirmed
compromise.

---

## Rule 2 — ARP Spoofing Detection

**Signal:** the same IP address being claimed by two different MAC
addresses in short succession. Legitimate IP-to-MAC bindings change
rarely (a device gets a new NIC, a VM migrates); a sudden conflict is a
strong signal of ARP cache poisoning, commonly used to impersonate a
gateway and intercept traffic.

**Architecture note:** this engine keeps its **own** IP→MAC binding table,
fed by `PacketCapture` calling `record_arp_sighting(mac, ip)` directly,
alongside — not instead of — the existing
`host_engine.record_sighting(mac, ip)` call for the same ARP packet. It
does **not** read or modify `HostDiscoveryEngine`'s internal `_hosts`
dict. Some duplication of "watch ARP sightings" between the two engines
is the deliberate trade-off already established by this codebase (see how
`TopTalkersEngine` and `HostDiscoveryEngine` are both independently fed
from the same packets rather than one reading the other) — it keeps each
engine's behavior independently reasoned about and testable without
worrying about another engine's internal state shape changing underneath
it.

**Debounce — 2 seconds.** A single stray or retransmitted ARP packet
claiming a conflicting MAC must not raise an alert by itself. The engine
only confirms a conflict once the *same* conflicting MAC is seen a second
time within 2 seconds of the first conflicting sighting. Real ARP
poisoning tools (arpspoof, ettercap, bettercap) work by repeatedly
re-sending forged replies every 1–3 seconds so the victim's cache doesn't
revert to the real binding — a genuine attack reliably produces that
second confirming sighting well inside a 2-second window. A single
malformed or duplicated packet, or a one-off race during a legitimate
IP/MAC change, does not.

**Cooldown — 30 seconds per contested IP.** Shorter than the port-scan
cooldown because ARP conflicts are rarer and more severe — an ongoing or
alternating spoof (attacker flips between the real and forged MAC) still
collapses to one alert every 30 seconds instead of one every time the
binding flips, without waiting as long as the port-scan cooldown before
re-alerting a fresh conflict.

**Severity — `high`.** Unlike port scanning, there are very few benign
explanations for a real IP suddenly being claimed by an unexpected second
MAC on a stable LAN (rare exceptions: a live VM migration or an HA
failover doing gratuitous ARP — both infrequent enough, and important
enough to notice even when benign, that treating this as high severity is
still the right default).

---

## Rule 3 — DNS Tunneling Detection

**Signal:** one source IP sending an unusually high number of DNS
queries with abnormally long, encoded-looking leftmost labels ("leaf"
labels) against the *same* parent domain within a short window. DNS
tunneling tools (iodine, dnscat2, dns2tcp) smuggle a data channel through
DNS by packing the payload into the queried name itself — normal
hostnames don't look like this, but a tunnel's queries do, repeatedly,
against one domain the attacker controls.

**Label length threshold — 32 characters.** Real hostnames people type
or that ordinary services generate rarely exceed ~20 characters; DNS
tunneling tools maximize bytes-per-query and routinely produce leaf
labels in the 32-63 character range (63 is DNS's own hard per-label
limit). 32 sits above ordinary naming conventions while still comfortably
inside what a real tunneling payload looks like.

**Parsing note:** the engine only ever sees `PacketModel.dns_query`
(already-parsed text like `"a1b2...z9.evil.example.com (TXT)"`), never a
raw DNS packet — `dns_tunnel_candidate()` in `threat_detection.py` strips
the trailing `" (TYPE)"` PacketParser appends, then requires at least
`leaf.domain.tld` (3+ labels) before checking the leaf's length. A query
that's just `domain.tld` has no separate leaf to inspect and is never a
candidate.

**Window — 20 seconds.** Shorter than the port-scan window — a tunnel is
simulating a data channel over DNS, so it's chatty by design and
reliably produces a burst of queries well inside 20 seconds. A longer
window would only delay detection without meaningfully reducing false
positives.

**Threshold — 20 oversized-label queries to the same parent domain
within the window.** Occasional long subdomains happen legitimately
(content hashes, some CDN/tracking endpoints) but not repeatedly against
one domain in a tight burst — 20 sits above what a handful of
coincidental long hostnames would produce and comfortably below what an
active tunnel session generates.

**Cooldown — 60 seconds per (source IP, parent domain) pair.** Same
reasoning as the port-scan cooldown: without it, an open tunnel would
keep matching on every subsequent query for as long as it stays active,
flooding the panel with near-duplicate rows. Tracked per parent domain
rather than per source alone, since one source could plausibly be
tunneling over more than one domain at once, and those are genuinely
separate incidents worth separate alerts.

**Severity — `medium`.** Same reasoning as port scanning: there are
uncommon but real benign explanations for occasional long subdomains
(content-addressed CDN assets, some hashed tracking/telemetry endpoints),
so this is reported for visibility as a strong signal, not treated as
confirmed exfiltration by itself.

---

## Rule 4 — SYN Flood Detection

**Signal:** one source IP sending an unusually high number of *bare* TCP
SYN packets — the SYN flag set and nothing else, no matching SYN-ACK or
ACK completing the handshake — to the same (destination IP, destination
port) pair within a short window. A SYN flood works by opening far more
half-open connections than a listener's backlog can hold, tying up
resources until legitimate connections start getting dropped; a burst of
bare SYNs with no completions is exactly what that looks like on the
wire.

**Parsing note:** the engine only ever sees `PacketModel.info` (already-
formatted text like `"TCP 51000 → 80 [S]"`), never a raw TCP flags byte
or a raw Scapy packet — `is_bare_syn()` in `threat_detection.py` parses
the trailing `[FLAGS]` PacketParser writes and matches only the exact
string `"S"`, so `"SA"` (a SYN-ACK reply), `"A"`, `"PA"`, `"FA"`, `"RA"`,
and every other combination are correctly not counted as a flood attempt
— they're normal traffic or a normal connection teardown, not a new
half-open connection attempt.

**Window — 5 seconds.** Shorter than every other rule's window here — a
real SYN flood is fast by design (the goal is exhausting a backlog before
entries can time out), so a short window catches the burst without
needing to remember much history. Ordinary traffic, like a browser
opening several parallel connections to one site, completes its
handshakes well inside this window and never accumulates as bare SYNs.

**Threshold — 40 bare SYNs to the same (destination IP, destination
port) within the window.** A browser opening a handful of parallel
connections to one host realistically stays under 10 SYNs in 5 seconds;
a flood — even a throttled one — sends dozens to thousands per second.
40 sits comfortably above ordinary concurrent-connection bursts and well
below what even a modest flood tool generates.

**Cooldown — 30 seconds per (source IP, destination IP, destination
port) triple.** Same reasoning as the port-scan cooldown: without it, an
ongoing flood would keep matching on every subsequent SYN for as long as
it runs, flooding the panel with near-duplicate rows. Tracked per
destination pair rather than per source alone, since one source could
plausibly be flooding more than one target — or more than one port on
the same target — at once, and those are genuinely separate incidents.

**Severity — `medium`, not `high`.** Unlike ARP Spoofing, there are
real, non-malicious reasons for a burst of unanswered SYNs to build up:
load-testing or monitoring tools that intentionally open many
connections quickly, or — just as plausibly — a firewall silently
dropping the *return* SYN-ACK, which makes an ordinary client's own
automatic retries look identical to an attacker's flood from this
engine's point of view. Reported for visibility, not treated as
confirmed denial-of-service by itself.

---

## Rule 5 — Beaconing Detection

**Signal:** one source IP repeatedly connecting to the same destination
`(IP, port)` at suspiciously regular intervals over an extended period —
the hallmark of C2 malware "phoning home" on a timer, as opposed to
human-driven or bursty traffic. Works equally over HTTP and HTTPS since
it never looks at payload content, only connection timing.

**Architecture note:** unlike every other rule here, this is *not* a
rolling time window. The engine keeps a fixed-size deque of the last
`BEACON_HISTORY_SIZE` connection timestamps per (source IP, destination
IP, destination port) triple — oldest evicted as new ones arrive — and on
every new connection recomputes the intervals between consecutive
timestamps and their coefficient of variation (stddev / mean). A time
window doesn't fit this signal: beaconing is a decision about the *shape*
of the gaps between connections, not "how many happened in the last N
seconds." `beacon_pattern_stats()` in `threat_detection.py` is the single
shared function that turns a timestamp history into "is this a beacon?",
used by both the live engine and the PCAP batch analyzer.

**Minimum observations — 8 consecutive intervals** before the rule trusts
a pattern enough to evaluate it at all. Fewer than this and a
coincidental run of 2-3 evenly-spaced connections (a person refreshing a
page a couple of times) could look "regular" purely by chance. Real C2
frameworks that beacon on a fixed sleep timer reliably produce this many
observations within their first few sleep cycles.

**History size — 9 timestamps** (`MIN_BEACON_OBSERVATIONS + 1`) — exactly
enough to compute 8 trailing intervals, no more. Keeping only this much
history (rather than, say, hundreds of timestamps) is what makes the
"old activity falls out of the window" behavior work here: a single
irregular gap eventually gets pushed out by enough new, regular
connections, letting a genuinely resumed beacon re-qualify.

**Coefficient of variation threshold — 0.15.** A CV below 15% means the
gap between check-ins varies by less than a seventh of the mean —
tighter than almost any legitimate traffic pattern, which naturally
carries jitter from retries, backoff, or queuing delay. Malware timers
deliberately hold to a fixed sleep value (sometimes with a small jitter
percentage, but rarely enough to push this above ~0.10–0.15). Set high
enough not to dismiss a real, slightly-jittered beacon; low enough that
ordinary bursty polling falls outside it.

**Suspicious periodicity range — 5 seconds to 1 hour.** Intervals faster
than 5 seconds look like an active bulk transfer (or a single session's
own retries/keepalives being miscounted as separate connections), not
deliberate periodic beaconing. Intervals slower than an hour would
require this session-scoped, in-memory engine to remember activity
spanning many hours just to accumulate enough observations to
evaluate — outside what it can reasonably track (see non-goals for
slow/low-and-slow C2).

**Cooldown — 300 seconds (5 minutes) per (source IP, destination IP,
destination port) triple.** Once a triple is confirmed as beaconing, the
same regular check-ins would otherwise re-qualify on literally every
subsequent connection for as long as the malware keeps running. Longer
than the port-scan/SYN-flood cooldowns because a confirmed beacon is an
ongoing background condition, not a fast-moving one-off burst — there's
no urgency to re-alert more often than every 5 minutes once the analyst
has already been told.

**Severity — `medium`, not `high`.** This is the rule with the largest
real false-positive surface of all six: many legitimate applications poll
on a fixed, regular schedule — health checks, chat/messaging clients
holding a long-poll or heartbeat connection, telemetry and crash-reporter
check-ins, software update checkers. A tight, regular interval to one
destination is a genuinely strong *timing* signal, but timing alone can't
distinguish "malware C2" from "well-behaved background service." Reported
for investigation, not treated as confirmed compromise.

---

## Rule 6 — Data Exfiltration Detection (volume-based)

**Signal:** one source IP sending an abnormally large total volume of
payload bytes to one destination IP within a rolling window — a coarse,
protocol-agnostic heuristic that a normal web session or API call would
not produce. Deliberately simple and volume-only: it never inspects
payload content, only the running byte total.

**Architecture note:** the engine keeps a rolling deque of
`(timestamp, payload_size)` pairs per (source IP, destination IP) pair,
summing `payload_size` within `EXFIL_WINDOW_SECONDS` on every new packet
and comparing the running total to `EXFIL_BYTE_THRESHOLD` — the same
rolling-window shape Rule 1 (Port Scan) and Rule 4 (SYN Flood) already
use, just summing bytes instead of counting distinct pairs or bare SYNs.

**Window — 60 seconds.** Long enough to catch a burst transfer while
it's happening, short enough that ordinary bursty traffic — even several
page loads or API calls stacked back-to-back — doesn't accidentally
accumulate toward a sustained-transfer volume by accident.

**Byte-volume threshold — 50,000,000 bytes (50MB).** A typical web page
load transfers on the order of a few hundred KB to a few MB total (even
a heavy page rarely exceeds 5-10MB); a typical API call moves kilobytes.
50MB to one destination inside the same 60-second window is an order of
magnitude beyond ordinary browsing/API traffic and matches what copying
a moderately sized file or directory off a host looks like on the wire —
comfortably above generous legitimate bursts (a software update, a large
email attachment) while still catching a real bulk transfer before it's
finished.

**Cooldown — 120 seconds (2 minutes) per (source IP, destination IP)
pair.** An ongoing transfer keeps the rolling sum above threshold for as
long as it continues, matching on every subsequent packet without a
cooldown. Longer than the port-scan cooldown since a bulk transfer is a
slower-moving, more sustained incident than a scan sweep — this
collapses one ongoing transfer into a small number of alerts instead of
one per packet, while still re-alerting if the same pair starts a
distinct new transfer later.

**Severity — `medium`, not `high`.** A large volume of traffic to one
destination has real benign explanations: a legitimate large file
download/upload, backup or sync software, cloud storage, or a big
software update pointed at a single external host. Reported for
visibility as a strong signal of bulk data movement, not treated as
confirmed exfiltration.

**Non-goal, named explicitly:** this only flags one specific
exfiltration *shape* — a burst to a single destination within one
60-second window. It does **not** catch slow/low-and-slow exfiltration
spread across time (staying under threshold by pacing the transfer over
hours or days) or across multiple destinations (splitting the same data
across several IPs, each individually under threshold). Same honest
trade-off Rule 1 makes for slow/distributed scans.

---

## Explicit non-goals for this v1

- **DNS tunneling detection is label-length-based, not entropy-based.**
  A sufficiently short encoding, or a tunnel that deliberately stays
  under the 32-character threshold per query (trading throughput for
  stealth), won't trip Rule 3 as written. Named honestly as a gap, not
  hidden — the same trade-off Rule 1 makes for slow scans.
- **Beaconing Detection has a real, named false-positive source:**
  legitimate periodic polling (health checks, chat clients, telemetry) is
  common and can look identical to a timer-based beacon from a pure
  timing signal alone — see Rule 5's severity note. This is why Rule 5 is
  `medium`, not `high`, severity.
- **Beaconing Detection assumes a roughly fixed interval.** A beacon that
  deliberately randomizes its sleep interval by more than
  `BEACON_CV_THRESHOLD` (jittered C2, common in more sophisticated
  frameworks) won't trip Rule 5 as written — same "not every evasion is
  covered" trade-off every rule here makes somewhere.
- **Data Exfiltration Detection only catches one shape: a burst to a
  single destination.** Slow/low-and-slow exfiltration spread across time
  or split across multiple destinations won't trip Rule 6 — see its
  non-goal note above.
- **No signature-based detection** — no known-bad IP lists, malware
  hashes, or threat-intel feeds. All six rules here are purely
  behavioral.
- **No distributed (multi-source) SYN flood detection.** Rule 4 tracks
  bare SYNs per *source* IP against a destination; a coordinated flood
  spread thin across many source IPs (each individually under
  `SYN_FLOOD_COUNT_THRESHOLD`) won't trip it — same cross-source
  correlation gap Rule 1 has for distributed port scans, not newly
  introduced here.
- **No automatic blocking.** Alerts are informational only. "Block IP" in
  `ThreatTable.tsx` stays a non-functional UI stub — wiring it to an
  actual firewall rule is a separate, much bigger scope decision
  (correctness here has real consequences: blocking the wrong IP is a
  self-inflicted outage) and isn't part of this task.
- **No tuning UI.** All twenty-one hardcoded constants above (window,
  threshold, and cooldown for each rule — DNS Tunneling adds a fourth,
  the label-length threshold; Beaconing has six of its own, since its
  fixed-size-history design needs a couple more knobs than a simple
  rolling window does) are hardcoded in `threat_detection.py`, not
  user-configurable. A real SOC tool would want per-network tuning
  eventually — named here as a legitimate future enhancement, the same
  way hostname resolution was named as one for Host Discovery, not
  silently deferred.
- **No slow/distributed scan detection.** A scan paced slower than 15
  distinct pairs per 10s window, or spread across multiple source IPs
  (a botnet-style distributed scan), won't trip Rule 1 as written. Named
  honestly as a gap, not hidden.

---

## Why a ring buffer instead of unbounded storage

Same reasoning as `packets.md`: the alert buffer is a bounded `deque`
(default 500 alerts) so memory stays flat regardless of session length.
Alerts are lower-volume than packets, so 500 covers a much longer session
before anything is evicted — but nothing here claims to be a permanent
audit log. Persisting the full alert history across restarts, or longer
than the buffer holds, is a separate Export/Reporting concern, not this
module's job.

---

*Next candidate: tuning UI for the twenty-one hardcoded constants above,
distributed/slow-scan detection for Port Scan and SYN Flood alike (both
would need cross-source correlation this engine's per-source-IP state
deliberately doesn't do), entropy-based DNS tunneling detection to catch
payloads that stay under the label-length threshold, or jitter-tolerant
beaconing detection to catch a C2 timer that deliberately randomizes its
sleep interval.*
