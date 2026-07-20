# PacketRadar Backend — Technical Reference

> For a project overview, quickstart, and architecture summary, see the
> [root README](../README.md). This document is a detailed, module‑by‑module
> reference: what's implemented, what's real vs. stubbed, and why.

Implements fourteen modules so far, per `../docs/contracts/`:

- **Module 1 — Live Monitor KPI cards** (`stats.md`)
- **Module 2 — Passive Host Discovery** (`hosts.md`), which also fills
  in the `lan_device_count` field that Module 1 stubbed at 0.
- **Module 3 — Live Packet Stream** (`packets.md`), the row-by-row
  packet table.
- **Module 4 — Continuous capture + Start/Stop Recording + Export PCAP**
  (`app/api/capture.py`). Sniffing is now always-on from server boot
  (not tied to WebSocket connect/disconnect like Modules 1-3 originally
  were); "recording" (writing to a `.pcap`) is a separate, explicit
  toggle on top of that.
- **Module 5 — Top Talkers** (`talkers.md`), the per-IP bandwidth
  ranking table.
- **Module 6 — Real Bandwidth Chart (Upload/Download Split)** (extends
  `stats.md` rather than a new contract — see that doc's "Upload/download
  split" section for why). Adds `upload_mbps`/`download_mbps` to the
  existing `stats:update` event by classifying each packet's direction
  against this machine's own IP address(es) (`app/capture/local_ip.py`).
- **Module 7 — Threat Detection Engine** (`threats.md`), two behavioral
  detection rules (Port Scan, ARP Spoofing) feeding a live alert panel,
  which also fills in the `threat_alert_count` field that Module 1
  stubbed at 0.
- **Module 8 — Top Applications** (`applications.md`), per-process
  upload/download ranking via `psutil`-based port→PID resolution
  (`app/capture/process_resolution.py`).
- **Module 9 — PCAP Analyzer: Upload & Capture Summary**
  (`pcap-upload.md`) — the first backend module for the second major
  page, previously 100% mock. `POST /api/pcap/upload` reuses the exact
  same `PacketParser` live capture uses (per the architecture's "never
  duplicate packet parsing logic" mandate) to parse an uploaded file and
  return the six Capture Summary cards.
- **Module 10 — PCAP Analyzer: DNS Analysis, Threat Analysis, Network
  Health Score** (`pcap-analysis.md`) — `GET /api/pcap/{capture_id}/insights`.
  Threat Analysis here reuses `ThreatDetectionEngine`'s exact two live rules,
  replayed once over the full stored capture using each packet's own
  historical timestamp rather than wall-clock time (`record_port_activity`/
  `record_arp_sighting` gained an optional `now` override for this).
  Required extending `PacketModel` with `src_mac`/`dst_mac` fields so ARP
  Spoofing Detection has MAC data to work with for stored (not live) packets.
  Superseded for Threat Analysis specifically by Module 12's dedicated
  endpoint — this one's `threats` field is the older, simpler per-packet
  version, kept because Health Score's formula already depends on it.
- **Module 11 — PCAP Analyzer: Top Hosts + Conversations**
  (`pcap-hosts-conversations.md`) — `GET /api/pcap/{capture_id}/hosts-conversations`.
- **Module 12 — PCAP Analyzer: Threat Analysis (dedicated)**
  (`pcap-threat-analysis.md`) — `GET /api/pcap/{capture_id}/threats`.
  Reimplements all six rules (Port Scan, ARP Spoofing, DNS Tunneling, SYN
  Flood, Beaconing, Data Exfiltration) as pure functions rather than
  reusing the live `ThreatDetectionEngine` instance (a live cooldown
  doesn't answer "did this happen anywhere in this file") — episode
  grouping for Port Scan, aggregate-per-IP for ARP Spoofing, and a
  `source` field the simpler Module 10 version never captured. This is
  the version `PcapAnalyzer.tsx`'s Threat Analysis section actually uses.
- **Module 13 — PCAP Analyzer: Packet Explorer**
  (`pcap-packet-explorer.md`) — `GET /api/pcap/{capture_id}/packets`,
  paginated (`offset`/`limit`, default 100/max 500 per page). Real Packet
  Details drawer (source/destination/MACs/ports/protocol info/DNS
  detail) — but TTL and a hex/ASCII payload view are explicitly *not*
  faked: `PacketModel` never stores a TTL or raw payload bytes, so those
  two drawer fields were dropped rather than continuing to show
  hardcoded placeholder values. See the contract's "What the drawer can
  — and can't — honestly show".
- **Module 14 — PCAP Analyzer: Protocol Distribution + Traffic Timeline**
  (`pcap-protocol-timeline.md`) — `GET /api/pcap/{capture_id}/protocol-timeline`.
  Protocol Distribution reuses `app.schemas.stats.ProtocolCount` (the
  live dashboard's identical `{label, value}` shape) instead of
  redefining an equivalent class. Traffic Timeline replaces the old
  mock's 24 fake hourly buckets (`"0:00"`-`"23:00"`) with 24
  evenly-spaced buckets across the capture's *real* min-to-max
  timestamp span, labeled with real clock times rather than a
  fixed day.

Nothing else is implemented yet — no other widget's backend exists, on
purpose (see the project constitution: one module at a time).

## What's real vs. stubbed — Live Monitor page

| Field / Widget | Status |
|---|---|
| `packets_per_sec`, `bandwidth_mbps` | Real — computed from live captured packets |
| `upload_mbps`, `download_mbps` | **Real as of Module 6** — same rolling 1s window as `bandwidth_mbps`, split by classifying each packet's source/destination IP against this machine's own resolved IP(s). Traffic between two other LAN hosts (seen in promiscuous mode) counts toward `bandwidth_mbps` but is excluded from both — not guessed at. Falls back to `0.0` for both (with `bandwidth_mbps` unaffected) if local IP resolution fails; see `app/capture/local_ip.py` |
| `active_connections` | Real — distinct 5-tuple flows seen in the last 30s |
| `dropped_packets` | Real, but only counts packets our own processing queue couldn't keep up with — not a libpcap-level drop counter (see `app/capture/sniffer.py` docstring) |
| `lan_device_count` | Real — count of hosts seen via ARP within the last 30s |
| Passive Host Discovery table | Real — built from ARP sightings; hostnames are not resolved (always "Unknown Device") |
| Live Packet Stream table | Real — every row is a captured, parsed packet (source, destination, protocol, length, info, DNS query/answer where applicable) |
| Start/Stop Recording, Export PCAP | Real — `app/api/capture.py`, streams the live capture to a `.pcap` file on demand |
| Top Talkers table | Real — per-IP packet counts (cumulative) and bandwidth (5s smoothed), ranked descending |
| `process` (packet stream column) | **Still stubbed at `null`** — no OS process attribution for the *packet stream* specifically, see `packets.md` (Top Applications, Module 8, does have process attribution — it's a separate data path) |
| Top Talkers `hostname` | **Still stubbed at `null`** — same hostname-resolution scope cut as Host Discovery |
| Threat Detection panel | Real — six behavioral rules: Port Scan, ARP Spoofing, DNS Tunneling, SYN Flood, Beaconing, and Data Exfiltration Detection. Purely behavioral (no signature/known-bad-IP matching), no automatic blocking — see `threats.md` for full thresholds/cooldowns and the explicit non-goals list |
| `threat_alert_count` | Real — cumulative count of alerts raised this session, from `ThreatDetectionEngine.alert_count` |
| **Top Applications table** | **Real as of Module 8** — per-process upload/download (5s smoothed) via `psutil` port→PID resolution, refreshed at most every 2s (not per-packet — see `process_resolution.py`) |
| Interface selection (Navbar dropdown) | **Not wired** — still a hardcoded list, no `GET /api/interfaces` endpoint yet |

## What's real vs. stubbed — PCAP Analyzer page

| Field / Widget | Status |
|---|---|
| Upload & Analyze, Capture Summary cards (6) | Real — `POST /api/pcap/upload`, see `pcap-upload.md` |
| Network Health Score | Real — `GET /api/pcap/{capture_id}/insights`, see `pcap-analysis.md`. Explicitly a heuristic/relative indicator, not a security audit |
| DNS Analysis (Top/Repeated/Failed Domains) | Real — same `/insights` call, see `pcap-analysis.md` |
| Threat Analysis | Real — `GET /api/pcap/{capture_id}/threats` (the dedicated, episode/aggregate-based engine — see `pcap-threat-analysis.md`), not the simpler version bundled into `/insights` |
| Top Hosts, Conversations | Real — `GET /api/pcap/{capture_id}/hosts-conversations`, see `pcap-hosts-conversations.md` |
| Packet Explorer, Packet Details drawer | Real — paginated `GET /api/pcap/{capture_id}/packets`, see `pcap-packet-explorer.md`. Drawer omits TTL and hex/ASCII payload view rather than faking them — `PacketModel` never stores either |
| Protocol Distribution, Traffic Timeline | Real — `GET /api/pcap/{capture_id}/protocol-timeline`, see `pcap-protocol-timeline.md` |
| Export PDF Report | Still mock (button has no handler) |


## Running it

Packet capture needs raw-socket access, so this needs elevated
privileges.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate        # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# macOS / Linux — needs root to open a raw socket:
sudo .venv/bin/uvicorn app.main:app --reload

# Windows — run your terminal as Administrator, then:
uvicorn app.main:app --reload
```

By default Scapy captures on the OS's default interface. Interface
selection is a separate widget (the dropdown in `Navbar.tsx`) and isn't
wired up yet — passing a specific interface currently requires editing
`capture.start()` in `app/state.py`/`app/main.py`'s lifespan handler to
`capture.start(interface="eth0")` (or your interface name).

**Host discovery specifically depends on your machine actually seeing
ARP traffic** — on some Wi-Fi networks with client isolation, or when
capturing on a loopback/VPN interface, you may see few or no ARP
packets. Try it on a wired connection or a simple home Wi-Fi network
first.

## Running the tests

Nearly every test is a pure unit test — no live capture or root
privileges needed. The exceptions — `test_pcap_upload_api.py`,
`test_pcap_threats_api.py`, and `test_pcap_packets_api.py` — write a
small synthetic `.pcap` with Scapy and hit the real FastAPI endpoints
end to end — that still doesn't need root (only *live* capture does),
but does need `httpx` for FastAPI's `TestClient`:

```bash
cd backend
pip install pytest httpx
python -m pytest tests/ -v
```

## Connecting the frontend

1. Start this backend (`sudo uvicorn app.main:app --reload`) — it listens on `http://localhost:8000`.
2. Start the frontend as usual (`npm run dev` from the project root) — it listens on `http://localhost:5173`.
3. Open the Live Monitor page. The badge above the KPI cards will switch
   from "Mock data (backend not connected)" to "Live backend data" once
   the shared `/ws/live` WebSocket connects. The KPI cards, the Passive
   Host Discovery table, the Live Packet Stream table, the Top Talkers
   table, and the Threat Detection panel all update from that one
   connection.

If the backend isn't running, the frontend falls back to the same mock
values it always used — the dashboard never shows a broken/blank state.

## Folder structure

```
app/
  main.py                FastAPI entrypoint, CORS, router registration, capture lifespan
  state.py                Process-wide engine/capture singletons (shared by REST + WS)
  api/
    capture.py             Start/stop recording + export PCAP (REST)
    packets.py              GET /packets — pull-based snapshot (see cache/ below)
    pcap.py                   PCAP Analyzer: upload/insights/hosts-conversations/threats/packets (REST)
  capture/
    sniffer.py             Only module allowed to touch Scapy directly (plus
                            parser/packet_parser.py, which it hands packets to)
    local_ip.py             Resolves this machine's own IP(s) for upload/download
                            direction classification (Module 6) — stdlib only
  parser/
    packet_parser.py        Converts a raw Scapy packet into the internal PacketModel
  models/
    packet.py               Rich internal packet representation (used by cache/, parser/)
  engines/
    statistics.py           Rolling-window stats computation (pure, unit-testable)
    host_discovery.py       ARP-based passive host table (pure, unit-testable)
    packet_stream.py        Bounded ring buffer + delta cursor for the packet table
    top_talkers.py           Per-IP bandwidth ranking (pure, unit-testable)
    threat_detection.py      All six behavioral threat rules, ring buffer + delta cursor
    top_applications.py       Per-process bandwidth ranking (pure, unit-testable)
    pcap_summary.py            Capture Summary aggregation for uploaded files (pure, unit-testable)
    pcap_insights.py            DNS + Threat (simple) + Health Score, bundled (pure, unit-testable)
    pcap_hosts_conversations.py  Top Hosts + Conversations for uploaded files (pure, unit-testable)
    pcap_threat_analysis.py      Dedicated version of all six rules over a full capture (pure functions)
    pcap_packet_explorer.py      Paginated Packet Explorer rows (pure function)
  cache/
    packet_cache.py         In-memory buffer backing GET /packets (REST, not the live WS feed)
    pcap_store.py             In-memory store for parsed PCAP uploads, keyed by capture_id
  schemas/
    stats.py                 Implements docs/contracts/stats.md
    hosts.py                  Implements docs/contracts/hosts.md
    packets.py                Implements docs/contracts/packets.md
    talkers.py                 Implements docs/contracts/talkers.md
    threats_live.py             Implements docs/contracts/threats.md
    applications.py               Implements docs/contracts/applications.md
    pcap.py                        Implements pcap-upload/pcap-analysis/pcap-hosts-conversations/pcap-threat-analysis/pcap-packet-explorer
  ws/
    manager.py                Generic WebSocket connection registry
    live_socket.py             /ws/live — multiplexes stats/hosts/packets/talkers/threats update events
captures/                    .pcap files from completed recordings (gitignored)
pcap_uploads/                 .pcap files from PCAP Analyzer uploads (gitignored)
tests/
  test_statistics_engine.py
  test_host_discovery_engine.py
  test_packet_stream_engine.py
  test_packet_parser.py
  test_top_talkers_engine.py
  test_threat_detection_engine.py
  test_top_applications_engine.py
  test_pcap_summary.py
  test_pcap_upload_api.py     Integration test — the one place that touches a real generated .pcap file
  test_pcap_hosts_conversations.py
  test_pcap_threat_analysis.py
  test_pcap_threats_api.py    Integration test — real .pcap through GET /{capture_id}/threats end to end
  test_pcap_packet_explorer.py
  test_pcap_packets_api.py    Integration test — real .pcap through GET /{capture_id}/packets end to end
  test_sniffer.py
  test_local_ip.py
```

## Known limitations / next steps

- `dropped_packets` undercounts real packet loss since it doesn't see
  OS/libpcap-level drops, only our own queue overflow (and there's no
  longer even a queue to overflow — see `sniffer.py`'s module docstring
  for why `_pending`/`MAX_PENDING` were removed rather than fixed).
- No interface selection endpoint yet (`GET /api/interfaces`) — needed to
  make the Navbar's interface dropdown functional.
- Host Discovery and Top Talkers both have no hostname resolution
  (DHCP/mDNS/reverse DNS) — every device shows as "Unknown Device".
  Documented as a deliberate scope cut in `docs/contracts/hosts.md` and
  `talkers.md`, not an oversight.
- Live Packet Stream has no process attribution (`process` is always
  `null`) and no server-side (BPF) filtering — the search/protocol/port
  filters in `FilterBar` only filter what's already in the client's
  buffer. Both are deliberate v1 scope cuts, documented in
  `docs/contracts/packets.md`.
- `packet_cache` (REST `/packets`) and `PacketStreamEngine`
  (`packets:update` over WebSocket) both store recent packets, fed from
  the same capture callback. Not accidental duplication — they serve
  different consumption patterns (pull/one-shot vs. push/delta) — but
  worth revisiting if the REST path stays unused for a long stretch.
- Top Talkers counts both the source and destination IP of every packet
  (a host is a "talker" whether sending or receiving), so summing all
  talkers' bandwidth double-counts each packet — a deliberate ranking
  choice, not a partition of total traffic. See `talkers.md`.
- Upload/download direction classification (`app/capture/local_ip.py`,
  Module 6) is interface-agnostic — it asks the OS which address it'd
  use to reach the internet and which address(es) resolve for the
  machine's own hostname, rather than querying the specific interface
  Scapy is capturing on. Matches on a typical single-NIC machine;
  can misclassify if capturing on a secondary NIC or VPN tunnel that
  differs from the default route. Same pragmatism tradeoff as Host
  Discovery's ARP-only approach. See `stats.md`'s "Upload/download
  split" for the full reasoning, including the documented fallback
  (`upload_mbps`/`download_mbps` both `0.0`, `bandwidth_mbps` unaffected)
  if resolution fails entirely.
- Threat Detection (Module 7, later extended) now covers six behavioral
  rules — Port Scan, ARP Spoofing, DNS Tunneling, SYN Flood, Beaconing, and
  Data Exfiltration Detection. Still no signature-based matching
  (known-bad IPs, malware hashes), no automatic blocking ("Block IP" stays
  a non-functional UI stub), and no tuning UI — every window, threshold,
  and cooldown is a hardcoded constant in
  `app/engines/threat_detection.py`. A scan paced slower than the
  threshold, or spread across multiple source IPs, won't trip Rule 1 as
  written; similar evasion caveats apply per-rule — see
  `docs/contracts/threats.md`'s "Explicit non-goals" section for the
  full list. All named explicitly, not hidden.
- `ThreatDetectionEngine` keeps its own IP→MAC bookkeeping for ARP
  Spoofing Detection rather than reading `HostDiscoveryEngine`'s internal
  state — `PacketCapture` calls both engines' sighting methods
  independently for the same ARP packet. Same "engines don't depend on
  each other" trade-off already made between `HostDiscoveryEngine` and
  `TopTalkersEngine`.
- Top Applications (Module 8) refreshes its port→PID table at most every
  2 seconds (`app/capture/process_resolution.py`), not per-packet — a
  process that opens and closes a connection entirely between two refresh
  ticks can be missed. Also requires the same elevated privileges packet
  capture already needs to see *other* users' processes; without them,
  the table degrades to empty rather than raising an error.
- PCAP Analyzer (Modules 9-14) covers Upload & Capture Summary, DNS
  Analysis, Threat Analysis, Network Health Score, Top Hosts,
  Conversations, Packet Explorer, and Protocol Distribution + Traffic
  Timeline. Export PDF Report is still mock data, on purpose. See
  `docs/contracts/pcap-upload.md`'s "Next candidates".
- Packet Explorer (Module 13) drops two drawer fields the old mock UI
  had rather than fake them: TTL (never parsed anywhere in
  `PacketParser`) and a hex/ASCII payload view (`PacketModel` stores
  `payload_size` as an int, never the actual bytes — retaining raw
  payloads for a 200,000-packet capture is a real memory cost nothing
  else in this codebase needs to pay). Both are named as legitimate
  future `PacketParser`/`PacketModel` additions, not bugs. See
  `docs/contracts/pcap-packet-explorer.md`.
- Uploaded `.pcap` files (`backend/pcap_uploads/`) are never deleted
  automatically after parsing, and `PcapAnalysisStore` only keeps the 5
  most recent uploads' *parsed* data in memory (oldest evicted first) —
  the files on disk outlive that in-memory eviction. A real cleanup
  policy is a legitimate future addition, not implemented here.
- PCAP upload parsing is synchronous inside the request handler, capped
  at 200,000 packets (`MAX_PACKETS` in `app/api/pcap.py`) so one huge file
  can't hang the request indefinitely. No background job queue or upload
  progress reporting — fine at this project's scale, named as a scope cut
  in `docs/contracts/pcap-upload.md`.
- Fixing `PacketParser.parse()`'s hardcoded `datetime.now()` timestamp
  (needed for `duration_seconds` to be meaningful on uploaded files) was
  done as a backward-compatible optional parameter — the one existing
  live-capture call site is unaffected. Worth knowing this bug existed
  silently in the parser until PCAP reuse actually exercised it; live
  capture's `stats:update` cadence never surfaced it because "packet
  parsed a few microseconds ago" and "packet captured a few microseconds
  ago" were indistinguishable there.


