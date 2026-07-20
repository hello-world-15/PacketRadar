# PacketRadar

Live network traffic monitor and offline PCAP analyzer, built as a full‑stack
app: a Python/Scapy packet‑capture backend feeding a real‑time React
dashboard, plus a separate analyzer for inspecting `.pcap`/`.pcapng` files
after the fact.

Watch traffic as it happens — top talkers, live packet stream, behavioral
threat detection, per‑process bandwidth — or drop in a capture file to get
DNS analysis, a network health score, protocol breakdowns, and a searchable
packet explorer.

> **Status:** actively developed portfolio project. See
> [Known limitations](#known-limitations) below for what's real vs. not yet
> built — documented deliberately, not hidden.

---

## Features

**Live Monitor**
- Real‑time KPI cards (packets/sec, bandwidth, active connections, dropped
  packets, LAN device count, threat alert count) over a WebSocket feed
- Passive host discovery via ARP sniffing
- Live packet stream table (source, destination, protocol, length, DNS
  query/answer detail)
- Top Talkers ranking by bandwidth
- Top Applications — per‑process upload/download via `psutil` port→PID
  resolution
- Threat Detection panel — **six** behavioral rules: Port Scan Detection,
  ARP Spoofing Detection, DNS Tunneling Detection, SYN Flood Detection,
  Beaconing Detection, and Data Exfiltration Detection (all behavioral —
  no signature matching, no auto‑blocking — see limitations)
- Start/Stop Recording and Export PCAP straight from the dashboard

**PCAP Analyzer**
- Upload a `.pcap`/`.pcapng` file and get a full capture summary
- DNS Analysis (top / repeated / failed domains)
- Threat Analysis (all six behavioral rules replayed over the whole file,
  with episode/aggregate grouping suited to a full capture rather than a
  live stream)
- Network Health Score (heuristic indicator, not a security audit)
- Top Hosts + Conversations
- Protocol Distribution + Traffic Timeline
- Paginated Packet Explorer with a packet‑detail drawer
- PDF report export (cover page, charts, findings, recommendations)

---

## Tech Stack

| Layer | Stack |
|---|---|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Chart.js, React Router |
| Backend | Python, FastAPI, Scapy, Pydantic, WebSockets, psutil |
| Reporting | ReportLab, Matplotlib |
| Testing | Pytest (backend) |

## Architecture

```
┌────────────────────┐        WebSocket (/ws/live)        ┌──────────────────────┐
│   React frontend    │ ◄────────────────────────────────► │   FastAPI backend     │
│   (src/)             │        REST (/api/pcap/...)        │   (backend/app/)       │
└────────────────────┘                                     └──────────┬────────────┘
                                                                        │
                                                             ┌──────────▼────────────┐
                                                             │  Scapy packet capture  │
                                                             │  (raw socket, needs    │
                                                             │   elevated privileges) │
                                                             └────────────────────────┘
```

The backend is organized in layers under `backend/app/`:

- `capture/` — the only layer allowed to touch Scapy directly (sniffing,
  local IP resolution, process/port resolution, watchdog)
- `parser/` — converts raw packets into an internal `PacketModel`
- `engines/` — pure, unit‑testable computation (stats, host discovery, top
  talkers, threat detection, PCAP analysis engines, etc.)
- `api/` + `ws/` — FastAPI REST routers and the WebSocket multiplexer
- `schemas/` — Pydantic response models, one per contract in `docs/contracts/`
- `report/` — the PDF report pipeline (models → builder → charts/tables →
  PDF generator)

Every feature has a written data contract in [`docs/contracts/`](docs/contracts/)
covering payload shape, transport (push vs. pull), and what's real vs.
deliberately stubbed — written before implementation, kept up to date after.
That folder is the best place to understand *why* something works the way it
does, not just what it does.

---

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Python 3.11+
- **Administrator/root privileges** — live packet capture opens a raw
  socket, which requires elevated privileges on every OS. The app still runs
  without them, but falls back to mock data on the Live Monitor page instead
  of a broken/blank screen.

### 1. Frontend

```bash
npm install
npm run dev
```

Runs at `http://localhost:5173`.

### 2. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# macOS / Linux (needs root to open a raw socket):
sudo .venv/bin/uvicorn app.main:app --reload

# Windows (run the terminal as Administrator):
uvicorn app.main:app --reload
```

Runs at `http://localhost:8000`. Health check: `GET /api/health`.

With both running, open the Live Monitor page — a badge above the KPI cards
switches from "Mock data" to "Live backend data" once the WebSocket
connects.

> Packet capture uses whatever interface Scapy picks by default. There's no
> interface‑selection endpoint yet — see [Known limitations](#known-limitations).

### Running tests

```bash
cd backend
pip install pytest httpx
python -m pytest tests/ -v
```

Almost every test is a pure unit test (no root needed). A few integration
tests generate a small synthetic `.pcap` with Scapy and hit the real FastAPI
endpoints end to end.

---

## Project Structure

```
.
├── src/                    # React frontend
│   ├── components/         # Reusable UI (tables, cards, charts, modals)
│   ├── pages/               # LiveMonitor, PcapAnalyzer, About
│   ├── hooks/                # useLiveSocket, useCaptureControl
│   ├── lib/                   # API/WebSocket client helpers
│   └── types/                  # Shared TypeScript types
├── backend/
│   ├── app/
│   │   ├── api/              # REST routers
│   │   ├── ws/                 # WebSocket routers/manager
│   │   ├── capture/             # Scapy sniffing, local IP, process resolution
│   │   ├── parser/               # Raw packet -> PacketModel
│   │   ├── engines/               # Pure computation (stats, threats, PCAP analysis...)
│   │   ├── schemas/                # Pydantic response models
│   │   ├── report/                  # PDF report generation pipeline
│   │   └── main.py                   # FastAPI entrypoint
│   ├── tests/                # Pytest suite (24 test files)
│   ├── captures/              # Local recordings (gitignored)
│   └── pcap_uploads/           # Local uploads (gitignored)
└── docs/
    └── contracts/            # Per-feature data contracts (source of truth)
```

## API Documentation

Every endpoint and WebSocket event is documented in
[`docs/contracts/`](docs/contracts/), organized by feature (e.g.
[`stats.md`](docs/contracts/stats.md), [`threats.md`](docs/contracts/threats.md),
[`pcap-analysis.md`](docs/contracts/pcap-analysis.md)). Each contract covers
the payload shape, transport, and — importantly — what's genuinely computed
vs. what's a deliberate scope cut for this version.

---

## Known limitations

Documented explicitly rather than left as silent gaps:

- Threat Detection covers six behavioral rules (Port Scan, ARP Spoofing,
  DNS Tunneling, SYN Flood, Beaconing, Data Exfiltration) — all purely
  behavioral, no signature/known‑bad‑IP matching, no automatic blocking
- No hostname resolution for discovered hosts or top talkers (shown as
  "Unknown Device")
- No process attribution on the live packet stream table (Top Applications
  has its own separate, working attribution path)
- No interface‑selection endpoint — capture uses Scapy's default interface
- `dropped_packets` reflects internal queue drops only, not OS/libpcap‑level
  packet loss
- Uploaded `.pcap` files are not automatically deleted after parsing

Full details, including the reasoning behind each cut, are in
`backend/README.md` and the relevant file under `docs/contracts/`.

## Roadmap

- Interface selection endpoint + working Navbar dropdown
- Hostname resolution (mDNS/DHCP/reverse DNS) for hosts and talkers
- Additional threat rules (DNS tunneling, C2 beaconing, exfiltration)
- Background job queue for large PCAP uploads with progress reporting

## License

MIT — see [LICENSE](LICENSE). Free to use, modify, and distribute, with
attribution.

## Responsible use

PacketRadar captures live traffic on whatever network interface it runs on.
Only run it against networks and devices you own or have explicit permission
to monitor.
