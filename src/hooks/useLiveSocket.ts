import { useEffect, useRef, useState } from 'react'
import type { DiscoveredHost, PacketRow, Protocol, ThreatAlert, TopApplication, TopTalker } from '@/types'
import { iconForApp } from '@/lib/appIcons'

/**
 * Mirrors backend/app/schemas/stats.py::LiveStats — keep in sync with
 * docs/contracts/stats.md if either side changes.
 */
export interface LiveStats {
  packets_per_sec: number
  bandwidth_mbps: number
  /** Same rolling 1s window as bandwidth_mbps, restricted to packets
   * whose source IP matched a local IP at capture start. 0 if local IP
   * resolution failed (see docs/contracts/stats.md) — bandwidth_mbps
   * stays correct either way, only the split is unavailable. */
  upload_mbps: number
  /** Same window, restricted to packets whose destination IP matched a
   * local IP. Packets matching neither (LAN-to-LAN traffic) count in
   * bandwidth_mbps but not here. */
  download_mbps: number
  active_connections: number
  threat_alert_count: number
  lan_device_count: number
  dropped_packets: number
  /** Cumulative counts per protocol since the capture started (not
   * windowed like the fields above) — raw counts, percentages are
   * computed client-side. {label, value}[] shape matches what
   * ProtocolPieChart expects. */
  protocol_distribution: { label: string; value: number }[]
}

/** Raw shape sent by the backend — see docs/contracts/hosts.md. */
interface BackendHost {
  ip: string
  mac: string
  hostname: string | null
  last_seen: number // unix seconds
  status: 'online' | 'offline'
}

/** Raw shape sent by the backend — see docs/contracts/packets.md. */
interface BackendPacketRow {
  no: number
  time: number // unix seconds
  source: string
  destination: string
  protocol: string
  length: number
  process: string | null
  info: string
  dns_query?: string | null
  dns_answer?: string | null
}

/** Raw shape sent by the backend — see docs/contracts/talkers.md. */
interface BackendTalker {
  ip: string
  hostname: string | null
  packets: number
  bandwidth_mbps: number
  bandwidth_pct: number
  connections: number
}

/** Raw shape sent by the backend — see docs/contracts/applications.md.
 * No `icon` field — that's presentation, filled in by `toApplication()`
 * via the same `appIcons` map the mock data always used. */
interface BackendApplication {
  pid: number
  name: string
  upload_kbps: number
  download_kbps: number
  connections: number
}

/** Raw shape sent by the backend — see docs/contracts/threats.md. `no`
 * is engine-internal bookkeeping only, used here to dedupe/merge and
 * dropped before reaching the frontend's `ThreatAlert` type, which has
 * no `no` field. */
interface BackendThreatAlert {
  no: number
  id: string
  time: number // unix seconds
  severity: 'high' | 'medium' | 'low'
  threat: string
  source: string
  description: string
}

interface StatsUpdateEvent {
  type: 'stats:update'
  data: LiveStats
}

interface HostsUpdateEvent {
  type: 'hosts:update'
  data: BackendHost[]
}

interface PacketsUpdateEvent {
  type: 'packets:update'
  data: BackendPacketRow[]
}

interface TalkersUpdateEvent {
  type: 'talkers:update'
  data: BackendTalker[]
}

interface ThreatsUpdateEvent {
  type: 'threats:update'
  data: BackendThreatAlert[]
}

interface ApplicationsUpdateEvent {
  type: 'applications:update'
  data: BackendApplication[]
}

type LiveEvent =
  | StatsUpdateEvent
  | HostsUpdateEvent
  | PacketsUpdateEvent
  | TalkersUpdateEvent
  | ThreatsUpdateEvent
  | ApplicationsUpdateEvent

// Client-side cap on the rolling packet table — the backend buffer is
// bigger (2000, see packet_stream.py) but the table only needs to
// render a scrollable few hundred rows at a time.
const MAX_PACKET_ROWS = 300

// Same idea for the threat alert panel — the backend buffer is bigger
// (500, see threat_detection.py) but the panel only needs a scrollable
// recent history, not the full session.
const MAX_THREAT_ALERTS = 200

const KNOWN_PROTOCOLS: Protocol[] = ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP']

const WS_URL = 'ws://localhost:8000/ws/live'
const RECONNECT_DELAY_MS = 2000

function formatClockTime(unixSeconds: number): string {
  const d = new Date(unixSeconds * 1000)
  const pad = (n: number) => n.toString().padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

function toDiscoveredHost(h: BackendHost): DiscoveredHost {
  return {
    hostname: h.hostname ?? 'Unknown Device',
    ip: h.ip,
    mac: h.mac,
    lastSeen: formatClockTime(h.last_seen),
    status: h.status,
  }
}

function toTopTalker(t: BackendTalker): TopTalker {
  return {
    ip: t.ip,
    hostname: t.hostname ?? 'Unknown Device',
    packets: t.packets,
    bandwidthMbps: t.bandwidth_mbps,
    bandwidthPct: t.bandwidth_pct,
    connections: t.connections,
  }
}

function toApplication(a: BackendApplication): TopApplication {
  return {
    pid: a.pid,
    name: a.name,
    uploadKbps: a.upload_kbps,
    downloadKbps: a.download_kbps,
    connections: a.connections,
    icon: iconForApp(a.name),
  }
}

/** Backend sends "OTHER"/"DNS"/etc. as a plain string; narrow it to the
 * frontend's Protocol union so anything unrecognized (rather than
 * crashing a lookup like protocolColor[r.protocol]) safely falls back
 * to "Other". */
function toProtocol(p: string): Protocol {
  const upper = p.toUpperCase()
  const match = KNOWN_PROTOCOLS.find((known) => known === upper)
  return match ?? 'Other'
}

function toPacketRow(p: BackendPacketRow): PacketRow {
  return {
    no: p.no,
    time: formatClockTime(p.time),
    source: p.source,
    destination: p.destination,
    protocol: toProtocol(p.protocol),
    length: p.length,
    process: p.process ?? undefined,
    info: p.info,
    dnsQuery: p.dns_query ?? undefined,
    dnsAnswer: p.dns_answer ?? undefined,
  }
}

/**
 * Merges a new batch of packets into the rolling buffer, deduping by
 * `no` (a client can legitimately see the same row twice — once in the
 * connect-time backlog, once in the next broadcast tick — see
 * docs/contracts/packets.md), newest first, capped at MAX_PACKET_ROWS.
 */
function mergePacketRows(existing: PacketRow[], incoming: PacketRow[]): PacketRow[] {
  const byNo = new Map<number, PacketRow>()
  for (const row of existing) byNo.set(row.no, row)
  for (const row of incoming) byNo.set(row.no, row)
  return Array.from(byNo.values())
    .sort((a, b) => b.no - a.no)
    .slice(0, MAX_PACKET_ROWS)
}

function toThreatAlert(a: BackendThreatAlert): ThreatAlert {
  return {
    id: a.id,
    time: formatClockTime(a.time),
    severity: a.severity,
    threat: a.threat,
    source: a.source,
    description: a.description,
  }
}

function alertSeq(id: string): number {
  const match = /-(\d+)$/.exec(id)
  return match ? Number(match[1]) : 0
}

/**
 * Merges a new batch of alerts into the rolling buffer, deduping by
 * `id` (same backlog-then-broadcast overlap as packets, see
 * docs/contracts/threats.md), newest first, capped at MAX_THREAT_ALERTS.
 * `ThreatAlert` has no `no` field, so the sequence number embedded in
 * `id` (f"threat-{no}") is what orders here — sorting the id strings
 * directly would break once ids reach double digits.
 */
function mergeThreatAlerts(existing: ThreatAlert[], incoming: ThreatAlert[]): ThreatAlert[] {
  const byId = new Map<string, ThreatAlert>()
  for (const alert of existing) byId.set(alert.id, alert)
  for (const alert of incoming) byId.set(alert.id, alert)
  return Array.from(byId.values())
    .sort((a, b) => alertSeq(b.id) - alertSeq(a.id))
    .slice(0, MAX_THREAT_ALERTS)
}

interface LiveSocketFallback {
  stats: LiveStats
  hosts: DiscoveredHost[]
  packets: PacketRow[]
  talkers: TopTalker[]
  threats: ThreatAlert[]
  applications: TopApplication[]
}

/**
 * Connects once to the backend's shared /ws/live socket and dispatches
 * incoming events by `type`. Both `stats:update` and `hosts:update` ride
 * the same connection — see docs/contracts/hosts.md for why.
 *
 * Falls back to `fallback` values whenever the socket isn't connected
 * (backend not running, or between reconnect attempts), so widgets never
 * render blank/undefined state.
 */
export function useLiveSocket(fallback: LiveSocketFallback) {
  const [stats, setStats] = useState<LiveStats>(fallback.stats)
  const [hosts, setHosts] = useState<DiscoveredHost[]>(fallback.hosts)
  const [packets, setPackets] = useState<PacketRow[]>(fallback.packets)
  const [talkers, setTalkers] = useState<TopTalker[]>(fallback.talkers)
  const [threats, setThreats] = useState<ThreatAlert[]>(fallback.threats)
  const [applications, setApplications] = useState<TopApplication[]>(fallback.applications)
  const [connected, setConnected] = useState(false)
  const socketRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    let cancelled = false

    function connect() {
      const socket = new WebSocket(WS_URL)
      socketRef.current = socket

      socket.onopen = () => {
        if (cancelled) return
        setConnected(true)
      }

      socket.onmessage = (event) => {
        if (cancelled) return
        try {
          const parsed: LiveEvent = JSON.parse(event.data)
          if (parsed.type === 'stats:update') {
            setStats(parsed.data)
          } else if (parsed.type === 'hosts:update') {
            setHosts(parsed.data.map(toDiscoveredHost))
          } else if (parsed.type === 'packets:update') {
            setPackets((prev) => mergePacketRows(prev, parsed.data.map(toPacketRow)))
          } else if (parsed.type === 'talkers:update') {
            setTalkers(parsed.data.map(toTopTalker))
          } else if (parsed.type === 'threats:update') {
            setThreats((prev) => mergeThreatAlerts(prev, parsed.data.map(toThreatAlert)))
          } else if (parsed.type === 'applications:update') {
            setApplications(parsed.data.map(toApplication))
          }
        } catch {
          // Malformed frame — ignore rather than crash the dashboard.
        }
      }

      const scheduleReconnect = () => {
        if (cancelled) return
        setConnected(false)
        reconnectTimer.current = setTimeout(connect, RECONNECT_DELAY_MS)
      }

      socket.onclose = scheduleReconnect
      socket.onerror = () => socket.close()
    }

    connect()

    return () => {
      cancelled = true
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      socketRef.current?.close()
    }
  }, [])

  return { stats, hosts, packets, talkers, threats, applications, connected }
}
