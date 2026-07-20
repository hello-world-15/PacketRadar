export type Severity = 'high' | 'medium' | 'low'
export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'ARP' | 'Other'

export interface TopTalker {
  ip: string
  hostname: string
  packets: number
  bandwidthMbps: number
  bandwidthPct: number
  connections: number
}

export interface TopApplication {
  name: string
  pid: number
  uploadKbps: number
  downloadKbps: number
  connections: number
  icon: string
}

export interface PacketRow {
  no: number
  time: string
  source: string
  destination: string
  protocol: Protocol
  length: number
  process?: string
  info: string
  /** Only set when protocol is 'DNS' — see docs/contracts/packets.md. */
  dnsQuery?: string
  /** Only set on DNS responses that actually resolved something. */
  dnsAnswer?: string
}

export interface ThreatAlert {
  id: string
  time: string
  severity: Severity
  threat: string
  source: string
  description: string
}

export interface DiscoveredHost {
  hostname: string
  ip: string
  mac: string
  lastSeen: string
  status: 'online' | 'offline'
}

export interface Conversation {
  a: string
  b: string
  packets: number
  bytes: string
  duration: string
}
