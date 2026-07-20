import type {
  TopTalker,
  TopApplication,
  PacketRow,
  ThreatAlert,
  DiscoveredHost,
  Conversation,
  Protocol,
} from '@/types'

const hostnames = [
  'DESKTOP-9J2KQ1', 'MBP-KAVYA', 'PIXEL-7-PRO', 'IOT-CAM-03', 'NAS-SYNOLOGY',
  'SMART-TV-LG', 'THINKPAD-X1', 'GALAXY-S24', 'ECHO-DOT-2', 'ROUTER-CORE',
  'PRINTER-HP', 'RASPI-HOMEBRIDGE', 'IPAD-AIR', 'WORKSTATION-DEV',
]

const processes = [
  'chrome.exe', 'discord.exe', 'spotify.exe', 'Code.exe', 'slack.exe',
  'steam.exe', 'zoom.exe', 'msedge.exe', 'explorer.exe', 'System',
  'firefox.exe', 'Teams.exe', 'obs64.exe', 'notion.exe',
]

const protocols: Protocol[] = ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP', 'Other']

function randInt(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

function randomPrivateIp() {
  const third = randInt(0, 5)
  return `192.168.${third}.${randInt(2, 254)}`
}

function randomMac() {
  return Array.from({ length: 6 }, () =>
    randInt(0, 255).toString(16).padStart(2, '0'),
  ).join(':').toUpperCase()
}

function pad(n: number) {
  return n.toString().padStart(2, '0')
}

function randomTimeAgo(maxSecondsAgo: number) {
  const d = new Date(Date.now() - randInt(0, maxSecondsAgo) * 1000)
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

export const topTalkers: TopTalker[] = Array.from({ length: 12 }).map((_, i) => {
  const bandwidthPct = randInt(4, 96)
  return {
    ip: randomPrivateIp(),
    hostname: hostnames[i % hostnames.length],
    packets: randInt(1200, 980000),
    bandwidthMbps: +(Math.random() * 48).toFixed(1),
    bandwidthPct,
    connections: randInt(1, 64),
  }
})

export const appIcons: Record<string, string> = {
  'chrome.exe': '🌐',
  'discord.exe': '🎮',
  'spotify.exe': '🎵',
  'Code.exe': '💻',
  'slack.exe': '💬',
  'steam.exe': '🕹️',
  'zoom.exe': '📹',
  'msedge.exe': '🌐',
  'explorer.exe': '🗂️',
  System: '⚙️',
  'firefox.exe': '🦊',
  'Teams.exe': '💬',
  'obs64.exe': '🎥',
  'notion.exe': '📝',
}

/** Shared by mock generation and real `applications:update` data alike —
 * see docs/contracts/applications.md's "Icons are frontend-only". */
export function iconForApp(name: string): string {
  return appIcons[name] ?? '📦'
}

export const topApplications: TopApplication[] = processes.map((name, i) => ({
  name,
  pid: 1000 + i * 137 + randInt(1, 99),
  uploadKbps: randInt(2, 4200),
  downloadKbps: randInt(10, 18000),
  connections: randInt(1, 40),
  icon: iconForApp(name),
}))

const mockDomains = [
  'api.github.com', 'www.google.com', 'accounts.spotify.com', 'discord.com',
  'cdn.cloudflare.com', 'graph.microsoft.com', 'www.netflix.com', 'slack.com',
]

function randomMockDnsFields(): { info: string; dnsQuery?: string; dnsAnswer?: string } {
  const domain = mockDomains[randInt(0, mockDomains.length - 1)]
  const isAAAA = Math.random() < 0.2
  const qtype = isAAAA ? 'AAAA' : 'A'
  const dnsQuery = `${domain} (${qtype})`
  const outcome = randInt(0, 9)

  if (outcome === 0) {
    // Occasional NXDOMAIN so the "no answer" Drawer state is reachable from mock data too.
    return { info: `DNS response: ${dnsQuery} \u2192 NXDOMAIN`, dnsQuery }
  }
  const answer = isAAAA
    ? `2606:2800:${randInt(100, 999)}:1::${randInt(1, 99)}`
    : `${randInt(1, 223)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`
  const isQuery = outcome < 3
  return isQuery
    ? { info: `DNS query: ${dnsQuery}`, dnsQuery }
    : { info: `DNS response: ${dnsQuery} \u2192 ${answer}`, dnsQuery, dnsAnswer: answer }
}

export function generatePacketStream(count: number): PacketRow[] {
  return Array.from({ length: count }).map((_, i) => {
    const protocol = protocols[randInt(0, protocols.length - 1)]
    const infoByProto: Record<Exclude<Protocol, 'DNS'>, string[]> = {
      TCP: ['SYN, ACK', 'PSH, ACK — HTTP/1.1 200 OK', 'FIN, ACK', 'Retransmission detected', 'Window Update'],
      UDP: ['Source port: 51820', 'QUIC handshake', 'Keep-alive probe'],
      ICMP: ['Echo (ping) request', 'Echo (ping) reply', 'Destination unreachable'],
      ARP: ['Who has 192.168.1.1? Tell 192.168.1.42', 'ARP reply'],
      Other: ['Malformed packet', 'Unknown transport'],
    }
    const dns = protocol === 'DNS' ? randomMockDnsFields() : null
    const info = dns
      ? dns.info
      : infoByProto[protocol as Exclude<Protocol, 'DNS'>][
          randInt(0, infoByProto[protocol as Exclude<Protocol, 'DNS'>].length - 1)
        ]
    return {
      no: i + 1,
      time: randomTimeAgo(600),
      source: randomPrivateIp(),
      destination: Math.random() > 0.5 ? randomPrivateIp() : `${randInt(1, 223)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`,
      protocol,
      length: randInt(54, 1514),
      process: processes[randInt(0, processes.length - 1)],
      info,
      dnsQuery: dns?.dnsQuery,
      dnsAnswer: dns?.dnsAnswer,
    }
  })
}

export const liveThreats: ThreatAlert[] = [
  {
    id: 't1',
    time: randomTimeAgo(300),
    severity: 'high',
    threat: 'Port Scan Detected',
    source: '203.0.113.44',
    description: 'Sequential SYN packets across 40+ ports within 3 seconds.',
  },
  {
    id: 't2',
    time: randomTimeAgo(300),
    severity: 'high',
    threat: 'Possible DNS Tunneling',
    source: '192.168.2.17',
    description: 'Abnormally long TXT record queries to unrecognized domain.',
  },
  {
    id: 't3',
    time: randomTimeAgo(600),
    severity: 'medium',
    threat: 'ARP Spoofing Suspected',
    source: '192.168.1.1',
    description: 'Duplicate MAC address responding for gateway IP.',
  },
  {
    id: 't4',
    time: randomTimeAgo(600),
    severity: 'medium',
    threat: 'Unusual Outbound Volume',
    source: '192.168.1.88',
    description: 'Host uploaded 1.2GB to an unfamiliar external IP overnight.',
  },
  {
    id: 't5',
    time: randomTimeAgo(900),
    severity: 'low',
    threat: 'Deprecated TLS Version',
    source: '192.168.1.23',
    description: 'Connection negotiated using TLS 1.0.',
  },
  {
    id: 't6',
    time: randomTimeAgo(1200),
    severity: 'low',
    threat: 'Repeated Failed DNS Lookups',
    source: '192.168.3.5',
    description: 'Multiple NXDOMAIN responses for generated-looking hostnames.',
  },
]

export const discoveredHosts: DiscoveredHost[] = hostnames.map((h) => ({
  hostname: h,
  ip: randomPrivateIp(),
  mac: randomMac(),
  lastSeen: randomTimeAgo(1800),
  status: (['online', 'online', 'offline'] as const)[randInt(0, 2)],
}))

export const conversations: Conversation[] = Array.from({ length: 10 }).map(() => ({
  a: randomPrivateIp(),
  b: Math.random() > 0.4 ? randomPrivateIp() : `${randInt(1, 223)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`,
  packets: randInt(120, 82000),
  bytes: `${(Math.random() * 900 + 10).toFixed(1)} MB`,
  duration: `${randInt(0, 12)}m ${randInt(0, 59)}s`,
}))

export const topDomains = [
  { domain: 'googleapis.com', queries: 1842 },
  { domain: 'cloudflare.com', queries: 1203 },
  { domain: 'spotify.com', queries: 940 },
  { domain: 'github.com', queries: 611 },
  { domain: 'discord.gg', queries: 588 },
  { domain: 'notion.so', queries: 340 },
]

export const repeatedQueries = [
  { domain: 'telemetry.suspicious-dns.net', count: 214 },
  { domain: 'ads.tracker-net.io', count: 176 },
  { domain: 'update.vendor-cdn.com', count: 92 },
]

export const failedQueries = [
  { domain: 'xj4k9z-c2.top', count: 41 },
  { domain: 'nonexistent-host.local', count: 18 },
]

export function bandwidthSeries(points: number) {
  const upload: number[] = []
  const download: number[] = []
  let u = 8
  let d = 22
  for (let i = 0; i < points; i++) {
    u = Math.max(1, u + (Math.random() - 0.5) * 6)
    d = Math.max(1, d + (Math.random() - 0.5) * 10)
    upload.push(+u.toFixed(1))
    download.push(+d.toFixed(1))
  }
  return { upload, download }
}

export const protocolDistribution = [
  { label: 'TCP', value: 52 },
  { label: 'UDP', value: 24 },
  { label: 'DNS', value: 11 },
  { label: 'ICMP', value: 5 },
  { label: 'ARP', value: 4 },
  { label: 'Other', value: 4 },
]
