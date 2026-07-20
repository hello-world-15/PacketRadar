/**
 * Client for POST /api/pcap/upload — see docs/contracts/pcap-upload.md.
 * Kept as a standalone function (not folded into useLiveSocket) since
 * this is a one-shot REST call, not part of the live WebSocket stream.
 */

export interface CaptureSummary {
  packet_count: number
  duration_seconds: number
  avg_packet_size_bytes: number
  unique_hosts: number
  connection_count: number
  dns_request_count: number
}

export interface PcapUploadResponse {
  capture_id: string
  filename: string
  summary: CaptureSummary
}

export interface DomainCount {
  domain: string
  count: number
}

export interface DnsAnalysis {
  top_domains: DomainCount[]
  repeated_queries: DomainCount[]
  failed_queries: DomainCount[]
}

export interface ThreatFinding {
  severity: string
  reason: string
  evidence: string
  recommendation: string
}

export interface HealthScoreResult {
  score: number
  factors: string[]
}

export interface PcapInsights {
  dns: DnsAnalysis
  threats: ThreatFinding[]
  health: HealthScoreResult
}

/** Raw shape sent by the backend — see
 * docs/contracts/pcap-hosts-conversations.md. */
export interface BackendPcapTopHost {
  ip: string
  hostname: string | null
  packets: number
  bandwidth_mbps: number
  bandwidth_pct: number
  connections: number
}

/** Raw shape sent by the backend — bytes/duration are already
 * pre-formatted display strings, not raw numbers. See contract's
 * "Format decision". */
export interface BackendConversation {
  a: string
  b: string
  packets: number
  bytes: string
  duration: string
}

export interface HostsConversationsResponse {
  top_hosts: BackendPcapTopHost[]
  conversations: BackendConversation[]
}

/** Raw shape sent by the backend — see
 * docs/contracts/pcap-threat-analysis.md. A separate, more capable
 * engine than the one behind PcapInsights.threats above (episode-based
 * Port Scan detection, aggregate-per-IP ARP Spoofing detection, and a
 * `source` field the simpler bundled version never captured) — this is
 * the one PcapAnalyzer.tsx's Threat Analysis section actually uses. */
export interface PcapThreatFinding {
  severity: string
  source: string
  reason: string
  evidence: string
  recommendation: string
}

export interface PcapThreatsResponse {
  threats: PcapThreatFinding[]
}

/** Raw shape sent by the backend — see
 * docs/contracts/pcap-packet-explorer.md. Carries more fields than the
 * live packets:update event (src_mac/dst_mac/src_port/dst_port) since
 * this is fetched once per page on demand, not rebroadcast continuously. */
export interface PcapPacketRow {
  no: number
  time: number // unix seconds
  source: string
  destination: string
  protocol: string
  length: number
  info: string
  src_mac: string | null
  dst_mac: string | null
  src_port: number | null
  dst_port: number | null
  dns_query: string | null
  dns_answer: string | null
}

export interface PcapPacketsResponse {
  packets: PcapPacketRow[]
  total: number
  offset: number
  limit: number
}

const API_BASE = 'http://localhost:8000'

async function parseErrorDetail(response: Response, fallback: string): Promise<string> {
  try {
    const body = await response.json()
    if (body?.detail) return body.detail
  } catch {
    // Response wasn't JSON — fall back to the generic message.
  }
  return fallback
}

export async function uploadPcap(file: File): Promise<PcapUploadResponse> {
  const formData = new FormData()
  formData.append('file', file)

  const response = await fetch(`${API_BASE}/api/pcap/upload`, {
    method: 'POST',
    body: formData,
  })

  if (!response.ok) {
    throw new Error(await parseErrorDetail(response, `Upload failed (${response.status})`))
  }

  return response.json()
}

/** Raw shape sent by the backend — see app.api.pcap's list_recorded_captures. */
export interface RecordedCapture {
  filename: string
  size_bytes: number
  captured_at: string // ISO 8601 UTC
}

/**
 * Client for GET /api/pcap/captures — the .pcap files Live Monitor's
 * Start/Stop Recording has already saved to backend/captures, offered
 * as an alternative to uploading a file from disk.
 */
export async function fetchRecordedCaptures(): Promise<RecordedCapture[]> {
  const response = await fetch(`${API_BASE}/api/pcap/captures`)

  if (!response.ok) {
    throw new Error(
      await parseErrorDetail(response, `Could not load recorded captures (${response.status})`),
    )
  }

  return response.json()
}

/**
 * Client for POST /api/pcap/captures/{filename}/analyze — same
 * parse-and-store flow as uploadPcap above, but for a file that's
 * already sitting in backend/captures rather than one picked from the
 * browser's file dialog. Returns the identical PcapUploadResponse
 * shape, so callers can treat both the same way afterward.
 */
export async function analyzeRecordedCapture(filename: string): Promise<PcapUploadResponse> {
  const response = await fetch(
    `${API_BASE}/api/pcap/captures/${encodeURIComponent(filename)}/analyze`,
    { method: 'POST' },
  )

  if (!response.ok) {
    throw new Error(await parseErrorDetail(response, `Analysis failed (${response.status})`))
  }

  return response.json()
}

export async function fetchPcapInsights(captureId: string): Promise<PcapInsights> {
  const response = await fetch(`${API_BASE}/api/pcap/${captureId}/insights`)

  if (!response.ok) {
    throw new Error(
      await parseErrorDetail(response, `Could not load analysis (${response.status})`),
    )
  }

  return response.json()
}

/**
 * Client for GET /api/pcap/{capture_id}/hosts-conversations — see
 * docs/contracts/pcap-hosts-conversations.md. Reads from the same
 * already-parsed capture uploadPcap produced; never re-uploads or
 * re-parses the file.
 */
export async function fetchHostsConversations(
  captureId: string,
): Promise<HostsConversationsResponse> {
  const response = await fetch(`${API_BASE}/api/pcap/${captureId}/hosts-conversations`)

  if (!response.ok) {
    throw new Error(
      await parseErrorDetail(response, `Failed to load hosts & conversations (${response.status})`),
    )
  }

  return response.json()
}

/**
 * Client for GET /api/pcap/{capture_id}/threats — see
 * docs/contracts/pcap-threat-analysis.md.
 */
export async function fetchPcapThreats(captureId: string): Promise<PcapThreatsResponse> {
  const response = await fetch(`${API_BASE}/api/pcap/${captureId}/threats`)

  if (!response.ok) {
    throw new Error(
      await parseErrorDetail(response, `Failed to load threat analysis (${response.status})`),
    )
  }

  return response.json()
}

/**
 * Client for GET /api/pcap/{capture_id}/packets — see
 * docs/contracts/pcap-packet-explorer.md. Paginated; a fresh call is
 * needed for each page (or "Load More" click), not a one-shot fetch
 * like the other PCAP Analyzer endpoints above.
 */
export async function fetchPcapPackets(
  captureId: string,
  offset: number,
  limit: number,
): Promise<PcapPacketsResponse> {
  const response = await fetch(
    `${API_BASE}/api/pcap/${captureId}/packets?offset=${offset}&limit=${limit}`,
  )

  if (!response.ok) {
    throw new Error(
      await parseErrorDetail(response, `Failed to load packets (${response.status})`),
    )
  }

  return response.json()
}

/** Raw shape sent by the backend — see
 * docs/contracts/pcap-protocol-timeline.md. protocol_distribution and
 * timeline share this one {label, value} row shape (a protocol slice's
 * count vs. a time bucket's count respectively) — matches the backend
 * reusing app.schemas.stats.ProtocolCount for the former rather than
 * defining an equivalent class twice. */
export interface ProtocolTimelineRow {
  label: string
  value: number
}

export interface ProtocolTimelineResponse {
  protocol_distribution: ProtocolTimelineRow[]
  timeline: ProtocolTimelineRow[]
}

/**
 * Client for GET /api/pcap/{capture_id}/protocol-timeline — see
 * docs/contracts/pcap-protocol-timeline.md.
 */
export async function fetchProtocolTimeline(captureId: string): Promise<ProtocolTimelineResponse> {
  const response = await fetch(`${API_BASE}/api/pcap/${captureId}/protocol-timeline`)

  if (!response.ok) {
    throw new Error(
      await parseErrorDetail(response, `Failed to load protocol/timeline data (${response.status})`),
    )
  }

  return response.json()
}

/**
 * Client for GET /api/pcap/{capture_id}/report.pdf. Returns the raw PDF
 * bytes as a Blob so the caller can trigger a browser download — this
 * endpoint isn't JSON, so it can't reuse the response.json() pattern the
 * other fetch* helpers above use.
 */
export async function fetchPcapReportPdf(captureId: string): Promise<Blob> {
  const response = await fetch(`${API_BASE}/api/pcap/${captureId}/report.pdf`)

  if (!response.ok) {
    throw new Error(
      await parseErrorDetail(response, `Failed to generate PDF report (${response.status})`),
    )
  }

  return response.blob()
}
