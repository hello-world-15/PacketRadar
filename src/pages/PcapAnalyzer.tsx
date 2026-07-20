import { useEffect, useMemo, useState, type ReactNode } from 'react'
import {
  FileStack,
  Timer as TimerIcon,
  Ruler,
  Users,
  Cable,
  Globe,
  Download,
  ChevronRight,
  Loader2,
  RotateCcw,
} from 'lucide-react'
import UploadZone from '@/components/UploadZone'
import {
  uploadPcap,
  fetchPcapInsights,
  fetchHostsConversations,
  fetchPcapThreats,
  fetchPcapPackets,
  fetchProtocolTimeline,
  fetchRecordedCaptures,
  analyzeRecordedCapture,
  fetchPcapReportPdf,
  type CaptureSummary,
  type PcapInsights,
  type BackendPcapTopHost,
  type BackendConversation,
  type PcapThreatFinding,
  type PcapPacketRow,
  type ProtocolTimelineRow,
  type PcapUploadResponse,
  type RecordedCapture,
} from '@/lib/pcapApi'
import StatCard from '@/components/StatCard'
import ChartCard from '@/components/ChartCard'
import SectionHeader from '@/components/SectionHeader'
import Button from '@/components/Button'
import Badge from '@/components/Badge'
import FilterBar from '@/components/FilterBar'
import PacketTable from '@/components/PacketTable'
import { HealthGauge, ProtocolPieChart } from '@/components/Charts'
import Drawer, { DrawerField } from '@/components/Drawer'
import type { PacketRow, Protocol, TopTalker, Conversation } from '@/types'

// Same "Backend* -> camelCase" mapping convention useLiveSocket.ts uses
// for its WebSocket payloads — see docs/contracts/pcap-hosts-conversations.md.
function toTopHost(h: BackendPcapTopHost): TopTalker {
  return {
    ip: h.ip,
    hostname: h.hostname ?? 'Unknown Device',
    packets: h.packets,
    bandwidthMbps: h.bandwidth_mbps,
    bandwidthPct: h.bandwidth_pct,
    connections: h.connections,
  }
}

function toConversation(c: BackendConversation): Conversation {
  return { a: c.a, b: c.b, packets: c.packets, bytes: c.bytes, duration: c.duration }
}

const KNOWN_PROTOCOLS: Protocol[] = ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP']

function toProtocol(p: string): Protocol {
  const upper = p.toUpperCase()
  return (KNOWN_PROTOCOLS.find((known) => known === upper) as Protocol) ?? 'Other'
}

function formatClockTime(unixSeconds: number): string {
  const d = new Date(unixSeconds * 1000)
  const pad = (n: number) => n.toString().padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

/** Packet Explorer's drawer needs more than the shared `PacketRow` type
 * carries (MACs, ports) — see docs/contracts/pcap-packet-explorer.md's
 * "Why this response carries more fields". Kept local to this page
 * rather than added to the shared type, since nothing else renders
 * these fields. */
interface ExplorerPacketRow extends PacketRow {
  srcMac: string | null
  dstMac: string | null
  srcPort: number | null
  dstPort: number | null
}

function toExplorerPacketRow(p: PcapPacketRow): ExplorerPacketRow {
  return {
    no: p.no,
    time: formatClockTime(p.time),
    source: p.source,
    destination: p.destination,
    protocol: toProtocol(p.protocol),
    length: p.length,
    info: p.info,
    dnsQuery: p.dns_query ?? undefined,
    dnsAnswer: p.dns_answer ?? undefined,
    srcMac: p.src_mac,
    dstMac: p.dst_mac,
    srcPort: p.src_port,
    dstPort: p.dst_port,
  }
}

const PACKETS_PAGE_SIZE = 100

const severityStyles = {
  high: 'border-danger/30 bg-danger/5',
  medium: 'border-warn/30 bg-warn/5',
  low: 'border-info/30 bg-info/5',
} as const

export default function PcapAnalyzer() {
  const [analyzed, setAnalyzed] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [filename, setFilename] = useState<string | null>(null)
  const [summary, setSummary] = useState<CaptureSummary | null>(null)
  const [captureId, setCaptureId] = useState<string | null>(null)
  const [insights, setInsights] = useState<PcapInsights | null>(null)
  const [insightsLoading, setInsightsLoading] = useState(false)
  const [insightsError, setInsightsError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [protocolFilter, setProtocolFilter] = useState('')
  const [selectedPacket, setSelectedPacket] = useState<ExplorerPacketRow | null>(null)

  // Files Live Monitor's Start/Stop Recording has already saved to
  // backend/captures — fetched once on mount so UploadZone's dropdown
  // has something to show alongside "Browse Files". See
  // app.api.pcap's GET /api/pcap/captures.
  const [recordedCaptures, setRecordedCaptures] = useState<RecordedCapture[]>([])
  const [recordedCapturesLoading, setRecordedCapturesLoading] = useState(false)
  const [recordedCapturesError, setRecordedCapturesError] = useState<string | null>(null)

  const [topHosts, setTopHosts] = useState<TopTalker[]>([])
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [hostsConvLoading, setHostsConvLoading] = useState(false)
  const [hostsConvError, setHostsConvError] = useState<string | null>(null)

  const [pcapThreats, setPcapThreats] = useState<PcapThreatFinding[]>([])
  const [threatsLoading, setThreatsLoading] = useState(false)
  const [threatsError, setThreatsError] = useState<string | null>(null)

  const [protocolDist, setProtocolDist] = useState<ProtocolTimelineRow[]>([])
  const [protocolTimelineLoading, setProtocolTimelineLoading] = useState(false)
  const [protocolTimelineError, setProtocolTimelineError] = useState<string | null>(null)

  const [explorerPackets, setExplorerPackets] = useState<ExplorerPacketRow[]>([])
  const [explorerTotal, setExplorerTotal] = useState(0)
  const [explorerLoading, setExplorerLoading] = useState(false)
  const [explorerError, setExplorerError] = useState<string | null>(null)

  const [exportingPdf, setExportingPdf] = useState(false)
  const [exportPdfError, setExportPdfError] = useState<string | null>(null)

  // Fetched once on mount, not tied to any capture — this is just the
  // list of files backend/captures already has sitting on disk,
  // independent of whatever the user has analyzed so far.
  useEffect(() => {
    let cancelled = false

    setRecordedCapturesLoading(true)
    setRecordedCapturesError(null)
    fetchRecordedCaptures()
      .then((data) => {
        if (cancelled) return
        setRecordedCaptures(data)
      })
      .catch((err) => {
        if (cancelled) return
        setRecordedCapturesError(
          err instanceof Error ? err.message : 'Could not load recorded captures.',
        )
      })
      .finally(() => {
        if (!cancelled) setRecordedCapturesLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [])

  // Shared by both entry points below (a fresh upload and picking an
  // already-recorded file) — everything past "we now have a
  // capture_id + summary" is identical either way.
  async function applyAnalysisResult(result: PcapUploadResponse) {
    setFilename(result.filename)
    setSummary(result.summary)
    setCaptureId(result.capture_id)
    setAnalyzed(true)

    // DNS Analysis and Network Health Score come from one combined
    // endpoint — a separate loading/error pair from the upload itself,
    // since the upload can succeed while this second fetch fails (e.g.
    // a transient network blip right after). Threat Analysis uses its
    // own dedicated endpoint instead — see the useEffect below.
    setInsightsLoading(true)
    setInsightsError(null)
    try {
      const insightsResult = await fetchPcapInsights(result.capture_id)
      setInsights(insightsResult)
    } catch (err) {
      setInsightsError(
        err instanceof Error ? err.message : 'Could not load DNS/Health analysis.',
      )
    } finally {
      setInsightsLoading(false)
    }
  }

  async function handleAnalyze(file: File) {
    setAnalyzing(true)
    setUploadError(null)
    try {
      const result = await uploadPcap(file)
      await applyAnalysisResult(result)
    } catch (err) {
      setUploadError(
        err instanceof Error
          ? err.message
          : 'Something went wrong analyzing this file. Is the backend running?',
      )
    } finally {
      setAnalyzing(false)
    }
  }

  async function handleSelectRecordedCapture(recordedFilename: string) {
    setAnalyzing(true)
    setUploadError(null)
    try {
      const result = await analyzeRecordedCapture(recordedFilename)
      await applyAnalysisResult(result)
    } catch (err) {
      setUploadError(
        err instanceof Error
          ? err.message
          : 'Something went wrong analyzing this capture. Is the backend running?',
      )
    } finally {
      setAnalyzing(false)
    }
  }

  // "Scan Another" — drops every piece of state the finished report
  // populated and returns to UploadZone, rather than a full page
  // reload. Every capture_id-keyed useEffect above re-fires naturally
  // once a fresh analysis sets captureId again, since captureId itself
  // is one of the things reset to null here.
  function handleScanAnother() {
    setAnalyzed(false)
    setAnalyzing(false)
    setUploadError(null)
    setFilename(null)
    setSummary(null)
    setCaptureId(null)
    setInsights(null)
    setInsightsLoading(false)
    setInsightsError(null)
    setSearch('')
    setProtocolFilter('')
    setSelectedPacket(null)

    setTopHosts([])
    setConversations([])
    setHostsConvLoading(false)
    setHostsConvError(null)

    setPcapThreats([])
    setThreatsLoading(false)
    setThreatsError(null)

    setProtocolDist([])
    setProtocolTimelineLoading(false)
    setProtocolTimelineError(null)

    setExplorerPackets([])
    setExplorerTotal(0)
    setExplorerLoading(false)
    setExplorerError(null)

    // A recording could have finished while this report was open —
    // refresh the dropdown so it's not stale on the way back in.
    setRecordedCapturesLoading(true)
    setRecordedCapturesError(null)
    fetchRecordedCaptures()
      .then(setRecordedCaptures)
      .catch((err) => {
        setRecordedCapturesError(
          err instanceof Error ? err.message : 'Could not load recorded captures.',
        )
      })
      .finally(() => setRecordedCapturesLoading(false))
  }

  // "Export PDF Report" — hits GET /api/pcap/{captureId}/report.pdf,
  // then turns the returned bytes into a downloadable file via a
  // throwaway object URL + anchor click (fetch, not a plain <a href>,
  // since the endpoint needs no query params but does need error
  // handling — e.g. a capture that's aged out of the backend cache).
  async function handleExportPdf() {
    if (!captureId) return

    setExportingPdf(true)
    setExportPdfError(null)
    try {
      const blob = await fetchPcapReportPdf(captureId)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      const safeName = (filename ?? 'capture').replace(/\.[^/.]+$/, '')
      link.download = `${safeName}_report.pdf`
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
    } catch (err) {
      setExportPdfError(err instanceof Error ? err.message : 'Failed to generate PDF report.')
    } finally {
      setExportingPdf(false)
    }
  }

  // Fetches once the upload finishes and capture_id is available — Top
  // Hosts + Conversations is a fixed dataset for a finished file, not a
  // live stream, so a single fetch (not a poll/socket) is the right
  // shape. See docs/contracts/pcap-hosts-conversations.md.
  useEffect(() => {
    if (!captureId) return
    let cancelled = false

    setHostsConvLoading(true)
    setHostsConvError(null)
    fetchHostsConversations(captureId)
      .then((data) => {
        if (cancelled) return
        setTopHosts(data.top_hosts.map(toTopHost))
        setConversations(data.conversations.map(toConversation))
      })
      .catch((err) => {
        if (cancelled) return
        setHostsConvError(err instanceof Error ? err.message : 'Failed to load hosts & conversations.')
      })
      .finally(() => {
        if (!cancelled) setHostsConvLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [captureId])

  // Same one-shot-fetch reasoning as hosts/conversations above — see
  // docs/contracts/pcap-threat-analysis.md.
  useEffect(() => {
    if (!captureId) return
    let cancelled = false

    setThreatsLoading(true)
    setThreatsError(null)
    fetchPcapThreats(captureId)
      .then((data) => {
        if (cancelled) return
        setPcapThreats(data.threats)
      })
      .catch((err) => {
        if (cancelled) return
        setThreatsError(err instanceof Error ? err.message : 'Could not load threat analysis.')
      })
      .finally(() => {
        if (!cancelled) setThreatsLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [captureId])

  // Packet Explorer loads its first page as soon as a capture_id exists,
  // then grows via loadMorePackets below as the analyst asks for more —
  // see docs/contracts/pcap-packet-explorer.md.
  useEffect(() => {
    if (!captureId) return
    let cancelled = false

    setExplorerPackets([])
    setExplorerTotal(0)
    setExplorerLoading(true)
    setExplorerError(null)
    fetchPcapPackets(captureId, 0, PACKETS_PAGE_SIZE)
      .then((data) => {
        if (cancelled) return
        setExplorerPackets(data.packets.map(toExplorerPacketRow))
        setExplorerTotal(data.total)
      })
      .catch((err) => {
        if (cancelled) return
        setExplorerError(err instanceof Error ? err.message : 'Could not load packets for this capture.')
      })
      .finally(() => {
        if (!cancelled) setExplorerLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [captureId])

  // Same one-shot-fetch reasoning as hosts/conversations and threats
  // above — a finished capture's protocol counts and timeline are a
  // fixed dataset, not a stream. See docs/contracts/pcap-protocol-timeline.md.
  useEffect(() => {
    if (!captureId) return
    let cancelled = false

    setProtocolTimelineLoading(true)
    setProtocolTimelineError(null)
    fetchProtocolTimeline(captureId)
      .then((data) => {
        if (cancelled) return
        setProtocolDist(data.protocol_distribution)
      })
      .catch((err) => {
        if (cancelled) return
        setProtocolTimelineError(
          err instanceof Error ? err.message : 'Could not load protocol/timeline data.',
        )
      })
      .finally(() => {
        if (!cancelled) setProtocolTimelineLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [captureId])

  async function loadMorePackets() {
    if (!captureId || explorerLoading) return
    setExplorerLoading(true)
    setExplorerError(null)
    try {
      const data = await fetchPcapPackets(captureId, explorerPackets.length, PACKETS_PAGE_SIZE)
      setExplorerPackets((prev) => [...prev, ...data.packets.map(toExplorerPacketRow)])
      setExplorerTotal(data.total)
    } catch (err) {
      setExplorerError(err instanceof Error ? err.message : 'Could not load more packets.')
    } finally {
      setExplorerLoading(false)
    }
  }

  const filtered = useMemo(
    () =>
      explorerPackets.filter((p) => {
        const matchSearch =
          !search ||
          p.source.includes(search) ||
          p.destination.includes(search) ||
          p.info.toLowerCase().includes(search.toLowerCase())
        const matchProto = !protocolFilter || p.protocol === protocolFilter
        return matchSearch && matchProto
      }),
    [explorerPackets, search, protocolFilter],
  )

  return (
    <div className="pb-10">
      <div className="mb-6">
        <h1 className="text-lg font-bold text-slate-50">PCAP Analyzer</h1>
        <p className="text-xs text-slate-500">Offline packet capture analysis</p>
      </div>

      {!analyzed && (
        <UploadZone
          onAnalyze={handleAnalyze}
          analyzing={analyzing}
          error={uploadError}
          recordedCaptures={recordedCaptures}
          recordedCapturesLoading={recordedCapturesLoading}
          recordedCapturesError={recordedCapturesError}
          onSelectRecordedCapture={handleSelectRecordedCapture}
        />
      )}

      {analyzed && (
        <div className="animate-fadeIn space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <FileStack size={15} className="text-neon" />
              <span className="font-mono">{filename ?? 'capture.pcap'}</span>
              <ChevronRight size={12} className="text-slate-600" />
              <span className="text-slate-500">Report generated</span>
            </div>
            <div className="flex flex-col items-end gap-1.5">
              <div className="flex items-center gap-2">
                <Button variant="secondary" icon={<RotateCcw size={14} />} onClick={handleScanAnother}>
                  Scan Another
                </Button>
                <Button
                  variant="primary"
                  icon={exportingPdf ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
                  onClick={handleExportPdf}
                  disabled={!captureId || exportingPdf}
                >
                  {exportingPdf ? 'Generating…' : 'Export PDF Report'}
                </Button>
              </div>
              {exportPdfError && (
                <p className="text-xs text-danger max-w-[280px] text-right">{exportPdfError}</p>
              )}
            </div>
          </div>

          {/* Capture Summary — real data from POST /api/pcap/upload */}
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
            <StatCard label="Packet Count" value={summary?.packet_count ?? 0} icon={FileStack} tone="neon" />
            <StatCard
              label="Duration"
              value={summary ? Math.round((summary.duration_seconds / 60) * 10) / 10 : 0}
              unit="min"
              icon={TimerIcon}
              tone="info"
            />
            <StatCard label="Avg Packet Size" value={summary?.avg_packet_size_bytes ?? 0} unit="B" icon={Ruler} tone="neutral" />
            <StatCard label="Unique Hosts" value={summary?.unique_hosts ?? 0} icon={Users} tone="info" />
            <StatCard label="Connections" value={summary?.connection_count ?? 0} icon={Cable} tone="neon" />
            <StatCard label="DNS Requests" value={summary?.dns_request_count ?? 0} icon={Globe} tone="warn" />
          </div>

          {/* Health Score, DNS Analysis, and Protocol Distribution are all
              real now. Top Hosts/Conversations, Threat Analysis, and Packet
              Explorer are real too — see their own sections below. */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
            <ChartCard title="Network Health Score" className="flex flex-col items-center justify-center">
              {insightsLoading && (
                <p className="text-sm text-slate-500">Analyzing…</p>
              )}
              {!insightsLoading && insightsError && (
                <p className="text-sm text-danger text-center max-w-[220px]">{insightsError}</p>
              )}
              {!insightsLoading && !insightsError && insights && (
                <>
                  <HealthGauge score={insights.health.score} />
                  <ul className="mt-4 space-y-1 text-center max-w-[260px]">
                    {insights.health.factors.map((factor, i) => (
                      <li key={i} className="text-xs text-slate-500">{factor}</li>
                    ))}
                  </ul>
                </>
              )}
            </ChartCard>
            <ChartCard title="Protocol Distribution">
              {protocolTimelineLoading && <p className="text-sm text-slate-500">Loading…</p>}
              {!protocolTimelineLoading && protocolTimelineError && (
                <p className="text-sm text-danger">{protocolTimelineError}</p>
              )}
              {!protocolTimelineLoading && !protocolTimelineError && (
                <div className="h-64">
                  <ProtocolPieChart data={protocolDist} />
                </div>
              )}
            </ChartCard>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
            <div>
              <SectionHeader title="Top Hosts" subtitle="By packet volume" />
              {hostsConvError && (
                <p className="text-xs text-danger bg-danger/10 border border-danger/30 rounded-lg px-3 py-2 mb-2">
                  {hostsConvError}
                </p>
              )}
              <div className="overflow-auto scrollbar-thin rounded-xl border border-border max-h-[320px]">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-secondary">
                    <tr className="text-left text-xs text-slate-500 uppercase tracking-wide">
                      <th className="px-4 py-3 font-medium">IP</th>
                      <th className="px-4 py-3 font-medium">Hostname</th>
                      <th className="px-4 py-3 font-medium">Packets</th>
                      <th className="px-4 py-3 font-medium">Bandwidth</th>
                    </tr>
                  </thead>
                  <tbody>
                    {!hostsConvLoading && !hostsConvError && topHosts.length === 0 && (
                      <tr>
                        <td colSpan={4} className="px-4 py-6 text-center text-xs text-slate-500">
                          No hosts found in this capture.
                        </td>
                      </tr>
                    )}
                    {topHosts.map((t) => (
                      <tr key={t.ip} className="border-t border-border/60 hover:bg-white/5">
                        <td className="px-4 py-3 font-mono text-xs text-slate-200">{t.ip}</td>
                        <td className="px-4 py-3 text-xs text-slate-400">{t.hostname}</td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-400">
                          {t.packets.toLocaleString()}
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-400">{t.bandwidthMbps} Mbps</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div>
              <SectionHeader title="Conversations" subtitle="Communication pairs" />
              <div className="overflow-auto scrollbar-thin rounded-xl border border-border max-h-[320px]">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-secondary">
                    <tr className="text-left text-xs text-slate-500 uppercase tracking-wide">
                      <th className="px-4 py-3 font-medium">Host A</th>
                      <th className="px-4 py-3 font-medium">Host B</th>
                      <th className="px-4 py-3 font-medium">Packets</th>
                      <th className="px-4 py-3 font-medium">Bytes</th>
                      <th className="px-4 py-3 font-medium">Duration</th>
                    </tr>
                  </thead>
                  <tbody>
                    {!hostsConvLoading && !hostsConvError && conversations.length === 0 && (
                      <tr>
                        <td colSpan={5} className="px-4 py-6 text-center text-xs text-slate-500">
                          No conversations found in this capture.
                        </td>
                      </tr>
                    )}
                    {conversations.map((c, i) => (
                      <tr key={i} className="border-t border-border/60 hover:bg-white/5">
                        <td className="px-4 py-3 font-mono text-xs text-slate-200">{c.a}</td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-200">{c.b}</td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-400">{c.packets.toLocaleString()}</td>
                        <td className="px-4 py-3 text-xs text-slate-400">{c.bytes}</td>
                        <td className="px-4 py-3 text-xs text-slate-400">{c.duration}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* DNS Analysis — real (PCAP Analyzer Insights module) */}
          <div>
            <SectionHeader title="DNS Analysis" />
            {insightsLoading && <p className="text-sm text-slate-500">Loading DNS analysis…</p>}
            {!insightsLoading && insightsError && (
              <p className="text-sm text-danger">{insightsError}</p>
            )}
            {!insightsLoading && !insightsError && insights && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                <ChartCard title="Top Domains">
                  {insights.dns.top_domains.length === 0 ? (
                    <p className="text-xs text-slate-500">No DNS queries found in this capture.</p>
                  ) : (
                    <ul className="space-y-2.5">
                      {insights.dns.top_domains.map((d) => (
                        <li key={d.domain} className="flex items-center justify-between text-sm">
                          <span className="text-slate-300 font-mono text-xs">{d.domain}</span>
                          <span className="text-slate-500 text-xs">{d.count.toLocaleString()}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </ChartCard>
                <ChartCard title="Repeated Queries">
                  {insights.dns.repeated_queries.length === 0 ? (
                    <p className="text-xs text-slate-500">No unusually repetitive queries found.</p>
                  ) : (
                    <ul className="space-y-2.5">
                      {insights.dns.repeated_queries.map((d) => (
                        <li key={d.domain} className="flex items-center justify-between text-sm">
                          <span className="text-warn font-mono text-xs">{d.domain}</span>
                          <span className="text-slate-500 text-xs">{d.count}×</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </ChartCard>
                <ChartCard title="Failed Queries">
                  {insights.dns.failed_queries.length === 0 ? (
                    <p className="text-xs text-slate-500">No failed DNS lookups found.</p>
                  ) : (
                    <ul className="space-y-2.5">
                      {insights.dns.failed_queries.map((d) => (
                        <li key={d.domain} className="flex items-center justify-between text-sm">
                          <span className="text-danger font-mono text-xs">{d.domain}</span>
                          <span className="text-slate-500 text-xs">{d.count}×</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </ChartCard>
              </div>
            )}
          </div>

          {/* Threat Analysis — real, via the dedicated
              GET /api/pcap/{capture_id}/threats endpoint (episode-based
              Port Scan + aggregate-per-IP ARP Spoofing detection — see
              docs/contracts/pcap-threat-analysis.md), not the simpler
              version bundled into /insights. */}
          <div>
            <SectionHeader title="Threat Analysis" subtitle="Findings from static and behavioral analysis" />
            {threatsLoading && <p className="text-sm text-slate-500">Analyzing for threats…</p>}
            {!threatsLoading && threatsError && (
              <p className="text-sm text-danger">{threatsError}</p>
            )}
            {!threatsLoading && !threatsError && (
              <div className="space-y-3">
                {pcapThreats.length === 0 ? (
                  <p className="text-sm text-slate-500">
                    No port-scan or ARP-spoofing patterns detected in this capture.
                  </p>
                ) : (
                  pcapThreats.map((t, i) => {
                    const style =
                      severityStyles[t.severity as keyof typeof severityStyles] ?? severityStyles.medium
                    const badgeVariant =
                      t.severity === 'high' ? 'danger' : t.severity === 'low' ? 'info' : 'warn'
                    return (
                      <div key={i} className={`glass rounded-xl border p-4 ${style}`}>
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant={badgeVariant} dot>
                            {t.severity[0].toUpperCase() + t.severity.slice(1)}
                          </Badge>
                          <p className="text-sm font-semibold text-slate-100">{t.reason}</p>
                        </div>
                        <p className="text-xs text-slate-500 mb-1">
                          <span className="text-slate-400 font-medium">Source: </span>
                          <span className="font-mono">{t.source}</span>
                        </p>
                        <p className="text-xs text-slate-500 mb-1">
                          <span className="text-slate-400 font-medium">Evidence: </span>
                          {t.evidence}
                        </p>
                        <p className="text-xs text-slate-500">
                          <span className="text-slate-400 font-medium">Recommendation: </span>
                          {t.recommendation}
                        </p>
                      </div>
                    )
                  })
                )}
              </div>
            )}
          </div>

          {/* Packet Explorer — real data, paginated, see
              docs/contracts/pcap-packet-explorer.md. Search/protocol
              filters only apply to pages already loaded into the
              browser, not a server-side query across the full capture
              — same limitation as the live Packet Stream. */}
          <div>
            <SectionHeader
              title="Packet Explorer"
              subtitle={
                explorerTotal > 0
                  ? `${filtered.length.toLocaleString()} shown of ${explorerPackets.length.toLocaleString()} loaded (${explorerTotal.toLocaleString()} total)`
                  : undefined
              }
            />
            {explorerError && (
              <p className="text-xs text-danger bg-danger/10 border border-danger/30 rounded-lg px-3 py-2 mb-2">
                {explorerError}
              </p>
            )}
            <FilterBar
              search={search}
              onSearchChange={setSearch}
              searchPlaceholder="Search source, destination, info…"
              selects={[
                {
                  label: 'Protocol',
                  value: protocolFilter,
                  options: ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP', 'Other'],
                  onChange: setProtocolFilter,
                },
              ]}
            />
            {explorerPackets.length === 0 && explorerLoading && (
              <p className="text-xs text-slate-500 flex items-center gap-2 py-3">
                <Loader2 size={12} className="animate-spin" /> Loading packets…
              </p>
            )}
            {explorerPackets.length === 0 && !explorerLoading && !explorerError && (
              <p className="text-xs text-slate-500 py-3">No packets found in this capture.</p>
            )}
            {explorerPackets.length > 0 && (
              <>
                <PacketTable
                  rows={filtered}
                  onRowClick={(row) => {
                    const detail = explorerPackets.find((p) => p.no === row.no) ?? null
                    setSelectedPacket(detail)
                  }}
                  showNo
                  maxHeight="440px"
                />
                {explorerPackets.length < explorerTotal && (
                  <div className="flex justify-center mt-3">
                    <Button variant="secondary" onClick={loadMorePackets} disabled={explorerLoading}>
                      {explorerLoading ? (
                        <span className="flex items-center gap-2">
                          <Loader2 size={13} className="animate-spin" /> Loading…
                        </span>
                      ) : (
                        `Load ${Math.min(PACKETS_PAGE_SIZE, explorerTotal - explorerPackets.length)} more`
                      )}
                    </Button>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}

      <Drawer
        open={!!selectedPacket}
        onClose={() => setSelectedPacket(null)}
        title="Packet Details"
        subtitle={selectedPacket ? `Packet #${selectedPacket.no}` : ''}
      >
        {selectedPacket && (
          <>
            <LayerCard title="Ethernet II">
              <DrawerField label="Src MAC" value={selectedPacket.srcMac ?? 'Not available'} />
              <DrawerField label="Dst MAC" value={selectedPacket.dstMac ?? 'Not available'} />
            </LayerCard>
            <LayerCard title={selectedPacket.protocol === 'ARP' ? 'ARP' : 'IP'}>
              <DrawerField label="Source" value={selectedPacket.source} />
              <DrawerField label="Destination" value={selectedPacket.destination} />
            </LayerCard>
            {(selectedPacket.srcPort != null || selectedPacket.dstPort != null) && (
              <LayerCard title={selectedPacket.protocol}>
                <DrawerField
                  label="Src Port"
                  value={selectedPacket.srcPort != null ? String(selectedPacket.srcPort) : 'Not available'}
                />
                <DrawerField
                  label="Dst Port"
                  value={selectedPacket.dstPort != null ? String(selectedPacket.dstPort) : 'Not available'}
                />
              </LayerCard>
            )}
            <LayerCard title="Summary">
              <DrawerField label="Info" value={selectedPacket.info || 'Not available'} />
              {selectedPacket.dnsQuery && <DrawerField label="DNS Query" value={selectedPacket.dnsQuery} />}
              {selectedPacket.dnsAnswer && <DrawerField label="DNS Answer" value={selectedPacket.dnsAnswer} />}
            </LayerCard>
            <LayerCard title="Payload">
              <DrawerField label="Length" value={`${selectedPacket.length} bytes`} />
            </LayerCard>

            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wide mb-1.5">Raw Payload</p>
              <p className="text-xs text-slate-500 bg-secondary rounded-lg p-3 border border-border leading-relaxed">
                Not captured in this build — packets are stored as parsed structured fields only, not
                raw bytes, so there's no hex/ASCII view to show. See docs/contracts/pcap-packet-explorer.md.
              </p>
            </div>
          </>
        )}
      </Drawer>
    </div>
  )
}

function LayerCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details open className="rounded-xl border border-border overflow-hidden">
      <summary className="px-3 py-2 text-xs font-semibold text-slate-300 bg-secondary cursor-pointer select-none">
        {title}
      </summary>
      <div className="p-1">{children}</div>
    </details>
  )
}
