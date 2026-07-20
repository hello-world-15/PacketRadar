import { useEffect, useState } from 'react'
import {
  Activity,
  Gauge,
  Network,
  ShieldAlert,
  Router as RouterIcon,
  PackageX,
} from 'lucide-react'
import Navbar from '@/components/Navbar'
import StatCard from '@/components/StatCard'
import ChartCard from '@/components/ChartCard'
import SectionHeader from '@/components/SectionHeader'
import { BandwidthChart, ProtocolPieChart, TimelineChart } from '@/components/Charts'
import TopTalkersTable from '@/components/TopTalkersTable'
import ProcessTable from '@/components/ProcessTable'
import PacketTable from '@/components/PacketTable'
import ThreatTable from '@/components/ThreatTable'
import HostTable from '@/components/HostTable'
import FilterBar from '@/components/FilterBar'
import Drawer, { DrawerField } from '@/components/Drawer'
import Button from '@/components/Button'
import Badge from '@/components/Badge'
import { useLiveSocket } from '@/hooks/useLiveSocket'
import type { PacketRow } from '@/types'

const timeRanges = ['30 sec', '60 sec', '5 min'] as const

// Neutral, empty state shown only until the backend WebSocket connects
// and sends real data — see useLiveSocket.
const emptyStatsFallback = {
  packets_per_sec: 0,
  bandwidth_mbps: 0,
  upload_mbps: 0,
  download_mbps: 0,
  active_connections: 0,
  threat_alert_count: 0,
  lan_device_count: 0,
  dropped_packets: 0,
  protocol_distribution: [],
}

// Rolling upload/download history for the Live Bandwidth chart — same
// client-side-only pattern as packetsPerSecHistory below (see Module 6
// task notes / docs/contracts/stats.md): the backend only ever ships the
// current instantaneous upload_mbps/download_mbps, so the time series is
// built up locally as stats:update ticks arrive. Sized for the longest
// of the three existing range options (5 min @ 1 sample/sec).
const MAX_BANDWIDTH_SAMPLES = 300

// Rolling packets/sec history for the Live Traffic chart — capped so
// memory doesn't grow the longer the tab stays open. Entirely
// client-side (see LiveMonitor task notes): it naturally fills in over
// the first ~60 seconds after connecting rather than backfilling from
// the server.
const MAX_PACKETS_PER_SEC_SAMPLES = 60
const packetsPerSecRanges = ['30 sec', '60 sec'] as const

export default function LiveMonitor() {
  const [range, setRange] = useState<(typeof timeRanges)[number]>('60 sec')
  const [packetsPerSecRange, setPacketsPerSecRange] =
    useState<(typeof packetsPerSecRanges)[number]>('60 sec')
  const [selectedPacket, setSelectedPacket] = useState<PacketRow | null>(null)
  const [search, setSearch] = useState('')
  const [protocolFilter, setProtocolFilter] = useState('')
  const { stats, hosts, packets, talkers, threats, applications, connected } = useLiveSocket({
    stats: emptyStatsFallback,
    hosts: [],
    packets: [],
    talkers: [],
    threats: [],
    applications: [],
  })

  // Append a sample every time a fresh stats:update ticks in. Keyed off
  // `stats` (not a timer) so this stays in lockstep with the backend's
  // real 1s cadence instead of drifting from its own interval.
  const [packetsPerSecHistory, setPacketsPerSecHistory] = useState<number[]>([])
  useEffect(() => {
    if (!connected) return
    setPacketsPerSecHistory((prev) =>
      [...prev, stats.packets_per_sec].slice(-MAX_PACKETS_PER_SEC_SAMPLES),
    )
  }, [stats.packets_per_sec, connected])

  const packetsPerSecPoints = packetsPerSecRange === '30 sec' ? 30 : 60
  const packetsPerSecData = packetsPerSecHistory.slice(-packetsPerSecPoints)
  const packetsPerSecLabels = packetsPerSecData.map(
    (_, i) => `-${packetsPerSecData.length - i}s`,
  )

  // Append a sample every time a fresh stats:update ticks in — same
  // pattern as packetsPerSecHistory above. Keyed off `stats` (not a
  // timer) so this stays in lockstep with the backend's real 1s cadence.
  const [uploadHistory, setUploadHistory] = useState<number[]>([])
  const [downloadHistory, setDownloadHistory] = useState<number[]>([])
  useEffect(() => {
    if (!connected) return
    setUploadHistory((prev) => [...prev, stats.upload_mbps].slice(-MAX_BANDWIDTH_SAMPLES))
    setDownloadHistory((prev) => [...prev, stats.download_mbps].slice(-MAX_BANDWIDTH_SAMPLES))
  }, [stats.upload_mbps, stats.download_mbps, connected])

  const bandwidthPoints = range === '30 sec' ? 30 : range === '60 sec' ? 60 : 300
  const upload = uploadHistory.slice(-bandwidthPoints)
  const download = downloadHistory.slice(-bandwidthPoints)
  const labels = upload.map((_, i) => `-${upload.length - i}s`)

  const filteredPackets = packets.filter((p) => {
    const matchesSearch =
      !search ||
      p.source.includes(search) ||
      p.destination.includes(search) ||
      p.info.toLowerCase().includes(search.toLowerCase()) ||
      p.process?.toLowerCase().includes(search.toLowerCase())
    const matchesProtocol = !protocolFilter || p.protocol === protocolFilter
    return matchesSearch && matchesProtocol
  })

  return (
    <div className="pb-10">
      <Navbar />

      {/* KPI Cards */}
      <div className="flex items-center gap-2 mb-3">
        <Badge variant={connected ? 'neon' : 'neutral'} dot>
          {connected ? 'Live backend data' : 'Waiting for backend connection…'}
        </Badge>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4 mb-6">
        <StatCard label="Packets/sec" value={stats.packets_per_sec} icon={Activity} tone="neon" />
        <StatCard label="Bandwidth" value={stats.bandwidth_mbps} unit="Mbps" decimals={1} icon={Gauge} tone="info" />
        <StatCard label="Active Connections" value={stats.active_connections} icon={Network} tone="neon" />
        <StatCard label="Threat Alerts" value={stats.threat_alert_count} icon={ShieldAlert} tone="danger" />
        <StatCard label="LAN Devices" value={stats.lan_device_count} icon={RouterIcon} tone="info" />
        <StatCard label="Dropped Packets" value={stats.dropped_packets} icon={PackageX} tone="warn" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-6">
        <ChartCard
          title="Live Bandwidth"
          className="xl:col-span-2"
          action={
            <div className="flex items-center gap-1 bg-secondary rounded-lg p-1 border border-border">
              {timeRanges.map((r) => (
                <button
                  key={r}
                  onClick={() => setRange(r)}
                  className={`px-2.5 py-1 text-xs rounded-md transition-colors ${
                    range === r ? 'bg-neon/15 text-neon' : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  {r}
                </button>
              ))}
            </div>
          }
        >
          <div className="h-64">
            <BandwidthChart labels={labels} upload={upload} download={download} />
          </div>
        </ChartCard>

        <ChartCard title="Protocol Distribution">
          <div className="h-64">
            <ProtocolPieChart data={stats.protocol_distribution} />
          </div>
        </ChartCard>
      </div>

      <div className="grid grid-cols-1 gap-5 mb-6">
        <ChartCard
          title="Live Traffic (Packets/sec)"
          action={
            <div className="flex items-center gap-1 bg-secondary rounded-lg p-1 border border-border">
              {packetsPerSecRanges.map((r) => (
                <button
                  key={r}
                  onClick={() => setPacketsPerSecRange(r)}
                  className={`px-2.5 py-1 text-xs rounded-md transition-colors ${
                    packetsPerSecRange === r ? 'bg-neon/15 text-neon' : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  {r}
                </button>
              ))}
            </div>
          }
        >
          <div className="h-64">
            <TimelineChart labels={packetsPerSecLabels} data={packetsPerSecData} />
          </div>
        </ChartCard>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 mb-6">
        <div>
          <SectionHeader title="Top Talkers" subtitle="Highest bandwidth consumers on the network" />
          <TopTalkersTable talkers={talkers} />
        </div>
        <div>
          <SectionHeader title="Top Applications" subtitle="Processes generating the most traffic" />
          <ProcessTable apps={applications} />
        </div>
      </div>

      <div className="mb-6">
        <SectionHeader
          title="Live Packet Stream"
          subtitle={`${filteredPackets.length} packets shown`}
        />
        <FilterBar
          search={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search IP, process, info…"
          selects={[
            {
              label: 'Protocol',
              value: protocolFilter,
              options: ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP', 'Other'],
              onChange: setProtocolFilter,
            },
          ]}
        />
        <PacketTable rows={filteredPackets} onRowClick={setSelectedPacket} maxHeight="440px" />
      </div>

      <div className="mb-6">
        <SectionHeader title="Threat Detection" subtitle="Active alerts from behavioral and signature analysis" />
        <ThreatTable threats={threats} />
      </div>

      <div className="mb-6">
        <SectionHeader title="Active Host Discovery" subtitle="Devices observed on the local network" />
        <HostTable hosts={hosts} />
      </div>

      <Drawer
        open={!!selectedPacket}
        onClose={() => setSelectedPacket(null)}
        title="Packet Investigation"
        subtitle={selectedPacket ? `#${selectedPacket.no} · ${selectedPacket.time}` : ''}
        footer={
          <>
            <Button variant="danger" className="flex-1">Block IP</Button>
            <Button variant="secondary" className="flex-1" onClick={() => setSelectedPacket(null)}>
              Close
            </Button>
          </>
        }
      >
        {selectedPacket && (
          <>
            <div className="flex items-center gap-2 mb-2">
              <Badge variant="info">{selectedPacket.protocol}</Badge>
              <Badge variant="neutral">{selectedPacket.length} bytes</Badge>
            </div>
            <div className="rounded-xl border border-border divide-y divide-border/60">
              <div className="p-1">
                <DrawerField label="Source" value={selectedPacket.source} />
                <DrawerField label="Destination" value={selectedPacket.destination} />
                <DrawerField label="Process" value={selectedPacket.process ?? '—'} />
                <DrawerField label="Protocol" value={selectedPacket.protocol} />
                <DrawerField label="Length" value={`${selectedPacket.length} bytes`} />
                {selectedPacket.protocol === 'DNS' && (
                  <>
                    <DrawerField label="DNS Query" value={selectedPacket.dnsQuery ?? '—'} />
                    <DrawerField
                      label="DNS Answer"
                      value={selectedPacket.dnsAnswer ?? 'No answer — see Info below'}
                    />
                  </>
                )}
              </div>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wide mb-1.5">Info</p>
              <p className="text-sm text-slate-300 font-mono bg-secondary rounded-lg p-3 border border-border">
                {selectedPacket.info}
              </p>
            </div>
          </>
        )}
      </Drawer>
    </div>
  )
}
