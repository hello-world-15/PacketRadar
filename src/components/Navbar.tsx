import { Circle, Square, Download } from 'lucide-react'
import Button from './Button'
import { useCaptureControl } from '@/hooks/useCaptureControl'

export default function Navbar() {
  const {
    capturing,
    captureError,
    captureStale,
    secondsSinceLastPacket,
    recording,
    elapsed,
    packetCount,
    exportReady,
    pending,
    error,
    startRecording,
    stopRecording,
    exportPcap,
  } = useCaptureControl()

  return (
    <div className="glass rounded-2xl px-5 py-4 mb-6 flex flex-wrap items-center gap-4 justify-between">
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-lg font-bold text-slate-50">Live Monitor</h1>
          <p className="text-xs text-slate-500">Real-time packet capture &amp; threat detection</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        {/* Reflects the backend's always-on sniffer, not a toggle — see
            useCaptureControl. Capturing starts automatically when the
            backend boots. */}
        <div
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border"
          title={capturing ? 'Packet capture is running' : (captureError ?? 'Packet capture is not running')}
        >
          <span
            className={`h-2 w-2 rounded-full ${capturing ? 'bg-neon animate-pulseGlow' : 'bg-slate-600'}`}
          />
          <span className="text-xs text-slate-300">{capturing ? 'Capturing' : 'Idle'}</span>
          {captureStale && (
            <span
              className="text-xs text-warn font-mono border-l border-border pl-2 ml-1"
              title={`No packets received in ${Math.round(secondsSinceLastPacket ?? 0)}s — capture may have stalled`}
            >
              No packets {Math.round(secondsSinceLastPacket ?? 0)}s
            </span>
          )}
          {recording && (
            <span className="text-xs text-danger font-mono border-l border-border pl-2 ml-1 flex items-center gap-1">
              <Circle size={8} className="fill-danger text-danger animate-pulseGlow" /> REC {elapsed}
            </span>
          )}
          {packetCount > 0 && (
            <span className="text-xs text-slate-500 font-mono border-l border-border pl-2 ml-1">
              {packetCount.toLocaleString()} pkts
            </span>
          )}
        </div>

        <Button
          variant={recording ? 'danger' : 'primary'}
          size="sm"
          icon={recording ? <Square size={14} /> : <Circle size={14} />}
          disabled={pending || !capturing}
          onClick={() => (recording ? stopRecording() : startRecording())}
          title={!capturing ? 'Packet capture is not running' : undefined}
        >
          {recording ? 'Stop Recording' : 'Start Recording'}
        </Button>
        <Button
          variant="secondary"
          size="sm"
          icon={<Download size={14} />}
          disabled={!exportReady}
          onClick={exportPcap}
          title={exportReady ? 'Download the last completed recording' : 'Stop a recording to enable export'}
        >
          Export PCAP
        </Button>
      </div>

      {(error || captureError) && (
        <div className="w-full basis-full text-xs text-danger bg-danger/10 border border-danger/30 rounded-lg px-3 py-2">
          {error ?? captureError}
        </div>
      )}
    </div>
  )
}
