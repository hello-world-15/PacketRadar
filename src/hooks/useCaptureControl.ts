import { useCallback, useEffect, useRef, useState } from 'react'

/** Mirrors backend/app/api/capture.py::CaptureStatus. */
interface CaptureStatusResponse {
  capturing: boolean
  capture_error: string | null
  interface: string | null
  last_packet_at: number | null // unix seconds — heartbeat, see backend docstring
  recording: boolean
  recording_started_at: number | null // unix seconds
  packet_count: number
  export_ready: boolean
}

const API_BASE = 'http://localhost:8000'
const POLL_INTERVAL_MS = 1000

// How long without a packet before the Navbar calls it out. Deliberately
// well above the 1s poll interval and above normal lulls in traffic —
// this is meant to catch "the sniffer thread died/stalled" (see
// backend/app/capture/sniffer.py's is_running docstring), not to flag
// every few-second quiet patch on an otherwise-idle LAN as a problem.
const STALE_HEARTBEAT_SECONDS = 15

function formatElapsed(seconds: number): string {
  const clamped = Math.max(0, Math.floor(seconds))
  const h = Math.floor(clamped / 3600)
  const m = Math.floor((clamped % 3600) / 60)
  const s = clamped % 60
  const pad = (n: number) => n.toString().padStart(2, '0')
  return `${pad(h)}:${pad(m)}:${pad(s)}`
}

async function parseErrorDetail(res: Response): Promise<string> {
  try {
    const body = await res.json()
    return body.detail ?? `Request failed (${res.status})`
  } catch {
    return `Request failed (${res.status})`
  }
}

/**
 * Drives the Navbar's capture indicator and Record/Export PCAP controls
 * against the backend's /api/capture/* endpoints.
 *
 * Packet capture itself is always-on server-side (started once when the
 * backend boots — see backend/app/main.py's lifespan handler), so
 * `capturing` here just reflects that state for the "Capturing/Idle"
 * badge; there's no start/stop for it in the UI. "Recording" is the
 * thing the button controls: streaming the already-running capture out
 * to a .pcap file, on demand.
 *
 * `capturing` now reflects whether the sniffer thread is actually alive
 * (see PacketCapture.is_running's docstring on the backend) rather than
 * just whether start() was ever called — but a thread can be alive
 * while the OS capture buffer has quietly stopped delivering packets to
 * it. `captureStale`/`secondsSinceLastPacket`, derived from the
 * backend's packet heartbeat (`last_packet_at`), catch that case too.
 *
 * Polls /status once a second — a lightweight REST poll rather than a
 * third thing riding the /ws/live socket, since record/export are
 * one-shot commands, not a stream Live Monitor's other widgets need.
 */
export function useCaptureControl() {
  const [capturing, setCapturing] = useState(false)
  const [captureError, setCaptureError] = useState<string | null>(null)
  const [lastPacketAt, setLastPacketAt] = useState<number | null>(null)
  const [recording, setRecording] = useState(false)
  const [elapsed, setElapsed] = useState('00:00:00')
  const [packetCount, setPacketCount] = useState(0)
  const [exportReady, setExportReady] = useState(false)
  const [pending, setPending] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null)

  const applyStatus = useCallback((status: CaptureStatusResponse) => {
    setCapturing(status.capturing)
    setCaptureError(status.capture_error)
    setLastPacketAt(status.last_packet_at)
    setRecording(status.recording)
    setPacketCount(status.packet_count)
    setExportReady(status.export_ready)
    setElapsed(
      status.recording_started_at
        ? formatElapsed(Date.now() / 1000 - status.recording_started_at)
        : '00:00:00',
    )
  }, [])

  const refreshStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/capture/status`)
      if (!res.ok) return
      applyStatus(await res.json())
    } catch {
      // Backend not reachable — leave last-known state in place rather
      // than flashing an error on every idle poll tick.
    }
  }, [applyStatus])

  useEffect(() => {
    refreshStatus()
    pollTimer.current = setInterval(refreshStatus, POLL_INTERVAL_MS)
    return () => {
      if (pollTimer.current) clearInterval(pollTimer.current)
    }
  }, [refreshStatus])

  const startRecording = useCallback(async () => {
    setPending(true)
    setActionError(null)
    try {
      const res = await fetch(`${API_BASE}/api/capture/record/start`, { method: 'POST' })
      if (!res.ok) throw new Error(await parseErrorDetail(res))
      applyStatus(await res.json())
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to start recording')
    } finally {
      setPending(false)
    }
  }, [applyStatus])

  const stopRecording = useCallback(async () => {
    setPending(true)
    setActionError(null)
    try {
      const res = await fetch(`${API_BASE}/api/capture/record/stop`, { method: 'POST' })
      if (!res.ok) throw new Error(await parseErrorDetail(res))
      applyStatus(await res.json())
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to stop recording')
    } finally {
      setPending(false)
    }
  }, [applyStatus])

  const exportPcap = useCallback(() => {
    // A plain navigation, not fetch()+blob: the endpoint already sets
    // Content-Disposition: attachment, so the browser handles the
    // download and filename on its own.
    window.location.href = `${API_BASE}/api/capture/export`
  }, [])

  // Derived, not stored: recomputed each render (poll ticks drive
  // re-renders once a second anyway) so it doesn't need its own timer.
  // null while capturing is false/unknown or no packet has arrived yet
  // this session — "stale" only means something once capture claims to
  // be running.
  const secondsSinceLastPacket =
    capturing && lastPacketAt != null ? Date.now() / 1000 - lastPacketAt : null
  const captureStale =
    capturing && secondsSinceLastPacket != null && secondsSinceLastPacket > STALE_HEARTBEAT_SECONDS

  return {
    capturing,
    captureError,
    captureStale,
    secondsSinceLastPacket,
    recording,
    elapsed,
    packetCount,
    exportReady,
    pending,
    error: actionError,
    startRecording,
    stopRecording,
    exportPcap,
  }
}
