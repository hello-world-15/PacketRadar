import { useState } from 'react'
import { UploadCloud, FileArchive, Loader2, FolderOpen } from 'lucide-react'
import Button from './Button'
import type { RecordedCapture } from '@/lib/pcapApi'

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatCapturedAt(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export default function UploadZone({
  onAnalyze,
  analyzing = false,
  error = null,
  recordedCaptures = [],
  recordedCapturesLoading = false,
  recordedCapturesError = null,
  onSelectRecordedCapture,
}: {
  onAnalyze: (file: File) => void
  analyzing?: boolean
  error?: string | null
  /** Files Live Monitor's Start/Stop Recording has already saved to
   * backend/captures — see app.api.pcap's GET /api/pcap/captures. */
  recordedCaptures?: RecordedCapture[]
  recordedCapturesLoading?: boolean
  recordedCapturesError?: string | null
  onSelectRecordedCapture?: (filename: string) => void
}) {
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState<File | null>(null)

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault()
        setDragging(true)
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault()
        setDragging(false)
        const f = e.dataTransfer.files?.[0]
        if (f) setFile(f)
      }}
      className={`glass rounded-2xl border-2 border-dashed p-12 text-center transition-colors ${
        dragging ? 'border-neon bg-neon/5' : 'border-border'
      }`}
    >
      <div className="mx-auto h-14 w-14 rounded-2xl bg-neon/10 border border-neon/30 flex items-center justify-center mb-4">
        <UploadCloud size={26} className="text-neon" />
      </div>
      <h3 className="text-slate-100 font-semibold mb-1">Drag &amp; Drop PCAP</h3>
      <p className="text-sm text-slate-500 mb-5">
        Supported formats: <span className="font-mono text-slate-400">.pcap</span> ·{' '}
        <span className="font-mono text-slate-400">.pcapng</span>
      </p>

      <div className="flex flex-wrap items-center justify-center gap-3">
        <label>
          <input
            type="file"
            accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/octet-stream"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) setFile(f)
            }}
          />
          <span className="inline-flex">
            <Button variant="secondary" className="cursor-pointer">
              Browse Files
            </Button>
          </span>
        </label>

        {onSelectRecordedCapture && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500">or</span>
            <div className="relative inline-flex items-center">
              <FolderOpen
                size={14}
                className="pointer-events-none absolute left-3 text-slate-500"
              />
              <select
                value=""
                disabled={recordedCapturesLoading || recordedCaptures.length === 0}
                onChange={(e) => {
                  if (e.target.value) onSelectRecordedCapture(e.target.value)
                }}
                className="appearance-none rounded-lg bg-secondary border border-border pl-8 pr-8 py-2 text-sm text-slate-300 focus:outline-none focus:border-neon/50 cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 max-w-[260px]"
              >
                <option value="" disabled>
                  {recordedCapturesLoading
                    ? 'Loading recorded captures…'
                    : recordedCaptures.length === 0
                      ? 'No recorded captures yet'
                      : 'Select a recorded capture'}
                </option>
                {recordedCaptures.map((c) => (
                  <option key={c.filename} value={c.filename}>
                    {formatCapturedAt(c.captured_at)} · {c.filename} ({formatSize(c.size_bytes)})
                  </option>
                ))}
              </select>
            </div>
          </div>
        )}
      </div>

      {recordedCapturesError && (
        <p className="mt-3 text-xs text-danger max-w-md mx-auto">{recordedCapturesError}</p>
      )}

      {file && (
        <div className="mt-6 flex items-center justify-center gap-3">
          <div className="flex items-center gap-2 rounded-lg bg-secondary border border-border px-3 py-2 text-sm text-slate-300">
            <FileArchive size={15} className="text-neon" />
            <span className="font-mono">{file.name}</span>
          </div>
          <Button variant="primary" onClick={() => onAnalyze(file)} disabled={analyzing}>
            {analyzing ? (
              <span className="flex items-center gap-2">
                <Loader2 size={14} className="animate-spin" /> Analyzing…
              </span>
            ) : (
              'Analyze Capture'
            )}
          </Button>
        </div>
      )}

      {error && (
        <p className="mt-4 text-sm text-danger max-w-md mx-auto">{error}</p>
      )}
    </div>
  )
}
