import type { PacketRow } from '@/types'

const protocolColor: Record<string, string> = {
  TCP: 'text-info',
  UDP: 'text-neon',
  ICMP: 'text-warn',
  DNS: 'text-purple-400',
  ARP: 'text-slate-400',
  Other: 'text-slate-500',
}

export default function PacketTable({
  rows,
  onRowClick,
  showNo = false,
  maxHeight = '420px',
}: {
  rows: PacketRow[]
  onRowClick?: (row: PacketRow) => void
  showNo?: boolean
  maxHeight?: string
}) {
  return (
    <div className="overflow-auto scrollbar-thin rounded-xl border border-border" style={{ maxHeight }}>
      <table className="w-full text-sm">
        <thead className="sticky top-0 z-10 bg-secondary">
          <tr className="text-left text-xs text-slate-500 uppercase tracking-wide">
            {showNo && <th className="px-4 py-3 font-medium">No.</th>}
            <th className="px-4 py-3 font-medium">Time</th>
            <th className="px-4 py-3 font-medium">Source</th>
            <th className="px-4 py-3 font-medium">Destination</th>
            <th className="px-4 py-3 font-medium">Protocol</th>
            <th className="px-4 py-3 font-medium">Length</th>
            {!showNo && <th className="px-4 py-3 font-medium">Process</th>}
            <th className="px-4 py-3 font-medium">Info</th>
          </tr>
        </thead>
        <tbody className="font-mono text-xs">
          {rows.map((r) => (
            <tr
              key={r.no}
              onClick={() => onRowClick?.(r)}
              className="border-t border-border/60 hover:bg-white/5 cursor-pointer transition-colors"
            >
              {showNo && <td className="px-4 py-2.5 text-slate-500">{r.no}</td>}
              <td className="px-4 py-2.5 text-slate-400">{r.time}</td>
              <td className="px-4 py-2.5 text-slate-200">{r.source}</td>
              <td className="px-4 py-2.5 text-slate-200">{r.destination}</td>
              <td className={`px-4 py-2.5 font-semibold ${protocolColor[r.protocol]}`}>
                {r.protocol}
              </td>
              <td className="px-4 py-2.5 text-slate-400">{r.length}</td>
              {!showNo && <td className="px-4 py-2.5 text-slate-400">{r.process}</td>}
              <td className="px-4 py-2.5 text-slate-500 truncate max-w-[280px]">{r.info}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
