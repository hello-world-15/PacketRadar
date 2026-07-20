import type { ThreatAlert } from '@/types'
import { severityBadge } from './Badge'

export default function ThreatTable({
  threats,
}: {
  threats: ThreatAlert[]
}) {
  return (
    <div className="overflow-auto scrollbar-thin rounded-xl border border-border">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-secondary">
          <tr className="text-left text-xs text-slate-500 uppercase tracking-wide">
            <th className="px-4 py-3 font-medium">Time</th>
            <th className="px-4 py-3 font-medium">Severity</th>
            <th className="px-4 py-3 font-medium">Threat</th>
            <th className="px-4 py-3 font-medium">Source</th>
            <th className="px-4 py-3 font-medium">Description</th>
          </tr>
        </thead>
        <tbody>
          {threats.map((t) => (
            <tr key={t.id} className="border-t border-border/60 hover:bg-white/5 transition-colors">
              <td className="px-4 py-3 text-xs text-slate-500 font-mono">{t.time}</td>
              <td className="px-4 py-3">{severityBadge(t.severity)}</td>
              <td className="px-4 py-3 text-slate-100 font-medium">{t.threat}</td>
              <td className="px-4 py-3 text-slate-400 font-mono text-xs">{t.source}</td>
              <td className="px-4 py-3 text-slate-500 text-xs max-w-xs">{t.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
