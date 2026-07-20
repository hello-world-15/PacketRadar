import type { DiscoveredHost } from '@/types'
import Badge from './Badge'

const statusVariant: Record<DiscoveredHost['status'], 'neon' | 'neutral'> = {
  online: 'neon',
  offline: 'neutral',
}

export default function HostTable({ hosts }: { hosts: DiscoveredHost[] }) {
  return (
    <div className="overflow-auto scrollbar-thin rounded-xl border border-border">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-secondary">
          <tr className="text-left text-xs text-slate-500 uppercase tracking-wide">
            <th className="px-4 py-3 font-medium">Hostname</th>
            <th className="px-4 py-3 font-medium">IP</th>
            <th className="px-4 py-3 font-medium">MAC</th>
            <th className="px-4 py-3 font-medium">Last Seen</th>
            <th className="px-4 py-3 font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((h) => (
            <tr key={h.mac} className="border-t border-border/60 hover:bg-white/5 transition-colors">
              <td className="px-4 py-3 text-slate-100 font-medium">{h.hostname}</td>
              <td className="px-4 py-3 text-slate-400 font-mono text-xs">{h.ip}</td>
              <td className="px-4 py-3 text-slate-500 font-mono text-xs">{h.mac}</td>
              <td className="px-4 py-3 text-slate-500 font-mono text-xs">{h.lastSeen}</td>
              <td className="px-4 py-3">
                <Badge variant={statusVariant[h.status]} dot>
                  {h.status[0].toUpperCase() + h.status.slice(1)}
                </Badge>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
