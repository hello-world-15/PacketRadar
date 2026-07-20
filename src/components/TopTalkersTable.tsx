import type { TopTalker } from '@/types'

export default function TopTalkersTable({ talkers }: { talkers: TopTalker[] }) {
  return (
    <div className="overflow-auto scrollbar-thin rounded-xl border border-border max-h-[360px]">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-secondary">
          <tr className="text-left text-xs text-slate-500 uppercase tracking-wide">
            <th className="px-4 py-3 font-medium">IP</th>
            <th className="px-4 py-3 font-medium">Hostname</th>
            <th className="px-4 py-3 font-medium">Packets</th>
            <th className="px-4 py-3 font-medium">Bandwidth</th>
            <th className="px-4 py-3 font-medium">Connections</th>
          </tr>
        </thead>
        <tbody>
          {talkers.map((t) => (
            <tr key={t.ip} className="border-t border-border/60 hover:bg-white/5 transition-colors">
              <td className="px-4 py-3 text-slate-200 font-mono text-xs">{t.ip}</td>
              <td className="px-4 py-3 text-slate-400 text-xs">{t.hostname}</td>
              <td className="px-4 py-3 text-slate-400 font-mono text-xs">
                {t.packets.toLocaleString()}
              </td>
              <td className="px-4 py-3 w-48">
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-1.5 rounded-full bg-white/5 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-neon"
                      style={{ width: `${t.bandwidthPct}%` }}
                    />
                  </div>
                  <span className="text-xs text-slate-500 font-mono w-14 text-right">
                    {t.bandwidthMbps} Mbps
                  </span>
                </div>
              </td>
              <td className="px-4 py-3 text-slate-400 text-xs">{t.connections}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
