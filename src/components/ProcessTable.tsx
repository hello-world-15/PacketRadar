import type { TopApplication } from '@/types'

export default function ProcessTable({ apps }: { apps: TopApplication[] }) {
  return (
    <div className="overflow-auto scrollbar-thin rounded-xl border border-border max-h-[360px]">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-secondary">
          <tr className="text-left text-xs text-slate-500 uppercase tracking-wide">
            <th className="px-4 py-3 font-medium">Application</th>
            <th className="px-4 py-3 font-medium">PID</th>
            <th className="px-4 py-3 font-medium">Upload</th>
            <th className="px-4 py-3 font-medium">Download</th>
            <th className="px-4 py-3 font-medium">Connections</th>
          </tr>
        </thead>
        <tbody>
          {apps.map((a) => (
            <tr key={a.pid} className="border-t border-border/60 hover:bg-white/5 transition-colors">
              <td className="px-4 py-3 text-slate-100">
                <span className="mr-2">{a.icon}</span>
                {a.name}
              </td>
              <td className="px-4 py-3 text-slate-500 font-mono text-xs">{a.pid}</td>
              <td className="px-4 py-3 text-neon font-mono text-xs">↑ {a.uploadKbps} KB/s</td>
              <td className="px-4 py-3 text-info font-mono text-xs">↓ {a.downloadKbps} KB/s</td>
              <td className="px-4 py-3 text-slate-400 text-xs">{a.connections}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
