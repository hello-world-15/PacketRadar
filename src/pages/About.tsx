import { Radar } from 'lucide-react'

const frontendStack = ['React', 'TypeScript', 'Vite', 'Tailwind CSS', 'Chart.js', 'React Router']
const backendStack = ['Python', 'FastAPI', 'Scapy', 'Pydantic', 'WebSockets']

export default function About() {
  return (
    <div className="pb-10 max-w-2xl">
      <div className="glass rounded-2xl p-8 mb-6 text-center">
        <div className="relative mx-auto h-16 w-16 rounded-2xl bg-neon/10 border border-neon/30 flex items-center justify-center mb-4">
          <Radar size={30} className="text-neon" />
          <span className="absolute inset-0 rounded-2xl border border-neon/40 animate-pulseGlow" />
        </div>
        <h1 className="text-xl font-bold text-slate-50">PacketRadar</h1>
        <p className="text-sm text-slate-500 mt-3 leading-relaxed">
          Live network capture and offline PCAP analysis in one dashboard —
          watch traffic as it happens, or drop in a capture file to see what
          happened. Six behavioral rules flag port scans, ARP spoofing, DNS
          tunneling, SYN floods, C2 beaconing, and bulk data exfiltration —
          no signature lists, just traffic that doesn't behave like the rest.
        </p>
      </div>

      <div className="glass rounded-2xl p-6">
        <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wide mb-4">
          Tech Stack
        </h2>
        <div className="space-y-4">
          <div>
            <p className="text-xs text-slate-500 mb-2">Frontend</p>
            <div className="flex flex-wrap gap-2">
              {frontendStack.map((t) => (
                <span
                  key={t}
                  className="text-xs font-mono px-3 py-1.5 rounded-full bg-secondary border border-border text-slate-400"
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
          <div>
            <p className="text-xs text-slate-500 mb-2">Backend</p>
            <div className="flex flex-wrap gap-2">
              {backendStack.map((t) => (
                <span
                  key={t}
                  className="text-xs font-mono px-3 py-1.5 rounded-full bg-secondary border border-border text-slate-400"
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
