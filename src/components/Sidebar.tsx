import { NavLink } from 'react-router-dom'
import { Radar, LayoutDashboard, FolderSearch, Info, CircleDot } from 'lucide-react'

const navItems = [
  { to: '/', label: 'Live Monitor', icon: LayoutDashboard },
  { to: '/analyzer', label: 'PCAP Analyzer', icon: FolderSearch },
  { to: '/about', label: 'About', icon: Info },
]

export default function Sidebar() {
  return (
    <aside className="fixed inset-y-0 left-0 z-40 w-60 flex flex-col bg-secondary border-r border-border">
      <div className="flex items-center gap-2.5 px-5 h-16 border-b border-border">
        <div className="relative flex items-center justify-center h-9 w-9 rounded-xl bg-neon/10 border border-neon/30">
          <Radar size={18} className="text-neon" strokeWidth={2.2} />
          <span className="absolute inset-0 rounded-xl border border-neon/40 animate-pulseGlow" />
        </div>
        <div>
          <p className="text-sm font-bold tracking-wide text-slate-50 leading-none">PacketRadar</p>
          <p className="text-[10px] text-slate-500 mt-1 tracking-wider uppercase">Network Security</p>
        </div>
      </div>

      <nav className="flex-1 px-3 py-5 space-y-1">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-neon/10 text-neon border border-neon/20'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-white/5 border border-transparent'
              }`
            }
          >
            <Icon size={17} strokeWidth={2} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="px-4 py-4 border-t border-border space-y-3">
        <div className="flex items-center gap-2 text-xs">
          <CircleDot size={13} className="text-neon animate-pulseGlow" />
          <span className="text-slate-400">Capture Active</span>
        </div>
      </div>
    </aside>
  )
}
