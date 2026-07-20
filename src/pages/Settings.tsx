import { useState, type ReactNode } from 'react'
import { Network, Bell, ShieldCheck, Database } from 'lucide-react'
import SectionHeader from '@/components/SectionHeader'
import Button from '@/components/Button'

function Toggle({ on, onClick }: { on: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`relative h-6 w-11 rounded-full transition-colors ${on ? 'bg-neon/80' : 'bg-white/10'}`}
    >
      <span
        className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform ${
          on ? 'translate-x-5' : 'translate-x-0.5'
        }`}
      />
    </button>
  )
}

function Row({
  label,
  description,
  children,
}: {
  label: string
  description?: string
  children: ReactNode
}) {
  return (
    <div className="flex items-center justify-between py-3.5 border-b border-border/60 last:border-0">
      <div>
        <p className="text-sm text-slate-200 font-medium">{label}</p>
        {description && <p className="text-xs text-slate-500 mt-0.5">{description}</p>}
      </div>
      {children}
    </div>
  )
}

export default function Settings() {
  const [autoBlock, setAutoBlock] = useState(true)
  const [notifications, setNotifications] = useState(true)
  const [darkOnly, setDarkOnly] = useState(true)
  const [telemetry, setTelemetry] = useState(false)

  return (
    <div className="pb-10 max-w-3xl">
      <div className="mb-6">
        <h1 className="text-lg font-bold text-slate-50">Settings</h1>
        <p className="text-xs text-slate-500">Configure capture behavior and preferences</p>
      </div>

      <div className="space-y-6">
        <div>
          <SectionHeader title="Capture" />
          <div className="glass rounded-2xl px-5 divide-y divide-border/60">
            <Row label="Default Interface" description="Interface selected on startup">
              <select className="rounded-lg bg-secondary border border-border px-3 py-1.5 text-sm text-slate-300">
                <option>eth0 — Ethernet</option>
                <option>wlan0 — Wi-Fi 6E</option>
              </select>
            </Row>
            <Row label="Buffer Size" description="Packet buffer allocated per capture session">
              <select className="rounded-lg bg-secondary border border-border px-3 py-1.5 text-sm text-slate-300">
                <option>64 MB</option>
                <option>128 MB</option>
                <option>256 MB</option>
              </select>
            </Row>
            <Row label="Promiscuous Mode" description="Capture all traffic on the segment, not just this host">
              <Toggle on={autoBlock} onClick={() => setAutoBlock((v) => !v)} />
            </Row>
          </div>
        </div>

        <div>
          <SectionHeader title="Threat Detection" />
          <div className="glass rounded-2xl px-5 divide-y divide-border/60">
            <Row label="Auto-block High Severity" description="Automatically block IPs flagged as high severity">
              <Toggle on={autoBlock} onClick={() => setAutoBlock((v) => !v)} />
            </Row>
            <Row label="Desktop Notifications" description="Show a system notification for new alerts">
              <Toggle on={notifications} onClick={() => setNotifications((v) => !v)} />
            </Row>
          </div>
        </div>

        <div>
          <SectionHeader title="Appearance" />
          <div className="glass rounded-2xl px-5 divide-y divide-border/60">
            <Row label="Dark Mode Only" description="PacketRadar currently supports dark theme only">
              <Toggle on={darkOnly} onClick={() => setDarkOnly((v) => !v)} />
            </Row>
          </div>
        </div>

        <div>
          <SectionHeader title="Privacy" />
          <div className="glass rounded-2xl px-5 divide-y divide-border/60">
            <Row label="Share Anonymous Telemetry" description="Help improve PacketRadar by sharing crash reports">
              <Toggle on={telemetry} onClick={() => setTelemetry((v) => !v)} />
            </Row>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Button variant="primary">Save Changes</Button>
          <Button variant="ghost">Reset to Defaults</Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8 text-center">
        {[
          { icon: Network, label: 'Interfaces', value: '4' },
          { icon: Bell, label: 'Alert Rules', value: '12' },
          { icon: ShieldCheck, label: 'Blocklist', value: '3' },
          { icon: Database, label: 'Stored Captures', value: '18' },
        ].map(({ icon: Icon, label, value }) => (
          <div key={label} className="glass rounded-xl p-4">
            <Icon size={16} className="text-neon mx-auto mb-2" />
            <p className="text-lg font-bold font-mono text-slate-100">{value}</p>
            <p className="text-xs text-slate-500">{label}</p>
          </div>
        ))}
      </div>
    </div>
  )
}
