import { useEffect, useRef, useState } from 'react'
import type { LucideIcon } from 'lucide-react'

type Tone = 'neon' | 'danger' | 'warn' | 'info' | 'neutral'

const toneClasses: Record<Tone, string> = {
  neon: 'text-neon bg-neon/10',
  danger: 'text-danger bg-danger/10',
  warn: 'text-warn bg-warn/10',
  info: 'text-info bg-info/10',
  neutral: 'text-slate-300 bg-white/5',
}

function useAnimatedNumber(target: number, duration = 900) {
  const [value, setValue] = useState(0)
  const start = useRef<number | null>(null)

  useEffect(() => {
    start.current = null
    let raf: number
    const step = (ts: number) => {
      if (start.current === null) start.current = ts
      const progress = Math.min((ts - start.current) / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setValue(target * eased)
      if (progress < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [target, duration])

  return value
}

export default function StatCard({
  label,
  value,
  unit,
  icon: Icon,
  tone = 'neon',
  trend,
  decimals = 0,
}: {
  label: string
  value: number
  unit?: string
  icon: LucideIcon
  tone?: Tone
  trend?: { direction: 'up' | 'down'; value: string }
  decimals?: number
}) {
  const animated = useAnimatedNumber(value)

  return (
    <div className="glass rounded-2xl p-5 shadow-card hover:border-neon/30 transition-colors duration-200 group">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs uppercase tracking-wider text-slate-500 font-medium">{label}</p>
          <p className="mt-2 text-2xl font-bold text-slate-50 font-mono">
            {animated.toLocaleString(undefined, {
              minimumFractionDigits: decimals,
              maximumFractionDigits: decimals,
            })}
            {unit && <span className="ml-1 text-sm text-slate-500 font-sans">{unit}</span>}
          </p>
        </div>
        <div className={`rounded-xl p-2.5 ${toneClasses[tone]} group-hover:scale-105 transition-transform`}>
          <Icon size={18} strokeWidth={2} />
        </div>
      </div>
      {trend && (
        <p className={`mt-3 text-xs font-medium ${trend.direction === 'up' ? 'text-neon' : 'text-danger'}`}>
          {trend.direction === 'up' ? '↑' : '↓'} {trend.value}
        </p>
      )}
    </div>
  )
}
