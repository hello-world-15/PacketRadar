import type { ReactNode } from 'react'

type BadgeVariant = 'neon' | 'danger' | 'warn' | 'info' | 'neutral'

const variantClasses: Record<BadgeVariant, string> = {
  neon: 'bg-neon/10 text-neon border-neon/30',
  danger: 'bg-danger/10 text-danger border-danger/30',
  warn: 'bg-warn/10 text-warn border-warn/30',
  info: 'bg-info/10 text-info border-info/30',
  neutral: 'bg-slate-500/10 text-slate-300 border-slate-500/30',
}

export default function Badge({
  children,
  variant = 'neutral',
  dot = false,
}: {
  children: ReactNode
  variant?: BadgeVariant
  dot?: boolean
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium tracking-wide ${variantClasses[variant]}`}
    >
      {dot && (
        <span className={`h-1.5 w-1.5 rounded-full ${variantClasses[variant].split(' ')[1]} bg-current`} />
      )}
      {children}
    </span>
  )
}

export function severityBadge(severity: 'high' | 'medium' | 'low') {
  if (severity === 'high') return <Badge variant="danger" dot>High</Badge>
  if (severity === 'medium') return <Badge variant="warn" dot>Medium</Badge>
  return <Badge variant="info" dot>Low</Badge>
}
