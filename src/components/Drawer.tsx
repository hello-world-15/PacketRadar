import type { ReactNode } from 'react'
import { X } from 'lucide-react'

export default function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
}: {
  open: boolean
  onClose: () => void
  title: string
  subtitle?: string
  children: ReactNode
  footer?: ReactNode
}) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50">
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm animate-fadeIn"
        onClick={onClose}
      />
      <div className="absolute right-0 top-0 h-full w-full max-w-md bg-secondary border-l border-border shadow-soft animate-slideIn flex flex-col">
        <div className="flex items-start justify-between px-6 py-5 border-b border-border">
          <div>
            <h3 className="text-base font-semibold text-slate-100">{title}</h3>
            {subtitle && <p className="text-xs text-slate-500 mt-1 font-mono">{subtitle}</p>}
          </div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-200 transition-colors mt-0.5"
          >
            <X size={18} />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto scrollbar-thin px-6 py-5 space-y-5">
          {children}
        </div>
        {footer && (
          <div className="px-6 py-4 border-t border-border flex items-center gap-3">
            {footer}
          </div>
        )}
      </div>
    </div>
  )
}

export function DrawerField({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-border/60 last:border-0">
      <span className="text-xs text-slate-500 uppercase tracking-wide">{label}</span>
      <span className="text-sm text-slate-200 font-mono">{value}</span>
    </div>
  )
}
