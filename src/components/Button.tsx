import type { ButtonHTMLAttributes, ReactNode } from 'react'

type Variant = 'primary' | 'secondary' | 'danger' | 'ghost'
type Size = 'sm' | 'md'

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  children: ReactNode
  variant?: Variant
  size?: Size
  icon?: ReactNode
}

const variants: Record<Variant, string> = {
  primary:
    'bg-neon text-matte hover:bg-neon/90 shadow-glow font-semibold',
  secondary:
    'bg-secondary border border-border text-slate-200 hover:border-neon/40 hover:text-neon',
  danger:
    'bg-danger/10 border border-danger/40 text-danger hover:bg-danger/20',
  ghost:
    'text-slate-400 hover:text-neon hover:bg-white/5',
}

const sizes: Record<Size, string> = {
  sm: 'text-xs px-2.5 py-1.5 gap-1.5',
  md: 'text-sm px-4 py-2 gap-2',
}

export default function Button({
  children,
  variant = 'secondary',
  size = 'md',
  icon,
  className = '',
  ...rest
}: Props) {
  return (
    <button
      className={`inline-flex items-center justify-center rounded-lg transition-all duration-150 active:scale-[0.97] disabled:opacity-40 disabled:cursor-not-allowed ${variants[variant]} ${sizes[size]} ${className}`}
      {...rest}
    >
      {icon}
      {children}
    </button>
  )
}
