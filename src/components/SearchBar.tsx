import { Search } from 'lucide-react'

export default function SearchBar({
  placeholder = 'Search…',
  value,
  onChange,
  className = '',
}: {
  placeholder?: string
  value: string
  onChange: (v: string) => void
  className?: string
}) {
  return (
    <div className={`relative ${className}`}>
      <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-lg bg-secondary border border-border pl-9 pr-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-neon/50 focus:ring-1 focus:ring-neon/20 transition-colors"
      />
    </div>
  )
}
