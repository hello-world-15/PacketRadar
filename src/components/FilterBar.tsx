import type { ReactNode } from 'react'
import SearchBar from './SearchBar'

export interface FilterSelect {
  label: string
  value: string
  options: string[]
  onChange: (v: string) => void
}

export default function FilterBar({
  search,
  onSearchChange,
  searchPlaceholder,
  selects = [],
  trailing,
}: {
  search: string
  onSearchChange: (v: string) => void
  searchPlaceholder?: string
  selects?: FilterSelect[]
  trailing?: ReactNode
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 mb-4">
      <SearchBar
        value={search}
        onChange={onSearchChange}
        placeholder={searchPlaceholder}
        className="w-full sm:w-64"
      />
      {selects.map((s) => (
        <select
          key={s.label}
          value={s.value}
          onChange={(e) => s.onChange(e.target.value)}
          className="rounded-lg bg-secondary border border-border px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-neon/50 cursor-pointer"
        >
          <option value="">{s.label}</option>
          {s.options.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      ))}
      <div className="ml-auto flex items-center gap-2">{trailing}</div>
    </div>
  )
}
