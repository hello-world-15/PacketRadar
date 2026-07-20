import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js'
import { Line, Pie } from 'react-chartjs-2'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
)

const gridColor = 'rgba(255,255,255,0.05)'
const tickColor = '#64748b'

export function BandwidthChart({
  labels,
  upload,
  download,
}: {
  labels: string[]
  upload: number[]
  download: number[]
}) {
  return (
    <Line
      data={{
        labels,
        datasets: [
          {
            label: 'Download',
            data: download,
            borderColor: '#39FF6A',
            backgroundColor: 'rgba(57,255,106,0.12)',
            fill: true,
            tension: 0.35,
            pointRadius: 0,
            borderWidth: 2,
          },
          {
            label: 'Upload',
            data: upload,
            borderColor: '#3B9DFF',
            backgroundColor: 'rgba(59,157,255,0.08)',
            fill: true,
            tension: 0.35,
            pointRadius: 0,
            borderWidth: 2,
          },
        ],
      }}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: {
            position: 'top',
            align: 'end',
            labels: { color: tickColor, boxWidth: 10, boxHeight: 10, usePointStyle: true },
          },
        },
        scales: {
          x: { grid: { color: gridColor }, ticks: { color: tickColor, maxTicksLimit: 8 } },
          y: {
            grid: { color: gridColor },
            ticks: { color: tickColor, callback: (v) => `${v} Mb/s` },
          },
        },
      }}
    />
  )
}

const protocolColors = ['#3B9DFF', '#39FF6A', '#FFB020', '#A78BFA', '#64748b', '#FF3B4E']

export function ProtocolPieChart({
  data,
}: {
  data: { label: string; value: number }[]
}) {
  return (
    <Pie
      data={{
        labels: data.map((d) => d.label),
        datasets: [
          {
            data: data.map((d) => d.value),
            backgroundColor: protocolColors,
            borderColor: '#161B22',
            borderWidth: 2,
          },
        ],
      }}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: tickColor, boxWidth: 10, boxHeight: 10, usePointStyle: true },
          },
        },
      }}
    />
  )
}

export function TimelineChart({ labels, data }: { labels: string[]; data: number[] }) {
  return (
    <Line
      data={{
        labels,
        datasets: [
          {
            label: 'Packets/sec',
            data,
            borderColor: '#39FF6A',
            backgroundColor: 'rgba(57,255,106,0.1)',
            fill: true,
            tension: 0.3,
            pointRadius: 0,
            borderWidth: 2,
          },
        ],
      }}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: gridColor }, ticks: { color: tickColor, maxTicksLimit: 10 } },
          y: { grid: { color: gridColor }, ticks: { color: tickColor } },
        },
      }}
    />
  )
}

export function HealthGauge({ score }: { score: number }) {
  const radius = 70
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference
  const color = score >= 80 ? '#39FF6A' : score >= 50 ? '#FFB020' : '#FF3B4E'
  const label = score >= 80 ? 'SAFE' : score >= 50 ? 'WARNING' : 'HIGH RISK'

  return (
    <div className="relative flex items-center justify-center">
      <svg width="180" height="180" className="-rotate-90">
        <circle cx="90" cy="90" r={radius} stroke="#2A2F36" strokeWidth="12" fill="none" />
        <circle
          cx="90"
          cy="90"
          r={radius}
          stroke={color}
          strokeWidth="12"
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 8px ${color}88)`, transition: 'stroke-dashoffset 1s ease' }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-3xl font-bold font-mono text-slate-50">{score}</span>
        <span className="text-xs text-slate-500">/ 100</span>
        <span
          className="mt-2 text-xs font-semibold tracking-wider px-2.5 py-1 rounded-full border"
          style={{ color, borderColor: `${color}55`, backgroundColor: `${color}15` }}
        >
          {label}
        </span>
      </div>
    </div>
  )
}
