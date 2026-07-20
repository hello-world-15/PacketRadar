import { Routes, Route } from 'react-router-dom'
import Sidebar from '@/components/Sidebar'
import LiveMonitor from '@/pages/LiveMonitor'
import PcapAnalyzer from '@/pages/PcapAnalyzer'
import About from '@/pages/About'

export default function App() {
  return (
    <div className="min-h-screen bg-matte">
      <Sidebar />
      <main className="ml-60 min-h-screen px-6 py-6 max-w-[1600px]">
        <Routes>
          <Route path="/" element={<LiveMonitor />} />
          <Route path="/analyzer" element={<PcapAnalyzer />} />
          <Route path="/about" element={<About />} />
        </Routes>
      </main>
    </div>
  )
}
