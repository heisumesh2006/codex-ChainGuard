import { lazy } from 'react'
import { BrowserRouter, Link, Route, Routes } from 'react-router-dom'
import AppLayout from './layouts/AppLayout'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const Agents = lazy(() => import('./pages/Agents'))
const TrustGraph = lazy(() => import('./pages/TrustGraph'))
const Governance = lazy(() => import('./pages/Governance'))
const ThreatLab = lazy(() => import('./pages/ThreatLab'))
const Analytics = lazy(() => import('./pages/Analytics'))
const Revocation = lazy(() => import('./pages/Revocation'))
const Evaluation = lazy(() => import('./pages/Evaluation'))
const AuditExplorer = lazy(() => import('./pages/AuditExplorer'))

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="agents" element={<Agents />} />
          <Route path="trust-graph" element={<TrustGraph />} />
          <Route path="governance" element={<Governance />} />
          <Route path="threat-lab" element={<ThreatLab />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="revocation" element={<Revocation />} />
          <Route path="evaluation" element={<Evaluation />} />
          <Route path="blockchain-audit" element={<AuditExplorer />} />
          <Route path="*" element={<section className="panel" style={{ padding: 24 }}>
            <h1>Page not found</h1>
            <p>The requested page does not exist. Use the navigation or return to the dashboard.</p>
            <Link className="button-primary" to="/">Return to dashboard</Link>
          </section>} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
