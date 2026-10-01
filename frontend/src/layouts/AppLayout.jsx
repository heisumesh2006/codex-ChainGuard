import { motion } from 'framer-motion'
import { Blocks, CircleDot, Menu, Presentation, RefreshCw, Shield, ShieldCheck, X } from 'lucide-react'
import { Suspense, useCallback, useLayoutEffect, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import PresentationBar, { presentationSteps } from '../components/PresentationBar'
import StatusPill from '../components/StatusPill'
import { navigation } from '../data/navigation'
import { useSystemData } from '../hooks/useSystemData'

export default function AppLayout() {
  const location = useLocation()
  const navigate = useNavigate()
  useLayoutEffect(() => {
    if (!location.hash) {
      window.scrollTo(0, 0)
      return undefined
    }
    const id = decodeURIComponent(location.hash.slice(1))
    const scrollToSection = () => {
      const target = document.getElementById(id)
      if (target) target.scrollIntoView({ block: 'start' })
      return Boolean(target)
    }
    if (scrollToSection()) return undefined
    window.scrollTo(0, 0)
    const observer = new MutationObserver(() => { if (scrollToSection()) observer.disconnect() })
    observer.observe(document.querySelector('.page-content'), { childList: true, subtree: true })
    return () => observer.disconnect()
  }, [location.pathname, location.hash])
  const [menuOpen, setMenuOpen] = useState(false)
  const [presentation, setPresentation] = useState(() => window.localStorage.getItem('chainguard-presentation') === '1')
  const [presentationStep, setPresentationStep] = useState(() => Math.max(0, presentationSteps.findIndex((item) => item.path === `${window.location.pathname}${window.location.search}${window.location.hash}`)))
  useLayoutEffect(() => {
    if (!presentation) return
    const index = presentationSteps.findIndex((item) => item.path === `${location.pathname}${location.search}${location.hash}`)
    if (index >= 0) setPresentationStep(index)
  }, [location.pathname, location.search, location.hash, presentation])
  const setPresentationScenario = useCallback((scenario) => {
    const index = presentationSteps.findIndex((item) => item.path === `/governance?scenario=${scenario}`)
    if (index >= 0) setPresentationStep(index)
  }, [])
  const { health, overview, metrics, error, loading, retry } = useSystemData()
  const current = navigation.find((item) => item.to === location.pathname) || navigation[0]
  const connected = Boolean(health?.rpc_connected && health?.contract_available)
  const shortAddress = health?.contract_address
    ? `${health.contract_address.slice(0, 6)}…${health.contract_address.slice(-4)}`
    : '—'
  const togglePresentation = () => {
    const next = !presentation
    setPresentation(next)
    window.localStorage.setItem('chainguard-presentation', next ? '1' : '0')
    if (next) {
      setPresentationStep(0)
      navigate('/evaluation#problem')
    }
  }

  return (
    <div className={`app-shell ${presentation ? 'app-shell--present' : ''}`}>
      <div className="ambient-grid" aria-hidden="true" />
      <button className="mobile-menu" onClick={() => setMenuOpen(true)} aria-label="Open navigation"><Menu size={20} /></button>
      {menuOpen && <button className="sidebar-scrim" onClick={() => setMenuOpen(false)} aria-label="Close navigation" />}
      <aside className={`sidebar ${menuOpen ? 'sidebar--open' : ''}`}>
        <div className="sidebar__header">
          <div className="brand-mark"><Shield size={23} strokeWidth={1.8} /><span className="brand-mark__spark" /></div>
          <div><div className="brand-title">ChainGuard<span>-AI</span></div><div className="brand-caption">TRUST OPERATIONS</div></div>
          <button className="sidebar-close" onClick={() => setMenuOpen(false)} aria-label="Close navigation"><X size={18} /></button>
        </div>
        <div className="sidebar__section-label">WORKSPACE</div>
        <nav className="sidebar__nav" aria-label="Primary navigation">
          {navigation.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to === '/'} onClick={() => setMenuOpen(false)}
              className={({ isActive }) => `nav-link ${isActive ? 'nav-link--active' : ''}`}>
              <Icon size={18} strokeWidth={1.8} /><span>{label}</span>
              {to === '/governance' && <span className="nav-link__signal" />}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar__bottom">
          <div className="network-card">
            <div className="network-card__label"><CircleDot size={14} /> NETWORK STATUS</div>
            <div className="network-card__status"><span className={`network-light ${connected ? 'network-light--on' : ''}`} />{connected ? 'Blockchain connected' : 'Blockchain offline'}</div>
            <div className="network-card__row"><span>Network</span><strong>Hardhat Local</strong></div>
            <div className="network-card__row"><span>Chain ID</span><strong>{health?.chain_id ?? '—'}</strong></div>
            <div className="network-card__row"><span>API</span><strong>{health?.api_online ? 'Online' : 'Offline'}</strong></div>
          </div>
          <div className="sidebar__footer">PROTOTYPE ENVIRONMENT <span>v1.0</span></div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div className="topbar__location"><span>CHAIN GUARD</span><span className="topbar__slash">/</span><strong>{current.label}</strong></div>
          <div className="topbar__right">
            <button className="presentation-toggle" onClick={togglePresentation}><Presentation size={16} /> {presentation ? 'Exit presentation' : 'Presentation Mode'}</button>
            <StatusPill label={health?.status === 'ONLINE' ? 'System Online' : loading ? 'Checking system' : 'System Offline'} tone={health?.status === 'ONLINE' ? 'emerald' : 'red'} pulse={health?.status === 'ONLINE'} />
            <span className="topbar__network"><Blocks size={15} /> Hardhat Local</span>
            <span className="topbar__contract">{shortAddress}</span>
          </div>
        </header>
        {presentation && <PresentationBar step={presentationStep} setStep={setPresentationStep} exit={() => { setPresentation(false); window.localStorage.setItem('chainguard-presentation', '0') }} />}
        {!loading && (!health || !health.rpc_connected || !health.contract_available || !health.ml_model_available || error) && <div className="system-alert"><Shield size={17} /><div><strong>{!health ? 'API OFFLINE' : !health.rpc_connected ? 'BLOCKCHAIN OFFLINE' : !health.contract_available ? 'REGISTRY CONTRACT UNAVAILABLE' : !health.ml_model_available ? 'ML MODEL UNAVAILABLE' : 'SYSTEM DATA UNAVAILABLE'}</strong><span>{error || health?.error || 'Check the service and retry the connection.'}</span></div><button onClick={retry}><RefreshCw size={15} /> Retry</button></div>}
        <main className="page-content">
          <motion.div key={location.pathname} initial={{ opacity: 0, y: 9 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.28 }}>
            <Suspense fallback={<div className="panel route-loading">Loading security workspace…</div>}><Outlet context={{ health, overview, metrics, error, loading, connected, retry, presentation, setPresentationScenario }} /></Suspense>
          </motion.div>
        </main>
        <footer className="workspace-footer"><span><ShieldCheck size={14} /> ChainGuard-AI · Verifiable agent governance</span><span>Local evaluation environment</span></footer>
      </div>
    </div>
  )
}
