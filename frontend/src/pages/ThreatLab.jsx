import { AnimatePresence, motion } from 'framer-motion'
import { ArrowRight, CirclePlay, Fingerprint, FlaskConical, ShieldAlert, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import DecisionBadge from '../components/DecisionBadge'
import Skeleton from '../components/Skeleton'
import { scenarios } from '../data/scenarios'
import { api } from '../services/api'

const reportCode = {
  normal: 'NORMAL', self_escalation: 'SELF_ESCALATION',
  unauthorized_delegation: 'UNAUTHORIZED_DELEGATION',
  post_decommission: 'POST_DECOMMISSION_ACTIVITY', scope_creep: 'SCOPE_CREEP',
}

export default function ThreatLab() {
  const navigate = useNavigate()
  const [report, setReport] = useState(null)
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => { let active = true; api.finalReport().then((data) => { if (active) setReport(data) }).catch((cause) => { if (active) setError(cause.message) }); return () => { active = false } }, [])
  return <div className="threat-page"><div className="eyebrow"><span className="eyebrow__line" /> SECURITY EXERCISE ENVIRONMENT</div><div className="page-heading"><div><h1>Threat Lab</h1><p>Replay real saved actions and held-out anomalies through the existing governance pipeline.</p></div><span className="page-heading__count">5 deterministic scenarios</span></div>
    <section className="panel threat-hero"><div className="threat-hero__icon"><FlaskConical size={30} /></div><div><span className="section-heading__overline">FACULTY DEMONSTRATION MODE</span><h2>See the defense layers work together.</h2><p>Auto Demo runs all five scenarios in sequence. Backend evaluation stays at full speed; the UI replays measured stages for presentation.</p></div><button className="button-primary" onClick={() => navigate('/governance?auto=1')}><CirclePlay size={18} /> Start auto demo <ArrowRight size={16} /></button></section>
    {error && <div className="error-banner">{error}</div>}
    <div className="section-heading"><div><span className="section-heading__overline">SAVED MODULE SCENARIOS</span><h2>Choose an exercise</h2></div><span className="section-heading__note">No simulated verdicts</span></div>
    <div className="threat-grid">{scenarios.map((item, index) => { const row = report?.scenarios?.find((scenario) => scenario.scenario === reportCode[item.id]); return <motion.button key={item.id} className={`panel threat-card threat-card--${item.tone}`} onClick={() => setSelected(item)} initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * .06 }} whileHover={{ y: -4 }}><div className="threat-card__top"><span className="threat-card__number">0{index + 1}</span><ShieldAlert size={21} /></div><span className="section-heading__overline">{item.eyebrow}</span><h3>{item.title}</h3><p>{item.description}</p><div className="threat-card__foot"><span>{item.actor}</span>{row ? <DecisionBadge decision={row.final_decision} compact /> : <Skeleton style={{ width: 55, height: 20 }} />}</div></motion.button> })}</div>
    <div className="threat-note"><Fingerprint size={17} /><span>Exercises reuse saved Module 1 / Module 4 scenario data. All proof and decision fields come from Modules 2–6.</span></div>
    <AnimatePresence>{selected && <motion.div className="scenario-modal__backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setSelected(null)}><motion.div role="dialog" aria-modal="true" aria-labelledby="scenario-title" className="scenario-modal panel" initial={{ opacity: 0, scale: .96, y: 12 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: .96 }} onClick={(event) => event.stopPropagation()}><button className="scenario-modal__close" onClick={() => setSelected(null)} aria-label="Close"><X size={18} /></button><span className="section-heading__overline">RUN SAVED SCENARIO</span><h2 id="scenario-title">{selected.title}</h2><p>{selected.description}</p><div className="scenario-modal__actor">Actor <strong>{selected.actor}</strong></div><div className="scenario-modal__actions"><button className="button-secondary" onClick={() => setSelected(null)}>Cancel</button><button className="button-primary" onClick={() => navigate(`/governance?scenario=${selected.id}`)}>Open live pipeline <ArrowRight size={16} /></button></div></motion.div></motion.div>}</AnimatePresence>
  </div>
}
