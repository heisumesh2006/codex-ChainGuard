import { ArrowLeft, ArrowRight, Play, X } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'

export const presentationSteps = [
  { title: 'Problem', path: '/evaluation#problem', detail: 'Autonomous agents need accountable authority.' },
  { title: 'Architecture', path: '/evaluation#architecture', detail: 'Six modules form one decision pipeline.' },
  { title: 'Agent delegation graph', path: '/trust-graph', detail: 'Rooted credentials and verified delegation hops.' },
  { title: 'Normal action', path: '/governance?scenario=normal', detail: 'A clean action passes the governance pipeline.' },
  { title: 'Self escalation', path: '/governance?scenario=self_escalation', detail: 'An agent cannot create its own root authority.' },
  { title: 'Unauthorized delegation', path: '/governance?scenario=unauthorized_delegation', detail: 'Delegation requires authority the source agent actually holds.' },
  { title: 'Scope creep', path: '/governance?scenario=scope_creep', detail: 'Valid authority with abnormal behavior prompts review.' },
  { title: 'Revocation attack', path: '/governance?scenario=post_decommission', detail: 'An action after revocation is blocked.' },
  { title: 'Blockchain proof', path: '/revocation', detail: 'A cold public verifier checks Ethereum state.' },
  { title: 'Final metrics', path: '/evaluation#metrics', detail: 'Measured coverage, latency, and model limitations.' },
]

export default function PresentationBar({ step, setStep, exit }) {
  const navigate = useNavigate()
  const go = (index) => { const next = Math.max(0, Math.min(presentationSteps.length - 1, index)); setStep(next); navigate(presentationSteps[next].path) }
  return <div className="presentation-bar"><div className="presentation-bar__intro"><span>CHAINGUARD-AI · FINAL-YEAR PROJECT DEMO</span><strong>{String(step + 1).padStart(2, '0')} / {String(presentationSteps.length).padStart(2, '0')} · {presentationSteps[step].title}</strong><small>{presentationSteps[step].detail}</small></div><div className="presentation-bar__progress">{presentationSteps.map((item, index) => <button key={item.title} aria-label={`Go to ${item.title}`} title={item.title} className={index === step ? 'is-active' : ''} onClick={() => go(index)} />)}</div><div className="presentation-bar__actions"><Link to="/governance?auto=1" className="button-primary"><Play size={14} /> Auto Demo</Link><button onClick={() => go(step - 1)} disabled={step === 0}><ArrowLeft size={15} /> Back</button><button onClick={() => go(step + 1)} disabled={step === presentationSteps.length - 1}>Next <ArrowRight size={15} /></button><button onClick={exit} aria-label="Exit presentation mode"><X size={17} /></button></div></div>
}
