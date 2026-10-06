import { AnimatePresence, motion } from 'framer-motion'
import { Activity, ArrowRight, CheckCircle2, Cpu, Fingerprint, GitBranch, LockKeyhole, Pause, Play, RotateCcw, ShieldCheck, ShieldX, SkipForward } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useOutletContext, useSearchParams } from 'react-router-dom'
import DecisionBadge from '../components/DecisionBadge'
import StatusPill from '../components/StatusPill'
import { autoDemoOrder, scenarioById, scenarios } from '../data/scenarios'
import { useGovernanceStream } from '../hooks/useGovernanceStream'

const steps = [
  { key: 'ACTION', title: 'Agent action', icon: Activity },
  { key: 'AUTHORIZATION', title: 'Authorization', icon: ShieldCheck },
  { key: 'TRACE', title: 'Delegation trace', icon: GitBranch },
  { key: 'DRIFT_SCORING', title: 'AI drift', icon: Cpu },
  { key: 'REVOCATION_CHECK', title: 'Revocation', icon: LockKeyhole },
  { key: 'BLOCKCHAIN_VERIFY', title: 'Blockchain', icon: Fingerprint },
  { key: 'VERDICT', title: 'Verdict', icon: CheckCircle2 },
]
const short = (value) => value ? `${value.slice(0, 10)}…${value.slice(-6)}` : '—'
const time = (value) => new Date(value).toLocaleTimeString([], { hour12: false })
const ms = (value) => value == null ? '—' : `${Number(value).toFixed(2)} ms`

function stageStatus(key, event, active) {
  if (!event) return active ? 'RUNNING' : 'PENDING'
  if (key === 'ACTION') return 'RECEIVED'
  if (key === 'VERDICT') return ms(event.total_latency_ms)
  return ms(event.latency_ms)
}

function stageDetail(key, event) {
  if (!event) return 'Waiting for evidence'
  if (key === 'ACTION') return `${event.actor} · ${event.action?.replaceAll('_', ' ')}`
  if (key === 'AUTHORIZATION') return event.authorized ? 'ALLOWED' : 'DENIED'
  if (key === 'TRACE') return `${event.trace_verdict}${event.chain_depth == null ? '' : ` · ${event.chain_depth} hop${event.chain_depth === 1 ? '' : 's'}`}`
  if (key === 'DRIFT_SCORING') return event.applicable ? `${event.drift_flagged ? 'FLAGGED' : 'NORMAL'} · ${event.drift_score?.toFixed(3) ?? '—'}` : 'Not applicable'
  if (key === 'REVOCATION_CHECK') return `${event.revoked ? 'REVOKED' : 'ACTIVE'}${event.proof_available ? ' · proof' : ''}`
  if (key === 'BLOCKCHAIN_VERIFY') return event.chain_verified ? event.proof_status.replaceAll('_', ' ') : 'PROOF FAILED'
  return event.decision
}

function storyFor(event) {
  switch (event.event) {
    case 'AUTHORIZATION_COMPLETE': return `Module 1 ${event.authorized ? 'allowed' : 'denied'} the action.`
    case 'TRACE_COMPLETE': return `Module 3 returned ${event.trace_verdict}${event.chain_depth == null ? '' : ` across ${event.chain_depth} verified hop${event.chain_depth === 1 ? '' : 's'}`}.`
    case 'DRIFT_SCORING_COMPLETE': return !event.applicable ? 'Module 4 skipped this administrative actor.' : `Module 4 ${event.drift_flagged ? 'flagged unusual behavior' : 'found no significant drift'} (score ${event.drift_score?.toFixed(3) ?? '—'}).`
    case 'REVOCATION_CHECK_COMPLETE': return `Module 5 found the actor ${event.revoked ? 'revoked' : 'active'}${event.proof_available ? ' with public proof' : ''}.`
    case 'BLOCKCHAIN_VERIFY_COMPLETE': return `Module 2 ${event.chain_verified ? 'verified the required blockchain evidence' : 'could not verify required evidence'}.`
    case 'VERDICT_COMPLETE': return `Final governance decision: ${event.decision}.`
    default: return null
  }
}

export default function Governance() {
  const [searchParams] = useSearchParams()
  const { health, setPresentationScenario } = useOutletContext()
  const requested = searchParams.get('scenario')
  const autoRequested = searchParams.get('auto') === '1'
  const { events, verdict, connection, error, start } = useGovernanceStream()
  const [scenario, setScenario] = useState(null)
  const [visibleCount, setVisibleCount] = useState(0)
  const [autoMode, setAutoMode] = useState(false)
  const [autoIndex, setAutoIndex] = useState(0)
  const [paused, setPaused] = useState(false)
  useEffect(() => { if (scenario) setPresentationScenario(scenario) }, [scenario, setPresentationScenario])

  const run = useCallback((name) => { setScenario(name); setVisibleCount(0); start(name) }, [start])
  useEffect(() => { if (autoRequested) { setAutoMode(true); setAutoIndex(0); setPaused(false); run(autoDemoOrder[0]) } else if (requested && scenarioById[requested]) { setAutoMode(false); run(requested) } }, [requested, autoRequested, run])
  useEffect(() => {
    if (paused || visibleCount >= events.length) return undefined
    const timer = window.setTimeout(() => setVisibleCount((count) => count + 1), autoMode ? 550 : 360)
    return () => window.clearTimeout(timer)
  }, [events.length, visibleCount, paused, autoMode])
  useEffect(() => {
    if (!autoMode || paused || !verdict || visibleCount < events.length || !events.length) return undefined
    const timer = window.setTimeout(() => {
      if (autoIndex === autoDemoOrder.length - 1) { setAutoMode(false); return }
      const next = autoIndex + 1
      setAutoIndex(next)
      run(autoDemoOrder[next])
    }, 1200)
    return () => window.clearTimeout(timer)
  }, [autoMode, paused, verdict, visibleCount, events.length, autoIndex, run])

  const beginAuto = () => { setAutoMode(true); setPaused(false); setAutoIndex(0); run(autoDemoOrder[0]) }
  const next = () => { const index = Math.min(autoIndex + 1, autoDemoOrder.length - 1); setAutoIndex(index); setPaused(false); run(autoDemoOrder[index]) }
  const visible = events.slice(0, visibleCount)
  const complete = (key) => visible.findLast((event) => event.event === (key === 'ACTION' ? 'ACTION_RECEIVED' : key === 'VERDICT' ? 'VERDICT_COMPLETE' : `${key}_COMPLETE`))
  const started = (key) => visible.some((event) => event.event === `${key}_STARTED`)
  const completedVerdict = complete('VERDICT')?.verdict
  const story = useMemo(() => visible.map(storyFor).filter(Boolean), [visible])
  const chainRef = complete('BLOCKCHAIN_VERIFY')?.reference

  return <div className="governance-page"><div className="eyebrow"><span className="eyebrow__line" /> LIVE GOVERNANCE MONITOR</div><div className="page-heading"><div><h1>Decision Pipeline</h1><p>Each stage displays measured output from the existing Modules 1–6.</p></div><StatusPill label={connection === 'RUNNING' ? 'PROCESSING' : connection === 'COMPLETE' ? 'PIPELINE COMPLETE' : 'READY'} tone={connection === 'ERROR' ? 'red' : 'cyan'} pulse={connection === 'RUNNING'} /></div>
    <div className="governance-toolbar panel"><div className="governance-toolbar__scenarios">{scenarios.map((item) => <button key={item.id} className={scenario === item.id ? 'is-active' : ''} onClick={() => { setAutoMode(false); setPaused(false); run(item.id) }}>{item.title}</button>)}</div><div className="governance-toolbar__demo"><button className="button-primary" onClick={beginAuto}><Play size={15} /> Auto demo</button>{autoMode && <><button onClick={() => setPaused((value) => !value)}>{paused ? <Play size={15} /> : <Pause size={15} />}{paused ? 'Resume' : 'Pause'}</button><button onClick={next}><SkipForward size={15} /> Next</button><button onClick={beginAuto}><RotateCcw size={15} /> Restart</button></>}</div></div>
    {error && <div className="error-banner">{error}</div>}
    <div className="governance-layout"><div className="governance-main"><section className="panel governance-stage-panel"><div className="panel__head"><div><span className="section-heading__overline">MEASURED STAGE REPLAY</span><h3>{scenario ? scenarioById[scenario]?.title : 'Select a scenario to begin'}</h3></div><span className="governance-stage-panel__network"><span className="network-light network-light--on" /> Ethereum evidence</span></div><div className="governance-stages">{steps.map(({ key, title, icon: Icon }, index) => { const event = complete(key); const active = !event && started(key); const tone = key === 'VERDICT' ? event?.decision?.toLowerCase() : key === 'AUTHORIZATION' && event && !event.authorized ? 'block' : key === 'DRIFT_SCORING' && event?.drift_flagged ? 'review' : key === 'REVOCATION_CHECK' && event?.revoked ? 'block' : event ? 'verified' : active ? 'active' : 'idle'; return <motion.div key={key} className={`governance-stage governance-stage--${tone}`} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * .04 }}><span className="governance-stage__icon"><Icon size={21} /></span><div className="governance-stage__text"><span>{String(index + 1).padStart(2, '0')} / {title}</span><strong>{stageDetail(key, event)}</strong></div><div className="governance-stage__right"><span>{stageStatus(key, event, active)}</span>{event && <CheckCircle2 size={15} />}</div></motion.div> })}</div><p className="governance-stage-panel__foot">{health?.chain_id === 11155111 ? 'Replay of saved Sepolia decisions. Pipeline timings were not recorded.' : <>Stage timings are from <code>time.perf_counter()</code>.</>} Animation happens only in this frontend.</p></section>
      <section className="panel governance-story"><span className="section-heading__overline">SCENARIO STORY</span><h3>{scenario ? scenarioById[scenario]?.description : 'Choose a saved scenario to inspect the decision path.'}</h3><div className="governance-story__steps">{story.map((line, index) => <motion.p key={`${scenario}-${index}`} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }}><span>{String(index + 1).padStart(2, '0')}</span>{line}</motion.p>)}</div></section>
      <AnimatePresence mode="wait">{completedVerdict && <motion.section key={`${scenario}-${completedVerdict.governance_decision}`} className={`panel verdict-visual verdict-visual--${completedVerdict.governance_decision.toLowerCase()}`} initial={{ opacity: 0, scale: .97 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }}><div className="verdict-visual__icon">{completedVerdict.governance_decision === 'BLOCK' ? <ShieldX size={35} /> : completedVerdict.governance_decision === 'REVIEW' ? <ScanIcon /> : <ShieldCheck size={35} />}</div><div><span>FINAL GOVERNANCE VERDICT</span><h2>{completedVerdict.governance_decision}</h2><p>{completedVerdict.reasons.join(' · ')}</p></div><strong>{ms(completedVerdict.total_latency_ms)}</strong></motion.section>}</AnimatePresence>
      {chainRef && <div className="governance-proof-line"><Fingerprint size={15} /> Chain reference <span className="mono" title={chainRef.transaction_hash}>{short(chainRef.transaction_hash)}</span> <span>Block {chainRef.block_number ?? '—'}</span></div>}
    </div><aside className="panel governance-timeline"><div className="panel__head"><div><span className="section-heading__overline">EVENT STREAM</span><h3>Security timeline</h3></div><Activity size={17} className="panel__accent-icon" /></div><div className="governance-timeline__list">{visible.length ? visible.map((event, index) => <div className={`timeline-event ${event.event === 'VERDICT_COMPLETE' ? `timeline-event--${event.decision?.toLowerCase()}` : ''}`} key={`${scenario}-${index}`}><time>{time(event.received_at)}</time><span className="timeline-event__dot" /><div><strong>{event.event.replaceAll('_', ' ')}</strong><p>{storyFor(event) || event.status}{event.latency_ms == null ? '' : ` · ${ms(event.latency_ms)}`}</p></div></div>) : <div className="governance-timeline__empty">Select a scenario or start Auto Demo to receive measured events.</div>}</div></aside></div>
  </div>
}

function ScanIcon() { return <Cpu size={35} /> }
