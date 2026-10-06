import { motion } from 'framer-motion'
import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Activity, ArrowRight, Blocks, CheckCircle2, Cpu, Fingerprint, GitBranch, LockKeyhole, Radar, ScanSearch, ShieldCheck, ShieldX } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import AnimatedNumber from '../components/AnimatedNumber'
import DecisionBadge from '../components/DecisionBadge'
import MetricCard from '../components/MetricCard'
import Skeleton from '../components/Skeleton'
import StatusPill from '../components/StatusPill'
import { api } from '../services/api'

const stages = [
  { label: 'Agent action', icon: Activity }, { label: 'Authorization', icon: ShieldCheck },
  { label: 'Delegation trace', icon: GitBranch }, { label: 'AI drift detection', icon: Cpu },
  { label: 'Revocation check', icon: LockKeyhole }, { label: 'Blockchain proof', icon: Fingerprint },
  { label: 'Governance verdict', icon: CheckCircle2 },
]
const stageNames = {
  authorization_ms: 'Authorization', trace_context_ms: 'Trace', drift_scoring_ms: 'AI drift',
  revocation_check_ms: 'Revocation', chain_verification_ms: 'Blockchain', verdict_assembly_ms: 'Verdict',
}
const categoryNames = {
  SELF_ESCALATION: 'Self escalation', UNAUTHORIZED_DELEGATION: 'Unauthorized delegation',
  POST_DECOMMISSION_ACTIVITY: 'Post revocation', SCOPE_CREEP: 'Scope creep',
}
const tooltipStyle = { background: '#101a2d', border: '1px solid #294061', borderRadius: 10, color: '#edf5ff', fontSize: 11 }
const short = (value, front = 6, end = 4) => value ? `${value.slice(0, front)}…${value.slice(-end)}` : '—'
const ms = (value) => value == null ? '—' : `${Number(value).toFixed(1)} ms`

export default function Dashboard() {
  const { health, overview, metrics, error, loading, connected } = useOutletContext()
  const [detail, setDetail] = useState({ agents: null, graph: null, report: null, revocation: null, error: null })
  useEffect(() => {
    let active = true
    Promise.all([api.agents(), api.graph(), api.finalReport(), api.revocation('Agent_C')])
      .then(([agents, graph, report, revocation]) => { if (active) setDetail({ agents, graph, report, revocation, error: null }) })
      .catch((cause) => { if (active) setDetail((before) => ({ ...before, error: cause.message })) })
    return () => { active = false }
  }, [])

  const cards = [
    { label: 'Registered agents', value: overview?.registered_agents, detail: 'Autonomous identities', icon: Blocks },
    { label: 'Credentials issued', value: overview?.credentials, detail: 'Scope-bound on Ethereum', icon: Fingerprint },
    { label: 'Delegations anchored', value: overview?.delegations, detail: 'Verified trust hops', icon: GitBranch },
    { label: 'Revocations', value: overview?.revocations, detail: 'Public chain proof', icon: LockKeyhole, tone: 'red' },
    { label: 'Action proofs', value: overview?.anchored_actions, detail: 'Tamper-evident commitments', icon: ScanSearch },
    { label: 'Attack coverage', value: overview ? overview.attack_coverage * 100 : null, detail: 'Integrated evaluation', icon: ShieldCheck, tone: 'emerald', suffix: '%' },
  ]
  const latencyData = useMemo(() => Object.entries(metrics?.module6?.latency?.average_ms || {}).map(([key, value]) => ({ name: stageNames[key], average: +value.toFixed(2), worst: +metrics.module6.latency.worst_case_ms[key].toFixed(2) })), [metrics])
  const modelData = useMemo(() => ['precision', 'recall', 'f1', 'false_positive_rate'].map((key) => ({ name: key === 'false_positive_rate' ? 'FPR' : key.toUpperCase(), isolation: (metrics?.module4?.isolation_forest?.[key] || 0) * 100, rules: (metrics?.module4?.rule_baseline?.[key] || 0) * 100 })), [metrics])
  const recallData = useMemo(() => Object.entries(metrics?.module4?.isolation_forest?.per_category || {}).map(([key, value]) => ({ name: categoryNames[key], recall: value.recall * 100 })), [metrics])
  const attackRows = detail.report?.layer_by_layer_attack_detection || []
  const detected = attackRows.filter((row) => row.detected_by?.length).length
  const coverageData = [{ name: 'Detected', value: detected }, { name: 'Missed', value: attackRows.length - detected }]
  const recent = useMemo(() => ['BLOCK', 'REVIEW', 'ALLOW'].flatMap((decision) => (detail.report?.scenarios || []).filter((row) => row.final_decision === decision).slice(-2).reverse()), [detail.report])
  const authority = (agent) => {
    if (agent.agent_id === 'Agent_C' && detail.revocation?.is_revoked) return 'Revoked on Ethereum'
    const incoming = detail.graph?.edges?.filter((edge) => edge.to === agent.agent_id) || []
    if (!incoming.length) return 'Checking proof…'
    if (incoming.every((edge) => edge.proof_status === 'PASS')) return incoming.some((edge) => edge.evidence_type === 'DELEGATION') ? 'Rooted delegation verified' : 'Root credential verified'
    return 'Proof needs review'
  }

  return <div className="dashboard dashboard-v2">
    <div className="eyebrow"><span className="eyebrow__line" /> SECURITY OPERATIONS <span className="eyebrow__time">{health?.chain_id === 11155111 ? 'PUBLIC SEPOLIA REGISTRY' : 'CANONICAL REGISTRY'}</span></div>
    <section className="hero-panel dashboard-hero"><div className="hero-panel__glow" aria-hidden="true" /><div className="hero-panel__content">
      <div className="hero-panel__eyebrow"><Radar size={15} /> AUTONOMOUS AGENT INFRASTRUCTURE</div>
      <h1>CHAIN GUARD <span>AI</span></h1><h2>Autonomous Agent Trust &amp; Governance Infrastructure</h2>
      <p>Blockchain-Anchored Delegation <span>•</span> AI Drift Detection <span>•</span> Verifiable Revocation</p>
      <div className="dashboard-hero__status"><StatusPill label={health?.status === 'ONLINE' ? 'SYSTEM ONLINE' : 'SYSTEM OFFLINE'} tone={connected ? 'emerald' : 'red'} pulse={connected} /><span>{health?.network_name || 'Checking network'}</span><span className="dashboard-hero__divider" /><span>Chain ID <strong>{health?.chain_id ?? '—'}</strong></span></div>
      <div className="hero-panel__actions"><Link className="button-primary" to="/governance">Launch live governance <ArrowRight size={17} /></Link><Link className="button-secondary" to="/trust-graph">Explore trust graph</Link></div>
    </div><div className="hero-panel__right"><div className="orbit-visual" aria-hidden="true"><div className="orbit-visual__ring orbit-visual__ring--one" /><div className="orbit-visual__ring orbit-visual__ring--two" /><div className="orbit-visual__core"><ShieldCheck size={38} strokeWidth={1.3} /></div><span className="orbit-visual__node orbit-visual__node--a" /><span className="orbit-visual__node orbit-visual__node--b" /><span className="orbit-visual__node orbit-visual__node--c" /></div><div className="hero-panel__proof"><span className={`network-light ${connected ? 'network-light--on' : ''}`} /> {connected ? `Registry ${short(health?.contract_address)}` : 'Registry connection unavailable'}</div></div></section>

    {(error || detail.error) && <div className="error-banner">Live data issue: {error || detail.error}</div>}
    <div className="section-heading"><div><span className="section-heading__overline">CHAIN-BACKED INVENTORY</span><h2>System at a glance</h2></div><span className="section-heading__note">{loading ? 'Loading verified metrics…' : 'From existing API and final report'}</span></div>
    <section className="metric-grid metric-grid--six">{cards.map((card, index) => loading ? <Skeleton key={card.label} className="metric-card" /> : <MetricCard key={card.label} {...card} index={index} />)}</section>

    <div className="section-heading"><div><span className="section-heading__overline">DECISION ARCHITECTURE</span><h2>Live governance flow</h2></div><Link className="text-link" to="/governance">Open interactive pipeline <ArrowRight size={15} /></Link></div>
    <section className="panel flow-panel"><div className="flow-panel__track"><span className="flow-panel__pulse" />{stages.map(({ label, icon: Icon }, index) => <motion.div key={label} className={`flow-stage ${index === 5 && connected ? 'flow-stage--verified' : ''}`} whileHover={{ y: -4 }} transition={{ duration: 0.18 }}><span className="flow-stage__number">0{index + 1}</span><span className="flow-stage__icon"><Icon size={22} strokeWidth={1.6} /></span><strong>{label}</strong></motion.div>)}</div><div className="flow-panel__foot"><span><span className="network-light network-light--on" /> Evidence anchored on Ethereum</span><span>Decision classes <b className="tone-allow">ALLOW</b> / <b className="tone-review">REVIEW</b> / <b className="tone-block">BLOCK</b></span></div></section>

    <div className="section-heading"><div><span className="section-heading__overline">IDENTITY POSTURE</span><h2>Agent security status</h2></div><Link className="text-link" to="/agents">View all agent details <ArrowRight size={15} /></Link></div>
    <section className="dashboard-agent-grid">{detail.agents ? detail.agents.map((agent) => { const revoked = agent.agent_id === 'Agent_C' && detail.revocation?.is_revoked; return <article className={`panel dashboard-agent ${revoked ? 'dashboard-agent--revoked' : ''}`} key={agent.agent_id}><div className="dashboard-agent__head"><div className="dashboard-agent__avatar">{agent.agent_id.slice(-1)}</div><StatusPill label={revoked ? 'REVOKED' : agent.status} tone={revoked ? 'red' : 'emerald'} /></div><h3>{agent.agent_id}</h3><p>{agent.role}</p><div className="dashboard-agent__line"><span>Effective scope</span><strong>{agent.effective_permissions.length ? agent.effective_permissions.join(', ') : 'None'}</strong></div><div className="dashboard-agent__line"><span>Authority</span><strong className={revoked ? 'tone-block' : 'tone-allow'}>{authority(agent)}</strong></div><div className="dashboard-agent__address mono">{short(agent.blockchain_address, 10, 8)}</div></article> }) : Array.from({ length: 4 }, (_, index) => <Skeleton key={index} className="dashboard-agent panel" />)}</section>

    <div className="dashboard-decision-grid"><section className="panel decision-ledger"><div className="panel__head"><div><span className="section-heading__overline">SAVED GOVERNANCE RUN</span><h3>Recent decisions by outcome</h3></div><Link className="text-link" to="/evaluation">Full report <ArrowRight size={14} /></Link></div><div className="decision-ledger__head"><span>Agent / action</span><span>Trace</span><span>Drift</span><span>Decision</span><span>Latency</span></div>{detail.report ? recent.map((row, index) => <div className="decision-ledger__row" key={`${row.record_id}-${index}`}><span><strong>{row.actor}</strong><small>{row.scenario.replaceAll('_', ' ')}</small></span><span className="mono">{row.trace_verdict}</span><span>{row.drift_score == null ? 'N/A' : row.drift_score.toFixed(3)}</span><span><DecisionBadge decision={row.final_decision} compact /></span><span>{ms(row.resolution_time_ms)}</span></div>) : Array.from({ length: 5 }, (_, index) => <Skeleton key={index} style={{ height: 48, marginTop: 6 }} />)}</section>
    <section className="panel coverage-summary"><div className="panel__head"><div><span className="section-heading__overline">INTEGRATED DEFENSE</span><h3>Attack / anomaly coverage</h3></div><ShieldX size={18} className="tone-block" /></div><div className="coverage-summary__chart"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={coverageData} dataKey="value" innerRadius={65} outerRadius={83} stroke="none" startAngle={90} endAngle={-270}>{coverageData.map((entry) => <Cell key={entry.name} fill={entry.name === 'Detected' ? '#44d8b0' : '#ef7483'} />)}</Pie><Tooltip contentStyle={tooltipStyle} /></PieChart></ResponsiveContainer><div className="coverage-summary__center"><strong><AnimatedNumber value={overview ? overview.attack_coverage * 100 : null} suffix="%" /></strong><span>coverage</span></div></div><div className="coverage-summary__note">{detected || '—'} of {attackRows.length || '—'} saved attack/anomaly scenarios detected by at least one layer.</div></section></div>

    <div className="section-heading"><div><span className="section-heading__overline">MEASURED PERFORMANCE</span><h2>Evidence in numbers</h2></div><span className="section-heading__note">No simulated dashboard metrics</span></div>
    <section className="dashboard-chart-grid">
      <div className="panel chart-panel"><div className="panel__head"><div><span className="section-heading__overline">END-TO-END PIPELINE</span><h3>Latency by stage</h3></div><span className="chart-panel__unit">ms</span></div><div className="chart-panel__body"><ResponsiveContainer width="100%" height="100%"><BarChart data={latencyData} margin={{ top: 8, right: 8, left: -20, bottom: 5 }}><CartesianGrid vertical={false} stroke="#263b55" strokeDasharray="3 6" /><XAxis dataKey="name" tick={{ fill: '#829bb2', fontSize: 9 }} interval={0} angle={-15} textAnchor="end" height={54} /><YAxis tick={{ fill: '#7894ad', fontSize: 9 }} /><Tooltip contentStyle={tooltipStyle} formatter={(value) => [`${Number(value).toFixed(2)} ms`]} /><Legend wrapperStyle={{ fontSize: 10 }} /><Bar dataKey="average" name="Average" fill="#42c6e7" radius={[4, 4, 0, 0]} /><Bar dataKey="worst" name="Worst" fill="#27698e" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer></div><div className="chart-panel__foot">{latencyData.length === 0 && 'Pipeline timings were not saved. '}Bottleneck: <strong>{stageNames[overview?.bottleneck_step] || '—'}</strong> · average {ms(overview?.average_pipeline_latency_ms)}</div></div>
      <div className="panel chart-panel"><div className="panel__head"><div><span className="section-heading__overline">MODULE 4 EVALUATION</span><h3>ML versus rule baseline</h3></div><Cpu size={18} className="panel__accent-icon" /></div><div className="chart-panel__body"><ResponsiveContainer width="100%" height="100%"><BarChart data={modelData} margin={{ top: 8, right: 8, left: -20, bottom: 5 }}><CartesianGrid vertical={false} stroke="#263b55" strokeDasharray="3 6" /><XAxis dataKey="name" tick={{ fill: '#829bb2', fontSize: 10 }} /><YAxis domain={[0, 100]} tick={{ fill: '#7894ad', fontSize: 9 }} /><Tooltip contentStyle={tooltipStyle} formatter={(value) => [`${Number(value).toFixed(1)}%`]} /><Legend wrapperStyle={{ fontSize: 10 }} /><Bar dataKey="isolation" name="Isolation Forest" fill="#52d5b3" radius={[4, 4, 0, 0]} /><Bar dataKey="rules" name="Rule baseline" fill="#427391" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer></div><div className="chart-panel__foot">Held-out normal and anomaly samples · values from Module 4.</div></div>
      <div className="panel chart-panel chart-panel--wide"><div className="panel__head"><div><span className="section-heading__overline">HELD-OUT ATTACK CATEGORIES</span><h3>Isolation Forest recall</h3></div><span className="chart-panel__unit">%</span></div><div className="chart-panel__body"><ResponsiveContainer width="100%" height="100%"><BarChart data={recallData} layout="vertical" margin={{ top: 3, right: 25, left: 100, bottom: 3 }}><CartesianGrid horizontal={false} stroke="#263b55" strokeDasharray="3 6" /><XAxis type="number" domain={[0, 100]} tick={{ fill: '#7894ad', fontSize: 9 }} /><YAxis type="category" dataKey="name" width={105} tick={{ fill: '#9ab0c4', fontSize: 10 }} /><Tooltip contentStyle={tooltipStyle} formatter={(value) => [`${Number(value).toFixed(1)}%`, 'Recall']} /><Bar dataKey="recall" radius={[0, 5, 5, 0]}>{recallData.map((entry) => <Cell key={entry.name} fill={entry.name === 'Scope creep' ? '#e7b85c' : '#48bedc'} />)}</Bar></BarChart></ResponsiveContainer></div><div className="chart-panel__foot">Per-category recall is reported independently; authorized scope creep remains a behavioral finding.</div></div>
    </section>
  </div>
}
