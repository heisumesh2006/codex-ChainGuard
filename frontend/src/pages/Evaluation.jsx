import { motion } from 'framer-motion'
import { Activity, ArrowRight, CheckCircle2, GitBranch, RefreshCw, ShieldCheck } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link, useLocation, useOutletContext } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import DecisionBadge from '../components/DecisionBadge'
import MetricCard from '../components/MetricCard'
import Skeleton from '../components/Skeleton'
import { api } from '../services/api'

const percent = (value) => value == null ? '—' : `${(value * 100).toFixed(2)}%`
const ms = (value) => value == null ? '—' : `${Number(value).toFixed(1)} ms`
const tooltipStyle = { background: '#101a2d', border: '1px solid #294061', borderRadius: 10, color: '#edf5ff', fontSize: 11 }
const latencyLabels = { authorization_ms: 'Authorization', trace_context_ms: 'Trace', drift_scoring_ms: 'Drift', revocation_check_ms: 'Revocation', chain_verification_ms: 'Blockchain', verdict_assembly_ms: 'Verdict' }
const architecture = [
  ['Agent action', 'The incoming agent action and its observed result enter the governance pipeline.'],
  ['Module 1 · Authorization', 'The existing permission check establishes the real-time access decision.'],
  ['Module 3 · Trace', 'Delegation hops and root credentials are traced through verified blockchain evidence.'],
  ['Module 4 · AI drift', 'The saved normal-only model scores behavior with Module 3 trace context.'],
  ['Module 5 · Revocation', 'Public Ethereum status and post-revocation audit catch stale credentials.'],
  ['Module 2 · Ethereum', 'The required credential, delegation, action, and revocation proofs are verified.'],
  ['Governance verdict', 'Authorization, drift, and evidence yield ALLOW, REVIEW, or BLOCK.'],
]

export default function Evaluation() {
  const { health } = useOutletContext()
  const location = useLocation()
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('ALL')
  const [activeStage, setActiveStage] = useState(1)
  const load = () => { setError(null); api.finalReport().then(setReport).catch((cause) => setError(cause.message)) }
  useEffect(load, [])
  useEffect(() => { if (report && location.hash) window.setTimeout(() => document.getElementById(location.hash.slice(1))?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100) }, [report, location.hash])
  const rows = useMemo(() => report?.scenarios?.filter((row) => filter === 'ALL' || row.final_decision === filter) || [], [report, filter])
  const ml = report?.modules?.module4_anomaly?.isolation_forest
  const trace = report?.modules?.module3_tracing
  const revocation = report?.modules?.module5_revocation
  const latency = report?.end_to_end_latency
  const coverage = report?.end_to_end_attack_coverage
  const latencyData = Object.entries(latency?.average_ms || {}).map(([key, value]) => ({ name: latencyLabels[key] || key, average: value, worst: latency?.worst_case_ms?.[key] || 0 }))
  const recallData = Object.entries(ml?.per_category || {}).map(([key, value]) => ({ name: key.replaceAll('_', ' '), recall: value.recall * 100 }))
  const decisions = ['ALLOW', 'REVIEW', 'BLOCK'].map((name) => ({ name, value: report?.scenarios?.filter((row) => row.final_decision === name).length || 0 }))
  const cards = [
    ['Attack coverage', coverage == null ? null : coverage * 100, '%'],
    ['Trace accuracy', trace?.delegation_trace_accuracy == null ? null : trace.delegation_trace_accuracy * 100, '%'],
    ['ML precision', ml?.precision == null ? null : ml.precision * 100, '%'],
    ['ML recall', ml?.recall == null ? null : ml.recall * 100, '%'],
    ['ML F1', ml?.f1 == null ? null : ml.f1 * 100, '%'],
    ['False positive rate', ml?.false_positive_rate == null ? null : ml.false_positive_rate * 100, '%'],
    ['Revocation completeness', revocation?.revocation_completeness == null ? null : revocation.revocation_completeness * 100, '%'],
    ['Average pipeline', latency?.total_average_ms, ' ms'],
    ['Worst pipeline', latency?.total_worst_case_ms, ' ms'],
  ]
  return <div className="evaluation-page">
    <div className="eyebrow"><span className="eyebrow__line" /> FINAL PROJECT EVIDENCE</div>
    <div className="page-heading"><div><h1>Evaluation</h1><p>Saved outcomes from the canonical Module 6 run and its {report?.scenario_counts?.total ?? '—'} scenarios.</p></div><span className="page-heading__count">FINAL REPORT · ETHEREUM {health?.chain_id ?? '—'}</span></div>
    {error && <div className="error-banner">Final report unavailable: {error} <button onClick={load}><RefreshCw size={14} /> Retry</button></div>}
    {!report && !error && <div className="evaluation-loading"><Skeleton className="metric-card" /><Skeleton className="metric-card" /><Skeleton className="metric-card" /></div>}
    {report && <>
      {report.evidence_source === 'profile_persisted_audit_records' && <p className="section-heading__note">Saved Sepolia decisions. Pipeline timings and trace accuracy were not recorded; blank values are unavailable. ML metrics use the shared synthetic benchmark.</p>}
      <section id="problem" className="panel evaluation-problem"><span className="section-heading__overline">THE PROBLEM</span><h3>Autonomous agents can act with delegated authority at machine speed.</h3><p>ChainGuard-AI combines permission checks, rooted delegation proofs, behavioral drift scoring, and public revocation evidence so unusual or unauthorized actions receive a measured governance decision.</p></section>
      <section id="metrics" className="evaluation-kpis">{cards.map(([label, value, suffix], index) => <MetricCard key={label} label={label} value={value} suffix={suffix} decimals={suffix === '%' ? 1 : 0} index={index} detail={label === 'Worst pipeline' ? 'Measured worst case' : 'Measured project result'} icon={[ShieldCheck, GitBranch, Activity][index % 3]} />)}</section>
      <div className="evaluation-highlight panel"><CheckCircle2 size={20} /><span>Pipeline bottleneck</span><strong>{latencyLabels[latency?.pipeline_bottleneck_step] || latency?.pipeline_bottleneck_step}</strong><span className="evaluation-highlight__separator" /><span>Saved run registry</span><strong className="mono">{report.blockchain_deployment?.contract_address}</strong><span>Chain {report.blockchain_deployment?.chain_id}</span></div>
      <div className="evaluation-charts">
        <section className="panel evaluation-chart evaluation-chart--wide"><span className="section-heading__overline">END-TO-END LATENCY</span><h3>Pipeline stages · average and worst case</h3><div className="evaluation-chart__plot"><ResponsiveContainer width="100%" height="100%"><BarChart data={latencyData} margin={{ top: 12, right: 8, left: 0, bottom: 5 }}><CartesianGrid vertical={false} stroke="#274058" strokeDasharray="3 6" /><XAxis dataKey="name" tick={{ fill: '#9bb4c7', fontSize: 10 }} /><YAxis tick={{ fill: '#7b9ab0', fontSize: 10 }} unit="ms" /><Tooltip contentStyle={tooltipStyle} formatter={(v) => ms(v)} /><Legend wrapperStyle={{ fontSize: 10 }} /><Bar dataKey="average" name="Average" fill="#4bc3dc" radius={[4, 4, 0, 0]} /><Bar dataKey="worst" name="Worst" fill="#dfae61" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer></div></section>
        <section className="panel evaluation-chart"><span className="section-heading__overline">GOVERNANCE OUTCOMES</span><h3>All {report.scenarios.length} scenarios</h3><div className="evaluation-chart__plot"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={decisions} dataKey="value" nameKey="name" innerRadius={53} outerRadius={83} paddingAngle={4}>{decisions.map((item) => <Cell key={item.name} fill={{ ALLOW: '#4fd1b1', REVIEW: '#dfae61', BLOCK: '#e97889' }[item.name]} />)}</Pie><Tooltip contentStyle={tooltipStyle} /><Legend wrapperStyle={{ fontSize: 10 }} /></PieChart></ResponsiveContainer></div></section>
        <section className="panel evaluation-chart"><span className="section-heading__overline">ATTACK COVERAGE</span><h3>Layered detection</h3><div className="evaluation-coverage"><strong>{percent(coverage)}</strong><span>End-to-end attack and anomaly coverage</span><p>Each layer's contribution is preserved in the scenario table below.</p></div></section>
        <section className="panel evaluation-chart evaluation-chart--wide"><span className="section-heading__overline">ML CATEGORY RECALL</span><h3>Held-out anomaly samples</h3><div className="evaluation-chart__plot"><ResponsiveContainer width="100%" height="100%"><BarChart data={recallData} layout="vertical" margin={{ top: 8, right: 15, left: 165, bottom: 5 }}><CartesianGrid horizontal={false} stroke="#274058" strokeDasharray="3 6" /><XAxis type="number" domain={[0, 100]} tick={{ fill: '#7b9ab0', fontSize: 10 }} unit="%" /><YAxis type="category" dataKey="name" width={165} tick={{ fill: '#9bb4c7', fontSize: 10 }} /><Tooltip contentStyle={tooltipStyle} formatter={(v) => `${v.toFixed(1)}%`} /><Bar dataKey="recall" name="Isolation Forest recall" fill="#4bc3dc" radius={[0, 4, 4, 0]} /></BarChart></ResponsiveContainer></div></section>
      </div>
      <section id="architecture" className="panel evaluation-architecture"><div className="panel__head"><div><span className="section-heading__overline">INTERACTIVE ARCHITECTURE</span><h3>Evidence from action to verdict</h3></div><Link to="/governance?auto=1" className="button-secondary">Run Auto Demo <ArrowRight size={14} /></Link></div><div className="evaluation-architecture__flow">{architecture.map(([name, description], index) => <motion.button key={name} type="button" onMouseEnter={() => setActiveStage(index)} onFocus={() => setActiveStage(index)} onClick={() => setActiveStage(index)} className={activeStage === index ? 'is-active' : ''} whileHover={{ y: -3 }}><span>{String(index + 1).padStart(2, '0')}</span><strong>{name}</strong></motion.button>)}</div><div className="evaluation-architecture__detail"><strong>{architecture[activeStage][0]}</strong><p>{architecture[activeStage][1]}</p></div></section>
      <section className="panel evaluation-table-panel"><div className="panel__head"><div><span className="section-heading__overline">CANONICAL MODULE 6 RUN</span><h3>{report.scenarios.length}-scenario evidence table</h3></div><div className="evaluation-filters">{['ALL', 'ALLOW', 'REVIEW', 'BLOCK'].map((option) => <button key={option} onClick={() => setFilter(option)} className={filter === option ? 'is-active' : ''}>{option}</button>)}</div></div><div className="evaluation-table-wrap"><table><thead><tr>{['Scenario', 'Actor', 'Class', 'Authorized', 'Drift', 'Trace', 'Revoked', 'Chain Verified', 'Decision', 'Detected By', 'Latency'].map((name) => <th key={name}>{name}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr key={`${row.record_id}-${index}`}><td><strong>{row.scenario}</strong></td><td>{row.actor}</td><td>{row.expected_class}</td><td>{row.authorized ? 'Yes' : 'No'}</td><td>{row.drift_applicable ? row.drift_flagged ? 'Flagged' : 'Clear' : 'N/A'}</td><td className="mono">{row.trace_verdict || '—'}</td><td>{row.revoked ? 'Yes' : 'No'}</td><td>{row.chain_verified ? 'Yes' : 'No'}</td><td><DecisionBadge decision={row.final_decision} /></td><td>{row.detected_by?.join(', ') || 'None'}</td><td className="mono">{ms(row.resolution_time_ms)}</td></tr>)}</tbody></table></div><p className="evaluation-table-panel__foot">Showing {rows.length} of {report.scenarios.length} saved scenarios.</p></section>
      <section className="panel evaluation-limits"><span className="section-heading__overline">KNOWN LIMITATIONS</span><h3>Prototype boundaries</h3><ul>{report.known_limitations?.map((item, index) => <li key={index}>{item}</li>)}</ul></section>
    </>}
  </div>
}
