import { motion } from 'framer-motion'
import { Activity, Clock3, Crosshair, Gauge, ScanSearch } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import MetricCard from '../components/MetricCard'
import Skeleton from '../components/Skeleton'
import { api } from '../services/api'

const names = { SELF_ESCALATION: 'Self escalation', UNAUTHORIZED_DELEGATION: 'Unauthorized delegation', POST_DECOMMISSION_ACTIVITY: 'Post revocation', SCOPE_CREEP: 'Scope creep' }
const tooltipStyle = { background: '#101a2d', border: '1px solid #294061', borderRadius: 10, color: '#edf5ff', fontSize: 11 }

export default function Analytics() {
  const { metrics, error } = useOutletContext()
  const [report, setReport] = useState(null)
  useEffect(() => { let active = true; api.finalReport().then((value) => { if (active) setReport(value) }).catch(() => {}); return () => { active = false } }, [])
  const ml = metrics?.module4?.isolation_forest
  const rules = metrics?.module4?.rule_baseline
  const dataset = metrics?.module4?.dataset
  const latency = metrics?.module4?.latency
  const threshold = metrics?.module4?.threshold
  const self = ml?.per_category?.SELF_ESCALATION
  const scope = report?.scenarios?.find((row) => row.scenario === 'SCOPE_CREEP' && row.authorized && row.trace_verdict === 'VALID_CHAIN')
  const normal = report?.scenarios?.find((row) => row.expected_class === 'NORMAL' && row.drift_score != null)
  const scores = [threshold, scope?.drift_score, normal?.drift_score].filter(Number.isFinite)
  const low = scores.length ? Math.min(0, ...scores) - .025 : -.1
  const high = scores.length ? Math.max(.1, ...scores) + .025 : .2
  const position = (score) => `${Math.max(0, Math.min(100, (score - low) / (high - low) * 100))}%`
  const cards = [
    { label: 'Precision', value: ml ? ml.precision * 100 : null, suffix: '%', decimals: 1, detail: 'Isolation Forest', icon: Crosshair },
    { label: 'Recall', value: ml ? ml.recall * 100 : null, suffix: '%', decimals: 1, detail: 'Held-out anomalies', icon: ScanSearch },
    { label: 'F1 score', value: ml ? ml.f1 * 100 : null, suffix: '%', decimals: 1, detail: 'Precision / recall balance', icon: Gauge },
    { label: 'False positive rate', value: ml ? ml.false_positive_rate * 100 : null, suffix: '%', decimals: 1, detail: 'Held-out normal actions', icon: Activity, tone: 'red' },
    { label: 'Average detection', value: latency?.average_ms, suffix: ' ms', decimals: 1, detail: 'Feature extraction + scoring', icon: Clock3 },
  ]
  const comparison = ['precision', 'recall', 'f1', 'false_positive_rate'].map((key) => ({ name: key === 'false_positive_rate' ? 'FPR' : key.toUpperCase(), isolation: (ml?.[key] || 0) * 100, rules: (rules?.[key] || 0) * 100 }))
  const categories = Object.entries(ml?.per_category || {}).map(([key, value]) => ({ name: names[key] || key, isolation: value.recall * 100, rules: (rules?.per_category?.[key]?.recall || 0) * 100 }))
  const matrix = ml?.confusion_matrix
  return <div className="analytics-page">
    <div className="eyebrow"><span className="eyebrow__line" /> BEHAVIORAL INTELLIGENCE</div>
    <div className="page-heading"><div><h1>ML Analytics</h1><p>Normal-only Isolation Forest evaluation on the held-out synthetic experiment.</p></div><span className="page-heading__count">MODULE 4 · SAVED MODEL</span></div>
    {error && <div className="error-banner">{error}</div>}
    <section className="analytics-kpis">{cards.map((card, index) => ml ? <MetricCard key={card.label} {...card} index={index} /> : <Skeleton key={card.label} className="metric-card" />)}</section>
    <div className="analytics-grid">
      <motion.section className="panel analytics-chart" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}><span className="section-heading__overline">HELD-OUT CLASSIFICATION</span><h3>Isolation Forest vs rule baseline</h3><div className="analytics-chart__body"><ResponsiveContainer width="100%" height="100%"><BarChart data={comparison} margin={{ top: 10, right: 10, left: -18, bottom: 5 }}><CartesianGrid vertical={false} stroke="#274058" strokeDasharray="3 6" /><XAxis dataKey="name" tick={{ fill: '#9bb4c7', fontSize: 10 }} /><YAxis domain={[0, 100]} tick={{ fill: '#7b9ab0', fontSize: 9 }} /><Tooltip contentStyle={tooltipStyle} formatter={(value) => `${value.toFixed(1)}%`} /><Legend wrapperStyle={{ fontSize: 10 }} /><Bar dataKey="isolation" name="Isolation Forest" fill="#4fd1b1" radius={[4, 4, 0, 0]} /><Bar dataKey="rules" name="Rule baseline" fill="#417b9a" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer></div><p>Lower FPR means fewer held-out normal actions were flagged.</p></motion.section>
      <motion.section className="panel analytics-chart" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: .08 }}><span className="section-heading__overline">CATEGORY RECALL</span><h3>Detection by behavior type</h3><div className="analytics-chart__body"><ResponsiveContainer width="100%" height="100%"><BarChart data={categories} layout="vertical" margin={{ top: 9, right: 10, left: 105, bottom: 5 }}><CartesianGrid horizontal={false} stroke="#274058" strokeDasharray="3 6" /><XAxis type="number" domain={[0, 100]} tick={{ fill: '#7b9ab0', fontSize: 9 }} /><YAxis type="category" dataKey="name" width={105} tick={{ fill: '#9bb4c7', fontSize: 10 }} /><Tooltip contentStyle={tooltipStyle} formatter={(value) => `${value.toFixed(1)}%`} /><Legend wrapperStyle={{ fontSize: 10 }} /><Bar dataKey="isolation" name="Isolation Forest" fill="#4bc3dc" radius={[0, 4, 4, 0]} /><Bar dataKey="rules" name="Rule baseline" fill="#416b86" radius={[0, 4, 4, 0]} /></BarChart></ResponsiveContainer></div><p>Scope creep retains valid authority; recall measures abnormal behavior.</p></motion.section>
    </div>
    {self && <section className="panel analytics-honesty"><ScanSearch size={21} /><div><span className="section-heading__overline">VISIBLE MODEL LIMITATION</span><h3>Self-escalation recall: {(self.recall * 100).toFixed(2)}%</h3><p>The model missed {Math.round(self.count * (1 - self.recall))} of {self.count} held-out self-escalation samples. The other hard-coded attack categories score {['UNAUTHORIZED_DELEGATION', 'POST_DECOMMISSION_ACTIVITY'].map((key) => `${names[key]} ${(ml.per_category[key]?.recall * 100).toFixed(2)}%`).join(' and ')}. The authorization and trace layers remain separate defenses.</p></div></section>}
    <div className="analytics-insight-grid">
      <section className="panel analytics-score"><span className="section-heading__overline">ANOMALY SCORE</span><h3>Normal zone → anomaly zone</h3>{threshold != null ? <><div className="analytics-score__axis"><div className="analytics-score__normal" style={{ width: position(threshold) }}>NORMAL</div><div className="analytics-score__anomaly">ANOMALOUS</div><span className="analytics-score__threshold" style={{ left: position(threshold) }} title={`Threshold ${threshold.toFixed(3)}`} /></div><div className="analytics-score__markers">{normal && <div><span className="analytics-score__dot analytics-score__dot--normal" style={{ left: position(normal.drift_score) }} /><strong>Held-out normal</strong><code>{normal.drift_score.toFixed(3)}</code></div>}{scope && <div><span className="analytics-score__dot analytics-score__dot--scope" style={{ left: position(scope.drift_score) }} /><strong>Held-out scope creep</strong><code>{scope.drift_score.toFixed(3)}</code></div>}</div><p>Higher is more anomalous. The threshold <strong>{threshold.toFixed(3)}</strong> came from normal validation scores.</p></> : <Skeleton style={{ height: 130 }} />}</section>
      <section className="panel analytics-scope"><span className="section-heading__overline">AUTHORIZED ≠ NORMAL</span><h3>Scope creep in the integrated run</h3>{scope ? <><div className="analytics-scope__row"><span>Agent</span><strong>{scope.actor}</strong></div><div className="analytics-scope__row"><span>Authorization</span><strong className="tone-allow">{scope.authorized ? 'VALID' : 'DENIED'}</strong></div><div className="analytics-scope__row"><span>Trace</span><strong className="tone-allow">{scope.trace_verdict}</strong></div><div className="analytics-scope__row"><span>ML behavior</span><strong className="tone-review">{scope.drift_flagged ? 'ANOMALOUS' : 'CLEAR'} · {scope.drift_score.toFixed(3)}</strong></div><div className="analytics-scope__row"><span>Decision</span><strong className="tone-review">{scope.final_decision}</strong></div><p>Valid blockchain authority can coexist with unusual behavior. The decision requests review.</p></> : <Skeleton style={{ height: 150 }} />}</section>
    </div>
    <div className="analytics-bottom"><section className="panel analytics-matrix"><span className="section-heading__overline">EVALUATION DETAIL</span><h3>Confusion matrix</h3>{matrix ? <div className="analytics-matrix__grid"><span /><span>Predicted normal</span><span>Predicted anomaly</span><span>Actual normal</span><strong>{matrix[0][0]}<small>TN</small></strong><strong>{matrix[0][1]}<small>FP</small></strong><span>Actual anomaly</span><strong>{matrix[1][0]}<small>FN</small></strong><strong>{matrix[1][1]}<small>TP</small></strong></div> : <Skeleton style={{ height: 150 }} />}</section><section className="panel analytics-dataset"><span className="section-heading__overline">REPRODUCIBLE EXPERIMENT</span><h3>Training and dataset</h3>{[['Normal actions', dataset?.normal_count], ['Normal training samples', dataset?.train_normal_count], ['Validation samples', dataset?.validation_normal_count], ['Held-out normal test', dataset?.test_normal_count], ['Anomaly samples', dataset ? Object.values(dataset.attack_counts).reduce((sum, count) => sum + count, 0) : null]].map(([name, value]) => <div className="analytics-dataset__row" key={name}><span>{name}</span><strong>{value ?? '—'}</strong></div>)}<p>Ground-truth labels are excluded from model features. Only normal actions were used for fitting.</p></section></div>
  </div>
}
