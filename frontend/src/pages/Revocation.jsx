import { AnimatePresence, motion } from 'framer-motion'
import { Activity, ArrowRight, Fingerprint, LockKeyhole, Search, ShieldCheck, ShieldX } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import AnimatedNumber from '../components/AnimatedNumber'
import Skeleton from '../components/Skeleton'
import StatusPill from '../components/StatusPill'
import { api } from '../services/api'

const options = ['Agent_C', 'Agent_B', 'Agent_A', 'Agent_D', 'Unknown_Agent']
const short = (value) => value ? `${value.slice(0, 12)}…${value.slice(-9)}` : '—'
const stages = ['Credential active', 'Delegation', 'Revocation', 'Attempted action', 'Violation detected']

export default function Revocation() {
  const { metrics } = useOutletContext()
  const [agentId, setAgentId] = useState('Agent_C')
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const lookup = async (id) => { setLoading(true); setError(null); setStatus(null); try { setStatus(await api.revocation(id)) } catch (cause) { setError(cause.message) } finally { setLoading(false) } }
  useEffect(() => { lookup('Agent_C') }, [])
  const proof = status?.chain_proof
  const revoked = status?.is_revoked
  const metric = metrics?.module5
  const normalDefense = Boolean(metric?.caught_by_realtime && metric?.caught_by_audit)
  const bypassCaught = Boolean(metric && metric.caught_by_audit > metric.caught_by_realtime && metric.caught_by_either === metric.post_revocation_attempts)
  return <div className="revocation-page">
    <div className="eyebrow"><span className="eyebrow__line" /> PUBLIC ETHEREUM VERIFICATION</div>
    <div className="page-heading"><div><h1>Revocation Center</h1><p>Query the current AgentTrustRegistry state. Revoked metadata comes directly from Ethereum.</p></div><span className="page-heading__count">MODULE 5 · CHAIN STATUS</span></div>
    <section className="panel revocation-search"><div className="revocation-search__icon"><Search size={20} /></div><div><span className="section-heading__overline">PUBLIC LOOKUP</span><h3>Verify an agent</h3></div><select value={agentId} onChange={(event) => setAgentId(event.target.value)} aria-label="Agent to verify">{options.map((item) => <option key={item}>{item}</option>)}</select><button className="button-primary" onClick={() => lookup(agentId)} disabled={loading}>{loading ? 'Querying Ethereum…' : 'Check chain status'} <ArrowRight size={15} /></button></section>
    {error && <div className="error-banner">{error} <button onClick={() => lookup(agentId)}>Retry</button></div>}
    {loading && <Skeleton className="revocation-result panel" />}
    <AnimatePresence mode="wait">{status && <motion.section className={`panel revocation-result ${revoked ? 'revocation-result--revoked' : ''}`} key={status.agent_id} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}><div className="revocation-result__header"><div className="revocation-result__icon">{revoked ? <ShieldX size={29} /> : status.agent_found ? <ShieldCheck size={29} /> : <Search size={29} />}</div><div><span className="section-heading__overline">AGENTTRUSTREGISTRY · BLOCK {status.checked_block_number}</span><h2>{status.agent_id}</h2></div><StatusPill label={status.status} tone={revoked ? 'red' : status.agent_found ? 'emerald' : 'cyan'} /></div>
      {revoked ? <div className="revocation-result__grid"><div className="revocation-result__field"><span>Revoked at</span><strong>{new Date(status.revoked_at).toLocaleString()}</strong></div><div className="revocation-result__field"><span>Revoked by</span><strong>{status.revoked_by}</strong></div><div className="revocation-result__field"><span>Revoked permissions</span><div className="permission-list">{status.revoked_permissions?.map((permission) => <span className="permission-chip permission-chip--revoked" key={permission}>{permission}</span>)}</div></div><div className="revocation-result__field"><span>Proof verification</span><strong className={status.proof_verified ? 'tone-allow' : 'tone-block'}>{status.proof_verified ? 'PASS · Ethereum receipt + contract state' : 'FAIL'}</strong></div></div> : <p className="revocation-result__message">{status.agent_found ? 'Registered agent is ACTIVE at the checked contract block. This is a current Ethereum state query.' : 'No registered blockchain identity was found for this agent ID.'}</p>}
      {revoked && <div className={`revocation-verified ${status.proof_verified ? '' : 'revocation-verified--failed'}`}><ShieldCheck size={26} /><div><strong>{status.proof_verified ? 'VERIFIED ON-CHAIN' : 'PROOF NOT VERIFIED'}</strong><span>{status.proof_verified ? 'Receipt, content hash, and current registry state match.' : 'Do not treat this revocation proof as confirmed.'}</span></div></div>}
      {proof && <div className="revocation-proof"><div><Fingerprint size={18} /><strong>{revoked ? 'Anchored revocation proof' : 'Current contract-state check'}</strong></div>{revoked && <><div><span>Transaction hash</span><code title={proof.transaction_hash}>{short(proof.transaction_hash)}</code></div><div><span>Block number</span><code>{proof.block_number}</code></div><div><span>Content hash</span><code title={proof.content_hash}>{short(proof.content_hash)}</code></div></>}<div><span>Contract</span><code title={proof.contract_address}>{short(proof.contract_address)}</code></div><div><span>Chain ID</span><code>{proof.chain_id}</code></div></div>}
    </motion.section>}</AnimatePresence>
    <div className="revocation-metrics"><section className="panel revocation-metric"><LockKeyhole size={22} /><span>REVOCATION COMPLETENESS</span><strong><AnimatedNumber value={metric ? metric.revocation_completeness * 100 : null} suffix="%" /></strong><p>{metric ? `${metric.caught_by_either} of ${metric.post_revocation_attempts} attempts caught by at least one layer` : 'Loading measured result…'}</p></section><section className="panel revocation-metric"><Activity size={22} /><span>PUBLIC LOOKUP</span><strong><AnimatedNumber value={metric?.public_lookup_latency_ms} decimals={1} suffix=" ms" /></strong><p>Average from Module 5’s public verifier measurement.</p></section><section className="panel revocation-metric"><Fingerprint size={22} /><span>REVOKE TO PROOF</span><strong><AnimatedNumber value={metric?.revocation_to_proof_latency_ms} decimals={1} suffix=" ms" /></strong><p>Local decommission through confirmed Ethereum proof.</p></section></div>
    <section className="panel revocation-audit"><div className="panel__head"><div><span className="section-heading__overline">POST-REVOCATION FORENSICS</span><h3>One revocation, two independent defenses</h3></div><Activity size={19} className="panel__accent-icon" /></div><div className="revocation-audit__timeline">{stages.map((stage, index) => <motion.div key={stage} initial={{ opacity: 0, y: 10 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: index * .1 }}><span>{String(index + 1).padStart(2, '0')}</span><strong>{stage}</strong></motion.div>)}</div><div className="revocation-audit__cases"><div><span className="section-heading__overline">REAL MODULE 1 ACTION</span><h4>Normal defense</h4><p>Real-time layer: <strong className={normalDefense ? 'tone-block' : ''}>{normalDefense ? 'BLOCKED' : 'Awaiting measured evidence'}</strong></p><p>Audit layer: <strong className={normalDefense ? 'tone-allow' : ''}>{normalDefense ? 'VIOLATION DETECTED' : 'Awaiting measured evidence'}</strong></p></div><div><span className="section-heading__overline">ISOLATED MODULE 5 FIXTURE</span><h4>Simulated real-time bypass</h4><p>Real-time result: <strong>{bypassCaught ? 'ALLOWED' : 'Awaiting measured evidence'}</strong></p><p>Audit result: <strong className={bypassCaught ? 'tone-allow' : ''}>{bypassCaught ? 'VIOLATION DETECTED' : 'Awaiting measured evidence'}</strong></p></div></div><p className="revocation-audit__foot">The bypass is an isolated audit fixture. Its outcome is derived from saved Module 5 attempt and catch counts; it does not modify Module 1.</p></section>
  </div>
}
