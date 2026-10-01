import { AnimatePresence, motion } from 'framer-motion'
import { ChevronDown, Fingerprint, KeyRound, Layers3, LockKeyhole, ShieldCheck, ShieldX } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api } from '../services/api'
import Skeleton from '../components/Skeleton'
import StatusPill from '../components/StatusPill'

const short = (value) => value ? `${value.slice(0, 10)}…${value.slice(-8)}` : '—'

function PermissionList({ items, empty = 'None' }) {
  return items?.length ? <div className="permission-list">{items.map((item) => <span key={item} className="permission-chip">{item}</span>)}</div> : <span className="agent-muted">{empty}</span>
}

function AgentCard({ agent, index }) {
  const [expanded, setExpanded] = useState(false)
  const [details, setDetails] = useState(null)
  const [error, setError] = useState(null)
  const revoked = agent.status === 'DECOMMISSIONED'
  const proofFailed = details?.credentials?.some((item) => item.proof_status !== 'PASS')
  const state = revoked ? 'REVOKED' : proofFailed ? 'REVIEW' : 'ACTIVE'

  const toggle = () => {
    setExpanded((value) => !value)
    if (!details && !error) api.agentCredentials(agent.agent_id).then(setDetails).catch((cause) => setError(cause.message))
  }

  return <motion.article className={`agent-card panel ${revoked ? 'agent-card--revoked' : ''}`} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * .08 }}>
    <div className="agent-card__top"><div className="agent-card__identity"><div className="agent-card__avatar">{agent.agent_id.slice(-1)}</div><div><span className="agent-card__eyebrow">BLOCKCHAIN IDENTITY</span><h2>{agent.agent_id}</h2><p>{agent.role}</p></div></div><StatusPill label={state} tone={state === 'REVOKED' ? 'red' : state === 'REVIEW' ? 'amber' : 'emerald'} /></div>
    <div className="agent-card__address"><Fingerprint size={15} /><span className="mono" title={agent.blockchain_address}>{short(agent.blockchain_address)}</span></div>
    <div className="agent-card__scopes"><div><span className="agent-card__label"><KeyRound size={13} /> Direct permissions</span><PermissionList items={agent.direct_permissions} /></div><div><span className="agent-card__label"><Layers3 size={13} /> Delegated permissions</span>{agent.delegated_permissions.length ? <div className="permission-list">{agent.delegated_permissions.map((item, i) => <span key={`${item.permission}-${i}`} className="permission-chip permission-chip--delegated" title={`From ${item.delegator}`}>{item.permission}</span>)}</div> : <span className="agent-muted">None</span>}</div></div>
    <div className="agent-card__effective"><span>EFFECTIVE SCOPE</span><PermissionList items={agent.effective_permissions} empty={revoked ? 'Cleared on decommission' : 'No granted permissions'} /></div>
    <button className="agent-card__expand" onClick={toggle} aria-expanded={expanded} aria-label={`${expanded ? 'Hide' : 'Show'} ${agent.agent_id} proof details`}>Credential and proof details <ChevronDown size={16} className={expanded ? 'rotate-180' : ''} /></button>
    <AnimatePresence initial={false}>{expanded && <motion.div className="agent-card__details" initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: .24 }}><div className="agent-card__details-inner">
      {error && <div className="error-banner">{error}</div>}
      {!details && !error && <Skeleton style={{ height: 80 }} />}
      {details?.credentials?.map((credential) => <div className="credential-row" key={credential.credential_id}><div className="credential-row__top"><strong>{credential.permission}</strong><span className={`proof-tag ${credential.proof_status === 'PASS' ? 'proof-tag--pass' : 'proof-tag--fail'}`}>{credential.proof_status === 'PASS' ? <ShieldCheck size={13} /> : <ShieldX size={13} />} {credential.proof_status}</span></div><div className="credential-row__meta"><span>Issuer <b>{credential.issuer}</b></span><span>Scope <b>{credential.delegation_scope.length ? 'Delegable' : 'Use only'}</b></span><span>Status <b className={credential.status === 'REVOKED' ? 'tone-block' : 'tone-allow'}>{credential.status}</b></span></div><div className="credential-row__hash mono" title={credential.content_hash}>Credential {short(credential.credential_id)}</div><div className="credential-row__hash mono" title={credential.transaction_hash}>Tx {short(credential.transaction_hash)} · Block {credential.block_number}</div><div className="credential-row__basis">Verified via {credential.proof_basis === 'ROOT_CREDENTIAL' ? 'root-issued credential and Ethereum receipt' : 'rooted delegation-chain trace'}</div></div>)}
      {agent.delegated_permissions.length > 0 && <div className="agent-card__detail-section"><span className="agent-card__label">AUTHORITY SOURCE</span>{agent.delegated_permissions.map((record, i) => <p key={i}>{record.permission} delegated by <b>{record.delegator}</b> · rooted at <b>{record.authority_source}</b></p>)}</div>}
      {revoked && <div className="agent-card__detail-section agent-card__detail-section--revoked"><span className="agent-card__label"><LockKeyhole size={13} /> REVOKED PERMISSIONS</span>{agent.revoked_permissions.map((item, i) => <p key={i}><b>{item.permission}</b> · {item.revoked_by} · {new Date(item.revoked_at).toLocaleString()}</p>)}</div>}
    </div></motion.div>}</AnimatePresence>
  </motion.article>
}

export default function Agents() {
  const [agents, setAgents] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => { let active = true; api.agents().then((value) => { if (active) setAgents(value) }).catch((cause) => { if (active) setError(cause.message) }); return () => { active = false } }, [])
  return <div className="agents-page"><div className="eyebrow"><span className="eyebrow__line" /> IDENTITY REGISTRY</div><div className="page-heading"><div><h1>Agent Directory</h1><p>Roles, scopes, Ethereum identities, and historical authority evidence.</p></div><span className="page-heading__count">{agents?.length ?? '—'} registered agents</span></div>{error && <div className="error-banner">{error}</div>}<div className="agents-grid">{agents ? agents.map((agent, index) => <AgentCard key={agent.agent_id} agent={agent} index={index} />) : Array.from({ length: 4 }, (_, index) => <Skeleton key={index} className="agent-card panel" />)}</div></div>
}
