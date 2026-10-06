import { AnimatePresence, motion } from 'framer-motion'
import {
  AlertTriangle, Blocks, Check, ChevronRight, Clock3,
  Copy, ExternalLink, Fingerprint, Layers3, RefreshCw, ScanSearch,
  ShieldCheck, ShieldX, Timer, XCircle,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import StatusPill from '../components/StatusPill'
import Skeleton from '../components/Skeleton'
import { api } from '../services/api'

const short = (value, head = 13, tail = 9) => value ? `${value.slice(0, head)}…${value.slice(-tail)}` : '—'
const time = (value) => value ? new Date(value).toLocaleString() : '—'
const seconds = (value) => value == null ? '—' : `${Number(value).toFixed(1)} s`

function CopyValue({ value, className = '' }) {
  const [copied, setCopied] = useState(false)
  if (!value) return <span className={`audit-muted ${className}`}>—</span>
  const copy = async (event) => {
    event.stopPropagation()
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1200)
    } catch {
      setCopied(false)
    }
  }
  return <span className={`audit-copy-value ${className}`} title={value}>
    <code>{short(value)}</code>
    <button onClick={copy} aria-label={`Copy ${value}`} title={copied ? 'Copied' : 'Copy'}>
      {copied ? <Check size={13} /> : <Copy size={13} />}
    </button>
  </span>
}

function resultTone(result) {
  if (result === 'VERIFIED') return 'emerald'
  if (result === 'TAMPERED' || result === 'ANCHOR FAILED' || result === 'VERIFY FAILED') return 'red'
  return 'amber'
}

export default function AuditExplorer() {
  const [status, setStatus] = useState(null)
  const [logs, setLogs] = useState([])
  const [batches, setBatches] = useState([])
  const [selectedBatch, setSelectedBatch] = useState(null)
  const [selectedAction, setSelectedAction] = useState('')
  const [proof, setProof] = useState(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [error, setError] = useState(null)

  const load = useCallback(async (quiet = false) => {
    if (quiet) setRefreshing(true)
    else setLoading(true)
    try {
      const [nextStatus, nextLogs, nextBatches] = await Promise.all([
        api.auditStatus(), api.auditLogs({ limit: 100, offset: 0 }), api.auditBatches({ limit: 100, offset: 0 }),
      ])
      setStatus(nextStatus)
      setLogs(nextLogs.records || [])
      setBatches(nextBatches.batches || [])
      setError(null)
      if (selectedAction && !(nextLogs.records || []).some((record) => record.action_id === selectedAction)) {
        setSelectedAction('')
        setProof(null)
      }
    } catch (cause) {
      setError(cause.message || 'Audit API is unavailable')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [selectedAction])

  useEffect(() => {
    load()
    const timer = window.setInterval(() => load(true), 5000)
    return () => window.clearInterval(timer)
  }, [load])

  const selectAction = async (actionId) => {
    setSelectedAction(actionId)
    setProof(null)
    if (!actionId) return
    try {
      setProof(await api.auditActionProof(actionId))
    } catch (cause) {
      setError(cause.message)
    }
  }

  const verify = async (tamper = false) => {
    if (!selectedAction) return
    setVerifying(true)
    try {
      let override
      if (tamper) {
        const result = await api.auditAction(selectedAction)
        override = { ...result.record, target: `${result.record.target || 'audit-record'} [tampered demo copy]` }
      }
      setProof(await api.verifyAuditAction(selectedAction, override))
      setError(null)
    } catch (cause) {
      setError(cause.message)
    } finally {
      setVerifying(false)
    }
  }

  const chooseBatch = async (batchId) => {
    try {
      setSelectedBatch(await api.auditBatch(batchId))
      setError(null)
    } catch (cause) {
      setError(cause.message)
    }
  }

  const explorer = status?.explorer_url
  const isSepolia = status?.chain_id === 11155111
  const pendingPercent = useMemo(() => status?.batch_size
    ? Math.min(100, (status.pending_log_count / status.batch_size) * 100) : 0, [status])
  const latestLogs = logs

  return <div className="audit-page">
    <div className="eyebrow"><span className="eyebrow__line" /> IMMUTABLE ACTION EVIDENCE</div>
    <div className="page-heading audit-heading">
      <div><h1>Blockchain Audit</h1><p>Off-chain action logs, deterministic Merkle proofs, and on-chain batch commitments.</p></div>
      <button className="button-secondary audit-refresh" onClick={() => load(true)} disabled={refreshing}>
        <RefreshCw size={15} className={refreshing ? 'audit-spin' : ''} /> {refreshing ? 'Refreshing' : 'Refresh'}
      </button>
    </div>

    {error && <div className="error-banner audit-error"><AlertTriangle size={17} /><span>{error}</span><button onClick={() => load(true)}>Retry</button></div>}

    <section className="audit-network panel">
      <div className="audit-network__identity"><span className="audit-network__icon"><Blocks size={21} /></span><div><span className="section-heading__overline">{isSepolia ? 'PUBLIC TEST NETWORK' : 'LOCAL DEVELOPMENT NETWORK'}</span><h2>{status?.network_name || status?.network || 'Loading network'}</h2></div><StatusPill label={!status ? 'CHECKING' : status.rpc_connected ? 'RPC CONNECTED' : (isSepolia ? 'SEPOLIA RPC OFFLINE' : 'RPC OFFLINE')} tone={!status ? 'cyan' : status.rpc_connected ? 'emerald' : 'red'} pulse={Boolean(status?.rpc_connected)} /></div>
      <div className="audit-network__fields">
        <div><span>Chain ID</span><strong>{status?.chain_id ?? '—'}</strong></div>
        <div><span>Latest block</span><strong>{status?.latest_block ?? status?.current_block ?? '—'}</strong></div>
        <div className="audit-network__contract"><span>Registry contract</span><CopyValue value={status?.contract_address} /></div>
      </div>
      {!status?.contract_available && <div className={`audit-network__alert ${status?.rpc_connected ? 'audit-network__alert--contract' : ''}`} role="status">{status?.rpc_connected ? 'CONTRACT NOT DEPLOYED ON CURRENT NETWORK' : (isSepolia ? 'SEPOLIA RPC OFFLINE' : 'BLOCKCHAIN RPC OFFLINE')}</div>}
      <div className="audit-network__note">{isSepolia ? 'Sepolia is a public Ethereum test network using test ETH, not Ethereum Mainnet. Audit roots are committed by ROOT_AUTHORIZER.' : 'Hardhat Local · Chain 31337 · Merkle roots are committed by ROOT_AUTHORIZER. No public explorer is configured.'}</div>
      {status?.explorer?.contract_url && <a className="audit-explorer-link audit-contract-link" href={status.explorer.contract_url} target="_blank" rel="noopener noreferrer">View Contract on Etherscan <ExternalLink size={14} /></a>}
    </section>

    <section className="audit-kpis" aria-label="Audit queue metrics">
      <motion.article className="panel audit-kpi" whileHover={{ y: -2 }}><span className="audit-kpi__icon audit-kpi__icon--cyan"><Layers3 size={18} /></span><span className="audit-kpi__label">PENDING LOGS</span><strong>{loading ? '—' : status?.pending_log_count ?? '—'}</strong><small>off-chain, not yet assigned</small></motion.article>
      <motion.article className="panel audit-kpi" whileHover={{ y: -2 }}><span className="audit-kpi__icon"><ScanSearch size={18} /></span><span className="audit-kpi__label">BATCH THRESHOLD</span><strong>{loading ? '—' : `${status?.batch_size ?? '—'} logs`}</strong><div className="audit-progress"><span style={{ width: `${pendingPercent}%` }} /></div><small>{status?.batch_max_age_seconds ?? '—'} s maximum pending age</small></motion.article>
      <motion.article className="panel audit-kpi" whileHover={{ y: -2 }}><span className="audit-kpi__icon audit-kpi__icon--amber"><Timer size={18} /></span><span className="audit-kpi__label">OLDEST PENDING AGE</span><strong>{loading ? '—' : seconds(status?.oldest_pending_age_seconds)}</strong><small>{status?.oldest_pending_action_id ? short(status.oldest_pending_action_id, 11, 5) : 'queue is clear'}</small></motion.article>
      <motion.article className="panel audit-kpi" whileHover={{ y: -2 }}><span className="audit-kpi__icon audit-kpi__icon--green"><ShieldCheck size={18} /></span><span className="audit-kpi__label">ANCHORED BATCHES</span><strong>{loading ? '—' : status?.anchored_batch_count ?? '—'}</strong><small>verified registry commitments</small></motion.article>
    </section>

    <div className="audit-main-grid">
      <section className="panel audit-batches-panel">
        <div className="panel__head"><div><span className="section-heading__overline">MERKLE ROOT REGISTRY</span><h3>Anchored batches</h3></div><span className="audit-count">{batches.length} total</span></div>
        {loading && batches.length === 0 ? <div className="audit-skeletons">{Array.from({ length: 4 }, (_, index) => <Skeleton key={index} style={{ height: 52 }} />)}</div> : batches.length === 0 ? <div className="audit-empty"><Layers3 size={25} /><strong>No sealed batches yet</strong><span>Governed actions are written to the append-only log. A root is anchored when the configured threshold is reached.</span></div> : <div className="audit-table-wrap"><table className="audit-table"><thead><tr><th>Batch ID / root</th><th>Logs</th><th>Block</th><th>Transaction</th><th>Status</th><th /></tr></thead><tbody>
          {batches.slice().reverse().map((batch) => <tr key={batch.batch_id} onClick={() => chooseBatch(batch.batch_id)} className={selectedBatch?.batch_id === batch.batch_id ? 'audit-row--selected' : ''}>
            <td><strong>{short(batch.batch_id, 18, 8)}</strong><small><CopyValue value={batch.merkle_root} /></small></td><td>{batch.log_count}</td><td>{batch.blockchain_block_number ?? '—'}{batch.explorer_block_url && <a className="audit-cell-link" href={batch.explorer_block_url} target="_blank" rel="noopener noreferrer" onClick={(event) => event.stopPropagation()} aria-label="View block on Etherscan"><ExternalLink size={12} /></a>}</td><td><span className="audit-transaction-cell"><CopyValue value={batch.blockchain_tx_hash} />{batch.explorer_transaction_url && <a className="audit-cell-link" href={batch.explorer_transaction_url} target="_blank" rel="noopener noreferrer" onClick={(event) => event.stopPropagation()} aria-label="View transaction on Etherscan"><ExternalLink size={12} /></a>}</span></td><td><StatusPill label={batch.status === 'ANCHORED' ? 'ANCHORED' : batch.anchor_error ? 'ANCHOR FAILED' : 'PENDING'} tone={batch.status === 'ANCHORED' ? 'emerald' : batch.anchor_error ? 'red' : 'amber'} /></td><td><ChevronRight size={16} /></td>
          </tr>)}
        </tbody></table></div>}
      </section>

      <section className="panel audit-open-panel">
        <div className="panel__head"><div><span className="section-heading__overline">OPEN QUEUE</span><h3>Current batch window</h3></div><Clock3 size={18} className="panel__accent-icon" /></div>
        {status?.current_batch ? <>
          <div className="audit-open-meter"><div><strong>{status.current_batch.log_count}</strong><span> / {status.batch_size} logs</span></div><div className="audit-open-meter__track"><span style={{ width: `${pendingPercent}%` }} /></div></div>
          <div className="audit-open-row"><span>First action</span><code>{short(status.current_batch.first_action_id, 16, 7)}</code></div>
          <div className="audit-open-row"><span>Latest action</span><code>{short(status.current_batch.last_action_id, 16, 7)}</code></div>
          <div className="audit-open-row"><span>Queue age</span><strong>{seconds(status.oldest_pending_age_seconds)}</strong></div>
          <p className="audit-open-note">Pending records remain off-chain until the size or age trigger seals this batch.</p>
        </> : <div className="audit-empty audit-empty--compact"><Check size={22} /><strong>No open batch</strong><span>All logged actions are currently assigned to batches.</span></div>}
      </section>
    </div>

    <section className="panel audit-verifier">
      <div className="panel__head audit-verifier__heading"><div><span className="section-heading__overline">RECORD-TO-ROOT VALIDATION</span><h3>Verify an action</h3><p>Recompute the leaf, validate sibling directions, then compare the result with the registry root.</p></div><div className="audit-verifier__seal"><Fingerprint size={22} /><span>PUBLIC PROOF CHECK</span></div></div>
      <div className="audit-verify-controls"><label htmlFor="audit-action-select">Action ID</label><select id="audit-action-select" value={selectedAction} onChange={(event) => selectAction(event.target.value)}>
        <option value="">Select a logged action</option>
        {latestLogs.map((record) => <option value={record.action_id} key={record.action_id}>{record.agent_id} · {record.action} · {short(record.action_id, 15, 6)}</option>)}
      </select>
      <button className="button-primary" onClick={() => verify(false)} disabled={!selectedAction || verifying}><ShieldCheck size={15} /> {verifying ? 'Verifying…' : 'Verify action'}</button>
      <button className="button-secondary audit-tamper-button" onClick={() => verify(true)} disabled={!selectedAction || verifying}><ShieldX size={15} /> Test tamper detection</button></div>

      {proof ? <div className="audit-proof-layout">
        <div className="audit-record-summary"><div className="audit-proof-subhead"><span>ORIGINAL RECORD</span><StatusPill label={proof.result} tone={resultTone(proof.result)} /></div>
          <div className="audit-summary-line"><span>Agent / action</span><strong>{proof.record?.agent_id} <i>·</i> {proof.record?.action}</strong></div>
          <div className="audit-summary-line"><span>Governance verdict</span><strong>{proof.record?.governance_verdict || '—'}</strong></div>
          <div className="audit-summary-line"><span>Timestamp</span><strong>{time(proof.record?.timestamp)}</strong></div>
          <div className="audit-summary-line"><span>Batch</span><CopyValue value={proof.batch_id} /></div>
          <div className="audit-summary-line"><span>Leaf hash</span><CopyValue value={proof.record_hash} /></div>
        </div>
        <div className="audit-proof-path"><div className="audit-proof-subhead"><span>MERKLE PROOF</span><span>{proof.proof_siblings?.length ?? 0} siblings</span></div>
          {proof.proof_siblings?.length ? <div className="audit-siblings">{proof.proof_siblings.map((sibling, index) => <div className="audit-sibling" key={`${sibling.hash}-${index}`}><span className={`audit-sibling__side audit-sibling__side--${sibling.position}`}>{sibling.position.toUpperCase()}</span><CopyValue value={sibling.hash} /></div>)}</div> : <div className="audit-proof-pending"><Timer size={16} /> Proof path becomes available when this action is assigned to a sealed batch.</div>}
          <div className="audit-root-grid"><div><span>Calculated root</span><CopyValue value={proof.calculated_root} /></div><div><span>On-chain root</span><CopyValue value={proof.blockchain_root} /></div></div>
          {proof.blockchain?.transaction_hash && <div className="audit-proof-tx"><div><span>Transaction</span><CopyValue value={proof.blockchain.transaction_hash} /></div><div><span>Block / chain</span><strong>{proof.blockchain.block_number} <i>·</i> {proof.blockchain.chain_id}</strong></div>{explorer && <a href={`${explorer}/tx/${proof.blockchain.transaction_hash}`} target="_blank" rel="noreferrer">View on explorer <ExternalLink size={13} /></a>}</div>}
        </div>
      </div> : <div className="audit-verify-placeholder"><ScanSearch size={23} /><span>Select an action to inspect its canonical leaf hash and batch proof.</span></div>}
      <AnimatePresence>{proof?.result === 'TAMPERED' && <motion.div className="audit-tamper-result" initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}><XCircle size={18} /><div><strong>TAMPERING DETECTED</strong><span>The submitted record copy does not reconstruct the anchored Merkle root. The stored audit log was not modified.</span></div></motion.div>}</AnimatePresence>
    </section>

    <AnimatePresence>{selectedBatch && <motion.aside className="audit-drawer-backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setSelectedBatch(null)}>
      <motion.section className="audit-drawer panel" initial={{ x: 35, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 25, opacity: 0 }} onClick={(event) => event.stopPropagation()}>
        <div className="audit-drawer__head"><div><span className="section-heading__overline">BATCH COMMITMENT</span><h2>Batch details</h2></div><button onClick={() => setSelectedBatch(null)} aria-label="Close batch details"><XCircle size={19} /></button></div>
        <StatusPill label={selectedBatch.proof_status || selectedBatch.status} tone={resultTone(selectedBatch.proof_status || selectedBatch.status)} />
        <div className="audit-drawer__fields">
          <div><span>Batch ID</span><CopyValue value={selectedBatch.batch_id} /></div>
          <div><span>Merkle root</span><CopyValue value={selectedBatch.merkle_root} /></div>
          <div><span>Logs</span><strong>{selectedBatch.log_count}</strong></div>
          <div><span>Action time range</span><strong>{time(selectedBatch.start_timestamp)}<br />to {time(selectedBatch.end_timestamp)}</strong></div>
          <div><span>First action</span><CopyValue value={selectedBatch.first_action_id} /></div>
          <div><span>Last action</span><CopyValue value={selectedBatch.last_action_id} /></div>
          <div><span>Transaction hash</span><CopyValue value={selectedBatch.blockchain_tx_hash} /></div>
          <div><span>Block</span><strong>{selectedBatch.blockchain_block_number ?? 'Pending'}</strong></div>
          <div><span>Contract</span><CopyValue value={selectedBatch.blockchain_contract_address} /></div>
          {selectedBatch.explorer_transaction_url && <a className="audit-explorer-link" href={selectedBatch.explorer_transaction_url} target="_blank" rel="noopener noreferrer">View Transaction on Etherscan <ExternalLink size={14} /></a>}
          {selectedBatch.explorer_block_url && <a className="audit-explorer-link" href={selectedBatch.explorer_block_url} target="_blank" rel="noopener noreferrer">View Block on Etherscan <ExternalLink size={14} /></a>}
          {selectedBatch.explorer_contract_url && <a className="audit-explorer-link" href={selectedBatch.explorer_contract_url} target="_blank" rel="noopener noreferrer">View Contract on Etherscan <ExternalLink size={14} /></a>}
          {selectedBatch.anchor_error && <div className="audit-drawer__error"><AlertTriangle size={15} /> {selectedBatch.anchor_error}</div>}
        </div>
      </motion.section>
    </motion.aside>}</AnimatePresence>
  </div>
}
