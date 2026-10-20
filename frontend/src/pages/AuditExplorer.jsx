import { AnimatePresence, motion } from 'framer-motion'
import {
  AlertTriangle, Blocks, Check, ChevronRight, Clock3,
  Copy, ExternalLink, Fingerprint, Layers3, RefreshCw, ScanSearch,
  ShieldCheck, ShieldX, Timer, XCircle,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import StatusPill from '../components/StatusPill'
import Skeleton from '../components/Skeleton'
import { api } from '../services/api'

const short = (value, head = 13, tail = 9) => value ? `${value.slice(0, head)}…${value.slice(-tail)}` : '—'
const time = (value) => value ? new Date(value).toLocaleString() : '—'
const seconds = (value) => value == null ? '—' : `${Number(value).toFixed(1)} s`

function CopyValue({ value, className = '' }) {
  const [copied, setCopied] = useState(false)
  const [copyError, setCopyError] = useState(false)
  if (!value) return <span className={`audit-muted ${className}`}>—</span>
  const copy = async (event) => {
    event.stopPropagation()
    setCopyError(false)
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1200)
    } catch {
      setCopied(false)
      setCopyError(true)
    }
  }
  return <span className={`audit-copy-value ${className}`} title={value}>
    <code>{short(value)}</code>
    <button onClick={copy} aria-label={`Copy ${value}`} title={copied ? 'Copied' : 'Copy'}>
      {copied ? <Check size={13} /> : <Copy size={13} />}
    </button>
    {copyError && <span role="status" style={{ display: 'block', maxWidth: 260, whiteSpace: 'normal', overflowWrap: 'anywhere' }}>Clipboard unavailable. Copy this full value manually: {value}</span>}
  </span>
}

function resultTone(result) {
  if (result === 'VERIFIED') return 'emerald'
  if (result === 'TAMPERED' || result === 'ANCHOR FAILED' || result === 'VERIFY FAILED') return 'red'
  return 'amber'
}

export default function AuditExplorer() {
  const loadingRequest = useRef(false)
  const proofRequest = useRef(0)
  const verificationBusy = useRef(false)
  const [status, setStatus] = useState(null)
  const [logs, setLogs] = useState([])
  const [batches, setBatches] = useState([])
  const [selectedBatch, setSelectedBatch] = useState(null)
  const [selectedAction, setSelectedAction] = useState('')
  const [proof, setProof] = useState(null)
  const [simulation, setSimulation] = useState(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [error, setError] = useState(null)
  const [proofError, setProofError] = useState(null)

  const load = useCallback(async (quiet = false) => {
    if (loadingRequest.current) return
    loadingRequest.current = true
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
        ++proofRequest.current
        verificationBusy.current = false
        setVerifying(false)
        setSelectedAction('')
        setProof(null)
        setSimulation(null)
        setProofError(null)
      }
    } catch (cause) {
      setError(cause.message || 'Audit API is unavailable')
    } finally {
      loadingRequest.current = false
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
    const requestId = ++proofRequest.current
    setSelectedAction(actionId)
    setProof(null)
    setSimulation(null)
    setProofError(null)
    verificationBusy.current = false
    setVerifying(Boolean(actionId))
    if (!actionId) return
    try {
      const nextProof = await api.auditActionProof(actionId)
      if (requestId === proofRequest.current) setProof(nextProof)
    } catch (cause) {
      if (requestId === proofRequest.current) setProofError(cause.message)
    } finally {
      if (requestId === proofRequest.current) setVerifying(false)
    }
  }

  const verify = async (tamper = false) => {
    if (!selectedAction || verificationBusy.current) return
    verificationBusy.current = true
    const requestId = ++proofRequest.current
    setVerifying(true)
    setSimulation(null)
    setProof(null)
    setProofError(null)
    try {
      const original = await api.verifyAuditAction(selectedAction)
      if (requestId !== proofRequest.current) return
      setProof(original)
      if (tamper) {
        if (original.result !== 'VERIFIED' || !original.blockchain_root) {
          setProofError('Simulation requires a successfully verified original and an available anchored root.')
          return
        }
        const originalValue = original.record.target
        const modifiedValue = `${originalValue || 'audit-record'} [tampered demo copy]`
        const candidate = { ...original.record, target: modifiedValue }
        const modified = await api.verifyAuditAction(selectedAction, candidate)
        if (requestId !== proofRequest.current) return
        const confirmed = modified.result === 'TAMPERED' && modified.record_hash !== original.record_hash
          && modified.action_id === original.action_id && modified.batch_id === original.batch_id
          && modified.blockchain_root?.toLowerCase() === original.blockchain_root.toLowerCase()
        setSimulation({ originalValue, modifiedValue, modified, confirmed })
      }
    } catch (cause) {
      if (requestId === proofRequest.current) setProofError(cause.message)
    } finally {
      if (requestId === proofRequest.current) {
        verificationBusy.current = false
        setVerifying(false)
      }
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
  const isHardhat = status?.chain_id === 31337
  const networkLabel = status ? (isSepolia ? 'PUBLIC TEST NETWORK' : isHardhat ? 'LOCAL DEVELOPMENT NETWORK' : 'UNKNOWN NETWORK') : error ? 'NETWORK UNAVAILABLE' : 'CHECKING NETWORK'
  const pendingPercent = useMemo(() => status?.batch_size
    ? Math.min(100, (status.pending_log_count / status.batch_size) * 100) : 0, [status])
  const latestLogs = logs

  return <div className="audit-page">
    <div className="eyebrow"><span className="eyebrow__line" /> IMMUTABLE ACTION EVIDENCE</div>
    <div className="page-heading audit-heading">
      <div><h1>Blockchain Audit</h1><p>Off-chain action logs, deterministic Merkle proofs, and on-chain batch commitments.</p></div>
      <button className="button-secondary audit-refresh" onClick={() => { selectAction(selectedAction); load(true) }} disabled={refreshing}>
        <RefreshCw size={15} className={refreshing ? 'audit-spin' : ''} /> {refreshing ? 'Refreshing' : 'Refresh'}
      </button>
    </div>

    {(error || proofError) && <div className="error-banner audit-error"><AlertTriangle size={17} /><span>{proofError || error}</span><button onClick={() => proofError ? selectAction(selectedAction) : load(true)}>Retry</button></div>}

    <section className="audit-network panel">
      <div className="audit-network__identity"><span className="audit-network__icon"><Blocks size={21} /></span><div><span className="section-heading__overline">{networkLabel}</span><h2>{status?.network_name || status?.network || (error ? 'Network unavailable' : 'Loading network')}</h2></div><StatusPill label={!status ? (error ? 'UNAVAILABLE' : 'CHECKING') : status.rpc_connected ? 'RPC CONNECTED' : (isSepolia ? 'SEPOLIA RPC OFFLINE' : 'RPC OFFLINE')} tone={!status ? 'cyan' : status.rpc_connected ? 'emerald' : 'red'} pulse={Boolean(status?.rpc_connected)} /></div>
      <div className="audit-network__fields">
        <div><span>Chain ID</span><strong>{status?.chain_id ?? '—'}</strong></div>
        <div><span>Latest block</span><strong>{status?.latest_block ?? status?.current_block ?? '—'}</strong></div>
        <div className="audit-network__contract"><span>Registry contract</span><CopyValue value={status?.contract_address} /></div>
      </div>
      {status && !status.contract_available && <div className={`audit-network__alert ${status?.rpc_connected ? 'audit-network__alert--contract' : ''}`} role="status">{status?.rpc_connected ? 'CONTRACT NOT DEPLOYED ON CURRENT NETWORK' : (isSepolia ? 'SEPOLIA RPC OFFLINE' : 'BLOCKCHAIN RPC OFFLINE')}</div>}
      <div className="audit-network__note">{!status ? (error ? 'Network metadata could not be loaded. Retry to check the configured network.' : 'Checking the configured network and registry connection?') : isSepolia ? 'Sepolia is a public Ethereum test network using test ETH, not Ethereum Mainnet. Audit roots are committed by ROOT_AUTHORIZER.' : 'Hardhat Local · Chain 31337 · Merkle roots are committed by ROOT_AUTHORIZER. No public explorer is configured.'}</div>
      {status?.explorer?.contract_url && <a className="audit-explorer-link audit-contract-link" href={status.explorer.contract_url} target="_blank" rel="noopener noreferrer">View Contract on Etherscan <ExternalLink size={14} /></a>}
    </section>

    <section className="audit-kpis" aria-label="Audit queue metrics">
      <motion.article className="panel audit-kpi" whileHover={{ y: -2 }}><span className="audit-kpi__icon audit-kpi__icon--cyan"><Layers3 size={18} /></span><span className="audit-kpi__label">PENDING LOGS</span><strong>{loading ? '—' : status?.pending_log_count ?? '—'}</strong><small>off-chain, not yet assigned</small></motion.article>
      <motion.article className="panel audit-kpi" whileHover={{ y: -2 }}><span className="audit-kpi__icon"><ScanSearch size={18} /></span><span className="audit-kpi__label">BATCH THRESHOLD</span><strong>{loading ? '—' : `${status?.batch_size ?? '—'} logs`}</strong><div className="audit-progress"><span style={{ width: `${pendingPercent}%` }} /></div><small>{status?.batch_max_age_seconds ?? '—'} s maximum pending age</small></motion.article>
      <motion.article className="panel audit-kpi" whileHover={{ y: -2 }}><span className="audit-kpi__icon audit-kpi__icon--amber"><Timer size={18} /></span><span className="audit-kpi__label">OLDEST PENDING AGE</span><strong>{loading ? '—' : seconds(status?.oldest_pending_age_seconds)}</strong><small>{status?.oldest_pending_action_id ? short(status.oldest_pending_action_id, 11, 5) : status ? 'queue is clear' : 'queue status unavailable'}</small></motion.article>
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
        </> : !status ? <div className="audit-empty audit-empty--compact"><Clock3 size={22} /><strong>{error ? 'Queue unavailable' : 'Checking queue'}</strong><span>Waiting for audit status.</span></div> : <div className="audit-empty audit-empty--compact"><Check size={22} /><strong>No open batch</strong><span>All logged actions are currently assigned to batches.</span></div>}
      </section>
    </div>

    <section className="panel audit-verifier">
      <div className="panel__head audit-verifier__heading"><div><span className="section-heading__overline">RECORD-TO-ROOT VALIDATION</span><h3>Verify an action</h3><p>Recompute the leaf, validate sibling directions, then compare the result with the registry root.</p></div><div className="audit-verifier__seal"><Fingerprint size={22} /><span>PUBLIC PROOF CHECK</span></div></div>
      <div className="audit-verify-controls"><label htmlFor="audit-action-select">Action ID</label><select id="audit-action-select" value={selectedAction} onChange={(event) => selectAction(event.target.value)}>
        <option value="">Select a logged action</option>
        {latestLogs.map((record) => <option value={record.action_id} key={record.action_id}>{record.agent_id} · {record.action} · {short(record.action_id, 15, 6)}</option>)}
      </select>
      <button className="button-primary" onClick={() => verify(false)} disabled={!selectedAction || verifying}><ShieldCheck size={15} /> {verifying ? 'Verifying…' : 'Verify Original'}</button>
      <button className="button-secondary audit-tamper-button" onClick={() => verify(true)} disabled={!selectedAction || verifying}><ShieldX size={15} /> Simulate Tampering</button></div>

      {proof ? <div className="audit-proof-layout">
        <div className="audit-record-summary"><div className="audit-proof-subhead"><span>{simulation ? 'ORIGINAL STORED RECORD' : 'ORIGINAL AUDIT RECORD'}</span><StatusPill label={proof.result} tone={resultTone(proof.result)} /></div>
          <div className="audit-summary-line"><span>Agent / action</span><strong>{proof.record?.agent_id} <i>·</i> {proof.record?.action}</strong></div>
          <div className="audit-summary-line"><span>Governance verdict</span><strong>{proof.record?.governance_verdict || '—'}</strong></div>
          <div className="audit-summary-line"><span>Timestamp</span><strong>{time(proof.record?.timestamp)}</strong></div>
          <div className="audit-summary-line"><span>Action ID</span><CopyValue value={proof.action_id} /></div>
          <div className="audit-summary-line"><span>Target</span><code>{JSON.stringify(proof.record?.target ?? null)}</code></div>
          <div className="audit-summary-line"><span>Batch</span><CopyValue value={proof.batch_id} /></div>
          <div className="audit-summary-line"><span>Original leaf hash</span><CopyValue value={proof.record_hash} /></div>
          <p className="audit-proof-explanation">{proof.result === 'VERIFIED' ? 'The original audit record matches the cryptographic commitment anchored on the selected blockchain.' : 'The original record has not been verified against an available blockchain commitment. Pending, missing or failed evidence is not a successful verification.'}</p>
        </div>
        <div className="audit-proof-path"><div className="audit-proof-subhead"><span>MERKLE PROOF</span><span>{proof.proof_siblings?.length ?? 0} siblings</span></div>
          {proof.proof_siblings?.length ? <div className="audit-siblings">{proof.proof_siblings.map((sibling, index) => <div className="audit-sibling" key={`${sibling.hash}-${index}`}><span className={`audit-sibling__side audit-sibling__side--${sibling.position}`}>{sibling.position.toUpperCase()}</span><CopyValue value={sibling.hash} /></div>)}</div> : <div className="audit-proof-pending"><Timer size={16} /> {proof.batch_id && proof.calculated_root ? 'A single-record proof needs no siblings: its leaf is the root.' : 'Proof path is unavailable until this action belongs to a valid sealed batch.'}</div>}
          <div className="audit-root-grid"><div><span>Reconstructed original root</span><CopyValue value={proof.calculated_root} /></div><div><span>Anchored root</span><CopyValue value={proof.blockchain_root} /></div></div>
          <p className="audit-proof-explanation">{status?.network_name || 'Network unavailable'} · Chain {proof.blockchain?.chain_id ?? status?.chain_id ?? 'unknown'} · Original record → Canonical JSON → Keccak-256 leaf → Merkle proof → Anchored root → {proof.result}</p>
          {proof.blockchain?.transaction_hash && <div className="audit-proof-tx"><div><span>Transaction</span><CopyValue value={proof.blockchain.transaction_hash} /></div><div><span>Block / chain</span><strong>{proof.blockchain.block_number} <i>·</i> {proof.blockchain.chain_id}</strong></div>{explorer && <a href={`${explorer}/tx/${proof.blockchain.transaction_hash}`} target="_blank" rel="noreferrer">View on explorer <ExternalLink size={13} /></a>}</div>}
        </div>
      </div> : <div className="audit-verify-placeholder" role="status"><ScanSearch size={23} /><span>{verifying ? "Verifying the selected record. Please wait." : selectedAction ? "Verification evidence is unavailable. Check the error above or verify the original again." : "Select an action to inspect its canonical leaf hash and batch proof."}</span></div>}
      <AnimatePresence>{simulation && <motion.section className="audit-simulation" aria-label="Simulated modified copy" initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
        <div className="audit-proof-subhead"><span>SIMULATED MODIFIED COPY</span><StatusPill label={simulation.confirmed ? 'TAMPERED' : 'NOT CONFIRMED'} tone={simulation.confirmed ? 'red' : 'amber'} /></div>
        <div className="audit-comparison-grid">
          <div><span>Changed field</span><strong>Target (target)</strong></div>
          <div><span>Original target value</span><code>{JSON.stringify(simulation.originalValue ?? null)}</code></div>
          <div><span>Modified target value</span><code>{JSON.stringify(simulation.modifiedValue)}</code></div>
          <div><span>Original leaf hash</span><CopyValue value={proof.record_hash} /></div>
          <div><span>Modified leaf hash</span><CopyValue value={simulation.modified.record_hash} /></div>
          <div><span>Stored blockchain root</span><CopyValue value={simulation.modified.blockchain_root} /></div>
          <div><span>Modified reconstructed root</span>{simulation.modified.calculated_root ? <CopyValue value={simulation.modified.calculated_root} /> : <p>Unavailable: the verifier rejects the changed committed leaf before returning a valid reconstructed root.</p>}</div>
        </div>
        <p className="audit-proof-explanation">Modified copy → Canonical JSON → Recomputed leaf → Original Merkle proof → {simulation.confirmed ? 'FAILED against the anchored commitment' : 'Comparison not confirmed'}</p>
        <div className="audit-tamper-result" role="status"><XCircle size={18} /><div><strong>{simulation.confirmed ? 'TAMPERING DETECTED' : 'SIMULATION NOT CONFIRMED'}</strong><span>{simulation.confirmed ? 'The selected record is unchanged. A temporary copy with a modified target fails validation against the original blockchain-anchored Merkle root. No audit record, batch or blockchain transaction was created or changed.' : 'The verification evidence is incomplete or inconsistent. This is not a successful tamper-detection demonstration; verify the original again.'}</span></div></div>
      </motion.section>}</AnimatePresence>
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
