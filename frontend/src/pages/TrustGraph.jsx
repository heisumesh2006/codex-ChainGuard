import { AnimatePresence, motion } from 'framer-motion'
import { ArrowLeft, ArrowRight, Fingerprint, GitBranch, LockKeyhole, ScanSearch, ShieldCheck, X } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import ReactFlow, { Background, BaseEdge, Controls, EdgeLabelRenderer, Handle, MiniMap, Position, getBezierPath } from 'reactflow'
import 'reactflow/dist/style.css'
import { api } from '../services/api'
import Skeleton from '../components/Skeleton'
import StatusPill from '../components/StatusPill'

const positions = {
  ROOT_AUTHORIZER: { x: 390, y: 35 }, Agent_A: { x: 390, y: 220 },
  Agent_B: { x: 390, y: 405 }, Agent_C: { x: 390, y: 590 }, Agent_D: { x: 815, y: 345 },
}
const short = (value, n = 9) => value ? `${value.slice(0, n)}…${value.slice(-6)}` : '—'

function AgentNode({ data }) {
  const root = data.label === 'ROOT_AUTHORIZER'
  const revoked = data.status === 'DECOMMISSIONED'
  return <div className={`graph-node ${root ? 'graph-node--root' : ''} ${revoked ? 'graph-node--revoked' : ''}`}>
    <Handle type="target" position={Position.Top} className="graph-node__handle" />
    <div className="graph-node__icon">{root ? <Fingerprint size={22} /> : revoked ? <LockKeyhole size={21} /> : <ShieldCheck size={21} />}</div>
    <div><span>{root ? 'SINGLE TRUST ROOT' : data.role}</span><strong>{data.label}</strong><small>{revoked ? 'REVOKED' : 'REGISTERED'}</small></div>
    <Handle type="source" position={Position.Bottom} className="graph-node__handle" />
  </div>
}

function TrustEdge(props) {
  const [path, labelX, labelY] = getBezierPath(props)
  const record = props.data.raw
  const delegation = record.evidence_type === 'DELEGATION'
  const revoked = record.delegation_status === 'REVOKED'
  return <><BaseEdge id={props.id} path={path} markerEnd={props.markerEnd} className={`trust-edge ${delegation && record.proof_status === 'PASS' ? 'trust-edge--animated' : ''}`} style={{ stroke: revoked ? '#cc6e81' : delegation ? '#59d5b2' : '#4aafd5', strokeWidth: delegation ? 2.4 : 1.5, opacity: delegation ? 1 : .7 }} /><EdgeLabelRenderer><button className={`trust-edge__label ${delegation ? 'trust-edge__label--delegated' : ''}`} style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }} onClick={() => props.data.onSelect({ type: 'edge', item: record })} title={`${record.permission} · ${record.proof_status} · ${short(record.transaction_hash)}`}><span>{record.permission}</span><small>{record.proof_status === 'PASS' ? '✓ PROOF' : '✕ PROOF'}</small></button></EdgeLabelRenderer></>
}

const nodeTypes = { agentNode: AgentNode }
const edgeTypes = { trustEdge: TrustEdge }

function ProofDrawer({ selection, onClose, agents }) {
  const [credentials, setCredentials] = useState(null)
  const [status, setStatus] = useState(null)
  useEffect(() => {
    setCredentials(null); setStatus(null)
    if (selection?.type !== 'node' || selection.item.id === 'ROOT_AUTHORIZER') return undefined
    let active = true
    Promise.all([api.agentCredentials(selection.item.id), api.revocation(selection.item.id)])
      .then(([nextCredentials, nextStatus]) => { if (active) { setCredentials(nextCredentials.credentials); setStatus(nextStatus) } })
    return () => { active = false }
  }, [selection])
  const item = selection?.item
  const agent = agents?.find((entry) => entry.agent_id === item?.id)
  return <AnimatePresence>{selection && <motion.aside className="graph-drawer" initial={{ x: 45, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 45, opacity: 0 }} transition={{ duration: .22 }}><div className="graph-drawer__head"><div><span className="section-heading__overline">{selection.type === 'edge' ? 'BLOCKCHAIN EVIDENCE' : 'AGENT IDENTITY'}</span><h3>{selection.type === 'edge' ? item.permission : item.id}</h3></div><button onClick={onClose} aria-label="Close details"><X size={18} /></button></div>
    {selection.type === 'edge' ? <div className="graph-drawer__body"><StatusPill label={item.proof_status === 'PASS' ? 'PROOF VERIFIED' : 'PROOF FAILED'} tone={item.proof_status === 'PASS' ? 'emerald' : 'red'} /><div className="graph-drawer__pair"><span>Delegator</span><strong>{item.from}</strong></div><div className="graph-drawer__pair"><span>Delegatee</span><strong>{item.to}</strong></div><div className="graph-drawer__pair"><span>Permission</span><strong>{item.permission}</strong></div><div className="graph-drawer__pair"><span>Evidence</span><strong>{item.evidence_type === 'ROOT_CREDENTIAL' ? 'Root credential' : 'Delegation anchor'}</strong></div><div className="graph-drawer__pair"><span>Authority source</span><strong>{item.authority_source}</strong></div><div className="graph-drawer__pair"><span>Block</span><strong>{item.block_number ?? '—'}</strong></div><div className="graph-drawer__hash"><span>Blockchain transaction</span><code title={item.transaction_hash}>{item.transaction_hash || '—'}</code></div><div className="graph-drawer__hash"><span>Content hash</span><code title={item.content_hash}>{item.content_hash || '—'}</code></div>{item.delegation_status === 'REVOKED' && <p className="graph-drawer__note">This historical delegation is anchored, but the delegatee was later revoked.</p>}</div> : <div className="graph-drawer__body">{item.id === 'ROOT_AUTHORIZER' ? <p className="graph-drawer__note">Single root authority. Root-issued credentials begin the verified permission paths.</p> : <><StatusPill label={status?.is_revoked ? 'REVOKED' : 'ACTIVE'} tone={status?.is_revoked ? 'red' : 'emerald'} /><div className="graph-drawer__pair"><span>Role</span><strong>{agent?.role || item.data?.role}</strong></div><div className="graph-drawer__pair"><span>Current permissions</span><strong>{agent?.effective_permissions?.join(', ') || 'None'}</strong></div><div className="graph-drawer__hash"><span>Ethereum identity</span><code>{agent?.blockchain_address || item.data?.address}</code></div><div className="graph-drawer__pair"><span>Revocation state</span><strong className={status?.is_revoked ? 'tone-block' : 'tone-allow'}>{status?.status || 'Checking…'}</strong></div><div className="graph-drawer__credential-title">Credentials</div>{credentials ? credentials.map((credential) => <div className="graph-drawer__credential" key={credential.credential_id}><b>{credential.permission}</b><span>{credential.proof_status} · issued by {credential.issuer}</span></div>) : <Skeleton style={{ height: 75 }} />}</>}</div>}
  </motion.aside>}</AnimatePresence>
}

export default function TrustGraph() {
  const [graph, setGraph] = useState(null)
  const [agents, setAgents] = useState(null)
  const [error, setError] = useState(null)
  const [selection, setSelection] = useState(null)
  const [agentId, setAgentId] = useState('Agent_C')
  const [permission, setPermission] = useState('CREATE_AGENT')
  const [trace, setTrace] = useState(null)
  const [tracing, setTracing] = useState(false)
  useEffect(() => { let active = true; Promise.all([api.graph(), api.agents()]).then(([g, a]) => { if (active) { setGraph(g); setAgents(a) } }).catch((cause) => { if (active) setError(cause.message) }); return () => { active = false } }, [])
  const nodes = useMemo(() => graph?.nodes?.map((node) => ({ ...node, position: positions[node.id] || node.position })) || [], [graph])
  const edges = useMemo(() => graph?.edges?.map((edge) => ({ ...edge, type: 'trustEdge', data: { raw: edge, onSelect: setSelection } })) || [], [graph])
  const selectedAgent = agents?.find((agent) => agent.agent_id === agentId)
  const permissions = Array.from(new Set(['CREATE_AGENT', ...(selectedAgent?.direct_permissions || []), ...(selectedAgent?.delegated_permissions || []).map((item) => item.permission), ...(selectedAgent?.revoked_permissions || []).map((item) => item.permission)]))
  const runTrace = async () => { setTracing(true); setTrace(null); try { setTrace(await api.trace(agentId, permission)) } catch (cause) { setError(cause.message) } finally { setTracing(false) } }
  const runRevokedActionTrace = async () => { setAgentId('Agent_C'); setPermission('CREATE_AGENT'); setTracing(true); setTrace(null); try { setTrace(await api.traceScenario('post_decommission')) } catch (cause) { setError(cause.message) } finally { setTracing(false) } }
  const rootFirst = trace?.chain?.length ? ['ROOT_AUTHORIZER', ...trace.chain.map((hop) => hop.to)] : []

  return <div className="trust-page"><div className="eyebrow"><span className="eyebrow__line" /> ANCHORED DELEGATION TOPOLOGY</div><div className="page-heading"><div><h1>Trust Graph</h1><p>Every line represents a real root credential or Ethereum-anchored delegation.</p></div><span className="page-heading__count">{edges.length || '—'} evidence links</span></div>{error && <div className="error-banner">{error}</div>}
    <div className="trust-layout"><section className="panel trust-canvas"><div className="trust-canvas__top"><div><GitBranch size={17} /><strong>Verified authority network</strong></div><span>Zoom, pan, or select evidence</span></div>{graph ? <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} onNodeClick={(_, node) => setSelection({ type: 'node', item: node })} onEdgeClick={(_, edge) => setSelection({ type: 'edge', item: edge.data.raw })} fitView fitViewOptions={{ padding: .18 }} minZoom={.45} maxZoom={1.5} nodesDraggable={false} proOptions={{ hideAttribution: true }}><Background color="#244665" gap={24} size={1} /><Controls showInteractive={false} /><MiniMap nodeColor={(node) => node.id === 'Agent_C' ? '#a65a69' : node.id === 'ROOT_AUTHORIZER' ? '#55c7e9' : '#3d8db0'} maskColor="#0b1627aa" /></ReactFlow> : <Skeleton className="trust-canvas__loading" />}<ProofDrawer selection={selection} onClose={() => setSelection(null)} agents={agents} /></section>
    <aside className="trust-side"><div className="panel trace-console"><div className="trace-console__head"><ScanSearch size={20} /><div><span className="section-heading__overline">MODULE 3</span><h3>Authority trace</h3></div></div><p>Follow one permission backward, verify each Ethereum hop, then display the rooted chain.</p><label>Trace agent<select value={agentId} onChange={(event) => { setAgentId(event.target.value); setPermission('CREATE_AGENT'); setTrace(null) }}>{['Agent_A', 'Agent_B', 'Agent_C', 'Agent_D'].map((value) => <option key={value}>{value}</option>)}</select></label><label>Permission<select value={permission} onChange={(event) => { setPermission(event.target.value); setTrace(null) }}>{permissions.map((value) => <option key={value}>{value}</option>)}</select></label><button className="button-primary trace-console__button" onClick={runTrace} disabled={tracing}>{tracing ? 'Verifying chain…' : 'Run blockchain trace'} <ArrowRight size={16} /></button><button className="trace-console__secondary" onClick={runRevokedActionTrace} disabled={tracing}>Trace Agent_C post-revocation action</button>
      <AnimatePresence mode="wait">{trace && <motion.div key={`${agentId}-${permission}-${trace.verdict}`} className="trace-result" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}><div className="trace-result__verdict"><StatusPill label={trace.verdict} tone={trace.valid ? 'emerald' : 'red'} /><span>{trace.trace_latency_ms.toFixed(1)} ms</span></div><p>{trace.reason}</p>{rootFirst.length > 0 && <><span className="trace-result__label">BACKWARD SEARCH</span><div className="trace-result__path">{[...rootFirst].reverse().map((name, index) => <motion.span key={`${name}-${index}`} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: index * .16 }}>{name}{index < rootFirst.length - 1 && <ArrowLeft size={12} />}</motion.span>)}</div><span className="trace-result__label">VERIFIED ROOT-FIRST CHAIN</span><div className="trace-result__path trace-result__path--verified">{rootFirst.map((name, index) => <motion.span key={`${name}-${index}`} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .55 + index * .16 }}>{name}{index < rootFirst.length - 1 && <ArrowRight size={12} />}</motion.span>)}</div><div className="trace-result__hops">{trace.chain.map((hop, index) => <div key={hop.record_id}><span>Hop {index + 1} · {hop.evidence_type}</span><b className={hop.proof_verified ? 'tone-allow' : 'tone-block'}>{hop.proof_verified ? 'PROOF PASS' : 'PROOF FAIL'}</b></div>)}</div></>}</motion.div>}</AnimatePresence>
    </div><div className="panel trust-legend"><span className="section-heading__overline">GRAPH KEY</span><div><span className="trust-legend__dot trust-legend__dot--root" /> Root credential</div><div><span className="trust-legend__dot trust-legend__dot--delegation" /> Verified delegation</div><div><span className="trust-legend__dot trust-legend__dot--revoked" /> Revoked agent / grant</div><p>Historical proof validity and current revocation status are shown separately.</p></div></aside></div>
  </div>
}
