const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options.headers },
  })
  if (!response.ok) {
    const details = await response.text()
    throw new Error(`${response.status} ${response.statusText}: ${details}`)
  }
  return response.json()
}

export const api = {
  health: () => request('/api/health'),
  overview: () => request('/api/system/overview'),
  agents: () => request('/api/agents'),
  agentCredentials: (agentId) => request(`/api/agents/${encodeURIComponent(agentId)}/credentials`),
  trace: (agentId, permission) => request(`/api/trace?agent_id=${encodeURIComponent(agentId)}&permission=${encodeURIComponent(permission)}`),
  traceScenario: (name) => request(`/api/trace/scenario/${encodeURIComponent(name)}`),
  graph: () => request('/api/delegation-graph'),
  metrics: () => request('/api/metrics'),
  revocation: (agentId) => request(`/api/revocation/${encodeURIComponent(agentId)}`),
  finalReport: () => request('/api/final-report'),
  evaluate: (action) => request('/api/governance/evaluate', { method: 'POST', body: JSON.stringify(action) }),
  scenario: (name) => request(`/api/scenarios/${encodeURIComponent(name)}`, { method: 'POST' }),
  auditStatus: () => request('/api/audit/status'),
  auditLogs: (params = {}) => request(`/api/audit/logs?${new URLSearchParams(params)}`),
  auditBatches: (params = {}) => request(`/api/audit/batches?${new URLSearchParams(params)}`),
  auditBatch: (batchId) => request(`/api/audit/batches/${encodeURIComponent(batchId)}`),
  auditAction: (actionId) => request(`/api/audit/actions/${encodeURIComponent(actionId)}`),
  auditActionProof: (actionId) => request(`/api/audit/actions/${encodeURIComponent(actionId)}/proof`),
  verifyAuditAction: (actionId, recordOverride) => request(`/api/audit/actions/${encodeURIComponent(actionId)}/verify`, {
    method: 'POST', body: JSON.stringify(recordOverride ? { record_override: recordOverride } : {}),
  }),
  governanceSocket: () => new WebSocket(`${API_BASE.replace(/^http/, 'ws')}/ws/governance`),
}
