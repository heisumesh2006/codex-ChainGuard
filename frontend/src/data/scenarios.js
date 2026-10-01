export const scenarios = [
  { id: 'normal', title: 'Normal action', eyebrow: 'AUTHORIZED BASELINE', actor: 'Agent_B', description: 'A purchase agent performs a routine permissioned action. The chain and behavior should remain within its normal profile.', tone: 'emerald' },
  { id: 'self_escalation', title: 'Self escalation', eyebrow: 'ROOT AUTHORITY ATTACK', actor: 'Agent_D', description: 'Agent_D attempts to grant itself CREATE_AGENT without a trusted root grant or delegation.', tone: 'red' },
  { id: 'unauthorized_delegation', title: 'Unauthorized delegation', eyebrow: 'DELEGATION ATTACK', actor: 'Agent_D', description: 'Agent_D attempts to delegate CREATE_AGENT to Agent_C without holding that permission.', tone: 'red' },
  { id: 'post_decommission', title: 'Post-revocation activity', eyebrow: 'REVOKED ACTOR', actor: 'Agent_C', description: 'Agent_C attempts to use CREATE_AGENT after its decommissioning was anchored on Ethereum.', tone: 'red' },
  { id: 'scope_creep', title: 'Scope creep', eyebrow: 'AUTHORIZED ANOMALY', actor: 'Agent_B', description: 'Agent_B has valid CREATE_AGENT authority, but its behavior is unusual relative to the trained baseline.', tone: 'amber' },
]
export const autoDemoOrder = ['normal', 'self_escalation', 'unauthorized_delegation', 'scope_creep', 'post_decommission']
export const scenarioById = Object.fromEntries(scenarios.map((item) => [item.id, item]))
