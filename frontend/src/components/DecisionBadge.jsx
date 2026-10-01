import { Check, Eye, ShieldX } from 'lucide-react'

export default function DecisionBadge({ decision, compact = false }) {
  const Icon = decision === 'ALLOW' ? Check : decision === 'REVIEW' ? Eye : ShieldX
  return <span className={`decision-badge decision-badge--${String(decision).toLowerCase()} ${compact ? 'decision-badge--compact' : ''}`}><Icon size={compact ? 12 : 14} />{decision}</span>
}
