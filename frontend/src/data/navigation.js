import {
  Activity, BarChart3, Blocks, FlaskConical, LayoutDashboard,
  LockKeyhole, Network, Radio,
} from 'lucide-react'

export const navigation = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, title: 'Command overview' },
  { to: '/agents', label: 'Agents', icon: Blocks, title: 'Identity registry' },
  { to: '/trust-graph', label: 'Trust Graph', icon: Network, title: 'Delegation topology' },
  { to: '/governance', label: 'Live Governance', icon: Radio, title: 'Pipeline monitor' },
  { to: '/threat-lab', label: 'Threat Lab', icon: FlaskConical, title: 'Attack simulations' },
  { to: '/analytics', label: 'ML Analytics', icon: BarChart3, title: 'Policy drift' },
  { to: '/revocation', label: 'Revocation', icon: LockKeyhole, title: 'Public proof' },
  { to: '/evaluation', label: 'Evaluation', icon: Activity, title: 'Final evidence' },
]
