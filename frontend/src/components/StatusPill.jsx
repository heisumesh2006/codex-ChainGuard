export default function StatusPill({ label, tone = 'cyan', pulse = false }) {
  return (
    <span className={`status-pill status-pill--${tone}`}>
      <span className={`status-dot ${pulse ? 'status-dot--pulse' : ''}`} />
      {label}
    </span>
  )
}
