import { useReducedMotion } from 'framer-motion'
import { useEffect, useState } from 'react'

export default function AnimatedNumber({ value, decimals = 0, suffix = '' }) {
  const reducedMotion = useReducedMotion()
  const numeric = typeof value === 'number' && Number.isFinite(value)
  const [shown, setShown] = useState(numeric ? 0 : value)

  useEffect(() => {
    if (!numeric) { setShown(value); return undefined }
    if (reducedMotion) { setShown(value); return undefined }
    let frame
    const start = performance.now()
    const tick = (now) => {
      const progress = Math.min((now - start) / 850, 1)
      setShown(value * (1 - (1 - progress) ** 3))
      if (progress < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [value, numeric, reducedMotion])

  if (!numeric) return <span>{value ?? '—'}</span>
  return <span>{Number(shown).toFixed(decimals)}{suffix}</span>
}
