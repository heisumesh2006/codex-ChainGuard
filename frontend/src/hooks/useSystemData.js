import { useCallback, useEffect, useState } from 'react'
import { api } from '../services/api'

export function useSystemData() {
  const [health, setHealth] = useState(null)
  const [overview, setOverview] = useState(null)
  const [metrics, setMetrics] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    const results = await Promise.allSettled([api.health(), api.overview(), api.metrics()])
    if (results[0].status === 'fulfilled') setHealth(results[0].value)
    else setHealth(null)
    if (results[1].status === 'fulfilled') setOverview(results[1].value)
    if (results[2].status === 'fulfilled') setMetrics(results[2].value)
    const failed = results.find((result) => result.status === 'rejected')
    setError(failed?.reason?.message || null)
    setLoading(false)
  }, [])
  useEffect(() => { load(); const timer = window.setInterval(load, 15000); return () => window.clearInterval(timer) }, [load])

  return { health, overview, metrics, error, loading, retry: load }
}
