import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../services/api'

export function useGovernanceStream() {
  const socketRef = useRef(null)
  const [events, setEvents] = useState([])
  const [verdict, setVerdict] = useState(null)
  const [connection, setConnection] = useState('IDLE')
  const [error, setError] = useState(null)

  const start = useCallback((scenario) => {
    socketRef.current?.close()
    setEvents([])
    setVerdict(null)
    setError(null)
    setConnection('CONNECTING')
    const socket = api.governanceSocket()
    socketRef.current = socket
    socket.onopen = () => { if (socketRef.current === socket) { setConnection('RUNNING'); socket.send(JSON.stringify({ scenario })) } }
    socket.onmessage = ({ data }) => {
      if (socketRef.current !== socket) return
      const event = JSON.parse(data)
      setEvents((before) => [...before, { ...event, received_at: new Date().toISOString() }])
      if (event.event === 'VERDICT_COMPLETE') { setVerdict(event.verdict); setConnection('COMPLETE') }
      if (event.event === 'ERROR') { setError(event.detail); setConnection('ERROR') }
    }
    socket.onerror = () => { if (socketRef.current === socket) { setError('Governance WebSocket connection failed'); setConnection('ERROR') } }
    socket.onclose = () => { if (socketRef.current === socket) socketRef.current = null }
  }, [])

  useEffect(() => () => { socketRef.current?.close(); socketRef.current = null }, [])
  return { events, verdict, connection, error, start }
}
