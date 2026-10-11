import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../services/api'

function closeSocket(socket) {
  if (!socket) return
  if (socket.readyState === WebSocket.CONNECTING) socket.onopen = () => socket.close()
  else socket.close()
}

export function useGovernanceStream() {
  const socketRef = useRef(null)
  const [events, setEvents] = useState([])
  const [verdict, setVerdict] = useState(null)
  const [connection, setConnection] = useState('IDLE')
  const [error, setError] = useState(null)

  const start = useCallback((scenario) => {
    closeSocket(socketRef.current)
    setEvents([])
    setVerdict(null)
    setError(null)
    setConnection('CONNECTING')
    const socket = api.governanceSocket()
    let finished = false
    socketRef.current = socket
    socket.onopen = () => { if (socketRef.current === socket) { setConnection('RUNNING'); socket.send(JSON.stringify({ scenario })) } }
    socket.onmessage = ({ data }) => {
      if (socketRef.current !== socket) return
      let event
      try { event = JSON.parse(data) } catch {
        finished = true; setError('Invalid governance response'); setConnection('ERROR'); socket.close(); return
      }
      setEvents((before) => [...before, { ...event, received_at: new Date().toISOString() }])
      if (event.event === 'VERDICT_COMPLETE') { finished = true; setVerdict(event.verdict); setConnection('COMPLETE') }
      if (event.event === 'ERROR') { finished = true; setError(event.detail); setConnection('ERROR') }
    }
    socket.onerror = () => { if (socketRef.current === socket) { setError('Governance WebSocket connection failed'); setConnection('ERROR') } }
    socket.onclose = () => {
      if (socketRef.current !== socket) return
      socketRef.current = null
      if (!finished) {
        setError('Governance connection closed before the verdict. Retry the scenario.')
        setConnection('ERROR')
      }
    }
  }, [])

  useEffect(() => () => { closeSocket(socketRef.current); socketRef.current = null }, [])
  return { events, verdict, connection, error, start }
}
