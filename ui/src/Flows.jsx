import { useEffect, useState } from 'react'

const kb = (n) => (n < 1024 ? n + ' B' : (n / 1024).toFixed(1) + ' KB')

export default function Flows() {
  const [flows, setFlows] = useState(null)
  useEffect(() => {
    const load = () => fetch('/api/flows').then((r) => r.json()).then(setFlows).catch(() => setFlows([]))
    load()
    const id = setInterval(load, 2000)
    return () => clearInterval(id)
  }, [])
  if (flows === null) return <div className="empty"><b>Loading…</b></div>
  if (!flows.length)
    return (
      <div className="empty">
        <b>No network flows yet</b>
        <span>The flow layer counts packets on each container's network interface while the agent runs.</span>
      </div>
    )
  return (
    <div className="rows">
      <div className="frow row-head">
        <span>Proto</span><span>Client → server</span><span>Services</span><span>Out</span><span>In</span><span>Flags</span>
      </div>
      {flows.map((f) => (
        <div className="frow" key={f.id}>
          <span className="method">{f.proto}</span>
          <span className="mono-s">{f.client} → {f.server}</span>
          <span className="flow">{f.client_service} <i>→</i> {f.server_service}</span>
          <span className="mono-s">{f.packets_out} pkt · {kb(f.bytes_out)}</span>
          <span className="mono-s">{f.packets_in} pkt · {kb(f.bytes_in)}</span>
          <span className="flags">{(f.tcp_flags || []).map((x) => <i key={x}>{x}</i>)}</span>
        </div>
      ))}
    </div>
  )
}
