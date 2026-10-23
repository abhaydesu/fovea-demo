import { useEffect, useState } from 'react'

const pretty = (s) => {
  if (!s) return ''
  try {
    return JSON.stringify(JSON.parse(s), null, 2)
  } catch {
    return s
  }
}

function Headers({ h }) {
  const entries = Object.entries(h || {}).sort()
  return (
    <details className="hdrs">
      <summary>Headers <span>{entries.length}</span></summary>
      <table>
        <tbody>
          {entries.map(([k, v]) => (
            <tr key={k}>
              <td>{k}</td>
              <td>{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  )
}

const kb = (n) => (n < 1024 ? n + ' B' : (n / 1024).toFixed(1) + ' KB')

function Chain({ trace, onSelect }) {
  if (!trace || trace.spans.length < 2) return null
  const total = Math.max(...trace.spans.map((s) => s.offset_ms + s.duration_ms), 0.001)
  return (
    <div className="sub">
      <div className="sub-head">
        <h3>Call chain</h3>
        {trace.root_cause_id && <span className="pill pill-bad">Root cause found</span>}
      </div>
      {trace.spans.map((s) => (
        <div key={s.id} className={'span' + (s.selected ? ' selected' : '') + (s.root_cause ? ' rc-row' : '')} onClick={() => onSelect(s.id)}>
          <div className="slabel" style={{ paddingLeft: s.depth * 16 }}>
            <span className={'status ' + (s.status >= 500 ? 's5' : s.status >= 400 ? 's4' : 's2')}>{s.status}</span>
            <span>{s.client_service} <i>→</i> {s.server_service}</span>
            <span className="muted">{s.method} {s.path}</span>
            {s.root_cause && <span className="pill pill-bad-solid">Root cause</span>}
          </div>
          <div className="bar">
            <div
              className={'fill ' + (s.status >= 400 ? 'bad' : 'ok')}
              style={{ left: (s.offset_ms / total) * 100 + '%', width: Math.max((s.duration_ms / total) * 100, 1.5) + '%' }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}

export default function Payload({ tx, onSelect }) {
  const failed = tx.status >= 400
  const [detail, setDetail] = useState(null)
  useEffect(() => {
    setDetail(null)
    fetch('/api/transactions/' + tx.id).then((r) => r.json()).then(setDetail).catch(() => {})
  }, [tx.id, tx.seen_by.length])
  const flow = detail?.flow
  return (
    <div className="payload">
      <div className="summary">
        <div className="summary-route">
          <b>{tx.client_service}</b> <i>→</i> <b>{tx.server_service}</b>
        </div>
        <div className="summary-meta">
          <span>{tx.src} → {tx.dst}</span>
          <span>captured at {tx.seen_by.join(' + ')}</span>
        </div>
      </div>

      <Chain trace={detail?.trace} onSelect={onSelect} />

      {flow && (
        <div className="sub flow-sub">
          <div className="sub-head">
            <h3>Network flow</h3>
            <span className="muted">same TCP connection</span>
          </div>
          <div className="flow-stats">
            <div><span>Out</span><b>{flow.packets_out} pkt · {kb(flow.bytes_out)}</b></div>
            <div><span>In</span><b>{flow.packets_in} pkt · {kb(flow.bytes_in)}</b></div>
            <div><span>Flags</span><b>{flow.tcp_flags?.join(' ') || '—'}</b></div>
          </div>
        </div>
      )}

      <div className="cols">
        <div className="col">
          <div className="col-head">
            <h3>Request</h3>
            <span className="reqline"><b className="method">{tx.method}</b> {tx.path}</span>
          </div>
          <Headers h={tx.req_headers} />
          <pre>{pretty(tx.req_body) || <span className="muted">(no body)</span>}</pre>
        </div>
        <div className="col">
          <div className="col-head">
            <h3>Response</h3>
            <span className="reqline">
              <span className={'status ' + (tx.status >= 500 ? 's5' : tx.status >= 400 ? 's4' : 's2')}>{tx.status}</span> {tx.duration_ms.toFixed(2)} ms
            </span>
          </div>
          <Headers h={tx.resp_headers} />
          <pre className={failed ? 'err' : ''}>{pretty(tx.resp_body) || <span className="muted">(no body)</span>}</pre>
        </div>
      </div>
    </div>
  )
}
