import { useEffect, useMemo, useRef, useState } from 'react'
import ServiceMap from './ServiceMap.jsx'
import Payload from './Payload.jsx'
import Flows from './Flows.jsx'

const MAX_TX = 1000

const statusClass = (s) => (s >= 500 ? 's5' : s >= 400 ? 's4' : 's2')
const fmtMs = (v) => (v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : Math.round(v)) + ' ms'
const fmtN = (n) => (n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e4 ? (n / 1e3).toFixed(1) + 'k' : String(n))
const timeOf = (ts) => new Date(ts).toLocaleTimeString([], { hour12: false })

function pct(sorted, p) {
  return sorted.length ? sorted[Math.floor(p * (sorted.length - 1))] : 0
}

export default function App() {
  const [txs, setTxs] = useState([])
  const [graph, setGraph] = useState({ nodes: [], edges: [] })
  const [selectedId, setSelectedId] = useState(() => new URLSearchParams(location.search).get('tx'))
  const [service, setService] = useState('')
  const [errorsOnly, setErrorsOnly] = useState(false)
  const [live, setLive] = useState(false)
  const [paused, setPaused] = useState(false)
  const [tab, setTab] = useState('tx')
  const [stats, setStats] = useState({})
  const pausedRef = useRef(false)
  pausedRef.current = paused

  useEffect(() => {
    fetch('/api/transactions?limit=300').then((r) => r.json()).then(setTxs).catch(() => {})
    const es = new EventSource('/api/stream')
    es.onopen = () => setLive(true)
    es.onerror = () => setLive(false)
    es.addEventListener('tx', (e) => {
      if (pausedRef.current) return
      const t = JSON.parse(e.data)
      setTxs((prev) => {
        const i = prev.findIndex((x) => x.id === t.id)
        if (i >= 0) {
          const next = prev.slice()
          next[i] = t
          return next
        }
        return [t, ...prev].slice(0, MAX_TX)
      })
    })
    return () => es.close()
  }, [])

  useEffect(() => {
    const load = () => fetch('/api/graph').then((r) => r.json()).then(setGraph).catch(() => {})
    load()
    const id = setInterval(load, 1500)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    const load = () => fetch('/api/stats').then((r) => r.json()).then(setStats).catch(() => {})
    load()
    const id = setInterval(load, 2000)
    return () => clearInterval(id)
  }, [])

  const clearAll = () =>
    fetch('/api/clear', { method: 'POST' })
      .then(() => { setTxs([]); setGraph({ nodes: [], edges: [] }); setSelectedId(null) })
      .catch(() => {})

  const services = useMemo(() => graph.nodes.map((n) => n.id), [graph])
  const shown = useMemo(
    () =>
      txs.filter(
        (t) =>
          (!service || t.client_service === service || t.server_service === service) &&
          (!errorsOnly || t.status >= 400),
      ),
    [txs, service, errorsOnly],
  )
  const selected = txs.find((t) => t.id === selectedId)
  const kpi = useMemo(() => {
    const errs = txs.filter((t) => t.status >= 400).length
    const durs = txs.map((t) => t.duration_ms).sort((a, b) => a - b)
    return {
      calls: stats.transactions_total ?? txs.length,
      errRate: txs.length ? (errs / txs.length) * 100 : 0,
      errs,
      p95: pct(durs, 0.95),
      services: graph.nodes.filter((n) => n.id !== 'external').length,
      events: stats.events_seen,
      dropped: stats.events_dropped ?? 0,
    }
  }, [txs, stats, graph])

  return (
    <div className="app">
      <header className="top">
        <span className="top-gradient" aria-hidden="true" />
        <div className="top-inner">
          <a className="brand" href="/" title="About Fovea">
            <span className="logo-mark" aria-hidden="true" />
            fovea
          </a>
          <div className="banner">
            <span className={'pulse' + (live ? '' : ' off')} aria-hidden="true" />
            Zero instrumentation · no code changes in the services
          </div>
          <div className="top-right">
            {stats.redaction && <span className="glass-chip" title="credentials and PII masked in stored payloads">Redaction on</span>}
            <span className="glass-chip">{live ? 'Live' : 'Disconnected'}</span>
            <a className="btn btn-glass" href="/">About</a>
          </div>
        </div>

        <div className="kpis">
          <div className="kpi"><span className="kpi-l">Calls reconstructed</span><span className="kpi-v">{fmtN(kpi.calls)}</span></div>
          <div className="kpi"><span className="kpi-l">Error rate</span><span className={'kpi-v' + (kpi.errs ? ' bad' : '')}>{kpi.errRate.toFixed(1)}%</span><span className="kpi-s">{kpi.errs} failed</span></div>
          <div className="kpi"><span className="kpi-l">p95 latency</span><span className="kpi-v">{kpi.p95.toFixed(2)}<small> ms</small></span></div>
          <div className="kpi"><span className="kpi-l">Services discovered</span><span className="kpi-v">{kpi.services}</span></div>
          <div className="kpi">
            <span className="kpi-l">Kernel events</span>
            <span className="kpi-v">{kpi.events === undefined ? '—' : fmtN(kpi.events)}</span>
            <span className={'kpi-s' + (kpi.dropped ? ' bad' : '')}>{kpi.dropped} dropped</span>
          </div>
        </div>
      </header>

      <main className="grid">
        <section className="card map">
          <div className="card-head">
            <h2>Service map</h2>
            <span className="card-hint">{service ? <>Filtering <b>{service}</b> · click again to clear</> : 'Click a service to filter'}</span>
          </div>
          <ServiceMap
            graph={graph}
            focus={service}
            onFocus={(s) => setService(s === service ? '' : s)}
            highlight={selected ? [selected.client_service, selected.server_service] : null}
          />
        </section>

        <section className="card list">
          <div className="card-head">
            <div className="seg" role="tablist">
              <button role="tab" aria-selected={tab === 'tx'} className={tab === 'tx' ? 'on' : ''} onClick={() => setTab('tx')}>Transactions</button>
              <button role="tab" aria-selected={tab === 'flows'} className={tab === 'flows' ? 'on' : ''} onClick={() => setTab('flows')}>Network flows</button>
            </div>
            {tab === 'tx' && (
              <div className="tools">
                <select value={service} onChange={(e) => setService(e.target.value)} aria-label="Filter by service">
                  <option value="">All services</option>
                  {services.map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
                <button className={'toggle' + (errorsOnly ? ' on' : '')} onClick={() => setErrorsOnly(!errorsOnly)} aria-pressed={errorsOnly}>
                  Errors only
                </button>
                <button className="btn" onClick={() => setPaused(!paused)}>{paused ? 'Resume' : 'Pause'}</button>
                <button className="btn" onClick={clearAll} title="Delete all captured requests and start from zero">Clear data</button>
              </div>
            )}
          </div>
          {tab === 'flows' && <Flows />}
          {tab === 'tx' && (
            <div className="rows">
              {shown.length > 0 && (
                <div className="row row-head">
                  <span>Status</span><span>Method</span><span>Path</span><span>Caller → callee</span><span>Duration</span><span>Time</span>
                </div>
              )}
              {shown.length === 0 && (
                <div className="empty">
                  <b>Waiting for traffic</b>
                  <span>Run <code>./scripts/traffic.sh</code> to send requests through the services.</span>
                </div>
              )}
              {shown.map((t) => (
                <div key={t.id} className={'row' + (t.id === selectedId ? ' sel' : '')} onClick={() => setSelectedId(t.id)}>
                  <span className={'status ' + statusClass(t.status)}>{t.status}</span>
                  <span className="method">{t.method}</span>
                  <span className="path">{t.path}</span>
                  <span className="flow">
                    {t.client_service} <i>→</i> {t.server_service}
                  </span>
                  <span className="dur">{fmtMs(t.duration_ms)}</span>
                  <span className="time">{timeOf(t.ts)}</span>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="card detail">
          <div className="card-head">
            <h2>Payload</h2>
            {selected && <span className="card-hint">{selected.id}</span>}
          </div>
          {selected ? (
            <Payload tx={selected} onSelect={setSelectedId} />
          ) : (
            <div className="empty empty-tall">
              <b>Select a transaction</b>
              <span>The captured request and response, the call chain it belongs to and its network flow will appear here.</span>
            </div>
          )}
        </section>
      </main>
    </div>
  )
}
