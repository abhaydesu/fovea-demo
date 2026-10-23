// Service map: services laid out in columns by call depth, drawn at the card's real
// pixel width (no SVG scaling, so text stays crisp). Error colouring separates the hop
// where a failure most likely originated from hops that only propagate it upstream.
import { useEffect, useState } from 'react'

const NW = 168, NH = 54, MIN_GAP = 150, PAD = 20, ROW = 84

const reduced = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

// callback ref, so it re-attaches when the element changes (empty state -> map)
function useWidth() {
  const [el, setEl] = useState(null)
  const [w, setW] = useState(720)
  useEffect(() => {
    if (!el) return
    const ro = new ResizeObserver(([e]) => setW(Math.floor(e.contentRect.width)))
    ro.observe(el)
    return () => ro.disconnect()
  }, [el])
  return [setEl, w]
}

function levels(nodes, edges) {
  const incoming = {}
  nodes.forEach((n) => (incoming[n.id] = 0))
  edges.forEach((e) => (incoming[e.to] = (incoming[e.to] || 0) + 1))
  const level = {}
  let frontier = nodes.filter((n) => !incoming[n.id]).map((n) => n.id)
  if (!frontier.length && nodes.length) frontier = [nodes[0].id]
  frontier.forEach((id) => (level[id] = 0))
  for (let i = 0; i < nodes.length && frontier.length; i++) {
    const next = []
    for (const id of frontier)
      for (const e of edges)
        if (e.from === id && (level[e.to] === undefined || level[e.to] < level[id] + 1) && level[id] + 1 < nodes.length) {
          level[e.to] = level[id] + 1
          next.push(e.to)
        }
    frontier = next
  }
  const cols = {}
  nodes.forEach((n) => {
    const l = level[n.id] ?? 0
    ;(cols[l] = cols[l] || []).push(n.id)
  })
  return cols
}

function layout(nodes, edges, width) {
  const cols = levels(nodes, edges)
  const nCols = Math.max(1, Object.keys(cols).length)
  const maxRows = Math.max(1, ...Object.values(cols).map((c) => c.length))
  const minW = nCols * NW + (nCols - 1) * MIN_GAP + PAD * 2
  const W = Math.max(width, minW)
  const gap = nCols > 1 ? (W - PAD * 2 - nCols * NW) / (nCols - 1) : 0
  const H = Math.max(150, maxRows * ROW + 56)
  const pos = {}
  Object.entries(cols).forEach(([l, ids]) => {
    ids.forEach((id, i) => {
      const x = nCols === 1 ? W / 2 : PAD + NW / 2 + l * (NW + gap)
      pos[id] = { x, y: 8 + ((i + 1) * (H - 16)) / (ids.length + 1) }
    })
  })
  return { pos, W, H }
}

// "origin" = failing hop whose callee has no failing downstream calls; "prop" = it only passes errors up
function classify(edges) {
  const failingOut = {}
  edges.forEach((e) => { if (e.errors > 0) failingOut[e.from] = true })
  const kind = {}
  edges.forEach((e) => {
    kind[e.from + '>' + e.to] = e.errors === 0 ? 'ok' : failingOut[e.to] ? 'prop' : 'origin'
  })
  return kind
}

const ms = (v) => (v < 10 ? v.toFixed(1) : Math.round(v)) + ' ms'
const pctTxt = (r) => (r > 0 && r < 0.01 ? '<1' : Math.round(r * 100)) + '%'

// point where the segment from box-centre a towards b leaves the box
function exit(a, b, pad = 0) {
  const dx = b.x - a.x, dy = b.y - a.y
  const t = Math.min((NW / 2 + pad) / Math.abs(dx || 1e-9), (NH / 2 + pad) / Math.abs(dy || 1e-9))
  return { x: a.x + dx * t, y: a.y + dy * t }
}

export default function ServiceMap({ graph, focus, onFocus, highlight }) {
  const [ref, width] = useWidth()
  const { nodes, edges } = graph
  if (!nodes.length)
    return (
      <div ref={ref} className="empty">
        <b>No services observed yet</b>
        <span>Services appear here as soon as Fovea sees them talk to each other.</span>
      </div>
    )

  const { pos, W, H } = layout(nodes, edges, width)
  const kind = classify(edges)
  const maxReq = Math.max(1, ...edges.map((e) => e.requests))
  const nodeKind = {}
  nodes.forEach((n) => {
    const ins = edges.filter((e) => e.to === n.id)
    const outs = edges.filter((e) => e.from === n.id)
    const originHere = ins.some((e) => kind[e.from + '>' + e.to] === 'origin')
    const propHere = ins.some((e) => kind[e.from + '>' + e.to] === 'prop') || outs.some((e) => e.errors > 0)
    nodeKind[n.id] = originHere ? 'origin' : propHere ? 'prop' : 'ok'
  })
  const anyOrigin = Object.values(kind).includes('origin')
  const anyProp = Object.values(kind).includes('prop')

  return (
    <div className="mapbox">
      <div ref={ref} className="mapwrap">
        <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} className="svgmap" role="img" aria-label="Service dependency map">
          <defs>
            {['ok', 'prop', 'origin'].map((k) => (
              <marker key={k} id={'arrow-' + k} viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="8" markerHeight="8" markerUnits="userSpaceOnUse" orient="auto">
                <path d="M0 1 L9 5 L0 9 z" className={'arrow ' + k} />
              </marker>
            ))}
            <filter id="node-shadow" x="-20%" y="-30%" width="140%" height="190%">
              <feDropShadow dx="0" dy="1" stdDeviation="1" floodColor="#27272a" floodOpacity="0.08" />
              <feDropShadow dx="0" dy="6" stdDeviation="8" floodColor="#27272a" floodOpacity="0.08" />
            </filter>
            <linearGradient id="badge-svc" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stopColor="#002869" />
              <stop offset=".6" stopColor="#0056ec" />
              <stop offset="1" stopColor="#60a0ff" />
            </linearGradient>
          </defs>

          {edges.map((e) => {
            const a = pos[e.from], b = pos[e.to]
            if (!a || !b) return null
            const k = kind[e.from + '>' + e.to]
            const hl = highlight && highlight[0] === e.from && highlight[1] === e.to
            const p1 = exit(a, b, 2), p2 = exit(b, a, 6)
            const mx = (p1.x + p2.x) / 2, my = (p1.y + p2.y) / 2
            // gentle S-curve when hops are on different rows, straight otherwise
            const d = `M${p1.x},${p1.y} C${mx},${p1.y} ${mx},${p2.y} ${p2.x},${p2.y}`
            const sw = 1.5 + 2.5 * (e.requests / maxReq)
            const id = 'edge-' + e.from + '-' + e.to
            const live = e.req_per_sec > 0 && !reduced
            const dur = Math.max(0.8, Math.min(4, 2.5 / Math.sqrt(e.req_per_sec + 0.05)))
            const chip = `p95 ${ms(e.p95_ms)}`
            const chipW = chip.length * 6.4 + 16
            return (
              <g key={id} className={'edge-g ' + k + (hl ? ' hl' : '')}>
                {hl && <path d={d} className="edge-glow" strokeWidth={sw + 9} />}
                <path id={id} d={d} className="edge" strokeWidth={sw} markerEnd={`url(#arrow-${k})`} />
                {live &&
                  [0, 1, 2].map((i) => (
                    <circle key={i} r="2.6" className="particle">
                      <animateMotion dur={dur + 's'} begin={(i * dur) / 3 + 's'} repeatCount="indefinite">
                        <mpath href={'#' + id} />
                      </animateMotion>
                    </circle>
                  ))}
                <g className="chip" transform={`translate(${mx},${my})`}>
                  <rect x={-chipW / 2} y={-24} width={chipW} height={18} rx={9} />
                  <text y={-11.5} textAnchor="middle">{chip}</text>
                </g>
                <text x={mx} y={my + 18} textAnchor="middle" className="edge-sub">
                  {e.requests} calls
                  {e.errors > 0 && <tspan className="edge-err"> · {pctTxt(e.error_rate)} failed</tspan>}
                </text>
              </g>
            )
          })}

          {nodes.map((n) => {
            const p = pos[n.id]
            const ext = n.id === 'external'
            const k = nodeKind[n.id]
            const sel = focus === n.id
            const failedOut = edges.filter((e) => e.from === n.id).reduce((a, e) => a + e.errors, 0)
            const own = Math.max(0, n.errors - failedOut) // failures not caused by a downstream call
            const sub = ext ? 'outside the app' : n.requests
              ? `${n.requests} req · ${pctTxt(own / n.requests)} err`
              : 'client only'
            const x0 = p.x - NW / 2, y0 = p.y - NH / 2
            return (
              <g
                key={n.id}
                onClick={() => onFocus(n.id)}
                onKeyDown={(ev) => (ev.key === 'Enter' || ev.key === ' ') && onFocus(n.id)}
                className={'node ' + k + (ext ? ' ext' : '') + (sel ? ' focus' : '')}
                role="button"
                tabIndex={0}
                aria-label={`${n.id}, ${sub}. Click to filter.`}
              >
                <title>{n.id}: {sub}</title>
                <rect x={x0} y={y0} width={NW} height={NH} rx={12} className="node-card" filter="url(#node-shadow)" />
                <rect x={x0 + 10} y={p.y - 15} width={30} height={30} rx={9} className="badge" fill={ext ? undefined : 'url(#badge-svc)'} />
                <text x={x0 + 25} y={p.y + 5} textAnchor="middle" className="badge-t">{ext ? '↗' : n.id[0].toUpperCase()}</text>
                <text x={x0 + 50} y={p.y - 2} className="node-t">{n.id}</text>
                <text x={x0 + 50} y={p.y + 13} className="node-s">{sub}</text>
                {!ext && <circle cx={x0 + NW - 13} cy={y0 + 13} r={4} className="hdot" />}
                {k === 'origin' && (
                  <g className="origin-tag" transform={`translate(${p.x},${y0 - 2})`}>
                    <rect x={-40} y={-9} width={80} height={18} rx={9} />
                    <text y={4} textAnchor="middle">likely origin</text>
                  </g>
                )}
              </g>
            )
          })}
        </svg>
      </div>
      <div className="legend">
        <span><i className="lg ok" /> healthy</span>
        {anyProp && <span><i className="lg prop" /> passing errors upstream</span>}
        {anyOrigin && <span><i className="lg origin" /> failing at this hop</span>}
        {highlight && <span><i className="lg hl" /> selected call</span>}
        <span className="lg-note">line width = traffic · moving dots = calls in the last 30 s</span>
      </div>
    </div>
  )
}
