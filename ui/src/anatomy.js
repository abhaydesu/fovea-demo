// Anatomy: an isometric "machine" of the Fovea pipeline. Three terraces: the services
// (user space) at the back, the kernel in the middle, the agent (user space again) at the
// front. One simulated request cycle drives every moving part and the readout, so the
// numbers beside the figure always match what the figure is doing.

const C = 0.8660254, S = 20
const P = (x, y, z) => [(x - y) * C * S, (x + y) * 0.5 * S - z * S]
const bb = [Infinity, Infinity, -Infinity, -Infinity]
const track = ([x, y]) => { bb[0] = Math.min(bb[0], x); bb[1] = Math.min(bb[1], y); bb[2] = Math.max(bb[2], x); bb[3] = Math.max(bb[3], y) }
const f1 = (n) => Math.round(n * 10) / 10
const pts = (a) => a.map((q) => { const p = P(...q); track(p); return f1(p[0]) + ',' + f1(p[1]) }).join(' ')

// four tones per material: top, left (+y face), right (+x face), edge
const M = {
  stone: { top: '#ffffff', left: '#ececef', right: '#dcdce1', line: '#27272a2e' },
  deck: { top: '#f4f4f6', left: '#e4e4e8', right: '#d3d3d9', line: '#27272a2e' },
  kernel: { top: '#17233d', left: '#111a2e', right: '#0b1222', line: '#ffffff17' },
  svc: { top: '#ffffff', left: '#f1f3f7', right: '#e0e4eb', line: '#27272a38' },
  metal: { top: '#dde1e7', left: '#c4cad3', right: '#a9b0bb', line: '#27272a33' },
  kmetal: { top: '#3b4c6e', left: '#2c3a58', right: '#212c45', line: '#ffffff21' },
  accent: { top: '#5b9bff', left: '#2f74ee', right: '#1f58c4', line: '#0b2a6b' },
  pkt: { top: '#3f3f46', left: '#27272a', right: '#18181b', line: '#00000040' },
  bad: { top: '#ff7a7f', left: '#e5484d', right: '#b8343a', line: '#7a1b1f40' },
  copy: { top: '#c4efff', left: '#76d0f4', right: '#4fb3dc', line: '#0b4a6b40' },
  doc: { top: '#ffffff', left: '#eef0f4', right: '#dfe3ea', line: '#27272a40' },
  docBad: { top: '#ffe3e4', left: '#f6c9cb', right: '#e9a9ac', line: '#b8343a66' },
}

function box([x0, x1, y0, y1, z0, z1], m) {
  const f = (c, q) => `<polygon points="${pts(q)}" fill="${c}" stroke="${m.line}" stroke-width=".75" stroke-linejoin="round"/>`
  return f(m.left, [[x0, y1, z0], [x1, y1, z0], [x1, y1, z1], [x0, y1, z1]]) +
    f(m.right, [[x1, y0, z0], [x1, y1, z0], [x1, y1, z1], [x1, y0, z1]]) +
    f(m.top, [[x0, y0, z1], [x1, y0, z1], [x1, y1, z1], [x0, y1, z1]])
}

function cyl(cx, cy, r, z0, z1, m) {
  const rx = f1(r * 1.2247 * S), ry = f1(r * 0.7071 * S)
  const [bx, by] = P(cx, cy, z0).map(f1), [tx, ty] = P(cx, cy, z1).map(f1)
  track([bx - rx, by + ry]); track([tx + rx, ty - ry])
  return `<path d="M${bx - rx},${by}L${tx - rx},${ty}L${tx + rx},${ty}L${bx + rx},${by}A${rx},${ry} 0 0 1 ${bx - rx},${by}Z" fill="${m.left}" stroke="${m.line}" stroke-width=".75"/>` +
    `<path d="M${bx},${f1(by + ry)}L${tx},${f1(ty + ry)}L${tx + rx},${ty}L${bx + rx},${by}A${rx},${ry} 0 0 1 ${bx},${f1(by + ry)}Z" fill="${m.right}"/>` +
    `<ellipse cx="${tx}" cy="${ty}" rx="${rx}" ry="${ry}" fill="${m.top}" stroke="${m.line}" stroke-width=".75"/>`
}

// annulus sector lying flat at height z
function sector(cx, cy, z, r1, r2, a0, a1) {
  const o = [], i = []
  for (let k = 0; k <= 5; k++) {
    const a = a0 + ((a1 - a0) * k) / 5
    o.push(P(cx + r2 * Math.cos(a), cy + r2 * Math.sin(a), z))
    i.push(P(cx + r1 * Math.cos(a), cy + r1 * Math.sin(a), z))
  }
  return 'M' + [...o, ...i.reverse()].map((p) => f1(p[0]) + ',' + f1(p[1])).join('L') + 'Z'
}

// ---------------------------------------------------------------- scene geometry
const SVC = [1.9, 7.2, 12.5] // frontend, orders, inventory (x centres)
const RING = [14.6, 4.6], RING_SLOTS = 12
const PKT_Z = 7.5

const wire = (a, b) => {
  const d = a < b ? 1.1 : -1.1
  return [[SVC[a] + d, 1.4, PKT_Z], [SVC[b] - d, 1.4, PKT_Z]]
}
const copyPath = (i) => [[SVC[i], 2.4, 6.95], [SVC[i], 3.2, 6.95], [SVC[i], 3.2, 4.2], [SVC[i], 4.6, 3.9], [13.4, 4.6, 3.9], [RING[0], RING[1], 4.55]]
const chunkPath = [[RING[0], RING[1], 4.55], [14.6, 5.95, 3.7], [14.6, 6.2, 3.6], [14.6, 6.2, 1.7], [14.6, 7.9, 1.68], [13.25, 7.9, 1.68]]
const docPath = (top) => [[10.5, 7.9, 1.38], [8.6, 7.9, 1.38], [5.4, 7.9, 1.33], [3.9, 7.9, 1.38], [2.6, 7.9, top]]

function serviceBlock(c) {
  const x0 = c - 1.1, x1 = c + 1.1
  let s = box([x0, x1, 0.4, 2.4, 6, 8.2], M.svc)
  s += box([c - 0.75, c - 0.25, 0.8, 1.3, 8.2, 8.5], M.metal) + box([c + 0.2, c + 0.7, 0.8, 1.3, 8.2, 8.4], M.metal)
  // windows on the front face
  for (let k = 0; k < 3; k++) {
    const wx = x0 + 0.35 + k * 0.55
    s += `<polygon points="${pts([[wx, 2.401, 7.2], [wx + 0.35, 2.401, 7.2], [wx + 0.35, 2.401, 7.75], [wx, 2.401, 7.75]])}" fill="#27272a" fill-opacity=".09"/>`
  }
  return s
}

function buildScene() {
  const L = []
  const part = (k, ...kids) => L.push(`<g data-part="${k}">${kids.join('')}</g>`)
  const slot = (n) => `<g data-slot="${n}"></g>`

  // back terrace: services
  L.push(box([0, 16, 0, 3, 0, 6], M.stone))
  part(1, ...SVC.map(serviceBlock), box([3.0, 6.1, 1.2, 1.6, 6.9, 7.3], M.metal), box([8.3, 11.4, 1.2, 1.6, 6.9, 7.3], M.metal))
  L.push(slot('tok1'))

  // middle terrace: kernel
  L.push(box([0, 16, 3, 6, 0, 3.5], M.kernel))
  part(2,
    ...SVC.map((c) => box([c - 0.2, c + 0.2, 3.0, 3.4, 3.5, 7.0], M.metal) + box([c - 0.2, c + 0.2, 2.4, 3.4, 6.6, 7.0], M.metal)),
    ...SVC.map((c) => cyl(c, 3.2, 0.48, 3.5, 4.0, M.kmetal)),
    box([1.7, 13.5, 4.4, 4.8, 3.5, 3.75], M.kmetal))
  part(3, box([8.9, 10.7, 5.0, 5.8, 3.5, 4.0], M.kmetal), slot('bars'))
  part(5, cyl(RING[0], RING[1], 1.1, 3.5, 4.3, M.accent), slot('ring'), cyl(RING[0], RING[1], 0.32, 4.3, 4.45, M.metal))
  part(4, box([12.9, 13.1, 3.95, 4.15, 3.5, 4.8], M.metal), box([12.9, 13.1, 3.95, 5.25, 4.8, 5.0], M.metal), box([12.9, 13.1, 5.05, 5.25, 3.5, 4.8], M.metal))
  part(6, box([14.4, 14.8, 5.5, 6.4, 3.2, 3.55], M.metal))
  L.push(slot('tok2'))

  // front terrace: the agent
  L.push(box([0, 16, 6, 10, 0, 1], M.deck))
  part(6, box([14.4, 14.8, 6.0, 6.4, 1.0, 3.55], M.metal), box([14.0, 15.2, 7.3, 8.5, 1.0, 1.5], M.metal))
  part(8, box([1.9, 3.2, 6.1, 6.6, 1.0, 1.08], M.metal), box([2.4, 2.7, 6.2, 6.4, 1.08, 1.6], M.metal),
    box([0.5, 4.6, 6.15, 6.45, 1.6, 4.4], M.kmetal),
    `<polygon points="${pts([[0.7, 6.451, 1.8], [4.4, 6.451, 1.8], [4.4, 6.451, 4.2], [0.7, 6.451, 4.2]])}" fill="#13213d"/>`, slot('screen'))
  part(6, box([10.6, 13.2, 6.9, 8.9, 1.0, 2.6], M.metal), box([11.4, 11.6, 7.8, 8.0, 2.6, 4.0], M.metal), box([12.2, 12.4, 7.8, 8.0, 2.6, 4.0], M.metal),
    slot('piston'), box([11.3, 12.5, 7.6, 8.2, 4.0, 4.3], M.metal), box([8.6, 10.6, 7.5, 8.3, 1.0, 1.3], M.metal))
  part(7, box([5.4, 8.6, 6.9, 8.9, 1.0, 1.25], M.metal), slot('rods'), box([3.9, 5.4, 7.5, 8.3, 1.0, 1.3], M.metal))
  part(8, box([1.3, 3.9, 7.1, 8.7, 1.0, 1.2], M.metal), slot('docs'))
  L.push(slot('tok3'))
  L.push(slot('pins'))
  return L.join('')
}

const PINS = [
  [1, [7.2, 1.4, 8.5], [0, -30]],
  [2, [1.9, 3.2, 4.0], [-34, 8]],
  [3, [9.8, 5.4, 4.6], [30, 14]],
  [4, [13.0, 4.6, 5.0], [0, -30]],
  [5, [RING[0], RING[1], 4.3], [36, -18]],
  [6, [12.5, 7.9, 4.3], [32, 4]],
  [7, [7.0, 7.9, 1.25], [10, 34]],
  [8, [0.5, 6.3, 4.4], [-10, -28]],
]

// ---------------------------------------------------------------- simulation model
function createSim(hooks) {
  const s = {
    t: 0, n: 0, forceErr: false, tokens: [], timers: [],
    ring: [], bytes: 0, calls: 0, roots: 0, flows: [0, 0, 0, 0],
    asm: {}, docs: [], screen: [], pressAt: -9, mapErr: false,
  }
  const at = (dt, fn) => s.timers.push({ t: s.t + dt, fn })
  const spawn = (kind, path, speed, onDone, err = false) => {
    const lens = []; let total = 0
    for (let i = 1; i < path.length; i++) {
      const [a, b] = [path[i - 1], path[i]]
      const l = Math.hypot(b[0] - a[0], b[1] - a[1], b[2] - a[2]); lens.push(l); total += l
    }
    s.tokens.push({ kind, path, lens, total, t0: s.t, speed, onDone, err })
  }
  const caption = (text, k) => hooks.caption(text, k)

  const copy = (svc, hop, size) => spawn('copy', copyPath(svc), 9, () => {
    s.ring.push({ hop, size }); s.bytes += size
  })
  const packet = (a, b, err, flow, onDone) => {
    s.flows[flow]++
    spawn('pkt', wire(a, b), 3.4, onDone, err)
  }

  function cycle() {
    const n = ++s.n
    const err = s.forceErr || n % 3 === 0
    s.forceErr = false
    const h1 = n + ':fo', h2 = n + ':oi'
    s.asm[h1] = { got: 0, err, root: false }
    s.asm[h2] = { got: 0, err, root: err }
    caption('frontend calls orders. To the kernel it is just a socket write.', 1)
    copy(0, h1, 182)
    packet(0, 1, false, 0, () => {
      copy(1, h1, 182)
      caption('The write and the matching read both trip eBPF hooks. Copies of the bytes head down the kernel bus.', 2)
      at(0.25, () => {
        copy(1, h2, 164)
        packet(1, 2, false, 1, () => {
          copy(2, h2, 164)
          at(0.4, () => {
            caption(err ? 'inventory answers 500 "insufficient stock". The flow counter only sees bytes; the hooks see the message.' : 'inventory answers 200. The flow counter tallies packets on the same connection.', 3)
            copy(2, h2, err ? 214 : 141)
            packet(2, 1, err, 2, () => {
              copy(1, h2, err ? 214 : 141)
              at(0.2, () => {
                if (err) caption('orders passes the failure up as a 502.', 1)
                copy(1, h1, err ? 236 : 158)
                packet(1, 0, err, 3, () => {
                  copy(0, h1, err ? 236 : 158)
                  at(3.5, cycle)
                })
              })
            })
          })
        })
      })
    })
  }

  // the agent drains the ring buffer at a steady pace
  let nextRead = 0
  function drain() {
    if (s.t < nextRead || !s.ring.length) return
    nextRead = s.t + 0.25
    const c = s.ring.shift()
    caption('Only the watched workloads got through the filter. The agent drains the ring buffer and stitches chunks back into whole HTTP calls.', 6)
    spawn('copy', chunkPath, 6, () => {
      const a = s.asm[c.hop]
      if (++a.got < 4) return
      s.pressAt = s.t
      at(0.3, () => {
        const top = 1.27 + s.docs.length * 0.14
        spawn('doc', docPath(top), 3.4, () => {
          if (s.docs.length >= 7) s.docs = []
          s.docs.push(a.err)
          s.calls++
          s.screen = [a.err, ...s.screen].slice(0, 4)
          if (a.root) { s.roots++; s.mapErr = true } else if (!a.err) s.mapErr = false
          caption(a.root ? 'Both calls are chained. The deepest failing hop, orders → inventory, is flagged as the root cause.'
            : a.err ? 'frontend → orders also failed, but only because the call below it did. That hop is marked as propagating.'
              : 'Each reconstructed call is linked into its chain and appears on the dashboard.', a.err ? 7 : 8)
        }, a.err)
        delete s.asm[c.hop]
      })
    }, false)
  }

  function step(dt) {
    s.t += dt
    const due = s.timers.filter((x) => x.t <= s.t)
    s.timers = s.timers.filter((x) => x.t > s.t)
    due.forEach((x) => x.fn())
    const done = []
    s.tokens = s.tokens.filter((k) => { if ((s.t - k.t0) * k.speed >= k.total) { done.push(k); return false } return true })
    done.forEach((k) => k.onDone && k.onDone())
    drain()
  }

  function pos(k) {
    let d = Math.min(k.total, (s.t - k.t0) * k.speed)
    for (let i = 0; i < k.lens.length; i++) {
      if (d <= k.lens[i] || i === k.lens.length - 1) {
        const u = k.lens[i] ? Math.min(1, d / k.lens[i]) : 1
        const [a, b] = [k.path[i], k.path[i + 1]]
        return [a[0] + (b[0] - a[0]) * u, a[1] + (b[1] - a[1]) * u, a[2] + (b[2] - a[2]) * u]
      }
      d -= k.lens[i]
    }
  }

  cycle()
  return { s, step, pos }
}

// ---------------------------------------------------------------- rendering
function mount(root) {
  const svg = root.querySelector('.anat-svg')
  svg.innerHTML = `<defs><filter id="anat-glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="6"/></filter></defs>` + buildScene()
  const pad = 26
  svg.setAttribute('viewBox', `${f1(bb[0] - pad)} ${f1(bb[1] - pad - 20)} ${f1(bb[2] - bb[0] + pad * 2)} ${f1(bb[3] - bb[1] + pad * 2 + 20)}`)
  const slot = (n) => svg.querySelector(`[data-slot="${n}"]`)
  const slots = Object.fromEntries(['tok1', 'tok2', 'tok3', 'bars', 'ring', 'piston', 'rods', 'docs', 'screen', 'pins'].map((n) => [n, slot(n)]))

  // ring glow sits under the ring buffer, the one accent-lit part
  const [gx, gy] = P(RING[0], RING[1], 3.9)
  slots.ring.closest('[data-part]').insertAdjacentHTML('afterbegin', `<ellipse cx="${f1(gx)}" cy="${f1(gy)}" rx="40" ry="24" fill="#4d90fd" opacity=".55" filter="url(#anat-glow)"/>`)

  slots.pins.innerHTML = PINS.map(([k, w, [dx, dy]]) => {
    const [x, y] = P(...w)
    return `<g class="pin" data-part="${k}"><line x1="${f1(x)}" y1="${f1(y)}" x2="${f1(x + dx)}" y2="${f1(y + dy)}"/><circle cx="${f1(x)}" cy="${f1(y)}" r="2"/><circle cx="${f1(x + dx)}" cy="${f1(y + dy)}" r="9"/><text x="${f1(x + dx)}" y="${f1(y + dy + 3.5)}">${k}</text></g>`
  }).join('')

  const out = {
    caption: root.querySelector('[data-r="caption"]'),
    inflight: root.querySelector('[data-r="inflight"]'),
    bytes: root.querySelector('[data-r="bytes"]'),
    ring: root.querySelector('[data-r="ring"]'),
    calls: root.querySelector('[data-r="calls"]'),
    roots: root.querySelector('[data-r="roots"]'),
  }
  const legend = [...root.querySelectorAll('.anat-legend li')]
  let nowPart = null
  const hooks = {
    caption(text, k) {
      if (out.caption.textContent !== text) out.caption.textContent = text
      nowPart = String(k)
      legend.forEach((li) => li.classList.toggle('now', li.dataset.part === nowPart))
    },
  }
  const sim = createSim(hooks)
  const { s } = sim

  function render() {
    // moving tokens, per terrace so the right things overlap them
    const layers = { tok1: '', tok2: '', tok3: '' }
    for (const k of s.tokens) {
      const [x, y, z] = sim.pos(k)
      if (k.kind === 'pkt') {
        const h = 0.2
        layers.tok1 += box([x - h, x + h, y - h, y + h, z - h, z + h], k.err ? M.bad : M.pkt)
      } else if (k.kind === 'copy') {
        const h = 0.13
        layers[y > 6 ? 'tok3' : z > 6.6 && y < 3 ? 'tok1' : 'tok2'] += box([x - h, x + h, y - h, y + h, z - h, z + h], M.copy)
      } else {
        layers.tok3 += box([x - 0.6, x + 0.6, y - 0.45, y + 0.45, z - 0.07, z + 0.07], k.err ? M.docBad : M.doc)
      }
    }
    for (const n in layers) slots[n].innerHTML = layers[n]

    // flow counter bars grow with packets seen per direction
    slots.bars.innerHTML = s.flows.map((v, i) => {
      const h = Math.min(1.3, 0.12 + 0.26 * Math.log2(1 + v))
      return box([9.1 + i * 0.4, 9.35 + i * 0.4, 5.2, 5.55, 4.0, 4.0 + h], i === 2 && s.mapErr ? M.bad : M.kmetal)
    }).join('')

    // ring buffer slots light up as chunks queue
    let r = ''
    for (let i = 0; i < RING_SLOTS; i++) {
      const a0 = (i / RING_SLOTS) * Math.PI * 2 + 0.05 - s.t * 0.6, a1 = a0 + (Math.PI * 2) / RING_SLOTS - 0.1
      r += `<path d="${sector(RING[0], RING[1], 4.3, 0.46, 0.98, a0, a1)}" fill="${i < s.ring.length ? '#e6f3ff' : '#2a63c9'}"/>`
    }
    slots.ring.innerHTML = r

    // press: quick stamp down, slower return
    const since = s.t - s.pressAt
    const drop = since < 0.12 ? since / 0.12 : since < 0.45 ? 1 - (since - 0.12) / 0.33 : 0
    const pz = 3.0 - drop * 0.5
    slots.piston.innerHTML = box([11.65, 12.15, 7.65, 8.15, pz, 4.0], M.metal)

    // correlator: three service pegs; the link under a passing call lights up
    let lit = [null, null]
    for (const k of s.tokens) {
      if (k.kind !== 'doc') continue
      const [x] = sim.pos(k)
      if (x < 8.6 && x > 5.4) lit = x > 7.0 ? [k.err ? 'bad' : 'ok', lit[1]] : [lit[0], k.err ? 'bad' : 'ok']
    }
    const rod = (st) => (st === 'bad' ? M.bad : st === 'ok' ? M.copy : M.kmetal)
    slots.rods.innerHTML = box([7.0, 8.1, 7.08, 7.22, 1.55, 1.68], rod(lit[0])) + box([5.9, 7.0, 7.08, 7.22, 1.55, 1.68], rod(lit[1])) +
      [5.9, 7.0, 8.1].map((x, i) => cyl(x, 7.15, 0.24, 1.25, 1.9, i === 2 && s.mapErr ? M.bad : M.kmetal)).join('')

    // stack of reconstructed calls
    slots.docs.innerHTML = s.docs.map((e, i) => box([1.95, 3.25, 7.45, 8.35, 1.2 + i * 0.14, 1.32 + i * 0.14], e ? M.docBad : M.doc)).join('')

    // dashboard screen: mini map (top) and the latest calls (rows)
    const Y = 6.452
    const quad = (x0, x1, z0, z1, c, o = 1) => `<polygon points="${pts([[x0, Y, z0], [x1, Y, z0], [x1, Y, z1], [x0, Y, z1]])}" fill="${c}" fill-opacity="${o}"/>`
    let sc = quad(1.35, 3.1, 3.73, 3.77, '#76d0f4', 0.5)
    sc += [1.1, 2.05, 3.0].map((x, i) => quad(x, x + 0.35, 3.55, 3.95, i === 2 && s.mapErr ? '#ff6369' : '#76d0f4')).join('')
    sc += quad(3.55, 4.25, 3.55, 3.95, '#ffffff', 0.18)
    s.screen.forEach((e, i) => {
      const z = 3.15 - i * 0.33
      sc += quad(0.95, 1.15, z, z + 0.2, e ? '#ff6369' : '#4ade80') + quad(1.3, 4.15, z, z + 0.2, '#ffffff', e ? 0.32 : 0.16)
    })
    slots.screen.innerHTML = sc

    const inflight = s.tokens.filter((k) => k.kind === 'pkt').length
    out.inflight.textContent = inflight
    out.bytes.textContent = s.bytes.toLocaleString('en-IN') + ' B'
    out.ring.textContent = `${s.ring.length} / ${RING_SLOTS}`
    out.calls.textContent = s.calls
    out.roots.textContent = s.roots
  }

  // ---- interaction
  const focus = (k) => {
    svg.querySelectorAll('[data-part]').forEach((g) => g.classList.toggle('dim', !!k && g.dataset.part !== k))
    legend.forEach((li) => li.classList.toggle('on', li.dataset.part === k))
  }
  let pinned = null
  svg.addEventListener('pointerover', (e) => { if (!pinned) focus(e.target.closest('[data-part]')?.dataset.part || null) })
  svg.addEventListener('pointerleave', () => { if (!pinned) focus(null) })
  svg.addEventListener('click', (e) => {
    const k = e.target.closest('[data-part]')?.dataset.part || null
    pinned = pinned === k ? null : k
    focus(pinned)
  })
  legend.forEach((li) => {
    const k = li.dataset.part
    li.addEventListener('mouseenter', () => { if (!pinned) focus(k) })
    li.addEventListener('mouseleave', () => { if (!pinned) focus(null) })
    li.addEventListener('focus', () => focus(k))
    li.addEventListener('blur', () => focus(pinned))
    li.addEventListener('click', () => { pinned = pinned === k ? null : k; focus(pinned) })
  })

  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  const playBtn = root.querySelector('[data-a="play"]')
  let playing = !reduced, visible = false, last = 0, raf = 0
  const loop = (now) => {
    const dt = Math.min(0.05, (now - last) / 1000 || 0)
    last = now
    sim.step(dt)
    render()
    raf = playing && visible ? requestAnimationFrame(loop) : 0
  }
  const kick = () => { if (playing && visible && !raf) { last = performance.now(); raf = requestAnimationFrame(loop) } }
  const setPlaying = (p) => { playing = p; playBtn.textContent = p ? 'Pause' : 'Play'; playBtn.setAttribute('aria-pressed', String(!p)); kick() }
  playBtn.addEventListener('click', () => setPlaying(!playing))
  root.querySelector('[data-a="fail"]').addEventListener('click', () => { s.forceErr = true; if (!playing) setPlaying(true) })

  // reduced motion: show a meaningful still frame (a failing cycle mid-flight), no autoplay
  if (reduced) { s.forceErr = true; for (let i = 0; i < 12 / 0.05; i++) sim.step(0.05); for (let i = 0; i < 2.6 / 0.05; i++) sim.step(0.05) }
  render()
  setPlaying(playing)

  if ('IntersectionObserver' in window) {
    new IntersectionObserver(([e]) => { visible = e.isIntersecting; kick() }, { threshold: 0.05 }).observe(svg)
  } else { visible = true; kick() }
}

const el = document.getElementById('anatomy')
if (el) mount(el)
