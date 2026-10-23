import '@fontsource-variable/inter'
import './landing.css'
import './anatomy.js'

// nav: transparent over the hero, frosted once scrolled
const nav = document.getElementById('nav')
const onScroll = () => nav.classList.toggle('scrolled', window.scrollY > 40)
onScroll()
window.addEventListener('scroll', onScroll, { passive: true })

// blur-in reveal: hero immediately (staggered), the rest on scroll
const hero = ['.badge', '.title', '.subtitle', '.hero .hero-ctas', '.preview']
hero.forEach((sel, i) => {
  const el = document.querySelector(sel)
  if (!el) return
  el.classList.add('reveal')
  setTimeout(() => el.classList.add('in'), 80 + i * 140)
})
const later = document.querySelectorAll('.section-head, .compare, .steps, .pipeline, .anat, .numbers-grid, .objectives, .cta-panel')
const io = 'IntersectionObserver' in window
  ? new IntersectionObserver((entries) => entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target) } }), { threshold: 0.15 })
  : null
later.forEach((el) => { el.classList.add('reveal'); io ? io.observe(el) : el.classList.add('in') })

// ---- live data from the agent (falls back to the static sample when it isn't running)
const $ = (id) => document.getElementById(id)
const pretty = (s) => { try { return JSON.stringify(JSON.parse(s), null, 2) } catch { return (s || '').trim() } }
const fmt = (n) => (n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e4 ? (n / 1e3).toFixed(1) + 'k' : String(n))

async function getJSON(url) {
  const r = await fetch(url, { cache: 'no-store' })
  if (!r.ok) throw new Error(r.status)
  return r.json()
}

async function loadPreview() {
  try {
    // prefer the deepest failure (inventory hop) so the root-cause body is shown
    const errs = await getJSON('/api/transactions?status=error&limit=20')
    const t = errs.find((x) => x.server_service === 'inventory') || errs[0]
    if (!t) return
    $('pv-title').textContent = `${t.client_service} → ${t.server_service}`
    $('pv-method').textContent = t.method
    $('pv-path').textContent = t.path
    $('pv-status').textContent = t.status
    $('pv-dur').textContent = t.duration_ms.toFixed(2) + ' ms'
    $('pv-req').textContent = pretty(t.req_body) || '(no body)'
    $('pv-resp').textContent = pretty(t.resp_body) || '(no body)'
    $('pv-tag').textContent = 'live capture'
    $('pv-tag').classList.add('live')
    $('pv-foot').textContent = `Captured by eBPF at ${t.seen_by.join(' + ')} side · ${t.src} → ${t.dst} · no code changes`
  } catch { /* agent not running: keep the sample */ }
}

const shown = {}
function countTo(el, target) {
  const from = shown[el.dataset.k] ?? 0
  shown[el.dataset.k] = target
  const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  if (from === target || still) { el.textContent = fmt(target); return }
  const t0 = performance.now(), dur = 700
  const step = (now) => {
    const p = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - p, 3)
    el.textContent = fmt(Math.round(from + (target - from) * e))
    if (p < 1) requestAnimationFrame(step)
  }
  requestAnimationFrame(step)
}

async function loadNumbers() {
  // each source is optional so one missing endpoint doesn't blank the whole band
  const [stats, graph, errs] = await Promise.allSettled([
    getJSON('/api/stats'), getJSON('/api/graph'), getJSON('/api/transactions?status=error&limit=50000'),
  ]).then((r) => r.map((x) => (x.status === 'fulfilled' ? x.value : null)))
  const vals = {
    calls: stats?.transactions_total ?? stats?.transactions,
    services: graph ? graph.nodes.filter((n) => n.id !== 'external').length : undefined,
    events: stats?.events_seen,
    errors: errs ? errs.length : undefined,
  }
  if (vals.calls === undefined && graph) vals.calls = graph.edges.reduce((a, e) => a + e.requests, 0)
  document.querySelectorAll('.num-v').forEach((el) => {
    const v = vals[el.dataset.k]
    if (v === undefined) el.textContent = '—'
    else countTo(el, v)
  })
  const live = graph !== null
  $('live-state').textContent = live ? 'Live from this machine' : 'Agent offline: start it to see live numbers'
  document.querySelectorAll('.numbers .pulse').forEach((p) => p.classList.toggle('off', !live))
}

loadPreview()
loadNumbers()
setInterval(loadNumbers, 3000)
setInterval(loadPreview, 10000)
