// Package assemble reassembles captured TCP chunks into HTTP/1.1 messages,
// pairs requests with responses and deduplicates client/server views.
package assemble

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"fovea/internal/capture"
	"fovea/internal/identity"
	"fovea/internal/redact"
)

const (
	maxBuf   = 1 << 20
	maxBody  = 64 << 10
	connIdle = 2 * time.Minute
)

var methods = []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "}

func looksRequest(b []byte) bool {
	for _, m := range methods {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}
func looksResponse(b []byte) bool { return bytes.HasPrefix(b, []byte("HTTP/1.")) }

const minToken = 9 // longer than any method token ("OPTIONS ") and "HTTP/1."

// partialToken reports whether b could still grow into a request line or status line.
func partialToken(b []byte) bool {
	if bytes.HasPrefix([]byte("HTTP/1."), b) {
		return true
	}
	for _, m := range methods {
		if bytes.HasPrefix([]byte(m), b) {
			return true
		}
	}
	return false
}

type connKey struct {
	tgid, fd     uint32
	laddr, raddr string
	lport, rport uint16
}

type pendingReq struct {
	method, path string
	headers      map[string]string
	body         string
	startNs      uint64
}

type conn struct {
	role     int // 0 unknown, 1 client, 2 server
	buf      [2][]byte
	firstTs  [2]uint64
	pending  []*pendingReq
	lastSeen time.Time
	comm     string
}

// Assembler consumes capture events and emits Transactions into a Store.
type Assembler struct {
	// Redact masks credentials/PII in headers and JSON bodies before storing.
	Redact bool
	// Node prefixes transaction ids so ids stay unique across agents.
	Node string

	res   identity.Resolver
	store *Store
	conns map[connKey]*conn
	// recent transactions by canonical key, for client/server dedup
	recent  map[string][]*Transaction
	seq     atomic.Int64
	bootOff int64 // wall-clock ns minus monotonic ns
}

func New(res identity.Resolver, store *Store) *Assembler {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return &Assembler{res: res, store: store, conns: map[connKey]*conn{}, recent: map[string][]*Transaction{},
		bootOff: time.Now().UnixNano() - ts.Nano()}
}

// Feed processes one captured chunk. Must be called from a single goroutine.
func (a *Assembler) Feed(ev *capture.Event) {
	k := connKey{ev.TGID, ev.FD, ev.LAddr.String(), ev.RAddr.String(), ev.LPort, ev.RPort}
	c := a.conns[k]
	if c == nil {
		c = &conn{}
		a.conns[k] = c
	}
	c.lastSeen = time.Now()
	c.comm = ev.Comm
	d := ev.Dir

	fresh := len(c.buf[d]) == 0
	if fresh {
		c.firstTs[d] = ev.TimeNs
	}
	c.buf[d] = append(c.buf[d], ev.Data...)
	if len(c.buf[d]) > maxBuf {
		c.buf[d] = nil
		return
	}
	// A message must start with an HTTP token, otherwise this is mid-stream
	// garbage (agent attached late) or not HTTP: drop it and resync later.
	// Very short first chunks are kept until the token can be recognised.
	if fresh || c.role == 0 {
		switch {
		case looksRequest(c.buf[d]):
			a.setRole(c, d, true)
		case looksResponse(c.buf[d]):
			a.setRole(c, d, false)
		case len(c.buf[d]) < minToken && partialToken(c.buf[d]):
			return
		default:
			c.buf[d] = nil
			return
		}
	}
	reqDir, respDir := a.dirs(c)
	if reqDir < 0 {
		return
	}
	if d == uint8(reqDir) {
		a.drainRequests(c, uint8(reqDir), ev.TimeNs)
	} else if d == uint8(respDir) {
		a.drainResponses(c, k, uint8(respDir), ev.TimeNs)
	}
}

// setRole records whether we are the client or server of this socket.
func (a *Assembler) setRole(c *conn, dir uint8, isRequest bool) {
	if c.role != 0 {
		return
	}
	switch {
	case isRequest && dir == capture.DirSend, !isRequest && dir == capture.DirRecv:
		c.role = 1
	default:
		c.role = 2
	}
}

// dirs returns the (request, response) directions for this conn's role.
func (a *Assembler) dirs(c *conn) (int, int) {
	switch c.role {
	case 1: // client: sends requests, receives responses
		return capture.DirSend, capture.DirRecv
	case 2:
		return capture.DirRecv, capture.DirSend
	}
	return -1, -1
}

func (a *Assembler) drainRequests(c *conn, d uint8, nowNs uint64) {
	for len(c.buf[d]) > 0 {
		rd := bytes.NewReader(c.buf[d])
		br := bufio.NewReader(rd)
		req, err := http.ReadRequest(br)
		if err != nil {
			a.onParseErr(c, d, err)
			return
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
		if err != nil || (req.ContentLength > 0 && int64(len(body)) < req.ContentLength && len(body) <= maxBody) {
			return // body incomplete, wait for more bytes
		}
		c.buf[d] = c.buf[d][len(c.buf[d])-rd.Len()-br.Buffered():]
		c.pending = append(c.pending, &pendingReq{
			method: req.Method, path: req.URL.RequestURI(), headers: flatten(req.Header, req.Host),
			body: clip(decode(req.Header, body)), startNs: c.firstTs[d],
		})
		c.firstTs[d] = nowNs
	}
}

func (a *Assembler) onParseErr(c *conn, d uint8, err error) {
	// Until the blank line ending the header block has arrived we cannot tell a
	// truncated message from a malformed one, so wait for more bytes.
	if err == io.EOF || err == io.ErrUnexpectedEOF || strings.Contains(err.Error(), "unexpected EOF") ||
		!bytes.Contains(c.buf[d], []byte("\r\n\r\n")) {
		return
	}
	c.buf[d] = nil // garbage: resync on next message boundary
}

func (a *Assembler) drainResponses(c *conn, k connKey, d uint8, nowNs uint64) {
	for len(c.buf[d]) > 0 {
		method := "GET"
		if len(c.pending) > 0 {
			method = c.pending[0].method
		}
		data := c.buf[d]
		rd := bytes.NewReader(data)
		br := bufio.NewReader(rd)
		resp, err := http.ReadResponse(br, &http.Request{Method: method})
		if err != nil {
			a.onParseErr(c, d, err)
			return
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		if err != nil || (resp.ContentLength > 0 && int64(len(body)) < resp.ContentLength && len(body) <= maxBody) {
			return
		}
		c.buf[d] = data[len(data)-rd.Len()-br.Buffered():]
		if len(c.pending) == 0 {
			c.firstTs[d] = nowNs
			continue // response whose request we never saw
		}
		p := c.pending[0]
		c.pending = c.pending[1:]
		c.firstTs[d] = nowNs
		a.emit(c, k, p, resp, body, nowNs)
	}
}

func flatten(h http.Header, host string) map[string]string {
	out := map[string]string{}
	if host != "" {
		out["Host"] = host
	}
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

// decode transparently inflates gzip bodies (clients advertise Accept-Encoding: gzip).
func decode(h http.Header, b []byte) []byte {
	if h.Get("Content-Encoding") != "gzip" || len(b) == 0 {
		return b
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return b
	}
	out, err := io.ReadAll(io.LimitReader(zr, maxBody+1))
	if err != nil && len(out) == 0 {
		return b
	}
	return out
}

func clip(b []byte) string {
	if len(b) > maxBody {
		return string(b[:maxBody]) + "\n…[truncated]"
	}
	return string(b)
}

func (a *Assembler) wall(ns uint64) time.Time { return time.Unix(0, int64(ns)+a.bootOff) }

func (a *Assembler) emit(c *conn, k connKey, p *pendingReq, resp *http.Response, body []byte, endNs uint64) {
	side := "client"
	srcIP, srcPort, dstIP, dstPort := k.laddr, k.lport, k.raddr, k.rport
	if c.role == 2 {
		side = "server"
		srcIP, srcPort, dstIP, dstPort = k.raddr, k.rport, k.laddr, k.lport
	}
	pidSvc := a.res.ServiceByPID(k.tgid)
	var client, server string
	if side == "client" {
		client, server = pidSvc, a.res.ServiceByIP(dstIP)
	} else {
		server, client = pidSvc, a.res.ServiceByIP(srcIP)
	}
	if client == "" {
		client = "external"
	}
	if server == "" {
		server = "external"
	}
	src := fmt.Sprintf("%s:%d", srcIP, srcPort)
	dst := fmt.Sprintf("%s:%d", dstIP, dstPort)
	dur := float64(endNs-p.startNs) / 1e6
	key := src + ">" + dst + " " + p.method + " " + p.path

	// Dedup: same call seen from the other end within ~1s and not yet merged.
	var best *Transaction
	var bestDiff int64 = 1 << 62
	for _, t := range a.recent[key] {
		if contains(t.Sides, side) {
			continue
		}
		diff := int64(t.startNs) - int64(p.startNs)
		if diff < 0 {
			diff = -diff
		}
		if diff < int64(time.Second) && diff < bestDiff {
			best, bestDiff = t, diff
		}
	}
	if best != nil {
		a.store.Mutate(func() {
			best.Sides = append(best.Sides, side)
			if side == "client" { // end-to-end latency as the caller saw it
				best.DurationMs = dur
				if client != "external" {
					best.ClientService = client
				}
			} else if server != "external" {
				best.ServerService = server
			}
		})
		a.store.Publish(best, false)
		return
	}
	respBody := clip(decode(resp.Header, body))
	reqHeaders, respHeaders, reqBody := p.headers, flatten(resp.Header, ""), p.body
	if a.Redact {
		reqHeaders, respHeaders = redact.Headers(reqHeaders), redact.Headers(respHeaders)
		reqBody, respBody = redact.Body(reqBody), redact.Body(respBody)
	}
	id := fmt.Sprintf("tx-%d", a.seq.Add(1))
	if a.Node != "" {
		id = a.Node + "-" + id
	}
	t := &Transaction{
		ID: id, Time: a.wall(p.startNs), DurationMs: dur,
		ClientService: client, ServerService: server, Method: p.method, Path: p.path,
		ReqHeaders: reqHeaders, ReqBody: reqBody, Status: resp.StatusCode,
		RespHeaders: respHeaders, RespBody: respBody, Src: src, Dst: dst,
		Sides: []string{side}, Node: a.Node, startNs: p.startNs,
	}
	list := append(a.recent[key], t)
	if len(list) > 8 {
		list = list[len(list)-8:]
	}
	a.recent[key] = list
	a.store.Publish(t, true)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// GC drops idle connections and stale dedup entries.
func (a *Assembler) GC() {
	now := time.Now()
	for k, c := range a.conns {
		if now.Sub(c.lastSeen) > connIdle {
			delete(a.conns, k)
		}
	}
	cut := now.Add(-10 * time.Second)
	for key, l := range a.recent {
		if len(l) > 0 && l[len(l)-1].Time.Before(cut) {
			delete(a.recent, key)
		}
	}
}
