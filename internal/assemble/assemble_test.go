package assemble

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net"
	"strings"
	"testing"

	"fovea/internal/capture"
)

type fakeRes struct{}

func (fakeRes) ServiceByPID(t uint32) string {
	return map[uint32]string{1: "frontend", 2: "orders"}[t]
}
func (fakeRes) ServiceByIP(ip string) string {
	return map[string]string{"10.0.0.1": "frontend", "10.0.0.2": "orders"}[ip]
}
func (fakeRes) CgroupIDs() map[uint64]bool { return nil }
func (fakeRes) Interfaces() []int          { return nil }
func (fakeRes) Refresh() error             { return nil }

var clock uint64 = 1_000_000_000

// ev builds a chunk seen by process tgid on its socket (local ip/port -> remote ip/port).
func ev(tgid uint32, dir uint8, lip string, lport uint16, rip string, rport uint16, data string) *capture.Event {
	clock += 100_000
	return &capture.Event{TimeNs: clock, TGID: tgid, FD: 7, Dir: dir, Data: []byte(data),
		LAddr: net.ParseIP(lip).To4(), RAddr: net.ParseIP(rip).To4(), LPort: lport, RPort: rport}
}

func newAsm() (*Assembler, *Store) {
	st := NewStore(100)
	return New(fakeRes{}, st), st
}

const (
	reqText  = "POST /order HTTP/1.1\r\nHost: orders:8081\r\nContent-Length: 26\r\nContent-Type: application/json\r\n\r\n{\"item\":\"widget\",\"qty\":50}"
	respText = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"error\":\"nope\"}\n"
)

// clientSide feeds what the frontend process saw (it sends the request, receives the response).
func clientSide(a *Assembler, req, resp string) {
	a.Feed(ev(1, capture.DirSend, "10.0.0.1", 40000, "10.0.0.2", 8081, req))
	a.Feed(ev(1, capture.DirRecv, "10.0.0.1", 40000, "10.0.0.2", 8081, resp))
}

func serverSide(a *Assembler, req, resp string) {
	a.Feed(ev(2, capture.DirRecv, "10.0.0.2", 8081, "10.0.0.1", 40000, req))
	a.Feed(ev(2, capture.DirSend, "10.0.0.2", 8081, "10.0.0.1", 40000, resp))
}

func TestSingleTransaction(t *testing.T) {
	a, st := newAsm()
	clientSide(a, reqText, respText)
	txs := st.Snapshot()
	if len(txs) != 1 {
		t.Fatalf("want 1 tx, got %d", len(txs))
	}
	tx := txs[0]
	if tx.Method != "POST" || tx.Path != "/order" || tx.Status != 502 ||
		tx.ReqBody != `{"item":"widget","qty":50}` || tx.ClientService != "frontend" || tx.ServerService != "orders" {
		t.Fatalf("unexpected tx: %+v", tx)
	}
}

func TestSplitChunks(t *testing.T) {
	a, st := newAsm()
	// request and response delivered a few bytes at a time
	for i := 0; i < len(reqText); i += 7 {
		end := min(i+7, len(reqText))
		a.Feed(ev(1, capture.DirSend, "10.0.0.1", 40000, "10.0.0.2", 8081, reqText[i:end]))
	}
	for i := 0; i < len(respText); i += 5 {
		end := min(i+5, len(respText))
		a.Feed(ev(1, capture.DirRecv, "10.0.0.1", 40000, "10.0.0.2", 8081, respText[i:end]))
	}
	txs := st.Snapshot()
	if len(txs) != 1 || txs[0].RespBody != "{\"error\":\"nope\"}\n" {
		t.Fatalf("got %d txs: %+v", len(txs), txs)
	}
}

func TestIncompleteBodyWaits(t *testing.T) {
	a, st := newAsm()
	a.Feed(ev(1, capture.DirSend, "10.0.0.1", 40000, "10.0.0.2", 8081, reqText[:len(reqText)-5]))
	a.Feed(ev(1, capture.DirRecv, "10.0.0.1", 40000, "10.0.0.2", 8081, respText))
	if st.Len() != 0 {
		t.Fatal("must not emit with a truncated request body")
	}
	a.Feed(ev(1, capture.DirSend, "10.0.0.1", 40000, "10.0.0.2", 8081, reqText[len(reqText)-5:]))
	// the response arrived first in this contrived order; nothing should crash
}

func TestKeepAliveSequentialRequests(t *testing.T) {
	a, st := newAsm()
	for i := 0; i < 3; i++ {
		clientSide(a, reqText, respText)
	}
	if st.Len() != 3 {
		t.Fatalf("want 3 sequential transactions on one connection, got %d", st.Len())
	}
}

func TestPipelinedRequestsInOneChunk(t *testing.T) {
	a, st := newAsm()
	a.Feed(ev(1, capture.DirSend, "10.0.0.1", 40000, "10.0.0.2", 8081, reqText+reqText))
	a.Feed(ev(1, capture.DirRecv, "10.0.0.1", 40000, "10.0.0.2", 8081, respText+respText))
	if st.Len() != 2 {
		t.Fatalf("want 2, got %d", st.Len())
	}
}

func TestGarbageDoesNotCrashAndResyncs(t *testing.T) {
	a, st := newAsm()
	a.Feed(ev(1, capture.DirSend, "10.0.0.1", 40000, "10.0.0.2", 8081, "\x16\x03\x01 binary tls junk"))
	a.Feed(ev(1, capture.DirRecv, "10.0.0.1", 40000, "10.0.0.2", 8081, "\x00\x01\x02"))
	clientSide(a, reqText, respText)
	if st.Len() != 1 {
		t.Fatalf("want recovery after garbage, got %d txs", st.Len())
	}
}

func TestResponseWithoutRequestIgnored(t *testing.T) {
	a, st := newAsm()
	a.Feed(ev(1, capture.DirRecv, "10.0.0.1", 40000, "10.0.0.2", 8081, respText))
	if st.Len() != 0 {
		t.Fatal("orphan response must be ignored")
	}
}

func TestDedupClientAndServerViews(t *testing.T) {
	a, st := newAsm()
	clientSide(a, reqText, respText)
	serverSide(a, reqText, respText)
	txs := st.Snapshot()
	if len(txs) != 1 {
		t.Fatalf("client+server views must merge, got %d", len(txs))
	}
	if len(txs[0].Sides) != 2 {
		t.Fatalf("want both sides recorded, got %v", txs[0].Sides)
	}
}

func TestTwoIdenticalCallsAreNotMerged(t *testing.T) {
	a, st := newAsm()
	clientSide(a, reqText, respText)
	serverSide(a, reqText, respText)
	clientSide(a, reqText, respText)
	serverSide(a, reqText, respText)
	if st.Len() != 2 {
		t.Fatalf("two real calls on one connection must stay two, got %d", st.Len())
	}
}

func TestChunkedResponse(t *testing.T) {
	a, st := newAsm()
	resp := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	clientSide(a, "GET /x HTTP/1.1\r\nHost: orders\r\n\r\n", resp)
	txs := st.Snapshot()
	if len(txs) != 1 || txs[0].RespBody != "hello world" {
		t.Fatalf("chunked decode failed: %+v", txs)
	}
}

func TestGzipResponseIsInflated(t *testing.T) {
	a, st := newAsm()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(`{"ok":true}`))
	zw.Close()
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s", buf.Len(), buf.String())
	clientSide(a, "GET /x HTTP/1.1\r\nHost: orders\r\n\r\n", resp)
	if txs := st.Snapshot(); len(txs) != 1 || txs[0].RespBody != `{"ok":true}` {
		t.Fatalf("gzip decode failed: %+v", txs)
	}
}

func TestRedaction(t *testing.T) {
	a, st := newAsm()
	a.Redact = true
	req := "POST /login HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abc\r\nContent-Length: 38\r\n\r\n{\"user\":\"bob\",\"password\":\"hunter2!!\"}"
	req = strings.Replace(req, "Content-Length: 38", fmt.Sprintf("Content-Length: %d", len(`{"user":"bob","password":"hunter2!!"}`)), 1)
	clientSide(a, req, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
	tx := st.Snapshot()[0]
	if strings.Contains(tx.ReqBody, "hunter2") || tx.ReqHeaders["Authorization"] != "[redacted]" || !strings.Contains(tx.ReqBody, "bob") {
		t.Fatalf("redaction failed: %+v", tx)
	}
}

func TestNonDemoTrafficIgnored(t *testing.T) {
	a, st := newAsm()
	a.Feed(ev(1, capture.DirSend, "10.0.0.1", 40000, "10.0.0.2", 5432, "SELECT 1;"))
	if st.Len() != 0 {
		t.Fatal("non-HTTP bytes must be ignored")
	}
	for _, c := range a.conns {
		if len(c.buf[0])+len(c.buf[1]) != 0 {
			t.Fatal("non-HTTP bytes must not be buffered")
		}
	}
}
