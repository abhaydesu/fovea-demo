package graph

import (
	"testing"
	"time"

	"fovea/internal/assemble"
)

func TestBuild(t *testing.T) {
	now := time.Now()
	var txs []assemble.Transaction
	for i := 1; i <= 10; i++ {
		st := 200
		if i == 10 {
			st = 500
		}
		txs = append(txs, assemble.Transaction{ClientService: "a", ServerService: "b", Status: st, DurationMs: float64(i), Time: now})
	}
	g := Build(txs)
	if len(g.Edges) != 1 || len(g.Nodes) != 2 {
		t.Fatalf("%+v", g)
	}
	e := g.Edges[0]
	if e.Requests != 10 || e.Errors != 1 || e.ErrorRate != 0.1 || e.P50Ms != 5 || e.P95Ms != 9 {
		t.Fatalf("bad edge stats: %+v", e)
	}
}
