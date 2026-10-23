// Package graph derives the service dependency graph from transactions.
package graph

import (
	"sort"
	"time"

	"fovea/internal/assemble"
)

type Node struct {
	ID       string `json:"id"`
	Requests int    `json:"requests"`
	Errors   int    `json:"errors"`
}

type Edge struct {
	From      string  `json:"from"`
	To        string  `json:"to"`
	Requests  int     `json:"requests"`
	Errors    int     `json:"errors"`
	ErrorRate float64 `json:"error_rate"`
	ReqPerSec float64 `json:"req_per_sec"` // over the trailing 30s window
	P50Ms     float64 `json:"p50_ms"`
	P95Ms     float64 `json:"p95_ms"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

const window = 30 * time.Second

// IsError treats 4xx/5xx as failed calls.
func IsError(status int) bool { return status >= 400 }

func Build(txs []assemble.Transaction) Graph {
	type acc struct {
		reqs, errs, recent int
		durs               []float64
	}
	edges := map[[2]string]*acc{}
	nodes := map[string]*Node{}
	cut := time.Now().Add(-window)
	node := func(id string) *Node {
		n := nodes[id]
		if n == nil {
			n = &Node{ID: id}
			nodes[id] = n
		}
		return n
	}
	for _, t := range txs {
		k := [2]string{t.ClientService, t.ServerService}
		e := edges[k]
		if e == nil {
			e = &acc{}
			edges[k] = e
		}
		e.reqs++
		e.durs = append(e.durs, t.DurationMs)
		if t.Time.After(cut) {
			e.recent++
		}
		node(t.ClientService)
		s := node(t.ServerService)
		s.Requests++
		if IsError(t.Status) {
			e.errs++
			s.Errors++
		}
	}
	g := Graph{Nodes: []Node{}, Edges: []Edge{}}
	for _, n := range nodes {
		g.Nodes = append(g.Nodes, *n)
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	for k, e := range edges {
		sort.Float64s(e.durs)
		g.Edges = append(g.Edges, Edge{
			From: k[0], To: k[1], Requests: e.reqs, Errors: e.errs,
			ErrorRate: float64(e.errs) / float64(e.reqs),
			ReqPerSec: float64(e.recent) / window.Seconds(),
			P50Ms:     pct(e.durs, 0.50), P95Ms: pct(e.durs, 0.95),
		})
	}
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		return g.Edges[i].To < g.Edges[j].To
	})
	return g
}

func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(p * float64(len(sorted)-1))
	return sorted[i]
}
