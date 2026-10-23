// Package trace infers caller→callee chains from captured transactions.
//
// No trace ids are injected into the services (zero instrumentation), so causality is
// inferred: transaction C is a child of P when P's server is C's client and C happened
// entirely inside P's time window. With heavy concurrency on one service this can
// attribute a call to the wrong parent; the smallest enclosing window is chosen.
package trace

import (
	"sort"
	"time"

	"fovea/internal/assemble"
)

const slack = 2 * time.Millisecond

type Span struct {
	ID            string  `json:"id"`
	ParentID      string  `json:"parent_id,omitempty"`
	Depth         int     `json:"depth"`
	ClientService string  `json:"client_service"`
	ServerService string  `json:"server_service"`
	Method        string  `json:"method"`
	Path          string  `json:"path"`
	Status        int     `json:"status"`
	DurationMs    float64 `json:"duration_ms"`
	OffsetMs      float64 `json:"offset_ms"` // start relative to the trace root
	RootCause     bool    `json:"root_cause,omitempty"`
	Selected      bool    `json:"selected,omitempty"`
}

type Trace struct {
	Spans []Span `json:"spans"`
	// RootCauseID is the deepest failing call: the first place the error originated.
	RootCauseID string `json:"root_cause_id,omitempty"`
}

func end(t *assemble.Transaction) time.Time {
	return t.Time.Add(time.Duration(t.DurationMs * float64(time.Millisecond)))
}

func failed(t *assemble.Transaction) bool { return t.Status >= 400 }

// Build returns the trace containing the transaction `id`.
func Build(all []assemble.Transaction, id string) *Trace {
	var target *assemble.Transaction
	for i := range all {
		if all[i].ID == id {
			target = &all[i]
			break
		}
	}
	if target == nil {
		return nil
	}
	// candidates: only transactions near the target in time
	var txs []*assemble.Transaction
	for i := range all {
		t := &all[i]
		if t.Time.After(target.Time.Add(-30*time.Second)) && t.Time.Before(target.Time.Add(30*time.Second)) {
			txs = append(txs, t)
		}
	}
	parent := map[string]*assemble.Transaction{}
	for _, c := range txs {
		var best *assemble.Transaction
		for _, p := range txs {
			if p == c || p.ServerService != c.ClientService {
				continue
			}
			if p.Time.After(c.Time.Add(slack)) || end(p).Before(end(c).Add(-slack)) {
				continue
			}
			if best == nil || p.DurationMs < best.DurationMs {
				best = p
			}
		}
		if best != nil {
			parent[c.ID] = best
		}
	}
	root := target
	for guard := 0; guard < 32; guard++ {
		p := parent[root.ID]
		if p == nil {
			break
		}
		root = p
	}
	children := map[string][]*assemble.Transaction{}
	for _, c := range txs {
		if p := parent[c.ID]; p != nil {
			children[p.ID] = append(children[p.ID], c)
		}
	}
	for _, l := range children {
		sort.Slice(l, func(i, j int) bool { return l[i].Time.Before(l[j].Time) })
	}

	tr := &Trace{}
	var deepestFail *Span
	var walk func(t *assemble.Transaction, depth int, pid string)
	walk = func(t *assemble.Transaction, depth int, pid string) {
		sp := Span{ID: t.ID, ParentID: pid, Depth: depth, ClientService: t.ClientService, ServerService: t.ServerService,
			Method: t.Method, Path: t.Path, Status: t.Status, DurationMs: t.DurationMs,
			OffsetMs: float64(t.Time.Sub(root.Time)) / float64(time.Millisecond), Selected: t.ID == id}
		tr.Spans = append(tr.Spans, sp)
		idx := len(tr.Spans) - 1
		if failed(t) && (deepestFail == nil || depth >= deepestFail.Depth) {
			deepestFail = &tr.Spans[idx]
		}
		for _, c := range children[t.ID] {
			walk(c, depth+1, t.ID)
		}
	}
	walk(root, 0, "")
	if deepestFail != nil {
		for i := range tr.Spans {
			if tr.Spans[i].ID == deepestFail.ID {
				tr.Spans[i].RootCause = true
				tr.RootCauseID = deepestFail.ID
			}
		}
	}
	return tr
}
