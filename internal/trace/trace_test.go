package trace

import (
	"testing"
	"time"

	"fovea/internal/assemble"
)

func tx(id, c, s string, off, dur float64, status int) assemble.Transaction {
	base := time.Unix(1_700_000_000, 0)
	return assemble.Transaction{ID: id, ClientService: c, ServerService: s, Time: base.Add(time.Duration(off * float64(time.Millisecond))),
		DurationMs: dur, Status: status, Method: "POST", Path: "/" + id}
}

func TestChainAndRootCause(t *testing.T) {
	all := []assemble.Transaction{
		tx("a", "external", "frontend", 0, 10, 502),
		tx("b", "frontend", "orders", 1, 8, 502),
		tx("c", "orders", "inventory", 2, 4, 500),
		tx("other", "frontend", "orders", 100, 5, 201), // unrelated, later
	}
	tr := Build(all, "c")
	if tr == nil || len(tr.Spans) != 3 {
		t.Fatalf("want 3 spans, got %+v", tr)
	}
	if tr.Spans[0].ID != "a" || tr.Spans[2].Depth != 2 {
		t.Fatalf("wrong nesting: %+v", tr.Spans)
	}
	if tr.RootCauseID != "c" {
		t.Fatalf("root cause should be the deepest failure, got %q", tr.RootCauseID)
	}
}

func TestSiblingsPickSmallestEnclosingParent(t *testing.T) {
	all := []assemble.Transaction{
		tx("p1", "external", "orders", 0, 50, 200),
		tx("p2", "external", "orders", 10, 5, 200),
		tx("c", "orders", "inventory", 11, 2, 200),
	}
	tr := Build(all, "c")
	if tr.Spans[0].ID != "p2" {
		t.Fatalf("child must attach to the tighter parent p2, got %s", tr.Spans[0].ID)
	}
}

func TestUnknownID(t *testing.T) {
	if Build(nil, "x") != nil {
		t.Fatal("want nil")
	}
}
