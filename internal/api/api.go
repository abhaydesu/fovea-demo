// Package api serves the transaction/graph HTTP API, the SSE stream and the UI.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"fovea/internal/assemble"
	"fovea/internal/graph"
	"fovea/internal/netflow"
	"fovea/internal/trace"
)

type Server struct {
	Store *assemble.Store
	UIDir string
	// Flows returns current network flows (nil when the flow layer is off).
	Flows func() []netflow.Flow
	// Stats returns agent counters for /api/stats.
	Stats func() map[string]any
	// Ingest enables POST /api/ingest (collector mode).
	Ingest bool
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/transactions", s.transactions)
	mux.HandleFunc("GET /api/transactions/{id}", s.detail)
	mux.HandleFunc("GET /api/graph", s.graph)
	mux.HandleFunc("GET /api/flows", s.flows)
	mux.HandleFunc("GET /api/stats", s.stats)
	mux.HandleFunc("GET /api/stream", s.stream)
	mux.HandleFunc("POST /api/clear", s.clear)
	if s.Ingest {
		mux.HandleFunc("POST /api/ingest", s.ingest)
	}
	if s.UIDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(s.UIDir)))
	}
	return cors(mux)
}

func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		h.ServeHTTP(w, r)
	})
}

func matches(t assemble.Transaction, service, status string) bool {
	if service != "" && t.ClientService != service && t.ServerService != service {
		return false
	}
	switch status {
	case "":
	case "error":
		return graph.IsError(t.Status)
	default:
		if strings.HasSuffix(status, "xx") && len(status) == 3 {
			return strconv.Itoa(t.Status)[0] == status[0]
		}
		if n, err := strconv.Atoi(status); err == nil {
			return t.Status == n
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) transactions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 50000 {
		limit = 200
	}
	all := s.Store.Snapshot()
	out := []assemble.Transaction{}
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- { // newest first
		if matches(all[i], q.Get("service"), q.Get("status")) {
			out = append(out, all[i])
		}
	}
	writeJSON(w, out)
}

// detail returns one transaction with its inferred call chain and the network flow of its connection.
func (s *Server) detail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tx, ok := s.Store.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	resp := map[string]any{"tx": tx, "trace": trace.Build(s.Store.Snapshot(), id)}
	if s.Flows != nil {
		for _, f := range s.Flows() {
			if f.Client == tx.Src && f.Server == tx.Dst {
				resp["flow"] = f
				break
			}
		}
	}
	writeJSON(w, resp)
}

func (s *Server) graph(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, graph.Build(s.Store.Snapshot()))
}

func (s *Server) clear(w http.ResponseWriter, r *http.Request) {
	s.Store.Clear()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) flows(w http.ResponseWriter, r *http.Request) {
	out := []netflow.Flow{}
	if s.Flows != nil {
		out = s.Flows()
	}
	if len(out) > 300 {
		out = out[:300]
	}
	writeJSON(w, out)
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	m := map[string]any{"transactions": s.Store.Len(), "transactions_total": s.Store.Total()}
	if s.Stats != nil {
		for k, v := range s.Stats() {
			m[k] = v
		}
	}
	writeJSON(w, m)
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	var batch []assemble.Transaction
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)).Decode(&batch); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	for _, t := range batch {
		s.Store.Upsert(t)
	}
	w.WriteHeader(204)
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch, cancel := s.Store.Subscribe()
	defer cancel()
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case t := <-ch:
			b, _ := json.Marshal(t)
			fmt.Fprintf(w, "event: tx\ndata: %s\n\n", b)
			fl.Flush()
		}
	}
}
