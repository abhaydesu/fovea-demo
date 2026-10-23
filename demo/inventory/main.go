package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

var (
	mu    sync.Mutex
	stock = map[string]int{"widget": 3, "gadget": 1000, "gizmo": 25}
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stock/{item}", func(w http.ResponseWriter, r *http.Request) {
		item := r.PathValue("item")
		mu.Lock()
		n, ok := stock[item]
		mu.Unlock()
		if !ok {
			writeJSON(w, 404, map[string]any{"error": "unknown item", "item": item})
			return
		}
		writeJSON(w, 200, map[string]any{"item": item, "available": n})
	})
	mux.HandleFunc("POST /reserve", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Item string `json:"item"`
			Qty  int    `json:"qty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]any{"error": "bad json"})
			return
		}
		mu.Lock()
		n, ok := stock[req.Item]
		mu.Unlock()
		switch {
		case !ok:
			writeJSON(w, 404, map[string]any{"error": "unknown item", "item": req.Item})
		case req.Qty > n:
			writeJSON(w, 500, map[string]any{"error": "insufficient stock", "item": req.Item, "available": n, "requested": req.Qty})
		default:
			writeJSON(w, 200, map[string]any{"reserved": true, "item": req.Item, "qty": req.Qty, "remaining": n - req.Qty})
		}
	})
	log.Fatal(http.ListenAndServe(":8082", mux))
}
