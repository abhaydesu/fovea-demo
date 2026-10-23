package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"sync/atomic"
)

var seq atomic.Int64

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func main() {
	inv := os.Getenv("INVENTORY_URL")
	if inv == "" {
		inv = "http://inventory:8082"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /order", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resp, err := http.Post(inv+"/reserve", "application/json", bytes.NewReader(body))
		if err != nil {
			writeJSON(w, 503, map[string]any{"error": "inventory unreachable"})
			return
		}
		defer resp.Body.Close()
		ib, _ := io.ReadAll(resp.Body)
		var detail json.RawMessage = ib
		if !json.Valid(ib) {
			detail, _ = json.Marshal(string(ib))
		}
		if resp.StatusCode != 200 {
			writeJSON(w, 502, map[string]any{"error": "order rejected by inventory", "inventory_status": resp.StatusCode, "inventory": detail})
			return
		}
		writeJSON(w, 201, map[string]any{"order_id": seq.Add(1), "status": "confirmed", "inventory": detail})
	})
	mux.HandleFunc("GET /stock/{item}", func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(inv + "/stock/" + r.PathValue("item"))
		if err != nil {
			writeJSON(w, 503, map[string]any{"error": "inventory unreachable"})
			return
		}
		defer resp.Body.Close()
		ib, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(ib)
	})
	log.Fatal(http.ListenAndServe(":8081", mux))
}
