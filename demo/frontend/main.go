package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
)

func proxy(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
		w.Write([]byte(`{"error":"orders unreachable"}` + "\n"))
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(b)
}

func main() {
	orders := os.Getenv("ORDERS_URL")
	if orders == "" {
		orders = "http://orders:8081"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /order", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		req, _ := http.NewRequest("POST", orders+"/order", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		proxy(w, req)
	})
	mux.HandleFunc("GET /stock/{item}", func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequest("GET", orders+"/stock/"+r.PathValue("item"), nil)
		proxy(w, req)
	})
	log.Fatal(http.ListenAndServe(":8080", mux))
}
