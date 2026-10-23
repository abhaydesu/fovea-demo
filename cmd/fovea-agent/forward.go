package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"fovea/internal/assemble"
)

// forward ships finished/updated transactions to a remote collector in small batches.
func forward(ctx context.Context, store *assemble.Store, url string) {
	ch, cancel := store.Subscribe()
	defer cancel()
	client := &http.Client{Timeout: 5 * time.Second}
	var batch []assemble.Transaction
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		b, _ := json.Marshal(batch)
		resp, err := client.Post(url+"/api/ingest", "application/json", bytes.NewReader(b))
		if err != nil {
			log.Printf("collector unreachable (%v); dropping %d transactions", err, len(batch))
		} else {
			resp.Body.Close()
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case t := <-ch:
			batch = append(batch, t)
			if len(batch) >= 200 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}
