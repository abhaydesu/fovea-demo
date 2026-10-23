// fovea-load: load generator + evaluator for Fovea.
//
//	run:     fovea-load -n 2000 -c 8 -truth truth.json [-pid <agent pid>]
//	verify:  fovea-load -verify truth.json -api http://localhost:9090
//
// `run` sends POST /order calls through the frontend (about 10% deliberately failing) and records
// ground truth (request id, body, status the client saw) plus latency and, with -pid, the agent's CPU use.
// `verify` compares that ground truth with the transactions Fovea reconstructed.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type truth struct {
	ID     int    `json:"id"`
	Body   string `json:"body"`
	Status int    `json:"status"`
}

type result struct {
	Requests   int           `json:"requests"`
	Seconds    float64       `json:"seconds"`
	RPS        float64       `json:"rps"`
	P50        float64       `json:"p50_ms"`
	P95        float64       `json:"p95_ms"`
	P99        float64       `json:"p99_ms"`
	AgentCPUPc *float64      `json:"agent_cpu_percent_of_one_core,omitempty"`
	Truth      []truth       `json:"truth"`
	LatMs      []float64     `json:"-"`
	Errors     int           `json:"transport_errors"`
	Wall       time.Duration `json:"-"`
}

func cpuTicks(pid int) (float64, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndex(s, ")")+2:])
	var u, k float64
	fmt.Sscan(f[11], &u)
	fmt.Sscan(f[12], &k)
	return (u + k) / 100.0, true // CLK_TCK = 100
}

func pct(s []float64, p float64) float64 {
	if len(s) == 0 {
		return 0
	}
	return s[int(p*float64(len(s)-1))]
}

func run(base string, n, c int, pid int, out string) {
	var cpu0 float64
	if pid > 0 {
		cpu0, _ = cpuTicks(pid)
	}
	jobs := make(chan int)
	var mu sync.Mutex
	var res result
	var errs atomic.Int64
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: c}}
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < c; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				item, qty := "gadget", 1
				if id%10 == 0 {
					item, qty = "widget", 50 // deterministic failure
				}
				body := fmt.Sprintf(`{"item":"%s","qty":%d,"req":%d}`, item, qty, id)
				t0 := time.Now()
				resp, err := client.Post(base+"/order", "application/json", bytes.NewReader([]byte(body)))
				if err != nil {
					errs.Add(1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				d := float64(time.Since(t0).Microseconds()) / 1000
				mu.Lock()
				res.LatMs = append(res.LatMs, d)
				res.Truth = append(res.Truth, truth{id, body, resp.StatusCode})
				mu.Unlock()
			}
		}()
	}
	base0 := int(time.Now().Unix()%100000) * 10000 // unique ids per run so old transactions never collide
	for i := 1; i <= n; i++ {
		jobs <- base0 + i
	}
	close(jobs)
	wg.Wait()
	wall := time.Since(start)
	sort.Float64s(res.LatMs)
	res.Requests, res.Seconds, res.Errors = len(res.Truth), wall.Seconds(), int(errs.Load())
	res.RPS = float64(res.Requests) / wall.Seconds()
	res.P50, res.P99 = pct(res.LatMs, .5), pct(res.LatMs, .99)
	res.P95 = pct(res.LatMs, .95)
	if pid > 0 {
		if cpu1, ok := cpuTicks(pid); ok {
			v := (cpu1 - cpu0) / wall.Seconds() * 100
			res.AgentCPUPc = &v
		}
	}
	fmt.Printf("requests=%d  time=%.2fs  throughput=%.0f req/s  latency p50=%.2fms p95=%.2fms p99=%.2fms  transport_errors=%d\n",
		res.Requests, res.Seconds, res.RPS, res.P50, res.P95, res.P99, res.Errors)
	if res.AgentCPUPc != nil {
		fmt.Printf("agent CPU: %.1f%% of one core\n", *res.AgentCPUPc)
	}
	if out != "" {
		b, _ := json.MarshalIndent(res, "", " ")
		os.WriteFile(out, b, 0o644)
	}
}

type tx struct {
	ClientService string `json:"client_service"`
	ServerService string `json:"server_service"`
	ReqBody       string `json:"req_body"`
	Status        int    `json:"status"`
	Path          string `json:"path"`
}

func verify(truthFile, api string) {
	var res result
	b, err := os.ReadFile(truthFile)
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal(b, &res)
	resp, err := http.Get(api + "/api/transactions?limit=50000")
	if err != nil {
		log.Fatal(err)
	}
	var txs []tx
	json.NewDecoder(resp.Body).Decode(&txs)
	resp.Body.Close()

	type hop struct{ c, s string }
	hops := []hop{{"external", "frontend"}, {"frontend", "orders"}, {"orders", "inventory"}}
	// index POST transactions by (hop, req id)
	idx := map[hop]map[int][]tx{}
	for _, h := range hops {
		idx[h] = map[int][]tx{}
	}
	for _, t := range txs {
		var m struct{ Req int }
		if json.Unmarshal([]byte(t.ReqBody), &m) != nil || m.Req == 0 {
			continue
		}
		h := hop{t.ClientService, t.ServerService}
		if _, ok := idx[h]; ok {
			idx[h][m.Req] = append(idx[h][m.Req], t)
		}
	}
	n := len(res.Truth)
	var found, bodyOK, statusOK, dup, chain, failChain int
	var failTotal int
	for _, g := range res.Truth {
		list := idx[hops[0]][g.ID]
		if len(list) > 0 {
			found++
			t := list[0]
			// compare JSON-equivalent bodies (key order is preserved by the sender)
			if strings.TrimSpace(t.ReqBody) == g.Body {
				bodyOK++
			}
			if t.Status == g.Status {
				statusOK++
			}
		}
		if len(list) > 1 {
			dup++
		}
		all := true
		for _, h := range hops {
			if len(idx[h][g.ID]) == 0 {
				all = false
			}
		}
		if all {
			chain++
		}
		if g.Status != 201 {
			failTotal++
			if all {
				failChain++
			}
		}
	}
	p := func(a, b int) string { return fmt.Sprintf("%d/%d (%.2f%%)", a, b, 100*float64(a)/float64(max(b, 1))) }
	fmt.Println("== payload reconstruction accuracy (client-observed ground truth vs Fovea)")
	fmt.Println("requests sent:                    ", n)
	fmt.Println("reconstructed (entry hop):        ", p(found, n))
	fmt.Println("request body byte-exact:          ", p(bodyOK, n))
	fmt.Println("status code matches client:       ", p(statusOK, n))
	fmt.Println("full 3-hop chain captured:        ", p(chain, n))
	fmt.Println("  of which deliberate failures:   ", p(failChain, failTotal))
	fmt.Println("duplicate entries (must be 0):    ", dup)
	if st, err := http.Get(api + "/api/stats"); err == nil {
		var m map[string]any
		json.NewDecoder(st.Body).Decode(&m)
		st.Body.Close()
		fmt.Printf("kernel events seen=%v dropped=%v  transactions_total=%v\n", m["events_seen"], m["events_dropped"], m["transactions_total"])
	}
}

func main() {
	base := flag.String("base", "http://localhost:8080", "frontend URL")
	n := flag.Int("n", 1000, "requests")
	c := flag.Int("c", 4, "concurrent clients")
	pid := flag.Int("pid", 0, "fovea-agent pid to sample CPU for")
	out := flag.String("truth", "", "write ground truth + results to this file")
	ver := flag.String("verify", "", "ground-truth file to verify against the API")
	api := flag.String("api", "http://localhost:9090", "Fovea API URL")
	flag.Parse()
	if *ver != "" {
		verify(*ver, *api)
		return
	}
	run(*base, *n, *c, *pid, *out)
}
