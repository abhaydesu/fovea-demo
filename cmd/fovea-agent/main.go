// fovea-agent: loads the eBPF programs, assembles HTTP transactions and
// serves the API/UI. Run as root: sudo ./bin/fovea-agent
//
// Modes:
//
//	all        (default) capture + collector + UI in one process
//	agent      capture only; forwards transactions to -collector URL
//	collector  no eBPF; receives transactions from agents, serves API/UI
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fovea/internal/api"
	"fovea/internal/assemble"
	"fovea/internal/capture"
	"fovea/internal/identity"
	"fovea/internal/netflow"
)

func main() {
	addr := flag.String("listen", ":9090", "API/UI listen address")
	ui := flag.String("ui", "ui/dist", "directory with built UI")
	project := flag.String("project", "demo", "docker compose project to observe")
	mode := flag.String("mode", "all", "all | agent | collector")
	collector := flag.String("collector", "", "collector base URL (agent mode), e.g. http://host:9090")
	node := flag.String("node", "", "node name used as transaction id prefix (default: hostname)")
	all := flag.Bool("all-processes", false, "capture every process, not just compose containers")
	redact := flag.Bool("redact", true, "mask credentials/PII in stored headers and JSON bodies")
	persist := flag.String("persist", "", "JSONL file to persist transactions across restarts")
	maxTx := flag.Int("max-tx", 20000, "transactions kept in memory")
	noFlows := flag.Bool("no-flows", false, "disable the network flow layer (TC counters on container veths)")
	jsonl := flag.Bool("jsonl", false, "print finished transactions as JSON lines")
	raw := flag.Bool("raw", false, "print raw captured chunks (debugging)")
	flag.Parse()

	if *node == "" {
		*node, _ = os.Hostname()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store := assemble.NewStore(*maxTx)
	if *persist != "" {
		if err := store.EnablePersistence(*persist); err != nil {
			log.Fatalf("persist: %v", err)
		}
		log.Printf("persistence: %s (%d transactions restored)", *persist, store.Len())
	}
	start := time.Now()
	apiSrv := &api.Server{Store: store, UIDir: *ui, Ingest: *mode == "collector"}
	stats := map[string]func() any{"mode": func() any { return *mode }, "uptime_s": func() any { return int(time.Since(start).Seconds()) },
		"redaction": func() any { return *redact }}

	if *jsonl {
		ch, _ := store.Subscribe()
		go func() {
			enc := json.NewEncoder(os.Stdout)
			for t := range ch {
				enc.Encode(t)
			}
		}()
	}

	var cap *capture.Capture
	var flows *capture.Flows
	var asm *assemble.Assembler
	var res identity.Resolver
	if *mode != "collector" {
		d := identity.NewDocker(*project)
		if err := d.Refresh(); err != nil {
			log.Printf("warning: identity refresh: %v", err)
		}
		res = d
		var err error
		if cap, err = capture.New(); err != nil {
			log.Fatalf("capture: %v", err)
		}
		defer cap.Close()
		if !*noFlows {
			if flows, err = capture.NewFlows(); err != nil {
				log.Printf("flow layer disabled: %v", err)
			} else {
				defer flows.Close()
				apiSrv.Flows = func() []netflow.Flow { return netflow.Merge(flows.Snapshot(), res) }
			}
		}
		sync := func() {
			if err := res.Refresh(); err != nil {
				return
			}
			ids := res.CgroupIDs()
			if *all {
				ids = nil
			}
			if err := cap.SetAllowedCgroups(ids); err != nil {
				log.Printf("set cgroups: %v", err)
			}
			if flows != nil {
				flows.SetInterfaces(res.Interfaces())
			}
		}
		sync()
		go func() { // pick up containers started after the agent
			for range time.Tick(2 * time.Second) {
				sync()
			}
		}()
		asm = assemble.New(res, store)
		asm.Redact, asm.Node = *redact, *node
		stats["events_seen"] = func() any { s, _ := cap.Stats(); return s }
		stats["events_dropped"] = func() any { _, d := cap.Stats(); return d }
	}
	apiSrv.Stats = func() map[string]any {
		m := map[string]any{}
		for k, f := range stats {
			m[k] = f()
		}
		return m
	}

	if *mode == "agent" {
		if *collector == "" {
			log.Fatal("agent mode needs -collector URL")
		}
		go forward(ctx, store, *collector)
	}
	srv := &http.Server{Addr: *addr, Handler: apiSrv.Handler()}
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("api: %v", err)
		}
	}()
	log.Printf("fovea up: mode=%s node=%s API/UI on %s (project=%s)", *mode, *node, *addr, *project)

	if *mode == "collector" {
		<-ctx.Done()
		srv.Shutdown(context.Background())
		return
	}

	events := make(chan *capture.Event, 8192)
	go cap.Run(ctx, events)
	gc := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down: detaching programs")
			srv.Shutdown(context.Background())
			return
		case <-gc.C:
			asm.GC()
		case ev := <-events:
			if *raw {
				log.Printf("%s pid=%d fd=%d dir=%d %s:%d<->%s:%d len=%d %q", ev.Comm, ev.TGID, ev.FD, ev.Dir,
					ev.LAddr, ev.LPort, ev.RAddr, ev.RPort, ev.SyscallLen, ev.Data)
			}
			asm.Feed(ev)
		}
	}
}
