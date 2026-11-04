package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/zc0350/congmq/internal/broker"
)

// bootTime is when the process started, which is what package initialisation
// gives for free and what an operator divides counters by to get a rate.
var bootTime = time.Now()

// processCost is the broker's own footprint. No packet counter answers "is this
// process growing because of a leak or because of load", and capacity planning
// is the one job that does, so the two numbers that matter — memory reserved
// from the OS and goroutines alive now — travel with the counters.
type processCost struct {
	PID           int64  `json:"pid"`
	StartedUnix   int64  `json:"started_unix"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	Goroutines    int    `json:"goroutines"`
	MemAllocBytes uint64 `json:"mem_alloc_bytes"` // live heap
	MemSysBytes   uint64 `json:"mem_sys_bytes"`   // reserved from the OS: the capacity number
	HeapObjects   uint64 `json:"heap_objects"`
	GCCycles      uint32 `json:"gc_cycles"`
	NumCPU        int    `json:"num_cpu"`
}

func processCostOf() processCost {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return processCost{
		PID:           int64(os.Getpid()),
		StartedUnix:   bootTime.Unix(),
		UptimeSeconds: int64(time.Since(bootTime).Seconds()),
		Goroutines:    runtime.NumGoroutine(),
		MemAllocBytes: ms.Alloc,
		MemSysBytes:   ms.Sys,
		HeapObjects:   ms.HeapObjects,
		GCCycles:      ms.NumGC,
		NumCPU:        runtime.NumCPU(),
	}
}

// metricsView is everything this endpoint publishes, in one shape shared by the
// JSON and the text view. Adding a counter to a struct here is enough to make it
// appear on both — and the test over promText fails until the text table knows
// about it too.
type metricsView struct {
	broker.Metrics
	processCost
	certStats
	reloadStats
}

// promKind is how the text exposition must treat one metric: what it means, and
// whether it may only go up. The names are the JSON keys with a congmq_ prefix,
// deliberately not renamed to Prometheus' _total convention — one metric should
// have one name across the two views, or an operator comparing a curl output with
// a graph is doing arithmetic nobody documented.
type promKind struct {
	help string
	kind string // counter or gauge
}

var promText = map[string]promKind{
	"total_connections":                 {"Connections accepted since start.", "counter"},
	"online":                            {"Connections with a live session right now.", "gauge"},
	"messages_in":                       {"PUBLISH packets received.", "counter"},
	"messages_out":                      {"PUBLISH packets delivered.", "counter"},
	"bytes_in":                          {"Bytes read from clients.", "counter"},
	"bytes_out":                         {"Bytes written to clients.", "counter"},
	"subscriptions":                     {"Subscription filters registered right now.", "gauge"},
	"retained_messages":                 {"Retained messages held right now.", "gauge"},
	"queue_spills":                      {"Messages moved to an offline queue.", "counter"},
	"store_sessions":                    {"Sessions the durable store is holding right now.", "gauge"},
	"store_queued":                      {"Messages waiting in the durable store for a client that is away.", "gauge"},
	"store_bytes":                       {"Bytes of the state file, 0 without -store.", "gauge"},
	"malformed_packets":                 {"Packets that failed to decode.", "counter"},
	"protocol_errors":                   {"Packets out of order for the protocol.", "counter"},
	"rejected_connections":              {"Connections refused before a session existed.", "counter"},
	"dropped_messages":                  {"Messages discarded to keep a bounded queue.", "counter"},
	"expired_messages":                  {"Messages dropped because their lifetime passed.", "counter"},
	"expired_sessions":                  {"Offline sessions reaped after their expiry interval.", "counter"},
	"dropped_over_peer_max_packet_size": {"Deliveries skipped as larger than the subscriber allows.", "counter"},
	"server_disconnects":                {"Disconnects sent by the server.", "counter"},
	"auth_rejected":                     {"CONNECT packets refused by the auth rules.", "counter"},
	"acl_denied_publish":                {"Publishes refused by the acl rules.", "counter"},
	"acl_denied_subscribe":              {"Subscriptions refused by the acl rules.", "counter"},
	"acl_denied_delivery":               {"Deliveries refused by the acl rules.", "counter"},
	"acl_unsafe_expansions":             {"Rules whose topic expanded to a wildcard.", "counter"},
	"connections_tls":                   {"TLS sessions established.", "counter"},
	"tls_handshake_failures":            {"TLS handshakes that never became a session.", "counter"},
	"rules_generation":                  {"Policy generation decisions are made against.", "gauge"},
	"rules_loaded_unix":                 {"When the live policy generation became live.", "gauge"},
	"rules_reloads":                     {"Policy swaps that took effect.", "counter"},
	"rules_reload_failures":             {"Rewrites of a rule file refused; the previous policy stayed in force.", "counter"},
	"rules_reloaded_unix":               {"When the last policy swap landed.", "gauge"},
	"reload_interval_seconds":           {"How often the rule and certificate files are re-checked, 0 for signal-only.", "gauge"},
	"tls_cert_generation":               {"Certificate generation handshakes are answered from.", "gauge"},
	"tls_cert_reloads":                  {"Certificate rotations that took effect.", "counter"},
	"tls_cert_reload_failures":          {"Certificate rotations refused; the previous leaf stayed in force.", "counter"},
	"tls_cert_not_after_unix":           {"When the certificate now in force stops being valid.", "gauge"},

	// The gate's own. Both refusal counters stay at zero while
	// -max-conns-per-ip, -conn-rate-per-ip and the credential limit are off, and
	// the two gauges say whether a limit is about to bite rather than the one that
	// already did. refused_over_subscription_cap is the per-client sibling of the
	// same idea, so it reads next to them on a dashboard.
	"refused_over_per_ip_connection_limit": {"Sockets closed because that address already holds the maximum.", "counter"},
	"refused_over_per_ip_connect_rate":     {"Sockets closed for starting too many connections per second.", "counter"},
	"per_ip_gate_entries":                  {"Source addresses the gate is tracking right now.", "gauge"},
	"per_ip_gate_held_sockets":             {"Sockets the gate is counting right now, across every address.", "gauge"},
	"auth_lockout_refusals":                {"CONNECTs refused because the source address is locked out, correct password included.", "counter"},
	"auth_locked_addresses":                {"Source addresses serving a credential lockout right now.", "gauge"},
	"refused_over_subscription_cap":        {"SUBSCRIBEs refused because that client already holds -max-subs filters.", "counter"},

	// The transport header's two numbers. connections_over_proxy_header is the one
	// that says the fleet is metered per device: behind a balancer, a value stuck at
	// zero means every address-keyed limit above is being applied to the balancer.
	// refused_over_proxy_header includes the headers sent by an address that may not
	// report another's — an attempt to borrow an identity, counted even though the
	// socket is closed either way.
	"connections_over_proxy_header": {"Sessions whose client address came from a transport header.", "counter"},
	"refused_over_proxy_header":     {"Sockets closed at the transport header stage.", "counter"},

	"pid":             {"Process id.", "gauge"},
	"started_unix":    {"When the process started.", "gauge"},
	"uptime_seconds":  {"Seconds since the process started.", "gauge"},
	"goroutines":      {"Goroutines alive right now.", "gauge"},
	"mem_alloc_bytes": {"Heap in use right now.", "gauge"},
	"mem_sys_bytes":   {"Memory reserved from the OS: the capacity number.", "gauge"},
	"heap_objects":    {"Heap objects alive right now.", "gauge"},
	"gc_cycles":       {"Garbage collections run.", "counter"},
	"num_cpu":         {"CPUs Go may use.", "gauge"},
}

// serveMetrics publishes the broker's counters. /metrics stays JSON, because that
// is what curl reads; /metrics.txt is the same snapshot in the format a scraper
// wants; /readyz answers the load balancer. Bind it to loopback unless something
// on the network is meant to scrape it.
//
// It reports the address it ended up on, which is not always the one asked for:
// port 0 is how a test gets an endpoint it can dial without guessing.
func serveMetrics(addr string, b *broker.Broker, certs *certHolder, rel *reloader, log *slog.Logger) (string, func(), error) {
	mux := http.NewServeMux()

	snapshot := func() metricsView {
		return metricsView{b.Metrics(), processCostOf(), certStatsOf(certs), rel.stats()}
	}

	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(snapshot()); err != nil {
			log.Error("cannot write metrics", "err", err)
		}
	})

	mux.HandleFunc("GET /metrics.txt", func(w http.ResponseWriter, r *http.Request) {
		out, err := prometheusText(snapshot())
		if err != nil {
			// A broken table is a bug in this binary, not a client error: say so
			// rather than serving a half-scrape that a dashboard reads as a outage.
			log.Error("cannot render metrics as text", "err", err)
			http.Error(w, "metrics unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(out))
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		online := b.Metrics().Online
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		status := "ready"
		if !b.Serving() {
			// Either Serve has not started yet or Shutdown is draining sessions.
			// Both mean "do not put a new device here", and neither is a 500.
			status = "draining"
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		fmt.Fprintf(w, `{"status":%q,"online":%d}`+"\n", status, online)
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics endpoint stopped", "err", err)
		}
	}()
	log.Info("metrics endpoint listening", "addr", ln.Addr().String(),
		"paths", "/metrics /metrics.txt /readyz")

	// The endpoint outlives the broker's own drain by design, so the last
	// counters stay readable while sessions are being flushed to the store — and
	// /readyz is what tells a probe that this window is open.
	return ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}

// prometheusText renders the snapshot in the exposition format Prometheus
// scrapes (text/plain; version=0.0.4). Hand-written on purpose: the whole broker
// takes no third-party packages, and this format is forty lines of text.
func prometheusText(v metricsView) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // the counters are 64-bit; a float would round the big ones
	var fields map[string]any
	if err := dec.Decode(&fields); err != nil {
		return "", err
	}

	names := make([]string, 0, len(promText))
	for name := range promText {
		names = append(names, name)
	}
	slices.Sort(names)

	var sb strings.Builder
	for _, name := range names {
		num, ok := fields[name].(json.Number)
		if !ok {
			return "", fmt.Errorf("congmq_%s is in the text table but not a number in the json view", name)
		}
		meta := promText[name]
		sb.WriteString("# HELP congmq_" + name + " " + meta.help + "\n")
		sb.WriteString("# TYPE congmq_" + name + " " + meta.kind + "\n")
		sb.WriteString("congmq_" + name + " " + num.String() + "\n")
	}
	return sb.String(), nil
}
