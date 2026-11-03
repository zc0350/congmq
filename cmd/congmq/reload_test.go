package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/tlscert"
)

// The tests here are about the parts an operator touches without stopping the
// process: a rule file rewritten in place, a certificate replaced under a live
// port, and the endpoint that has to tell the truth about both.

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// ---------------------------------------------------------------- text ----

// stringMetrics are the fields the JSON view carries and the text view cannot:
// the exposition format has no place for a sample whose value is a word.
var stringMetrics = map[string]bool{
	"id":          true,
	"tls_cert_cn": true,
}

func snapshot() metricsView {
	return metricsView{broker.New(broker.Options{}).Metrics(), processCostOf(), certStatsOf(nil), reloadStats{}}
}

func TestPrometheusTextCoversTheWholeJSONView(t *testing.T) {
	raw, err := json.Marshal(snapshot())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for name := range fields {
		if _, ok := promText[name]; !ok && !stringMetrics[name] {
			t.Errorf("metric %q is published as json but the text view says nothing about it", name)
		}
		if stringMetrics[name] {
			if _, ok := fields[name].(string); !ok {
				t.Errorf("%q is listed as a string but the json view gives %T", name, fields[name])
			}
		}
	}
	for name := range promText {
		if _, ok := fields[name]; !ok {
			t.Errorf("the text table names %q, which the json view does not publish", name)
		}
	}
}

func TestPrometheusTextIsWellFormed(t *testing.T) {
	out, err := prometheusText(snapshot())
	if err != nil {
		t.Fatalf("prometheusText: %v", err)
	}

	types := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "# TYPE "); ok {
			f := strings.Fields(rest)
			if len(f) != 2 {
				t.Fatalf("bad # TYPE line %q", line)
			}
			types[f[0]] = f[1]
		}
	}

	valid := regexp.MustCompile(`^congmq_[a-z0-9_]+$`)
	var samples int
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "#") {
				if !strings.HasPrefix(line, "# HELP ") && !strings.HasPrefix(line, "# TYPE ") {
					t.Fatalf("unexpected comment line %q", line)
				}
			}
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			t.Fatalf("sample %q is not \"name value\"", line)
		}
		if !valid.MatchString(parts[0]) {
			t.Fatalf("metric name %q is not a valid prometheus name", parts[0])
		}
		// Every sample needs its own TYPE line, and only two kinds exist. A
		// scraper that meets an untyped series keeps the points but loses the
		// rate() it was asked for.
		kind := types[parts[0]]
		if kind != "counter" && kind != "gauge" {
			t.Fatalf("metric %q has # TYPE %q", parts[0], kind)
		}
		// Integers print as digits, not 1.5e+06: json.Number is why.
		if _, err := strconv.ParseInt(parts[1], 10, 64); err != nil {
			t.Fatalf("value of %q is %q, want whole digits", parts[0], parts[1])
		}
		samples++
	}
	if samples < 30 {
		t.Fatalf("only %d samples rendered; the view carries more counters than that", samples)
	}
}

// ---------------------------------------------------------------- readyz ----

func TestReadyzSaysDrainingOnceShutdownStarted(t *testing.T) {
	b := broker.New(broker.Options{Logger: quietLog()})
	if err := b.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("broker listen: %v", err)
	}
	go func() { _ = b.Serve() }()

	addr, closeEndpoint, err := serveMetrics("127.0.0.1:0", b, nil, nil, quietLog())
	if err != nil {
		t.Fatalf("serveMetrics: %v", err)
	}
	defer closeEndpoint()

	waitUntilReady(t, b)
	if code, body := probe(t, addr); code != http.StatusOK || !strings.Contains(body, "ready") {
		t.Fatalf("readyz while serving = %d %q, want 200 ready", code, body)
	}

	if err := b.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	// The endpoint outlives the drain on purpose, so this is the answer a load
	// balancer gets while sessions are still being flushed to the store.
	if code, body := probe(t, addr); code != http.StatusServiceUnavailable || !strings.Contains(body, "draining") {
		t.Fatalf("readyz while draining = %d %q, want 503 draining", code, body)
	}
}

func waitUntilReady(t *testing.T, b *broker.Broker) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !b.Serving() {
		if time.Now().After(deadline) {
			t.Fatal("Serve never reached the window where a probe should say ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func probe(t *testing.T, addr string) (int, string) {
	t.Helper()
	res, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatalf("readyz: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

// ---------------------------------------------------------------- cert ----

func TestRotatedLeafIsServedToTheNextHandshake(t *testing.T) {
	dir := t.TempDir()
	first := mint(t, dir, "congmq.first")
	h := start(t, dir)

	if cn := seenByClient(t, h, poolOf(t, first.CA)); cn != "congmq.first" {
		t.Fatalf("the client saw %q before any rotation, want congmq.first", cn)
	}

	// Replacing the files under a live port is what an operator actually does.
	second := mint(t, dir, "congmq.second")
	changed, gen, err := h.poll()
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if !changed {
		t.Fatal("the rotation was not picked up")
	}
	if gen.leaf.Subject.CommonName != "congmq.second" {
		t.Fatalf("new generation carries %q, want congmq.second", gen.leaf.Subject.CommonName)
	}
	if cn := seenByClient(t, h, poolOf(t, second.CA)); cn != "congmq.second" {
		t.Fatalf("the client saw %q after the rotation, want congmq.second", cn)
	}

	// And the retired CA no longer vouches for what the port presents — which is
	// the thing a fleet provisioned against it has to hear about.
	if _, err := handshake(h, poolOf(t, first.CA)); err == nil {
		t.Error("a client trusting only the retired CA still completes the handshake")
	}
}

func TestBrokenCertificateFileKeepsTheLeafInForce(t *testing.T) {
	dir := t.TempDir()
	first := mint(t, dir, "congmq.good")
	h := start(t, dir)

	write(t, filepath.Join(dir, "server.crt"), "not a certificate\n")
	changed, _, err := h.poll()
	if err == nil {
		t.Fatal("a garbage leaf was accepted as a rotation")
	}
	if changed {
		t.Error("poll reported a new generation while refusing the file")
	}
	if got := h.current().leaf.Subject.CommonName; got != "congmq.good" {
		t.Errorf("certificate in force = %q, want congmq.good", got)
	}
	if h.failures.Load() != 1 {
		t.Errorf("tls_cert_reload_failures = %d, want 1", h.failures.Load())
	}
	// Handshakes keep working off the generation still in force.
	if cn := seenByClient(t, h, poolOf(t, first.CA)); cn != "congmq.good" {
		t.Errorf("handshake after a refused rotation served %q", cn)
	}

	// Re-polling the same broken content is silent: no new attempt, no new error,
	// no new line in the log. The number answers "how many rewrites were refused",
	// not "how many ticks the file was bad".
	changed, _, err = h.poll()
	if err != nil || changed {
		t.Errorf("re-poll of refused content = changed %v err %v, want nothing to happen", changed, err)
	}
	if h.failures.Load() != 1 {
		t.Errorf("tls_cert_reload_failures = %d after re-polling the same file, want 1", h.failures.Load())
	}

	// The latch must not wedge the port: a rewritten file is new content, and the
	// next poll tries it.
	third := mint(t, dir, "congmq.repaired")
	changed, gen, err := h.poll()
	if err != nil || !changed {
		t.Fatalf("poll after the operator fixed the file = changed %v err %v", changed, err)
	}
	if gen.leaf.Subject.CommonName != "congmq.repaired" {
		t.Errorf("new generation carries %q, want congmq.repaired", gen.leaf.Subject.CommonName)
	}
	if cn := seenByClient(t, h, poolOf(t, third.CA)); cn != "congmq.repaired" {
		t.Errorf("handshake after the repair served %q", cn)
	}
}

func TestExpiredLeafIsRefusedAtRotation(t *testing.T) {
	dir := t.TempDir()
	mint(t, dir, "congmq.good")
	h := start(t, dir)

	expired, err := tlscert.Generate(tlscert.Options{ServerCN: "congmq.expired", ValidFor: -time.Hour})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	write(t, filepath.Join(dir, "server.crt"), string(expired.ServerPEM))
	write(t, filepath.Join(dir, "server.key"), string(expired.ServerKey))

	_, _, err = h.poll()
	if err == nil {
		t.Fatal("an expired leaf was rotated in")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("refusal said %q, want it to name expiry", err)
	}
	if got := h.current().leaf.Subject.CommonName; got != "congmq.good" {
		t.Errorf("certificate in force = %q, want the previous one", got)
	}
}

func TestRefusedRotationIsCountedAndReported(t *testing.T) {
	dir := t.TempDir()
	mint(t, dir, "congmq.good")
	h := start(t, dir)
	write(t, filepath.Join(dir, "server.crt"), "garbage\n")
	_, _, _ = h.poll()

	stats := certStatsOf(h)
	if stats.CertReloads != 0 || stats.CertFailures != 1 || stats.CertGeneration != 1 {
		t.Errorf("cert stats = %+v, want the boot generation still counted with one refusal", stats)
	}
	if stats.CertCN != "congmq.good" {
		t.Errorf("cert_stats.cn = %q, want the leaf actually being served", stats.CertCN)
	}
	if stats.CertNotAfterUnix == 0 {
		t.Error("tls_cert_not_after_unix is zero, so nothing can alert on expiry")
	}
}

// ---------------------------------------------------------------- rules ----

func TestReloaderKeepsTheOldPolicyAndCountsTheRewriteOnce(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.jsonl")
	aclPath := filepath.Join(dir, "acl.jsonl")
	write(t, authPath, `{"username":"one","salt":"x","alg":"md5","scheme":"username+salt"}`+"\n")
	write(t, aclPath, `{"effect":"allow","action":"all","topics":["#"]}`+"\n")

	b := broker.New(broker.Options{Logger: quietLog()})
	rel := &reloader{log: quietLog(), b: b, authPath: authPath, aclPath: aclPath,
		interval: time.Second, ruleStamp: stampPair(authPath, aclPath)}

	// A half-written file is the ordinary shape of a broken deploy.
	write(t, authPath, `{"username":"one","salt":"x","alg":"md5","scheme":"username+salt"}
{"username":"two","salt"
`)
	rel.check()
	rel.check()
	rel.check()
	if got := b.Metrics().RulesGeneration; got != 1 {
		t.Errorf("rules_generation = %d after a refused rewrite, want the policy to stay at 1", got)
	}
	if got := rel.stats().RulesReloadFailures; got != 1 {
		t.Errorf("rules_reload_failures = %d, want 1 for one broken version however many polls see it", got)
	}

	// The operator fixes it. Same poll, new content, new generation.
	write(t, authPath, `{"username":"one","salt":"x","alg":"md5","scheme":"username+salt"}
{"username":"two","salt":"x","alg":"md5","scheme":"username+salt"}
`)
	rel.check()
	m := b.Metrics()
	if m.RulesGeneration != 2 {
		t.Fatalf("rules_generation = %d after the fix, want 2", m.RulesGeneration)
	}
	if got := rel.stats(); got.RulesReloads != 1 || got.RulesReloadFailures != 1 || got.RulesReloadedUnix == 0 {
		t.Errorf("reload stats = %+v, want one reload, one failure and a timestamp", got)
	}

	// An unchanged file does not invent a generation.
	rel.check()
	if got := b.Metrics().RulesGeneration; got != 2 {
		t.Errorf("rules_generation = %d with nothing rewritten, want 2", got)
	}
}

func TestReloaderRefusesCertRulesWithoutATLSPort(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.jsonl")
	write(t, authPath, `{"username":"one","salt":"x","alg":"md5","scheme":"username+salt"}`+"\n")

	b := broker.New(broker.Options{Logger: quietLog()})
	rel := &reloader{log: quietLog(), b: b, authPath: authPath,
		interval: time.Second, ruleStamp: stampPair(authPath, "")}

	// A cert_cn rule is a promise that a client certificate can be looked at.
	// With no TLS port it can never be met, so this rewrite would lock the fleet
	// out through a window nobody meant to open.
	write(t, authPath, `{"cert_cn":"congmq-device-1"}`+"\n")
	rel.check()
	if got := b.Metrics().RulesGeneration; got != 1 {
		t.Errorf("rules_generation = %d, want the password policy to stay in force", got)
	}
	if got := rel.stats().RulesReloadFailures; got != 1 {
		t.Errorf("rules_reload_failures = %d, want 1", got)
	}

	// With a TLS port the same rule is loadable, which is the only difference.
	rel.tlsOn = true
	rel.failedStamp = ""
	rel.check()
	if got := b.Metrics().RulesGeneration; got != 2 {
		t.Errorf("rules_generation = %d with tls enabled, want 2", got)
	}
}

func TestReloaderWithNoRuleFilesWatchesNothing(t *testing.T) {
	b := broker.New(broker.Options{Logger: quietLog()})
	rel := &reloader{log: quietLog(), b: b, interval: time.Second}
	rel.check()
	if got := rel.stats(); got.RulesReloads != 0 || got.RulesReloadFailures != 0 {
		t.Errorf("stats = %+v for a broker started without rules, want nothing to move", got)
	}
	if got := b.Metrics().RulesGeneration; got != 1 {
		t.Errorf("rules_generation = %d, want the boot generation", got)
	}
}

// ---------------------------------------------------------------- helpers ----

// mint writes a fresh chain into dir under the fixed names the flags use, and
// returns it. Writing the same paths is what a rotation looks like on disk.
func mint(t *testing.T, dir, cn string) *tlscert.Bundle {
	t.Helper()
	bundle, err := tlscert.Generate(tlscert.Options{ServerCN: cn})
	if err != nil {
		t.Fatalf("mint %s: %v", cn, err)
	}
	write(t, filepath.Join(dir, "server.crt"), string(bundle.ServerPEM))
	write(t, filepath.Join(dir, "server.key"), string(bundle.ServerKey))
	write(t, filepath.Join(dir, "ca.crt"), string(bundle.CA))
	return bundle
}

func start(t *testing.T, dir string) *certHolder {
	t.Helper()
	h, err := newCertHolder(tlsSettings{
		Addr:     "127.0.0.1:0",
		CertPath: filepath.Join(dir, "server.crt"),
		KeyPath:  filepath.Join(dir, "server.key"),
	})
	if err != nil {
		t.Fatalf("newCertHolder: %v", err)
	}
	return h
}

func poolOf(t *testing.T, pem []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the minted CA did not parse")
	}
	return pool
}

// handshake completes one TLS negotiation against the holder and returns the
// leaf the client was served. It runs over a loopback socket rather than
// net.Pipe: a certificate flight is a kilobyte-scale write, and a pipe that
// blocks until the peer reads deadlocks the two halves of a handshake, which is
// a property of the test plumbing and not of the certificate choice it is here
// to check.
func handshake(h *certHolder, roots *x509.CertPool) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		sc := tls.Server(conn, h.cfg)
		_ = sc.HandshakeContext(context.Background())
		_ = sc.Close()
	}()

	tc, err := tls.Dial("tcp", ln.Addr().String(),
		&tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if err != nil {
		return "", err
	}
	defer tc.Close()
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("the handshake carried no certificate")
	}
	return certs[0].Subject.CommonName, nil
}

func seenByClient(t *testing.T, h *certHolder, roots *x509.CertPool) string {
	t.Helper()
	cn, err := handshake(h, roots)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return cn
}
