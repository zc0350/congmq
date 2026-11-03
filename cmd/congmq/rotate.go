package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// certGen is one validated read of the material a TLS port is built from: the
// leaf this broker presents, the key that matches it and the pool client
// certificates must chain to. Generations are never edited, which is what lets a
// handshake pick one up mid-flight without seeing half of a rotation.
type certGen struct {
	pair       tls.Certificate
	leaf       *x509.Certificate
	pool       *x509.CertPool
	clientAuth tls.ClientAuthType
	notAfter   time.Time

	// stamp identifies the files this generation was read from, so a poll can
	// tell "nothing moved" from "the operator replaced the leaf".
	stamp string
}

// certHolder keeps that material current while the port stays open. Replacing a
// certificate used to mean a restart, and a restart means every device in the
// fleet reconnecting at once — so the rotation that was supposed to be routine
// becomes the outage.
type certHolder struct {
	s   tlsSettings
	cfg *tls.Config

	cur        atomic.Pointer[certGen]
	generation atomic.Int64
	reloads    atomic.Int64
	failures   atomic.Int64
	// failedStamp is the file content already tried and refused. Without it every
	// poll would re-read the same broken leaf, turning tls_cert_reload_failures
	// into "how many ticks the file was bad" and repeating one log line until it
	// stopped being news. Only the reloader's own goroutine calls poll.
	failedStamp string
}

// newCertHolder reads the files once, strictly. The same read runs on every
// rotation, so a leaf that would have refused to start is refused at rotation
// too, and the operator hears about it in the log instead of in a fleet that
// cannot connect.
func newCertHolder(s tlsSettings) (*certHolder, error) {
	minVersion, err := parseTLSVersion(s.MinVersion)
	if err != nil {
		return nil, err
	}
	gen, err := loadCertGen(s)
	if err != nil {
		return nil, err
	}
	gen.stamp = stampOf(s)

	h := &certHolder{s: s}
	h.cfg = &tls.Config{
		Certificates: []tls.Certificate{gen.pair},
		ClientCAs:    gen.pool,
		ClientAuth:   gen.clientAuth,
		MinVersion:   minVersion,
	}
	// A handshake asks who it is answering before it chooses a certificate, so
	// this callback is where a rotation lands: the next device sees the new leaf
	// while the sessions already open keep running on the one they negotiated.
	h.cfg.GetConfigForClient = h.configForClient

	h.cur.Store(gen)
	h.generation.Add(1)
	return h, nil
}

// current is the generation in force.
func (h *certHolder) current() *certGen { return h.cur.Load() }

// configForClient answers one handshake out of one generation. The clone is
// shallow over a certificate and an immutable pool, so the cost is a struct copy
// next to the asymmetric work the handshake is already doing.
func (h *certHolder) configForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	g := h.cur.Load()
	cfg := h.cfg.Clone()
	// Cleared so a config handed to this callback can never call it again.
	cfg.GetConfigForClient = nil
	cfg.Certificates = []tls.Certificate{g.pair}
	cfg.ClientCAs = g.pool
	cfg.ClientAuth = g.clientAuth
	return cfg, nil
}

// poll reloads when the files moved. It says whether a new generation took
// effect; a broken file keeps the old one in force and is counted, because a
// half-rotated port is worse than an unrotated one.
func (h *certHolder) poll() (bool, *certGen, error) {
	before := stampOf(h.s)
	if before == h.current().stamp || before == h.failedStamp {
		return false, nil, nil
	}
	gen, err := loadCertGen(h.s)
	if err != nil {
		h.failures.Add(1)
		h.failedStamp = before
		return false, nil, err
	}
	after := stampOf(h.s)
	if after != before {
		// The operator replaced the file again while it was being read. Serve what
		// was read but make the next poll re-check it, rather than stamping a
		// generation that may match neither version of the file.
		gen.stamp = ""
	} else {
		gen.stamp = before
	}
	h.cur.Store(gen)
	h.generation.Add(1)
	h.reloads.Add(1)
	h.failedStamp = ""
	return true, gen, nil
}

// certStats travel with the counters: which leaf is being served, how many
// rotations have landed, and how many were refused.
type certStats struct {
	CertGeneration   int64  `json:"tls_cert_generation"`
	CertReloads      int64  `json:"tls_cert_reloads"`
	CertFailures     int64  `json:"tls_cert_reload_failures"`
	CertCN           string `json:"tls_cert_cn"`
	CertNotAfterUnix int64  `json:"tls_cert_not_after_unix"`
}

// certStatsOf reports the live certificate, or zeros for a broker with no TLS
// port. The keys are always present so a scraper sees the same shape either way.
func certStatsOf(h *certHolder) certStats {
	if h == nil {
		return certStats{}
	}
	g := h.current()
	return certStats{
		CertGeneration:   h.generation.Load(),
		CertReloads:      h.reloads.Load(),
		CertFailures:     h.failures.Load(),
		CertCN:           g.leaf.Subject.CommonName,
		CertNotAfterUnix: g.notAfter.Unix(),
	}
}

// stampOf is the fingerprint of every file the TLS port is built from. Size and
// modification time together catch a replacement leaf and a rewritten CA without
// a third-party file watcher.
func stampOf(s tlsSettings) string {
	return fileStamp(s.CertPath) + "|" + fileStamp(s.KeyPath) + "|" + fileStamp(s.CAPath)
}

func fileStamp(path string) string {
	if path == "" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil {
		// A missing file is its own stamp: the next poll tries to read it, is
		// refused, and the generation already in force keeps serving handshakes.
		return "unreadable"
	}
	return fmt.Sprintf("%d:%d", fi.ModTime().UnixNano(), fi.Size())
}
