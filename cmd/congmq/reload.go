package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/rules"
)

// reloader keeps a running broker honest about the files it was configured from.
// A policy that can only change with a restart does change — but on the operator's
// worst day, because the restart drops every session at once. Watching the files
// instead makes a rewrite of a rule set or a new leaf an ordinary event.
//
// One goroutine owns all of this state, so the SIGHUP trigger arrives through a
// channel rather than racing the ticker.
type reloader struct {
	log      *slog.Logger
	b        *broker.Broker
	authPath string
	aclPath  string
	certs    *certHolder
	interval time.Duration
	tlsOn    bool

	reloads   atomic.Int64
	failures  atomic.Int64
	lastGood  atomic.Int64
	ruleStamp string
	// failedStamp is the content already tried and refused. Without it every
	// poll tick would re-load the same broken file, turning
	// rules_reload_failures into "how many ticks the file has been wrong" and
	// burying the one log line that matters under the same message.
	failedStamp string
}

// reloadStats travel with the counters. Together with rules_generation from the
// broker they answer the two questions an operator has after pushing a change:
// did it land, and how many times was it refused. The certificate half lives on
// the holder, which is the only copy of those counts.
type reloadStats struct {
	RulesReloads         int64 `json:"rules_reloads"`
	RulesReloadFailures  int64 `json:"rules_reload_failures"`
	RulesReloadedUnix    int64 `json:"rules_reloaded_unix"`
	ReloadIntervalSecond int64 `json:"reload_interval_seconds"`
}

func (r *reloader) stats() reloadStats {
	if r == nil {
		return reloadStats{}
	}
	return reloadStats{
		RulesReloads:         r.reloads.Load(),
		RulesReloadFailures:  r.failures.Load(),
		RulesReloadedUnix:    r.lastGood.Load(),
		ReloadIntervalSecond: int64(r.interval / time.Second),
	}
}

// run polls the configured files until the broker is shutting down. A SIGHUP (or
// the ticker, whichever comes first) runs one check.
func (r *reloader) run(ctx context.Context, hup <-chan os.Signal) {
	if r.interval <= 0 {
		// Polling off: SIGHUP is then the only trigger, which on a platform that
		// never delivers one means no reload at all. Saying so at start-up beats
		// letting an operator conclude the flag did nothing.
		r.log.Info("rule and certificate reloading is signal-only", "interval", 0, "hint", "SIGHUP on unix")
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				r.check()
			}
		}
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.check()
		case <-hup:
			r.check()
		}
	}
}

func (r *reloader) check() {
	r.rotateCert()
	r.reloadRules()
}

// rotateCert installs a new certificate generation if the files moved, and says
// out loud what is now being served — because the point of the rotation is that
// nobody was watching when it happened.
func (r *reloader) rotateCert() {
	if r.certs == nil {
		return
	}
	changed, gen, err := r.certs.poll()
	if err != nil {
		r.log.Error("tls material refused, still serving the certificate already in force",
			"err", err, "cn", r.certs.current().leaf.Subject.CommonName,
			"cert", r.certs.s.CertPath, "ca", r.certs.s.CAPath)
		return
	}
	if !changed {
		return
	}
	r.log.Info("tls certificate rotated",
		"generation", r.certs.generation.Load(),
		"cn", gen.leaf.Subject.CommonName, "sans", sansOf(gen.leaf),
		"not_after", gen.leaf.NotAfter.Format(time.RFC3339),
		"client_auth", clientAuthName(gen.clientAuth))
	if left := time.Until(gen.leaf.NotAfter); left < 7*24*time.Hour {
		r.log.Warn("the tls certificate expires soon", "days_left", int(left.Hours()/24),
			"not_after", gen.leaf.NotAfter.Format(time.RFC3339), "path", r.certs.s.CertPath)
	}
}

// reloadRules installs whatever the two rule files say right now. Both halves are
// loaded before either is swapped: an authoriser from the new file glued to a
// credential check from the old one is a policy nobody wrote down, and half a
// policy is worse than the one still in force.
func (r *reloader) reloadRules() {
	if r.authPath == "" && r.aclPath == "" {
		return
	}
	stamp := stampPair(r.authPath, r.aclPath)
	if stamp == r.ruleStamp || stamp == r.failedStamp {
		return
	}
	auth, acl, err := loadPolicies(r.authPath, r.aclPath)
	if err == nil {
		err = r.policyAllowed(auth, acl)
	}
	if err != nil {
		r.failures.Add(1)
		r.failedStamp = stamp
		r.log.Error("rules refused, keeping the policy in force",
			"err", err, "auth", r.authPath, "acl", r.aclPath,
			"generation", r.b.Metrics().RulesGeneration)
		return
	}

	gen := r.b.SetRules(auth, acl)
	r.reloads.Add(1)
	r.lastGood.Store(time.Now().Unix())
	r.ruleStamp = stamp
	r.failedStamp = ""
	r.log.Info("rules reloaded", "generation", gen,
		"auth", ruleCount(auth), "acl", aclCount(acl))
}

// loadPolicies reads both files, or returns nothing at all.
func loadPolicies(authPath, aclPath string) (*rules.Authenticator, *rules.ACL, error) {
	var auth *rules.Authenticator
	if authPath != "" {
		a, err := rules.LoadAuth(authPath)
		if err != nil {
			return nil, nil, fmt.Errorf("auth: %w", err)
		}
		auth = a
	}
	var acl *rules.ACL
	if aclPath != "" {
		a, err := rules.LoadACL(aclPath)
		if err != nil {
			return nil, nil, fmt.Errorf("acl: %w", err)
		}
		acl = a
	}
	return auth, acl, nil
}

// policyAllowed repeats the promise start-up makes. A cert_cn rule is a promise
// that a client certificate can be looked at; with no TLS port no connection ever
// carries one, so installing such a rule would lock the fleet out through a
// window nobody meant to open.
func (r *reloader) policyAllowed(auth *rules.Authenticator, acl *rules.ACL) error {
	if r.tlsOn {
		return nil
	}
	switch {
	case auth != nil && auth.UsesCertificates():
		return fmt.Errorf("auth rules ask for a client certificate but no tls listener is configured, so they can never be met (add -tls-addr with -tls-ca)")
	case acl != nil && acl.UsesCertificates():
		return fmt.Errorf("acl rules ask for a client certificate but no tls listener is configured, so they can never be met (add -tls-addr with -tls-ca)")
	}
	return nil
}

func ruleCount(a *rules.Authenticator) int {
	if a == nil {
		return 0
	}
	return a.Count()
}

func aclCount(a *rules.ACL) int {
	if a == nil {
		return 0
	}
	return a.Count()
}

// stampPair is the fingerprint of the two rule files.
func stampPair(authPath, aclPath string) string {
	return fileStamp(authPath) + "|" + fileStamp(aclPath)
}
