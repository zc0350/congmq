package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"
)

// tlsSettings is the -tls-* part of the command line, after parsing.
type tlsSettings struct {
	Addr          string
	CertPath      string
	KeyPath       string
	CAPath        string
	RequireClient bool
	MinVersion    string
	Handshake     time.Duration
}

func (s tlsSettings) enabled() bool { return s.Addr != "" }

// given returns the -tls-* flags the operator actually typed, in name order.
// An option that does nothing is a bug report waiting to happen: -tls-ca on a
// broker with no TLS port looks like mTLS is on when the port itself is absent.
func tlsGiven() []string {
	var names []string
	flag.Visit(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "tls-") && f.Name != "tls-addr" {
			names = append(names, "-"+f.Name)
		}
	})
	slices.Sort(names)
	return names
}

// holder is the one call main makes: it reads the TLS material once, strictly,
// and hands back the thing that keeps it current. A nil holder with a nil error
// means no TLS port was asked for.
func (s tlsSettings) holder(log *slog.Logger) (*certHolder, error) {
	if !s.enabled() {
		return nil, nil
	}
	h, err := newCertHolder(s)
	if err != nil {
		return nil, err
	}
	reportTLS(log, s, h.current().leaf, h.cfg)
	return h, nil
}

// loadCertGen is the strict read of the files a TLS port is built from: the key
// pair this broker presents and, when a CA is named, the pool a client
// certificate must chain to. It is the whole of what a rotation re-runs, so
// start-up and reload refuse the same broken file with the same words. Every
// failure here is fatal at start-up: a listener that rejects every handshake is
// worse than one that refuses to bind.
func loadCertGen(s tlsSettings) (*certGen, error) {
	if s.CertPath == "" || s.KeyPath == "" {
		return nil, fmt.Errorf("-tls-addr needs both -tls-cert and -tls-key")
	}
	pair, err := tls.LoadX509KeyPair(s.CertPath, s.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("-tls-cert/-tls-key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("-tls-cert %s: %w", s.CertPath, err)
	}
	// An expired leaf would still hand out handshakes — to nobody that can verify
	// them. Every modern client aborts, so the broker would look healthy while
	// locking out the whole fleet.
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("-tls-cert %s is not valid until %s (the clock may be wrong)",
			s.CertPath, leaf.NotBefore.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("-tls-cert %s expired on %s", s.CertPath, leaf.NotAfter.Format(time.RFC3339))
	}

	gen := &certGen{pair: pair, leaf: leaf, notAfter: leaf.NotAfter}
	switch {
	case s.CAPath != "":
		// Naming a CA is the stronger statement and implies the requirement: a
		// certificate that is presented but not checked is decoration.
		pool, err := certPoolFromFile(s.CAPath)
		if err != nil {
			return nil, err
		}
		gen.pool = pool
		gen.clientAuth = tls.RequireAndVerifyClientCert
	case s.RequireClient:
		gen.clientAuth = tls.RequireAnyClientCert
	}
	return gen, nil
}

func certPoolFromFile(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("-tls-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("-tls-ca %s holds no certificate (first PEM block is %s)",
			path, pemKind(raw))
	}
	return pool, nil
}

func parseTLSVersion(s string) (uint16, error) {
	switch strings.TrimSpace(s) {
	case "", "1.2":
		// TLS 1.0 and 1.1 are not offered at all: they carry known weaknesses and
		// no MQTT device this broker targets speaks them.
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("-tls-min-version must be 1.2 or 1.3, got %q", s)
	}
}

// reportTLS tells the operator what will be enforced, in the order anyone
// debugging a device would ask for: which name, which hosts, until when, and
// whether a client certificate is expected.
func reportTLS(log *slog.Logger, s tlsSettings, leaf *x509.Certificate, cfg *tls.Config) {
	log.Info("tls listener configured", "addr", s.Addr,
		"cn", leaf.Subject.CommonName, "sans", sansOf(leaf),
		"not_after", leaf.NotAfter.Format(time.RFC3339),
		"min_version", versionName(cfg.MinVersion),
		"client_auth", clientAuthName(cfg.ClientAuth), "handshake_timeout", s.Handshake.String())
	if left := time.Until(leaf.NotAfter); left < 7*24*time.Hour {
		// A certificate that expires during the next maintenance window is news now,
		// not the morning a fleet stops connecting.
		log.Warn("the tls certificate expires soon", "days_left", int(left.Hours()/24),
			"not_after", leaf.NotAfter.Format(time.RFC3339), "path", s.CertPath)
	}
	if cfg.ClientAuth == tls.RequireAnyClientCert {
		// The distinction matters for the rule files: with no -tls-ca nothing is
		// verified, so a "cert_cn" rule can never match and the fleet looks
		// unauthorised for a reason no log line would otherwise explain.
		log.Warn("client certificates are required but not verified: add -tls-ca to check them against a CA",
			"client_auth", "any (unverified)")
	}
}

func sansOf(leaf *x509.Certificate) string {
	names := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	names = append(names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		return "(none — every verifying client will reject this certificate)"
	}
	return strings.Join(names, ",")
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "1.2"
	}
}

func clientAuthName(a tls.ClientAuthType) string {
	switch a {
	case tls.RequireAndVerifyClientCert:
		return "required and verified against -tls-ca"
	case tls.RequireAnyClientCert:
		return "required, unverified"
	default:
		return "not requested"
	}
}

// pemKind is the header line of a PEM file, for an error message that tells the
// operator what to look at rather than only that something failed.
func pemKind(raw []byte) string {
	b, _ := pem.Decode(raw)
	if b == nil {
		return "not PEM"
	}
	return b.Type
}
