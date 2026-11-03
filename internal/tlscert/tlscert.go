// Package tlscert mints throwaway certificate chains for tests and smoke runs.
//
// It exists so a broker with TLS turned on can be exercised end to end — Go
// tests, the Node harness, an operator's laptop — without anyone installing
// openssl or buying a certificate first. Every chain is signed by a brand-new CA
// that exists only in the output directory, which is exactly why it is fine for
// a loopback test and wrong for anything reachable from a network.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// caCN is the root's identity. It is a constant because a test trusts this chain
// by handing over the CA file, never by checking who signed it.
const caCN = "congmq-test-ca"

// Bundle is a minted chain in PEM form.
type Bundle struct {
	CA        []byte
	ServerPEM []byte
	ServerKey []byte
	ClientPEM []byte
	ClientKey []byte
	// CACommonName is the root's, so a tool that lists the chain does not have to
	// guess what the file it just wrote says.
	CACommonName string
	ServerCN     string
	ClientCN     string
	// ServerSANs are the names a verifying client accepts, formatted for display:
	// DNS names first, then addresses. Callers see the defaults this package
	// filled in rather than having to re-read the PEM.
	ServerSANs []string
	// NotAfter is the server certificate's, which is the one a broker warns about.
	NotAfter time.Time
}

// Options picks the identities and the lifetime. The zero value is a usable
// loopback server plus one client, valid for a day.
type Options struct {
	ServerCN string
	ClientCN string
	// DNSNames and IPs become the server certificate's Subject Alternative Names.
	// A client that verifies the chain checks these, not the CommonName, so a
	// server certificate without them is unusable rather than merely untidy.
	DNSNames []string
	IPs      []net.IP
	// ValidFor is how long the issued certificates stay valid. A negative value
	// yields certificates that are already expired, which is what an expiry test
	// needs.
	ValidFor time.Duration
	// NotBefore backdates the whole chain; zero means an hour of slack.
	NotBefore time.Time
}

func (o *Options) withDefaults() {
	if o.ServerCN == "" {
		o.ServerCN = "congmq.test"
	}
	if o.ClientCN == "" {
		o.ClientCN = "congmq-device-1"
	}
	if o.ValidFor == 0 {
		o.ValidFor = 24 * time.Hour
	}
	if o.NotBefore.IsZero() {
		// Two processes on one machine can disagree with the clock by seconds, and
		// a test failing for that reason points at the wrong thing.
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if len(o.DNSNames) == 0 && len(o.IPs) == 0 {
		o.DNSNames = []string{"localhost"}
		o.IPs = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}
}

// Generate builds a CA and signs one server and one client certificate with it.
func Generate(opt Options) (*Bundle, error) {
	opt.withDefaults()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlscert: ca key: %w", err)
	}
	// The CA outlives the leaves it signs, otherwise a still-valid certificate
	// would stop verifying because its issuer quietly expired.
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: caCN, Organization: []string{"congmq"}},
		NotBefore:             opt.NotBefore,
		NotAfter:              notAfter(opt, abs(opt.ValidFor)+24*time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("tlscert: sign the ca: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("tlscert: parse the ca: %w", err)
	}

	// Only the server gets SANs. A client certificate proves who holds it, and
	// rules read its CommonName; nothing checks a hostname on it.
	serverCert, serverPEM, serverKeyPEM, err := signLeaf(caCert, caKey, opt.ServerCN,
		x509.ExtKeyUsageServerAuth, opt.DNSNames, opt.IPs, opt)
	if err != nil {
		return nil, err
	}
	_, clientPEM, clientKeyPEM, err := signLeaf(caCert, caKey, opt.ClientCN,
		x509.ExtKeyUsageClientAuth, nil, nil, opt)
	if err != nil {
		return nil, err
	}

	return &Bundle{
		CA:           pemBlock("CERTIFICATE", caDER),
		ServerPEM:    serverPEM,
		ServerKey:    serverKeyPEM,
		ClientPEM:    clientPEM,
		ClientKey:    clientKeyPEM,
		CACommonName: caCert.Subject.CommonName,
		ServerCN:     opt.ServerCN,
		ClientCN:     opt.ClientCN,
		ServerSANs: append(append([]string{}, serverCert.DNSNames...),
			ipStrings(serverCert.IPAddresses)...),
		NotAfter: serverCert.NotAfter,
	}, nil
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// WriteDir lays the bundle out as the files a broker and a client start with:
// ca.crt, server.crt, server.key, client.crt, client.key. Existing files are
// overwritten and the directory is created when missing.
//
// The keys ask for 0600, which Windows ignores: it has no Unix permission bits,
// so a private key here is readable by the whole user account either way. That is
// another reason these files belong in a test directory and not on a server.
func (b *Bundle) WriteDir(dir string) error {
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"ca.crt", b.CA, 0o644},
		{"server.crt", b.ServerPEM, 0o644},
		{"server.key", b.ServerKey, 0o600},
		{"client.crt", b.ClientPEM, 0o644},
		{"client.key", b.ClientKey, 0o600},
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("tlscert: create %s: %w", dir, err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return fmt.Errorf("tlscert: write %s: %w", f.name, err)
		}
	}
	return nil
}

func signLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string,
	use x509.ExtKeyUsage, dnsNames []string, ips []net.IP, opt Options) (*x509.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("tlscert: key for %q: %w", cn, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"congmq"}},
		NotBefore:    opt.NotBefore,
		NotAfter:     notAfter(opt, opt.ValidFor),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{use},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("tlscert: sign %q: %w", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER), nil
}

func notAfter(opt Options, d time.Duration) time.Time {
	return opt.NotBefore.Add(d)
}

func pemBlock(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		// rand.Reader failing means a broken platform entropy source, not a case a
		// caller can plan for, and a deterministic serial would let two chains
		// shadow each other.
		panic("tlscert: no entropy: " + err.Error())
	}
	return new(big.Int).Add(n, big.NewInt(1))
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
