package broker_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/tlscert"
)

// These tests speak MQTT over a real TLS listener, with a chain minted by
// internal/tlscert, so every assertion is about what this broker does to a
// handshake rather than about what crypto/tls promises.

func certBundle(t *testing.T) *tlscert.Bundle {
	t.Helper()
	b, err := tlscert.Generate(tlscert.Options{})
	if err != nil {
		t.Fatalf("generate a chain: %v", err)
	}
	return b
}

func caPool(t *testing.T, b *tlscert.Bundle) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b.CA) {
		t.Fatalf("the bundle's CA is not a certificate")
	}
	return pool
}

func serverTLSConfig(t *testing.T, b *tlscert.Bundle, requireClient bool) *tls.Config {
	t.Helper()
	pair, err := tls.X509KeyPair(b.ServerPEM, b.ServerKey)
	if err != nil {
		t.Fatalf("server pair: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}}
	if requireClient {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(b.CA)
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg
}

// startTLSBroker binds a TLS listener on a random loopback port, and a plain one
// too when asked, so one test can prove the two ports do not interfere.
func startTLSBroker(t *testing.T, b *tlscert.Bundle, plain bool, requireClient bool, tweak func(*broker.Options)) *broker.Broker {
	t.Helper()
	opt := broker.Options{
		ID:             "tls-test",
		QueueMax:       50,
		InflightWindow: 4,
		MailboxSize:    8,
		RetryInterval:  300 * time.Millisecond,
		WriteTimeout:   2 * time.Second,
		DeliverTimeout: 2 * time.Second,
		Logger:         testLogger(t),
		TLSConfig:      serverTLSConfig(t, b, requireClient),
	}
	if tweak != nil {
		tweak(&opt)
	}
	br := broker.New(opt)

	plainAddr := ""
	if plain {
		plainAddr = "127.0.0.1:0"
	}
	if err := br.Listen(plainAddr); err != nil {
		t.Fatalf("listen plain: %v", err)
	}
	if err := br.ListenTLS("127.0.0.1:0"); err != nil {
		t.Fatalf("listen tls: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- br.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := br.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("Serve did not return after Shutdown")
		}
	})
	return br
}

// dialTLSBroker returns the same test client the plain tests use, with the socket
// replaced by a verified TLS one. It dials by IP and names the certificate's own
// hostname, which is exactly what a device pointing at an address must do.
func dialTLSBroker(t *testing.T, br *broker.Broker, pool *x509.CertPool, certPEM, keyPEM []byte) *client {
	t.Helper()
	cfg := &tls.Config{RootCAs: pool, ServerName: "localhost"}
	if certPEM != nil {
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("client pair: %v", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	conn, err := tls.Dial("tcp", br.TLSAddr(), cfg)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	c := &client{t: t, conn: conn, r: bufio.NewReader(conn), ver: packets.V311}
	t.Cleanup(func() { _ = c.conn.Close() })
	return c
}

func waitForCounter(t *testing.T, get func() int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if get() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("counter never reached %d (last value %d)", want, get())
}

func TestTLSPublishAndSubscribe(t *testing.T) {
	bundle := certBundle(t)
	pool := caPool(t, bundle)
	br := startTLSBroker(t, bundle, true, false, nil)

	sub := dialTLSBroker(t, br, pool, nil, nil)
	sub.connect("tls-sub", true)
	sub.subscribe(1, flt("tls/#", packets.QoS1))

	pub := dialTLSBroker(t, br, pool, nil, nil)
	pub.connect("tls-pub", true)
	pub.publishQoS1(2, "tls/a", "hello over tls")

	got := sub.expect(packets.TypePublish).(*packets.Publish)
	if string(got.Payload) != "hello over tls" {
		t.Fatalf("payload = %q", got.Payload)
	}
	sub.send(&packets.Puback{PacketID: got.PacketID})

	m := br.Metrics()
	if m.ConnectionsTLS != 2 {
		t.Errorf("connections_tls = %d, want 2", m.ConnectionsTLS)
	}
	if m.TLSHandshakeFailures != 0 {
		t.Errorf("tls_handshake_failures = %d, want 0", m.TLSHandshakeFailures)
	}
	if m.TotalConns != 2 || m.Online != 2 {
		t.Errorf("total/online = %d/%d, want 2/2", m.TotalConns, m.Online)
	}
	if m.MessagesIn != 1 || m.MessagesOut != 1 {
		t.Errorf("messages_in/out = %d/%d, want 1/1", m.MessagesIn, m.MessagesOut)
	}
	if br.Addr() == "" || br.TLSAddr() == "" || br.Addr() == br.TLSAddr() {
		t.Errorf("plain addr %q and tls addr %q must both exist and differ", br.Addr(), br.TLSAddr())
	}
}

func TestPlainClientOnTLSPortIsCounted(t *testing.T) {
	bundle := certBundle(t)
	br := startTLSBroker(t, bundle, true, false, nil)

	// The mistake this test exists for: a device left pointing at the secure port
	// with plain MQTT. The handshake fails, the failure is counted, and the plain
	// port keeps working.
	conn, err := net.DialTimeout("tcp", br.TLSAddr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	frame, err := packets.EncodeBytesVersion(packets.V311, &packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: packets.ProtocolLevel,
		ClientID: "mistake", KeepAlive: 120,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, rerr := conn.Read(make([]byte, 16)); n != 0 || rerr == nil {
		t.Errorf("the broker answered a plain CONNECT on the secure port (n=%d err=%v)", n, rerr)
	}

	waitForCounter(t, func() int64 { return br.Metrics().TLSHandshakeFailures }, 1)
	if m := br.Metrics(); m.ConnectionsTLS != 0 || m.TotalConns != 0 {
		t.Errorf("a failed handshake became a session: tls=%d total=%d", m.ConnectionsTLS, m.TotalConns)
	}

	plain := dial(t, br)
	plain.connect("plain-still-ok", true)
}

func TestTLSOnlyBroker(t *testing.T) {
	bundle := certBundle(t)
	pool := caPool(t, bundle)
	br := startTLSBroker(t, bundle, false, false, nil)
	if br.Addr() != "" {
		t.Errorf("plain addr = %q, want empty", br.Addr())
	}

	c := dialTLSBroker(t, br, pool, nil, nil)
	c.connect("only-tls", true)
	c.subscribe(1, flt("x", packets.QoS0))
	if m := br.Metrics(); m.ConnectionsTLS != 1 {
		t.Errorf("connections_tls = %d, want 1", m.ConnectionsTLS)
	}
}

func TestListenTLSRefusesAConfigThatCannotServe(t *testing.T) {
	noCfg := broker.New(broker.Options{Logger: testLogger(t)})
	if err := noCfg.ListenTLS("127.0.0.1:0"); err == nil {
		t.Errorf("ListenTLS accepted a broker with no TLSConfig")
	}

	emptyCfg := broker.New(broker.Options{Logger: testLogger(t), TLSConfig: &tls.Config{}})
	if err := emptyCfg.ListenTLS("127.0.0.1:0"); err == nil {
		t.Errorf("ListenTLS accepted a config with no certificate")
	}
	if emptyCfg.TLSAddr() != "" {
		t.Errorf("a refused ListenTLS still bound a socket at %q", emptyCfg.TLSAddr())
	}

	nothing := broker.New(broker.Options{Logger: testLogger(t)})
	if err := nothing.Serve(); err == nil {
		t.Errorf("Serve returned nil with no listener at all")
	}
}

func TestRequireClientCert(t *testing.T) {
	bundle := certBundle(t)
	pool := caPool(t, bundle)
	br := startTLSBroker(t, bundle, false, true, nil)

	// TLS 1.3 sends the client certificate after the server's own flight, so the
	// client's Dial can return nil even with nothing to present. Enforcement is
	// the server's: the handshake there fails, and no session is ever made.
	anon, err := tls.Dial("tcp", br.TLSAddr(), &tls.Config{RootCAs: pool, ServerName: "localhost"})
	if err != nil {
		t.Logf("the client noticed at handshake time (TLS 1.2 behaviour): %v", err)
	} else {
		defer anon.Close()
		frame, _ := packets.EncodeBytesVersion(packets.V311, &packets.Connect{
			ProtocolName: packets.ProtocolName, ProtocolLevel: packets.ProtocolLevel,
			ClientID: "no-cert", KeepAlive: 120,
		})
		_ = anon.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, werr := anon.Write(frame); werr != nil {
			t.Logf("write of the CONNECT failed as expected: %v", werr)
		}
		_ = anon.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, rerr := anon.Read(make([]byte, 16)); rerr == nil {
			t.Errorf("the broker answered a CONNECT from a client with no certificate")
		} else {
			t.Logf("no-cert client got: %v", rerr)
		}
	}

	waitForCounter(t, func() int64 { return br.Metrics().TLSHandshakeFailures }, 1)
	if m := br.Metrics(); m.TotalConns != 0 || m.Online != 0 || m.ConnectionsTLS != 0 {
		t.Errorf("a rejected handshake reached the session layer: total=%d online=%d tls=%d",
			m.TotalConns, m.Online, m.ConnectionsTLS)
	}

	c := dialTLSBroker(t, br, pool, bundle.ClientPEM, bundle.ClientKey)
	c.connect("with-cert", true)
	if m := br.Metrics(); m.ConnectionsTLS != 1 {
		t.Errorf("connections_tls = %d, want 1", m.ConnectionsTLS)
	}

	// What the client holds of the same connection: the server's leaf, and a chain
	// that ends at this bundle's CA.
	st := c.conn.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		t.Fatalf("no peer certificates on a verified connection")
	}
	if got := st.PeerCertificates[0].Subject.CommonName; got != bundle.ServerCN {
		t.Errorf("the leaf the client saw = %q, want the server's %q", got, bundle.ServerCN)
	}
	if len(st.VerifiedChains) == 0 {
		t.Fatalf("the client verified no chain, so it trusted something else")
	}
	root := st.VerifiedChains[0][len(st.VerifiedChains[0])-1]
	if root.Subject.CommonName != bundle.CACommonName {
		t.Errorf("chain root = %q, want %q", root.Subject.CommonName, bundle.CACommonName)
	}
}

func TestBrokerHoldsAVerifiedClientIdentityBeforeAnySession(t *testing.T) {
	bundle := certBundle(t)
	pool := caPool(t, bundle)

	// The certificate rules rest on this: at the moment the server finishes the
	// handshake it already has the client's identity and a chain that was checked
	// against ClientCAs, while total_connections is still untouched.
	type observed struct {
		cn        string
		chains    int
		totalWhen int64
	}
	seen := make(chan observed, 4)

	var br *broker.Broker
	cfg := serverTLSConfig(t, bundle, true)
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		o := observed{chains: len(verifiedChains)}
		if len(rawCerts) > 0 {
			if leaf, err := x509.ParseCertificate(rawCerts[0]); err == nil {
				o.cn = leaf.Subject.CommonName
			}
		}
		if br != nil {
			o.totalWhen = br.Metrics().TotalConns
		}
		seen <- o
		return nil
	}

	br = startTLSBroker(t, bundle, false, true, func(o *broker.Options) { o.TLSConfig = cfg })
	c := dialTLSBroker(t, br, pool, bundle.ClientPEM, bundle.ClientKey)
	c.connect("cert-identity", true)

	select {
	case o := <-seen:
		if o.cn != bundle.ClientCN {
			t.Errorf("client CN = %q, want %q", o.cn, bundle.ClientCN)
		}
		if o.chains == 0 {
			t.Errorf("no verified chain, so a rule could not trust this identity")
		}
		if o.totalWhen != 0 {
			t.Errorf("the identity arrived after %d sessions existed, want before any", o.totalWhen)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("the server never inspected a client certificate")
	}
}

func TestSilentPeerDoesNotStallTheTLSPort(t *testing.T) {
	bundle := certBundle(t)
	pool := caPool(t, bundle)
	br := startTLSBroker(t, bundle, true, false, func(o *broker.Options) {
		o.HandshakeTimeout = 300 * time.Millisecond
	})

	silent, err := net.DialTimeout("tcp", br.TLSAddr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer silent.Close()

	// Someone else is trying to connect and says nothing. A real client must not
	// wait for that peer's timeout.
	start := time.Now()
	c := dialTLSBroker(t, br, pool, nil, nil)
	c.connect("not-blocked", true)
	if el := time.Since(start); el > 250*time.Millisecond {
		t.Errorf("a good handshake waited %v behind a silent peer", el)
	}

	_ = silent.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, rerr := silent.Read(make([]byte, 8)); n != 0 || rerr == nil {
		t.Errorf("the silent peer was not closed (n=%d err=%v)", n, rerr)
	}
	waitForCounter(t, func() int64 { return br.Metrics().TLSHandshakeFailures }, 1)
	if m := br.Metrics(); m.ConnectionsTLS != 1 || m.TotalConns != 1 {
		t.Errorf("tls=%d total=%d, want 1/1: the good client must be the only session", m.ConnectionsTLS, m.TotalConns)
	}
}
