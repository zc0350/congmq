package broker_test

import (
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/packets"
)

// These tests put the certificate rules of internal/rules behind a real TLS
// listener, so what is asserted is the identity the broker actually holds when
// it answers CONNECT — not the identity a unit test hand-writes.

// meterSaltSha256 is sha256("s" + "meter"), computed outside this package, so
// the password half of a certificate-bound rule is checked and not restated.
const meterSaltSha256 = "66e6048a25131b2c4b8ab2165b3439ef1a6a260cecfa9a82da8f30075b5fa6e6"

// certRule returns a rule line naming the client this bundle's CA signed, with
// the given fields ahead of it.
func certRule(cn string, rest string) string {
	return fmt.Sprintf(`{"cert_cn":%q,%s}`, cn, rest)
}

// certOnly is the shortest certificate rule there is: the handshake is the whole
// credential, so nothing else needs to be asked.
func certOnly(cn string) string {
	return fmt.Sprintf(`{"cert_cn":%q}`, cn)
}

func TestCertificateIsTheWholeCredentialOverTLS(t *testing.T) {
	bundle := certBundle(t)
	pool := caPool(t, bundle)
	// One certificate stands for the whole fleet here, so both devices get in on
	// it; the client id is deliberately not part of the rule.
	auth := loadAuth(t, certOnly(bundle.ClientCN))
	acl := loadACL(t, certRule(bundle.ClientCN, `"effect":"deny","action":"publish","topics":["plant/secret/#"]}`)+
		"\n"+certRule(bundle.ClientCN, `"effect":"allow","action":"all","topics":["plant/#"]}`))
	br := startTLSBroker(t, bundle, false, true, func(o *broker.Options) {
		o.Auth = auth
		o.ACL = acl
	})

	dev := dialTLSBroker(t, br, pool, bundle.ClientPEM, bundle.ClientKey)
	// No username, no password: the handshake is the credential.
	if ack := dev.connectAs("dev-1", true, "", ""); ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("a verified certificate was refused with code %d", ack.ReturnCode)
	}

	watch := dialTLSBroker(t, br, pool, bundle.ClientPEM, bundle.ClientKey)
	if ack := watch.connectAs("dev-2", true, "", ""); ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("the second device was refused with code %d", ack.ReturnCode)
	}
	watch.subscribe(1, flt("plant/#", packets.QoS1))

	dev.publishQoS1(2, "plant/row/1", "over tls")
	watch.receive("plant/row/1", "over tls")

	// The deny rule comes first, so a topic under the same tree is refused. The
	// PUBACK still arrives because 3.1.1 has no code for "not your topic".
	dev.send(&packets.Publish{Topic: "plant/secret/x", QoS: packets.QoS1, PacketID: 3, Payload: []byte("nope")})
	dev.expect(packets.TypePuback)
	watch.expectNothing(600 * time.Millisecond)

	m := br.Metrics()
	if m.ConnectionsTLS != 2 || m.TLSHandshakeFailures != 0 {
		t.Errorf("metrics = tls %d connections, %d handshake failures; want 2 and 0",
			m.ConnectionsTLS, m.TLSHandshakeFailures)
	}
	if m.AuthRejected != 0 {
		t.Errorf("auth_rejected = %d, want 0: the certificate carried both sessions", m.AuthRejected)
	}
	if m.DeniedPublish != 1 {
		t.Errorf("acl_denied_publish = %d, want 1", m.DeniedPublish)
	}
}

func TestPlainPortCannotMeetACertificateRule(t *testing.T) {
	bundle := certBundle(t)
	pool := caPool(t, bundle)
	auth := loadAuth(t, certOnly(bundle.ClientCN))
	br := startTLSBroker(t, bundle, true, true, func(o *broker.Options) { o.Auth = auth })

	// The same device id over the plain port presents no certificate, so the
	// rule that names one cannot be satisfied — and says so with a refusal
	// rather than by falling through to a looser line.
	plain := dial(t, br)
	if ack := plain.connectAs("dev-1", true, "", ""); ack.ReturnCode != packets.ConnBadCredentials {
		t.Errorf("a plain connection met a certificate rule (code %d)", ack.ReturnCode)
	}
	if m := br.Metrics(); m.AuthRejected != 1 || m.ConnectionsTLS != 0 {
		t.Errorf("metrics = auth_rejected %d, connections_tls %d; want 1 and 0",
			m.AuthRejected, m.ConnectionsTLS)
	}

	// And the TLS port with the right certificate still gets in, which is what
	// makes the refusal above about the transport rather than about the client.
	dev := dialTLSBroker(t, br, pool, bundle.ClientPEM, bundle.ClientKey)
	if ack := dev.connectAs("dev-1", true, "", ""); ack.ReturnCode != packets.ConnAccepted {
		t.Errorf("the same identity over TLS was refused with code %d", ack.ReturnCode)
	}
}

func TestUnverifiedClientCertificateCarriesNoIdentity(t *testing.T) {
	bundle := certBundle(t)
	pool := caPool(t, bundle)
	auth := loadAuth(t, certOnly(bundle.ClientCN))

	// -tls-require-client-cert without -tls-ca: a certificate must be presented
	// but nothing checks who signed it. The broker stores no common name from it,
	// because an unchecked name is a value the peer chose for itself.
	br := startTLSBroker(t, bundle, false, false, func(o *broker.Options) {
		o.Auth = auth
		pair, err := tls.X509KeyPair(bundle.ServerPEM, bundle.ServerKey)
		if err != nil {
			t.Fatalf("server pair: %v", err)
		}
		o.TLSConfig = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAnyClientCert}
	})

	dev := dialTLSBroker(t, br, pool, bundle.ClientPEM, bundle.ClientKey)
	if ack := dev.connectAs("dev-1", true, "", ""); ack.ReturnCode != packets.ConnBadCredentials {
		t.Error("an unverified certificate was trusted as an identity")
	}
	m := br.Metrics()
	if m.ConnectionsTLS != 1 || m.TLSHandshakeFailures != 0 {
		t.Errorf("metrics = tls %d connections, %d handshake failures; want 1 and 0 (the handshake did succeed)",
			m.ConnectionsTLS, m.TLSHandshakeFailures)
	}
	if m.AuthRejected != 1 {
		t.Errorf("auth_rejected = %d, want 1", m.AuthRejected)
	}
}

func TestCertificateScopedRulesStopCoveringAnOfflineQueue(t *testing.T) {
	// A certificate belongs to a connection. When the device is away there is no
	// connection to point at, so the stored identity carries no CertCN and a
	// certificate-scoped allow rule cannot be satisfied — the message is refused
	// at routing time and never enters the queue. The clientid-scoped rule next to
	// it is the control: same disconnect, same offline session, still delivers.
	bundle := certBundle(t)
	pool := caPool(t, bundle)
	auth := loadAuth(t, certOnly(bundle.ClientCN))
	acl := loadACL(t,
		certRule(bundle.ClientCN, `"effect":"allow","action":"publish","topics":["plant/#","shop/#"]`)+
			"\n"+certRule(bundle.ClientCN, `"effect":"allow","action":"all","topics":["plant/#"]`)+
			"\n"+`{"effect":"allow","clientid":"away","action":"all","topics":["shop/#"]}`)
	br := startTLSBroker(t, bundle, false, true, func(o *broker.Options) {
		o.Auth = auth
		o.ACL = acl
	})

	away := dialTLSBroker(t, br, pool, bundle.ClientPEM, bundle.ClientKey)
	if ack := away.connectAs("away", false, "", ""); ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("the subscriber was refused with code %d", ack.ReturnCode)
	}
	away.subscribe(1, flt("plant/#", packets.QoS1))
	away.subscribe(2, flt("shop/#", packets.QoS1))
	away.send(&packets.Disconnect{})

	pub := dialTLSBroker(t, br, pool, bundle.ClientPEM, bundle.ClientKey)
	if ack := pub.connectAs("pub-1", true, "", ""); ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("the publisher was refused with code %d", ack.ReturnCode)
	}
	pub.publishQoS1(3, "plant/row/1", "needs the certificate")
	pub.publishQoS1(4, "shop/bin/1", "needs only the clientid")
	if m := br.Metrics(); m.DeniedDelivery != 1 {
		t.Errorf("acl_denied_delivery = %d, want 1: the certificate-scoped topic has no connection to authorise it",
			m.DeniedDelivery)
	}

	back := dialTLSBroker(t, br, pool, bundle.ClientPEM, bundle.ClientKey)
	if ack := back.connectAs("away", false, "", ""); !ack.SessionPresent {
		t.Fatal("the offline session did not come back")
	}
	back.receive("shop/bin/1", "needs only the clientid")
	back.expectNothing(600 * time.Millisecond)
}

func TestCertificateRuleStillNeedsTheBoundUsername(t *testing.T) {
	bundle := certBundle(t)
	pool := caPool(t, bundle)
	// A rule that asks for both: the certificate pins who the device is, and the
	// password is still checked. Half of it is not enough.
	auth := loadAuth(t, certRule(bundle.ClientCN, `"username":"meter","salt":"s","alg":"sha256","scheme":"salt+username"`))
	br := startTLSBroker(t, bundle, false, true, func(o *broker.Options) { o.Auth = auth })

	silent := dialTLSBroker(t, br, pool, bundle.ClientPEM, bundle.ClientKey)
	if ack := silent.connectAs("dev-1", true, "meter", ""); ack.ReturnCode != packets.ConnBadCredentials {
		t.Errorf("the certificate alone opened a rule that also wants a password (code %d)", ack.ReturnCode)
	}

	full := dialTLSBroker(t, br, pool, bundle.ClientPEM, bundle.ClientKey)
	if ack := full.connectAs("dev-1", true, "meter", meterSaltSha256); ack.ReturnCode != packets.ConnAccepted {
		t.Errorf("certificate and password were refused with code %d", ack.ReturnCode)
	}
	if m := br.Metrics(); m.ConnectionsTLS != 2 {
		t.Errorf("connections_tls = %d, want 2", m.ConnectionsTLS)
	}
}
