package broker_test

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/store"
)

// These tests are about one sentence: a decision keyed on the peer must be a
// decision about the peer. Behind a load balancer the socket's peer is the
// balancer, so everything below — the gate, the credential lockout, the ip rules,
// the identity written into a durable session — has to be handed the address the
// balancer named in its transport header. The assertions are deliberately made
// downstream of that address rather than on the parse, which internal/proxyproto
// already pins on its own.

// v1 writes the text form of a v4 header: "PROXY TCP4 src dst sport dport".
func v1(src string, sport int, dst string, dport int) []byte {
	return []byte(fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", src, dst, sport, dport))
}

// v1Unknown is the form a sender may use when it cannot name a source — it says
// "I am a balancer" and nothing else.
func v1Unknown() []byte { return []byte("PROXY UNKNOWN\r\n") }

// v2Sig is the fixed 12-byte magic that opens a binary header.
var v2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

// v2 assembles a binary header from its command, family and address body.
func v2(cmd, fam byte, body []byte) []byte {
	h := append([]byte{}, v2Sig...)
	h = append(h, 0x20|cmd, fam)
	h = append(h, byte(len(body)>>8), byte(len(body)))
	return append(h, body...)
}

// v2Proxy4 is a v2 header naming a v4 source and destination.
func v2Proxy4(src string, sport int, dst string, dport int) []byte {
	body := make([]byte, 12)
	copy(body[0:4], net.ParseIP(src).To4())
	copy(body[4:8], net.ParseIP(dst).To4())
	body[8], body[9] = byte(sport>>8), byte(sport)
	body[10], body[11] = byte(dport>>8), byte(dport)
	return v2(0x01, 0x11, body)
}

// v2Local is a v2 LOCAL command with no address body: what a balancer writes for
// its own health check.
func v2Local() []byte { return v2(0x00, 0x00, nil) }

// prefixes compiles a -trusted-proxy-cidr value for an Options field.
func prefixes(t *testing.T, list string) []netip.Prefix {
	t.Helper()
	p, err := broker.ParsePrefixes(list)
	if err != nil {
		t.Fatalf("ParsePrefixes(%q): %v", list, err)
	}
	return p
}

// proxiedClient dials from socket, writes a transport header in front of the
// payload, and hands back a client that then speaks MQTT normally.
func proxiedClient(t *testing.T, b *broker.Broker, socket string, header []byte) *client {
	t.Helper()
	conn := dialFrom(t, b.Addr(), socket)
	if _, err := conn.Write(header); err != nil {
		t.Fatalf("write the header from %s: %v", socket, err)
	}
	return &client{t: t, conn: conn, r: bufio.NewReader(conn), ver: packets.V311}
}

// refusedSocket dials, sends what a caller wants sent and reports whether the
// broker hung up without opening a session. A refusal at the transport header is
// a bare FIN with nothing in front of it: the peer is told nothing about why, so
// this is all the evidence the socket itself gives.
func refusedSocket(t *testing.T, b *broker.Broker, src string, payload []byte, why string) {
	t.Helper()
	before := b.Metrics()
	conn := dialFrom(t, b.Addr(), src)
	if payload != nil {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("%s: write: %v", why, err)
		}
	}
	if !hungUp(t, conn, 3*time.Second) {
		t.Fatalf("%s: the broker left the socket open", why)
	}
	if m := b.Metrics(); m.TotalConns != before.TotalConns {
		t.Errorf("%s: total_connections moved to %d; a header refusal must not reach accept", why, m.TotalConns)
	}
}

// connectFrame is a bare 3.1.1 CONNECT, for tests that need a real client's first
// bytes rather than a header.
func connectFrame(t *testing.T, id string) []byte {
	t.Helper()
	f, err := packets.EncodeBytesVersion(packets.V311, &packets.Connect{
		ProtocolName:  packets.ProtocolName,
		ProtocolLevel: packets.ProtocolLevel,
		ClientID:      id,
		CleanSession:  true,
		KeepAlive:     120,
	})
	if err != nil {
		t.Fatalf("encode CONNECT: %v", err)
	}
	return f
}

// TestRequireModeRefusesWhatIsNotAHeader is the point of the mode: on a listener
// that only a balancer may reach, a connection without a header is not a client.
func TestRequireModeRefusesWhatIsNotAHeader(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) {
		o.Proxy = broker.ProxyRequire
		o.ProxyHeaderTimeout = 200 * time.Millisecond
	})

	// Silence, and a real MQTT CONNECT. Both are refused the same way, because
	// neither said whose device it was forwarding — the silent one only after its
	// own timeout, since nothing arriving is indistinguishable from nothing
	// arriving slowly.
	refusedSocket(t, b, "127.0.0.1", nil, "a silent socket on a require listener")
	refusedSocket(t, b, "127.0.0.1", connectFrame(t, "direct"), "a CONNECT with no header in front of it")

	m := b.Metrics()
	if m.RefusedProxy != 2 || m.ConnectionsProxy != 0 {
		t.Errorf("refused_over_proxy_header = %d, connections_over_proxy_header = %d; want 2 and 0",
			m.RefusedProxy, m.ConnectionsProxy)
	}
	// The socket is closed before the gate is consulted, so a peer that sprays
	// headerless connections cannot fill the address buckets it is refused out of.
	if m.GateHeld != 0 {
		t.Errorf("per_ip_gate_held_sockets = %d, want 0: a refused header holds nothing", m.GateHeld)
	}
}

// TestRequireModeAcceptsBothHeaderForms is the pair of wire encodings a balancer
// may use, checked through a live session rather than through the parser.
func TestRequireModeAcceptsBothHeaderForms(t *testing.T) {
	cases := []struct {
		name   string
		header []byte
	}{
		{"v1 text", v1("203.0.113.7", 49101, "198.51.100.9", 1883)},
		{"v2 binary", v2Proxy4("203.0.113.7", 49101, "198.51.100.9", 1883)},
	}
	for _, tc := range cases {
		b := startBroker(t, nil, func(o *broker.Options) { o.Proxy = broker.ProxyRequire })
		c := proxiedClient(t, b, "127.0.0.1", tc.header)
		c.connect("dev-7", true)

		m := b.Metrics()
		if m.ConnectionsProxy != 1 {
			t.Errorf("%s: connections_over_proxy_header = %d, want 1", tc.name, m.ConnectionsProxy)
		}
		if m.TotalConns != 1 || m.RefusedProxy != 0 {
			t.Errorf("%s: total_connections %d, refused_over_proxy_header %d; want 1 and 0",
				tc.name, m.TotalConns, m.RefusedProxy)
		}
	}
}

// TestHeaderAndConnectInOneSegment is the reason the wrapper has to keep what the
// parser over-read: a balancer that writes the header and the first payload bytes
// in one segment, into a broker that buffers both, would otherwise have its
// CONNECT swallowed.
func TestHeaderAndConnectInOneSegment(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) { o.Proxy = broker.ProxyRequire })

	conn := dialFrom(t, b.Addr(), "127.0.0.1")
	segment := append(v1("203.0.113.7", 49101, "198.51.100.9", 1883), connectFrame(t, "one-segment")...)
	if _, err := conn.Write(segment); err != nil {
		t.Fatalf("write the combined segment: %v", err)
	}
	c := &client{t: t, conn: conn, r: bufio.NewReader(conn), ver: packets.V311}
	ack, ok := c.expect(packets.TypeConnack).(*packets.Connack)
	if !ok || ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("the CONNECT behind a header in the same segment was not accepted")
	}

	if m := b.Metrics(); m.ConnectionsProxy != 1 {
		t.Errorf("connections_over_proxy_header = %d, want 1", m.ConnectionsProxy)
	}
}

// TestTrustedModeRefusesAHeaderFromAnAddressThatMayNotReportOne is the spoofing
// case, and the reason a header from outside the list is refused rather than
// quietly ignored: the only reason to write a header you know will not be believed
// is to find out whether it will be.
func TestTrustedModeRefusesAHeaderFromAnAddressThatMayNotReportOne(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) {
		o.Proxy = broker.ProxyTrusted
		o.TrustedProxies = prefixes(t, "127.0.0.1/32")
	})

	// A well-formed header from an address that is not on the list.
	refusedSocket(t, b, "127.0.0.2",
		append(v1("203.0.113.7", 49101, "198.51.100.9", 1883), connectFrame(t, "spoofed")...),
		"a header from an address that may not report one")

	// The same list, the same absence of a header: an address the broker was told
	// forwards traffic is expected to say whose. Ignoring this instead would leave
	// the balancer's own port scan reading as a fleet of directly connected clients.
	refusedSocket(t, b, "127.0.0.1", connectFrame(t, "balancer-without-a-header"),
		"the trusted address sending no header")

	if m := b.Metrics(); m.RefusedProxy != 2 || m.ConnectionsProxy != 0 {
		t.Errorf("refused_over_proxy_header = %d, connections_over_proxy_header = %d; want 2 and 0",
			m.RefusedProxy, m.ConnectionsProxy)
	}
}

// TestTrustedModeKeepsDirectClientsAndHonoursTheList covers both halves of the
// mixed listener: a device that arrives directly keeps its own address, and the
// balancer's header is believed.
func TestTrustedModeKeepsDirectClientsAndHonoursTheList(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) {
		o.Proxy = broker.ProxyTrusted
		o.TrustedProxies = prefixes(t, "127.0.0.1/32")
	})

	// Direct, from an address outside the list: no header expected, none sent.
	direct := dialAt(t, b, "127.0.0.2")
	direct.connect("direct-1", true)

	// Through the balancer.
	viaLB := proxiedClient(t, b, "127.0.0.1", v1("203.0.113.7", 49101, "198.51.100.9", 1883))
	viaLB.connect("device-7", true)

	waitUntil(t, func() bool { return b.Metrics().Online == 2 })
	m := b.Metrics()
	if m.TotalConns != 2 || m.RefusedProxy != 0 {
		t.Fatalf("total_connections %d, refused_over_proxy_header %d; want 2 and 0", m.TotalConns, m.RefusedProxy)
	}
	// Only the header's session counts as proxied, which is what makes the number
	// readable: it is the fleet behind the balancer, not everything.
	if m.ConnectionsProxy != 1 {
		t.Errorf("connections_over_proxy_header = %d, want 1", m.ConnectionsProxy)
	}
}

// TestLocalAndUnknownHeadersKeepTheSocketAddress is the health-check case: a
// well-formed header that names nobody is not a refusal, and not a claim either.
// It is what lets the same listener answer a probe.
func TestLocalAndUnknownHeadersKeepTheSocketAddress(t *testing.T) {
	cases := []struct {
		name   string
		header []byte
	}{
		{"v2 LOCAL", v2Local()},
		{"v1 UNKNOWN", v1Unknown()},
	}
	for _, tc := range cases {
		b := startBroker(t, nil, func(o *broker.Options) { o.Proxy = broker.ProxyRequire })
		c := proxiedClient(t, b, "127.0.0.1", tc.header)
		c.connect("probe", true)

		m := b.Metrics()
		if m.RefusedProxy != 0 {
			t.Errorf("%s: refused_over_proxy_header = %d, want 0: a probe is not an attack", tc.name, m.RefusedProxy)
		}
		if m.ConnectionsProxy != 0 {
			t.Errorf("%s: connections_over_proxy_header = %d, want 0: nothing was claimed", tc.name, m.ConnectionsProxy)
		}
	}
}

// TestHeaderTimeoutClosesASilentPeer is why the read has a deadline at all: a peer
// that opens a socket and says nothing, or starts a header and stops, would
// otherwise hold the parsing goroutine for as long as it liked.
func TestHeaderTimeoutClosesASilentPeer(t *testing.T) {
	const headerTimeout = 150 * time.Millisecond
	b := startBroker(t, nil, func(o *broker.Options) {
		o.Proxy = broker.ProxyRequire
		o.ProxyHeaderTimeout = headerTimeout
	})

	start := time.Now()
	// The signature and the fixed part, then silence: the deadline has to catch a
	// header that started and never finished, not only one that never began.
	conn := dialFrom(t, b.Addr(), "127.0.0.1")
	if _, err := conn.Write([]byte("\r\n\r\n\x00\r\nQUIT\n\x22\x11\x00\x0c")); err != nil {
		t.Fatalf("write a half header: %v", err)
	}
	if !hungUp(t, conn, 3*time.Second) {
		t.Fatalf("the broker never closed a socket stuck in the middle of a header")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("a %v header timeout took %v to act on", headerTimeout, elapsed)
	}
	if m := b.Metrics(); m.RefusedProxy != 1 {
		t.Errorf("refused_over_proxy_header = %d, want 1", m.RefusedProxy)
	}
}

// TestRealAddressDrivesThePerIPConnectionLimit is the load-bearing test of the
// phase. Every socket here arrives from the same loopback address, so with the
// header ignored the first connection would have spent the whole allowance and the
// second would be refused. It is not, because the limit is applied to the two
// addresses the balancer named.
func TestRealAddressDrivesThePerIPConnectionLimit(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) {
		o.Proxy = broker.ProxyRequire
		o.MaxConnsPerIP = 1
	})

	a := proxiedClient(t, b, "127.0.0.1", v1("203.0.113.1", 49101, "198.51.100.9", 1883))
	a.connect("tenant-a", true)
	other := proxiedClient(t, b, "127.0.0.1", v1("203.0.113.2", 49102, "198.51.100.9", 1883))
	other.connect("tenant-b", true)

	waitUntil(t, func() bool { return b.Metrics().GateHeld == 2 })

	// A second socket for the first device's address is the one that gets refused.
	refused := dialFrom(t, b.Addr(), "127.0.0.1")
	if _, err := refused.Write(v1("203.0.113.1", 49103, "198.51.100.9", 1883)); err != nil {
		t.Fatalf("write a header for an address already at its limit: %v", err)
	}
	if !hungUp(t, refused, 3*time.Second) {
		t.Fatalf("the third socket claimed a full address and was not refused")
	}

	m := b.Metrics()
	if m.RefusedPerIPConns != 1 {
		t.Errorf("refused_over_per_ip_connection_limit = %d, want 1", m.RefusedPerIPConns)
	}
	if m.GateEntries != 2 {
		t.Errorf("per_ip_gate_entries = %d, want 2: the gate is tracking devices, not the balancer", m.GateEntries)
	}
	if m.TotalConns != 2 {
		t.Errorf("total_connections = %d, want 2", m.TotalConns)
	}
}

// TestRealAddressDrivesTheCredentialLockout is the same argument about the limit
// that can hurt a device: two tenants behind one balancer, one of them spraying
// passwords. Without a real address the lockout would shut the honest tenant out
// with the dishonest one, which is the exact failure this feature exists to stop.
func TestRealAddressDrivesTheCredentialLockout(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) {
		o.Proxy = broker.ProxyRequire
		o.Auth = loadAuth(t, lockoutRule)
		o.AuthFailLimit = 2
		o.AuthFailWindow = time.Minute
		o.AuthLockout = 750 * time.Millisecond
	})

	const sprayer = "203.0.113.11"
	const neighbour = "203.0.113.12"
	for i := 0; i < 2; i++ {
		c := proxiedClient(t, b, "127.0.0.1", v1(sprayer, 49101+i, "198.51.100.9", 1883))
		if ack := c.connectAs("guesser", true, "dashboard", wrongDigest); ack.ReturnCode != packets.ConnBadCredentials {
			t.Fatalf("failure %d answered with code %d, want bad credentials", i+1, ack.ReturnCode)
		}
	}
	waitUntil(t, func() bool { return b.Metrics().AuthLockedAddresses == 1 })

	// The locked address is still refused, correct password included.
	locked := proxiedClient(t, b, "127.0.0.1", v1(sprayer, 49120, "198.51.100.9", 1883))
	if ack := locked.connectAs("honest", true, "dashboard", dashboardSha256); ack.ReturnCode != packets.ConnBadCredentials {
		t.Fatalf("the lockout did not refuse the correct password from %s (code %d)", sprayer, ack.ReturnCode)
	}

	// Its neighbour behind the very same balancer is untouched.
	other := proxiedClient(t, b, "127.0.0.1", v1(neighbour, 49130, "198.51.100.9", 1883))
	if ack := other.connectAs("neighbour", true, "dashboard", dashboardSha256); ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("the honest tenant was refused with code %d: the lockout was applied to the balancer, not to the device", ack.ReturnCode)
	}

	if m := b.Metrics(); m.AuthLockoutRefusals != 1 || m.AuthRejected != 2 {
		t.Errorf("auth_lockout_refusals = %d, auth_rejected = %d; want 1 and 2", m.AuthLockoutRefusals, m.AuthRejected)
	}
}

// TestRealAddressDrivesTheACLIpRule is the rule-file half: an acl that says "this
// topic is only for that address" now means the device, so a balancer's address
// neither grants every device nor denies every one.
func TestRealAddressDrivesTheACLIpRule(t *testing.T) {
	acl := loadACL(t, `
{"effect":"allow","ip":"203.0.113.7","action":"subscribe","topics":["plant/#"]}
{"effect":"deny","action":"subscribe","topics":["#"]}
`)
	b := startBroker(t, nil, func(o *broker.Options) {
		o.Proxy = broker.ProxyRequire
		o.ACL = acl
	})

	allowed := proxiedClient(t, b, "127.0.0.1", v1("203.0.113.7", 49101, "198.51.100.9", 1883))
	allowed.connect("device-7", true)
	if codes := allowed.subscribe(1, flt("plant/#", packets.QoS0)); codes[0] != packets.QoS0 {
		t.Errorf("the claimed address was granted %d, want QoS 0", codes[0])
	}

	denied := proxiedClient(t, b, "127.0.0.1", v1("198.51.100.7", 49102, "198.51.100.9", 1883))
	denied.connect("device-8", true)
	if codes := denied.subscribe(2, flt("plant/#", packets.QoS0)); codes[0] != packets.SubAckFailure {
		t.Errorf("a different claimed address was granted %d, want the 0x80 failure", codes[0])
	}

	// Both sockets arrived from 127.0.0.1. A rule keyed on the balancer would have
	// answered them identically, so the two opposite verdicts are the proof.
	if m := b.Metrics(); m.DeniedSubscribe != 1 {
		t.Errorf("acl_denied_subscribe = %d, want 1", m.DeniedSubscribe)
	}
}

// TestRealAddressIsWhatTheSessionRemembers closes the chain at the store: the
// identity written down for a session is the device's, which is the one a later
// delivery is authorised against after a restart.
func TestRealAddressIsWhatTheSessionRemembers(t *testing.T) {
	st := store.NewMemoryStore()
	b := startBroker(t, st, func(o *broker.Options) { o.Proxy = broker.ProxyRequire })

	c := proxiedClient(t, b, "127.0.0.1", v1("203.0.113.7", 49101, "198.51.100.9", 1883))
	c.connect("dev-7", false)
	c.subscribe(1, flt("plant/7/telemetry", packets.QoS0))

	waitUntil(t, func() bool {
		s, ok := st.Get("dev-7")
		return ok && s.RemoteIP != ""
	})
	s, _ := st.Get("dev-7")
	if s.RemoteIP != "203.0.113.7" {
		t.Errorf("the session remembers %q, want the address the header named, not the balancer's", s.RemoteIP)
	}
}

// TestProxyOffReadsNoHeader is the zero-cost promise: with the feature off, the
// accept path reads no prefix, so what a peer writes first is payload and nothing
// is resolved or refused at the header stage.
func TestProxyOffReadsNoHeader(t *testing.T) {
	b := startBroker(t, nil, nil)

	// A client id that starts with the header's first letters, in case anything
	// ever sniffed the stream before the decoder.
	c := dial(t, b)
	c.connect("PROXYTCP4device", true)

	// And a real header on a listener that never asked for one: it is payload, and
	// a packet that is not a CONNECT ends the connection rather than naming
	// somebody.
	raw := dial(t, b)
	_ = raw.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := raw.conn.Write(v1("203.0.113.7", 49101, "198.51.100.9", 1883)); err != nil {
		t.Fatalf("write a header nobody asked for: %v", err)
	}
	raw.expectClosed()

	if m := b.Metrics(); m.ConnectionsProxy != 0 || m.RefusedProxy != 0 {
		t.Errorf("connections_over_proxy_header = %d, refused_over_proxy_header = %d; want both 0 with the feature off",
			m.ConnectionsProxy, m.RefusedProxy)
	}
}
