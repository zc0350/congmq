package broker_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/store"
)

// These tests drive the per-address gate through a real listener, because what
// it is for is the shape of load a limit checked at CONNECT cannot see: a peer
// that opens sockets, sends nothing, and asks for more.

// dialFrom opens a TCP socket with a chosen loopback source address. Both
// Windows and Linux answer for the whole of 127/8, so one test can be about two
// tenants of the network rather than about one address's bad day.
func dialFrom(t *testing.T, addr, src string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 3 * time.Second}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s from %s: %v", addr, src, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// hungUp reports whether the broker closed the socket without reading it. A
// refusal is a bare FIN with no MQTT behind it: the peer is deliberately told
// nothing that would let it tell a gate refusal from a device fault, so this is
// all the evidence the socket itself gives.
func hungUp(t *testing.T, conn net.Conn, within time.Duration) bool {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(within))
	b := make([]byte, 1)
	n, err := conn.Read(b)
	if n == 0 && errors.Is(err, io.EOF) {
		return true
	}
	var ne net.Error
	if err != nil && errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	t.Fatalf("reading a refused socket gave n=%d err=%v, want EOF or a timeout", n, err)
	return false
}

// admitted dials one socket and says which way the broker decided. The counters
// answer rather than the socket, because proving a connection was *not* refused
// would otherwise mean sitting through a read timeout to learn that nothing
// arrived.
func admitted(t *testing.T, b *broker.Broker, addr, src string) bool {
	t.Helper()
	before := b.Metrics()
	deniedBefore := before.RefusedPerIPConns + before.RefusedPerIPRate
	conn := dialFrom(t, addr, src)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		m := b.Metrics()
		if m.TotalConns > before.TotalConns {
			return true
		}
		if m.RefusedPerIPConns+m.RefusedPerIPRate > deniedBefore {
			if !hungUp(t, conn, 2*time.Second) {
				t.Fatalf("the gate counted a refusal but left %s's socket open", src)
			}
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the broker never decided about a socket dialled at %s", addr)
	return false
}

// dialAt opens an MQTT client whose socket comes from a chosen loopback source
// address. The credential lockout is keyed on where a CONNECT arrived, so a test
// about two tenants of the network has to be able to arrive as both of them.
func dialAt(t *testing.T, b *broker.Broker, src string) *client {
	t.Helper()
	conn := dialFrom(t, b.Addr(), src)
	return &client{t: t, conn: conn, r: bufio.NewReader(conn), ver: packets.V311}
}

// One account, one correct password: sha256("c0ng-2026" + "dashboard"), which
// rules_test.go already carries as dashboardSha256 rather than recomputing.
const lockoutRule = `{"username":"dashboard","salt":"c0ng-2026","alg":"sha256","scheme":"salt+username"}`

// The lockout is the part of the gate a device can be hurt by, so the interesting
// assertions are the ones about what it costs: a correct password refused while
// the address serves its term, and a neighbour behind another address unaffected.
func TestCredentialLockoutRefusesEvenTheCorrectPassword(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) {
		o.Auth = loadAuth(t, lockoutRule)
		o.AuthFailLimit = 3
		o.AuthFailWindow = time.Minute
		o.AuthLockout = 750 * time.Millisecond
	})

	for i := 0; i < 3; i++ {
		if ack := dialAt(t, b, "127.0.0.1").connectAs("guesser", true, "dashboard", wrongDigest); ack.ReturnCode != packets.ConnBadCredentials {
			t.Fatalf("failure %d answered with code %d, want bad credentials", i+1, ack.ReturnCode)
		}
	}
	waitUntil(t, func() bool { return b.Metrics().AuthLockedAddresses == 1 })
	if got := b.Metrics().AuthRejected; got != 3 {
		t.Fatalf("auth_rejected = %d after three wrong passwords, want 3", got)
	}

	// The cost, said plainly: this device knows its password and is still turned
	// away. It is answered with the same code, because a lockout an attacker can
	// recognise is a lockout it can time around — it just waits, or sprays from
	// another address and reads the difference as a progress report.
	if ack := dialAt(t, b, "127.0.0.1").connectAs("honest", true, "dashboard", dashboardSha256); ack.ReturnCode != packets.ConnBadCredentials {
		t.Fatalf("the lockout answered a correct password with code %d, want the same code a wrong one gets", ack.ReturnCode)
	}
	m := b.Metrics()
	if m.AuthLockoutRefusals != 1 {
		t.Errorf("auth_lockout_refusals = %d, want 1: the two counters mean opposite things to whoever is debugging", m.AuthLockoutRefusals)
	}
	if m.AuthRejected != 3 {
		t.Errorf("auth_rejected = %d, want the three from before: a lockout refusal is not a bad credential", m.AuthRejected)
	}

	// One address's bad day stays its own.
	if ack := dialAt(t, b, "127.0.0.2").connectAs("neighbour", true, "dashboard", dashboardSha256); ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("127.0.0.2 got code %d for what 127.0.0.1 did", ack.ReturnCode)
	}
	if n := b.Metrics().AuthLockedAddresses; n != 1 {
		t.Errorf("locked addresses = %d, want still only the one", n)
	}

	// Serving the term is the whole penalty. The address comes back on its own,
	// with no residual count: the three failures were spent earning the lockout,
	// not banked against the next window.
	waitUntil(t, func() bool { return b.Metrics().AuthLockedAddresses == 0 })
	if ack := dialAt(t, b, "127.0.0.1").connectAs("returned", true, "dashboard", dashboardSha256); ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("after its term the address got code %d, want accepted", ack.ReturnCode)
	}
	for i := 0; i < 2; i++ {
		dialAt(t, b, "127.0.0.1").connectAs("fumbler", true, "dashboard", wrongDigest)
	}
	if n := b.Metrics().AuthLockedAddresses; n != 0 {
		t.Fatalf("locked addresses = %d after two fresh failures at a limit of 3, want 0", n)
	}
	if ack := dialAt(t, b, "127.0.0.1").connectAs("still_in", true, "dashboard", dashboardSha256); ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("a correct password got code %d while the address was under its limit", ack.ReturnCode)
	}
}

// Nobody asked for this feature, so nothing may change about the broker they
// already run: every attempt answered on its merits, nothing remembered about the
// address, and no bucket in a table nobody is consulting.
func TestLockoutOffAnswersEveryAttemptOnItsMerits(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) { o.Auth = loadAuth(t, lockoutRule) })

	for i := 0; i < 12; i++ {
		if ack := dialAt(t, b, "127.0.0.1").connectAs("guesser", true, "dashboard", wrongDigest); ack.ReturnCode != packets.ConnBadCredentials {
			t.Fatalf("attempt %d got code %d, want the plain credential refusal", i+1, ack.ReturnCode)
		}
	}
	if ack := dialAt(t, b, "127.0.0.1").connectAs("honest", true, "dashboard", dashboardSha256); ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("a correct password got code %d with no lockout configured", ack.ReturnCode)
	}
	m := b.Metrics()
	if m.AuthRejected != 12 {
		t.Errorf("auth_rejected = %d, want the 12 failures asked for", m.AuthRejected)
	}
	if m.AuthLockoutRefusals != 0 || m.AuthLockedAddresses != 0 {
		t.Errorf("counted %d lockout refusals across %d locked addresses with the feature off",
			m.AuthLockoutRefusals, m.AuthLockedAddresses)
	}
	if m.GateEntries != 0 {
		t.Errorf("per_ip_gate_entries = %d with no gate armed, want 0", m.GateEntries)
	}
}

// The whole point of defaulting the gate off is that nobody pays for it until
// they ask for it, so an unarmed broker must look like the broker that was
// shipped before this code existed: no address parsed, nothing counted, everyone
// connected.
func TestGateOffLeavesEveryAddressUnmetered(t *testing.T) {
	b := startBroker(t, nil, nil)

	for i := 0; i < 10; i++ {
		if !admitted(t, b, b.Addr(), "127.0.0.1") {
			t.Fatalf("silent socket %d was refused with no gate switched on", i+1)
		}
	}
	m := b.Metrics()
	if m.TotalConns != 10 {
		t.Fatalf("total_connections = %d, want the 10 sockets asked for", m.TotalConns)
	}
	if m.GateEntries != 0 || m.GateHeld != 0 {
		t.Errorf("an off gate reports %d entries holding %d sockets, want 0/0", m.GateEntries, m.GateHeld)
	}
	if m.RefusedPerIPConns != 0 || m.RefusedPerIPRate != 0 {
		t.Errorf("an off gate refused %d/%d", m.RefusedPerIPConns, m.RefusedPerIPRate)
	}

	// And MQTT is untouched: the gate is not in the way of a real session.
	c := dial(t, b)
	c.connect("unmetered", true)
	waitUntil(t, func() bool { return b.Metrics().Online == 1 })
}

func TestPerIPConnectionLimitClosesSilentSockets(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) { o.MaxConnsPerIP = 2 })

	held := []net.Conn{
		dialFrom(t, b.Addr(), "127.0.0.1"),
		dialFrom(t, b.Addr(), "127.0.0.1"),
	}
	waitUntil(t, func() bool { return b.Metrics().GateHeld == 2 })

	// Two silent sockets are the whole allowance. Neither has identified itself as
	// MQTT, which is exactly why the limit counts sockets rather than sessions.
	if admitted(t, b, b.Addr(), "127.0.0.1") {
		t.Fatal("a third socket from the same address got past a limit of 2")
	}
	m := b.Metrics()
	if m.RefusedPerIPConns != 1 || m.RefusedPerIPRate != 0 {
		t.Errorf("refusals = %d/%d, want one connection-limit refusal and no rate refusal",
			m.RefusedPerIPConns, m.RefusedPerIPRate)
	}
	// A refusal never became a connection: no session, no read loop, no CONNACK.
	if m.TotalConns != 2 || m.Online != 0 {
		t.Errorf("after the refusal: total_connections=%d online=%d, want 2/0", m.TotalConns, m.Online)
	}

	// A second address is not this one's neighbour's problem.
	if !admitted(t, b, b.Addr(), "127.0.0.2") {
		t.Fatal("127.0.0.2 was refused for what 127.0.0.1 had used up")
	}
	if n := b.Metrics().GateEntries; n != 2 {
		t.Errorf("per_ip_gate_entries = %d, want both addresses on record", n)
	}

	// The room comes back with the connection that ends.
	_ = held[0].Close()
	waitUntil(t, func() bool { return b.Metrics().GateHeld == 2 })
	if !admitted(t, b, b.Addr(), "127.0.0.1") {
		t.Fatal("closing a socket never returned its slot to the address")
	}
	if got := b.Metrics().RefusedPerIPConns; got != 1 {
		t.Errorf("refusals = %d after the slot came back, want only the one from before", got)
	}
}

// A rate limit has to survive the cheapest evasion of a concurrency limit: open,
// close, open, close. What it meters is arrivals, so a socket given back does not
// buy its token back.
func TestPerIPConnectRateLimitsChurn(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) {
		o.ConnectRatePerIP = 0.5 // one new connection every two seconds
		o.ConnectBurstPerIP = 2
	})

	if !admitted(t, b, b.Addr(), "127.0.0.1") {
		t.Fatal("the first arrival of a fresh burst was refused")
	}
	if !admitted(t, b, b.Addr(), "127.0.0.1") {
		t.Fatal("the second of a burst of 2 was refused")
	}
	if admitted(t, b, b.Addr(), "127.0.0.1") {
		t.Fatal("a third arrival inside the burst was admitted")
	}

	// The two admitted sockets are still open, and none of that matters to the
	// window: the tokens were spent when the sockets arrived. TestRateIsATokenBucket
	// holds the clock-level version of this; what is worth pinning here is that a
	// refusal over a real listener is counted as a rate refusal and not something
	// else, because that is the number an operator ends up reading.
	if m := b.Metrics(); m.RefusedPerIPRate == 0 {
		t.Fatal("a rate refusal over a real listener was not counted as one")
	}

	// Time is the only thing that refills it. One attempt per 100ms until the
	// bucket has a token again; two seconds of quiet should do it, and six says so.
	deadline := time.Now().Add(6 * time.Second)
	for {
		if admitted(t, b, b.Addr(), "127.0.0.1") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("six quiet seconds never bought the address a token back")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// The TLS listener is where a held slot matters most, because the expensive part
// of a connection happens before any protocol: a peer that completes the TCP
// handshake and stops costs the broker a socket and a whole handshake timeout,
// and it is that window the address is charged for.
func TestTLSSlotIsHeldForTheWholeHandshake(t *testing.T) {
	bundle := certBundle(t)
	b := startTLSBroker(t, bundle, false, false, func(o *broker.Options) {
		o.MaxConnsPerIP = 1
		o.HandshakeTimeout = 700 * time.Millisecond
	})

	// A peer that finishes the TCP part and stops. dialFrom's cleanup closes it,
	// though by then the broker has already hung up on it itself.
	_ = dialFrom(t, b.TLSAddr(), "127.0.0.1")
	waitUntil(t, func() bool { return b.Metrics().GateHeld == 1 })

	// No session exists, no byte has been read, and the address has no room left.
	if admitted(t, b, b.TLSAddr(), "127.0.0.1") {
		t.Fatal("a second TLS arrival got past a limit of 1 while the first handshake was outstanding")
	}

	// The timed-out handshake is the release: this path produces no client, so
	// there is no cleanup to run and nothing else to give the slot back.
	waitUntil(t, func() bool { return b.Metrics().TLSHandshakeFailures >= 1 })
	waitUntil(t, func() bool { return b.Metrics().GateHeld == 0 })

	// A real device then gets in, over a verified handshake, and holds one slot.
	c := dialTLSBroker(t, b, caPool(t, bundle), nil, nil)
	c.connect("tls-after-gate", true)
	waitUntil(t, func() bool { return b.Metrics().Online == 1 })
	if m := b.Metrics(); m.GateHeld != 1 || m.ConnectionsTLS != 1 {
		t.Errorf("after a real TLS session: gate_held=%d connections_tls=%d, want 1/1",
			m.GateHeld, m.ConnectionsTLS)
	}
}

// The subscription cap is the per-client half of the same idea, and it is the one
// limit here that can silently cost a device its topics: a refused SUBSCRIBE is
// not a dropped connection, it is a subscription that never happens. So the
// interesting assertions are about what stays allowed at the limit.
func TestSubscriptionCapRefusesOnlyNewFilters(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) { o.MaxSubs = 2 })

	c := dial(t, b)
	c.connect("capped", true)
	if codes := c.subscribe(1, flt("a/1", packets.QoS1), flt("a/2", packets.QoS1)); codes[0] != packets.QoS1 || codes[1] != packets.QoS1 {
		t.Fatalf("the first two filters of a cap of 2 came back %v", codes)
	}

	// Replacing a filter the session already holds costs nothing, so it is granted
	// even at the cap. A device that filled its allowance must still be able to
	// re-negotiate the QoS of what it has.
	if codes := c.subscribe(2, flt("a/1", packets.QoS0)); codes[0] != packets.QoS0 {
		t.Fatalf("re-subscribing a held filter at the cap came back %#02x, want the new QoS granted", codes[0])
	}
	if codes := c.subscribe(3, flt("a/3", packets.QoS1)); codes[0] != packets.SubAckFailure {
		t.Fatalf("a third distinct filter came back %#02x, want the 3.1.1 failure code", codes[0])
	}
	if got := b.Metrics().SubsOverCap; got != 1 {
		t.Fatalf("refused_over_subscription_cap = %d, want 1", got)
	}

	// A batch with room for one is granted the one: the cap counts filters, not the
	// packet carrying them, and a client that asks for five in one SUBSCRIBE gets
	// five verdicts back.
	if codes := c.subscribe(4, flt("a/1", packets.QoS2), flt("a/4", packets.QoS1), flt("a/5", packets.QoS1)); codes[0] != packets.QoS2 || codes[1] != packets.SubAckFailure || codes[2] != packets.SubAckFailure {
		t.Fatalf("mixed batch = %v, want the held filter re-granted at QoS 2 and the two new ones refused", codes)
	}

	// Unsubscribing returns the room, so the cap needs no release path of its own.
	c.send(&packets.Unsubscribe{PacketID: 6, TopicFilters: []string{"a/2"}})
	c.expect(packets.TypeUnsuback)
	if codes := c.subscribe(7, flt("a/6", packets.QoS1)); codes[0] != packets.QoS1 {
		t.Fatalf("a new filter after an unsubscribe came back %#02x, want it granted", codes[0])
	}

	// The allowance is per client, not global: one chatty subscriber cannot spend
	// another's room.
	other := dial(t, b)
	other.connect("other", true)
	if codes := other.subscribe(1, flt("b/1", packets.QoS1), flt("b/2", packets.QoS1)); codes[0] != packets.QoS1 || codes[1] != packets.QoS1 {
		t.Fatalf("a second client's first two filters came back %v, want both granted", codes)
	}
	// And what it is subscribed to keeps working while the refusals pile up.
	pub := dial(t, b)
	pub.connect("pub", true)
	pub.publishQoS1(9, "a/6", "through-the-cap")
	if p := ackDelivery(c); p.Topic != "a/6" {
		t.Fatalf("delivery on %q, want the filter that was granted after the cap bit", p.Topic)
	}
	if m := b.Metrics(); m.SubsOverCap != 3 {
		t.Errorf("refused_over_subscription_cap = %d, want the 3 new filters asked for past the cap and no other refusal", m.SubsOverCap)
	}
}

// With the cap off, a client may hold as many filters as the topic tree can carry.
// This is the deployment every existing installation is running, so the only
// difference they should see is none.
func TestNoSubscriptionCapMeansNoRefusals(t *testing.T) {
	b := startBroker(t, nil, nil)

	c := dial(t, b)
	c.connect("uncapped", true)
	var want []packets.Subscription
	for i := 0; i < 200; i++ {
		want = append(want, flt(fmt.Sprintf("wide/%d", i), packets.QoS1))
	}
	for start := 0; start < len(want); start += 50 {
		end := min(start+50, len(want))
		for _, code := range c.subscribe(uint16(start+1), want[start:end]...) {
			if code != packets.QoS1 {
				t.Fatalf("a subscription came back %#02x with no cap configured", code)
			}
		}
	}
	if m := b.Metrics(); m.SubsOverCap != 0 || m.Subscriptions != 200 {
		t.Errorf("refused_over_subscription_cap=%d subscriptions=%d, want 0/200", m.SubsOverCap, m.Subscriptions)
	}
}

// MQTT 5 has a reason code for this and 3.1.1 does not, and the two versions must
// not be confused with the acl refusal: one is a limit to raise, the other is a
// rule file to edit.
func TestSubscriptionCapAnswersQuotaExceededAndKeepsAclFirst(t *testing.T) {
	acl := loadACL(t, `
{"effect":"deny","user":"cap","action":"subscribe","topics":["secret/#"]}
{"effect":"allow","user":"cap","action":"subscribe","topics":["#"]}
`)
	b := startBroker(t, nil, func(o *broker.Options) {
		o.ACL = acl
		o.MaxSubs = 1
	})

	c := dialV5(t, b)
	c.mustV5As("capped", "cap", true, 0)
	if codes := c.v5sub(1, nil, flt("open/1", packets.QoS1)); codes[0] != packets.QoS1 {
		t.Fatalf("the first filter came back %#02x, want it granted", codes[0])
	}
	// The cap is reached, but this filter was never allowed either. The security
	// answer wins, because it is the one that does not depend on how much the
	// client has already asked for.
	if codes := c.v5sub(2, nil, flt("secret/1", packets.QoS1)); codes[0] != packets.RNotAuthorized {
		t.Fatalf("a filter the rules refuse at the cap came back %#02x, want not authorized", codes[0])
	}
	if codes := c.v5sub(3, nil, flt("open/2", packets.QoS1)); codes[0] != packets.RQuotaExceeded {
		t.Fatalf("an allowed filter at the cap came back %#02x, want quota exceeded", codes[0])
	}
	m := b.Metrics()
	if m.DeniedSubscribe != 1 || m.SubsOverCap != 1 {
		t.Errorf("acl_denied_subscribe=%d refused_over_subscription_cap=%d, want 1/1: the two have opposite fixes",
			m.DeniedSubscribe, m.SubsOverCap)
	}
}

// Lowering -max-subs on a broker that already has sessions above the new number is
// the case a limit like this has to get right: the subscriptions the broker already
// promised keep being served, and the cap starts biting on the next new filter.
// Restoring them is not a SUBSCRIBE the client sends, so nothing may refuse it.
func TestSubscriptionCapDoesNotPunishARestoredSession(t *testing.T) {
	st := store.NewMemoryStore()
	held := map[string]store.Sub{}
	for i := 1; i <= 4; i++ {
		held[fmt.Sprintf("d/%d", i)] = store.Sub{QoS: packets.QoS1}
	}
	if err := st.Put(&store.Session{
		ClientID:      "restored",
		Subscriptions: held,
		Proto:         packets.V311,
	}); err != nil {
		t.Fatalf("seed the session: %v", err)
	}

	b := startBroker(t, st, func(o *broker.Options) { o.MaxSubs = 2 })
	c := dial(t, b)
	c.connect("restored", false)
	// The count is the evidence that this is the stored session and not a new one:
	// 3.1.1's Session Present flag only reports queued or unacknowledged state, and
	// this session has none. The subscriptions are reinstalled before the CONNACK is
	// written, so nothing here needs to wait for them.
	if n := b.Metrics().Subscriptions; n != 4 {
		t.Fatalf("subscriptions = %d after restoring four of them under a cap of 2, want 4", n)
	}

	// Every restored filter still delivers, which is the whole claim: a lowered cap
	// must not quietly unserve a device that never asked for anything.
	pub := dial(t, b)
	pub.connect("pub", true)
	for i := 1; i <= 4; i++ {
		topic := fmt.Sprintf("d/%d", i)
		pub.publishQoS1(uint16(10+i), topic, "still-here")
		if p := ackDelivery(c); p.Topic != topic {
			t.Fatalf("restored delivery on %q, want %q: the cap cost this filter its subscription", p.Topic, topic)
		}
	}

	// From here the cap is in force, and it is the new filter that is refused.
	if codes := c.subscribe(30, flt("d/5", packets.QoS1)); codes[0] != packets.SubAckFailure {
		t.Fatalf("a fifth filter came back %#02x, want the cap to refuse it", codes[0])
	}
	if got := b.Metrics().SubsOverCap; got != 1 {
		t.Errorf("refused_over_subscription_cap = %d, want 1", got)
	}
}
