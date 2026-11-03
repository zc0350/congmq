package broker_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/store"
)

// startBroker brings up a broker on a random loopback port and returns it.
// The same store can be handed to a second call to simulate a restart.
func startBroker(t *testing.T, st store.Store, tweak func(*broker.Options)) *broker.Broker {
	t.Helper()
	if st == nil {
		st = store.NewMemoryStore()
	}
	opt := broker.Options{
		ID:             "test",
		Store:          st,
		QueueMax:       50,
		InflightWindow: 4,
		MailboxSize:    8,
		RetryInterval:  300 * time.Millisecond,
		WriteTimeout:   2 * time.Second,
		DeliverTimeout: 2 * time.Second,
		Logger:         testLogger(t),
	}
	if tweak != nil {
		tweak(&opt)
	}
	b := broker.New(opt)
	if err := b.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- b.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := b.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("Serve did not return after Shutdown")
		}
	})
	return b
}

func testLogger(t *testing.T) *slog.Logger {
	if os.Getenv("CONGMQ_TEST_LOG") == "" {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// client is a deliberately literal MQTT client: it speaks the wire format and
// nothing else, so the tests assert exactly what the broker sends. ver picks
// the encoding it uses in both directions; the tests that started life as
// 3.1.1 checks leave it alone.
type client struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	id   string
	ver  packets.Version
}

func dial(t *testing.T, b *broker.Broker) *client {
	t.Helper()
	conn, err := net.DialTimeout("tcp", b.Addr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := &client{t: t, conn: conn, r: bufio.NewReader(conn), ver: packets.V311}
	t.Cleanup(func() { _ = c.conn.Close() })
	return c
}

// dialV5 opens a connection that speaks MQTT 5.0.
func dialV5(t *testing.T, b *broker.Broker) *client {
	t.Helper()
	c := dial(t, b)
	c.ver = packets.V5
	return c
}

func (c *client) send(p packets.Packet) {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	frame, err := packets.EncodeBytesVersion(c.ver, p)
	if err != nil {
		c.t.Fatalf("encode %s: %v", p.Type(), err)
	}
	if _, err := c.conn.Write(frame); err != nil {
		c.t.Fatalf("write %s: %v", p.Type(), err)
	}
}

func (c *client) recv(wait time.Duration) (packets.Packet, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(wait))
	return packets.DecodeVersion(c.r, c.ver)
}

func (c *client) expect(typ packets.Type) packets.Packet {
	c.t.Helper()
	p, err := c.recv(3 * time.Second)
	if err != nil {
		c.t.Fatalf("waiting for %s: %v", typ, err)
	}
	if p.Type() != typ {
		c.t.Fatalf("got %s, want %s", p.Type(), typ)
	}
	return p
}

// expectNothing fails if the broker pushes anything within the window, which
// is how these tests prove a message was acknowledged and not re-sent.
func (c *client) expectNothing(wait time.Duration) {
	c.t.Helper()
	p, err := c.recv(wait)
	if err == nil {
		if pub, ok := p.(*packets.Publish); ok {
			c.t.Fatalf("expected silence, got PUBLISH %q dup=%v", pub.Topic, pub.Dup)
		}
		c.t.Fatalf("expected silence, got %s", p.Type())
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		c.t.Fatalf("expected silence, got read error: %v", err)
	}
}

func (c *client) expectClosed() {
	c.t.Helper()
	_, err := c.recv(3 * time.Second)
	if err == nil {
		c.t.Fatalf("expected the broker to close the connection")
	}
}

func (c *client) connect(id string, clean bool) *packets.Connack {
	c.t.Helper()
	c.id = id
	c.send(&packets.Connect{
		ProtocolName:  packets.ProtocolName,
		ProtocolLevel: packets.ProtocolLevel,
		ClientID:      id,
		CleanSession:  clean,
		KeepAlive:     120,
	})
	ack, ok := c.expect(packets.TypeConnack).(*packets.Connack)
	if !ok {
		c.t.Fatalf("expected CONNACK")
	}
	if ack.ReturnCode != packets.ConnAccepted {
		c.t.Fatalf("connect refused with code %d", ack.ReturnCode)
	}
	return ack
}

func (c *client) subscribe(packetID uint16, want ...packets.Subscription) []byte {
	c.t.Helper()
	c.send(&packets.Subscribe{PacketID: packetID, Subscriptions: want})
	ack := c.expect(packets.TypeSuback).(*packets.Suback)
	if ack.PacketID != packetID {
		c.t.Fatalf("SUBACK id = %d, want %d", ack.PacketID, packetID)
	}
	if len(ack.ReturnCodes) != len(want) {
		c.t.Fatalf("SUBACK has %d codes, want %d", len(ack.ReturnCodes), len(want))
	}
	return ack.ReturnCodes
}

func (c *client) publishQoS0(topic, payload string) {
	c.t.Helper()
	c.send(&packets.Publish{Topic: topic, QoS: packets.QoS0, Payload: []byte(payload)})
}

func (c *client) publishQoS1(packetID uint16, topic, payload string) {
	c.t.Helper()
	c.send(&packets.Publish{Topic: topic, QoS: packets.QoS1, PacketID: packetID, Payload: []byte(payload)})
	c.expect(packets.TypePuback)
}

// publishQoS2Inbound sends a PUBLISH and stops at PUBREC, so the test can
// control when the PUBREL arrives.
func (c *client) publishQoS2Inbound(packetID uint16, topic, payload string) {
	c.t.Helper()
	c.send(&packets.Publish{Topic: topic, QoS: packets.QoS2, PacketID: packetID, Payload: []byte(payload)})
	rec := c.expect(packets.TypePubrec).(*packets.Pubrec)
	if rec.PacketID != packetID {
		c.t.Fatalf("PUBREC id = %d, want %d", rec.PacketID, packetID)
	}
}

func (c *client) ackQoS2Outbound(p *packets.Publish) {
	c.t.Helper()
	c.send(&packets.Pubrec{PacketID: p.PacketID})
	c.expect(packets.TypePubrel)
	c.send(&packets.Pubcomp{PacketID: p.PacketID})
}

func flt(filter string, qos byte) packets.Subscription {
	return packets.Subscription{TopicFilter: filter, MaxQoS: qos}
}

func TestConnectSubscribeAndReject(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dial(t, b)

	ack := c.connect("c1", true)
	if ack.SessionPresent {
		t.Error("a first clean session must not report a stored session")
	}

	codes := c.subscribe(1, flt("a/b", packets.QoS1), flt("bad##", packets.QoS0))
	if codes[0] != packets.QoS1 {
		t.Errorf("granted QoS = %d, want 1", codes[0])
	}
	if codes[1] != packets.SubAckFailure {
		t.Errorf("invalid filter returned code %#x, want 0x80", codes[1])
	}

	// A protocol level this broker does not speak is refused, not guessed at.
	// Level 3 is the pre-3.1.1 protocol; level 5 is now spoken for, so the
	// unsupported-probe moved down a version rather than being dropped.
	c2 := dial(t, b)
	c2.send(&packets.Connect{ProtocolName: packets.ProtocolName, ProtocolLevel: 3, ClientID: "c2", KeepAlive: 30})
	refused := c2.expect(packets.TypeConnack).(*packets.Connack)
	if refused.ReturnCode != packets.ConnBadProtocol {
		t.Errorf("return code = %d, want %d", refused.ReturnCode, packets.ConnBadProtocol)
	}

	// Anything before CONNECT is a protocol violation.
	c3 := dial(t, b)
	c3.send(&packets.Publish{Topic: "a", QoS: packets.QoS0, Payload: []byte("x")})
	c3.expectClosed()

	if m := b.Metrics(); m.Online != 1 {
		t.Errorf("online = %d, want 1 (the refused sockets must not linger)", m.Online)
	}
}

func TestQoS0FanoutIncludesThePublisher(t *testing.T) {
	b := startBroker(t, nil, nil)
	subA := dial(t, b)
	subA.connect("subA", true)
	subA.subscribe(1, flt("sensor/+/temp", packets.QoS0))

	subB := dial(t, b)
	subB.connect("subB", true)
	subB.subscribe(1, flt("sensor/1/temp", packets.QoS0))

	pub := dial(t, b)
	pub.connect("pub", true)
	pub.subscribe(2, flt("sensor/#", packets.QoS0))
	pub.publishQoS0("sensor/1/temp", "21.5")

	for _, c := range []*client{subA, subB, pub} {
		p := c.expect(packets.TypePublish).(*packets.Publish)
		if p.Topic != "sensor/1/temp" || string(p.Payload) != "21.5" {
			t.Fatalf("%s got %q/%q", c.id, p.Topic, p.Payload)
		}
		if p.QoS != packets.QoS0 {
			t.Errorf("%s got QoS %d, want 0 (the granted QoS is the lower of the two)", c.id, p.QoS)
		}
	}
}

// TestQoS1ResendsUntilPuback exercises the window and the retry timer: an
// unacknowledged message must come back with DUP set, and must stop coming
// back once the PUBACK lands.
func TestQoS1ResendsUntilPuback(t *testing.T) {
	b := startBroker(t, nil, nil)
	sub := dial(t, b)
	sub.connect("sub", true)
	sub.subscribe(1, flt("cmd/1", packets.QoS1))

	pub := dial(t, b)
	pub.connect("pub", true)
	pub.publishQoS1(11, "cmd/1", "open")

	first := sub.expect(packets.TypePublish).(*packets.Publish)
	if first.QoS != packets.QoS1 || first.PacketID == 0 {
		t.Fatalf("PUBLISH qos=%d id=%d, want qos 1 with an identifier", first.QoS, first.PacketID)
	}
	if first.Dup {
		t.Error("the first delivery must not carry DUP")
	}

	// Hold the PUBACK back and watch the broker retry the same identifier.
	second := sub.expect(packets.TypePublish).(*packets.Publish)
	if !second.Dup {
		t.Error("a re-sent message must carry DUP")
	}
	if second.PacketID != first.PacketID || string(second.Payload) != string(first.Payload) {
		t.Errorf("retry changed the message: id %d vs %d", second.PacketID, first.PacketID)
	}

	sub.send(&packets.Puback{PacketID: first.PacketID})
	// A released window slot must not produce any further traffic.
	before := b.Metrics().MessagesOut
	sub.expectNothing(1200 * time.Millisecond)
	if after := b.Metrics().MessagesOut; after != before {
		t.Errorf("the broker kept resending after the PUBACK: messages out %d -> %d", before, after)
	}
}

// TestQoS2ExactlyOnce checks both directions of the four-step handshake and
// that a replayed PUBLISH is deduplicated rather than delivered twice.
func TestQoS2ExactlyOnce(t *testing.T) {
	b := startBroker(t, nil, nil)
	sub := dial(t, b)
	sub.connect("sub", true)
	sub.subscribe(1, flt("dev/data", packets.QoS2))

	pub := dial(t, b)
	pub.connect("pub", true)

	pub.publishQoS2Inbound(77, "dev/data", "payload")

	// A replay before the PUBREL must be answered with PUBREC and nothing may
	// reach the subscriber: the message is not yet committable.
	pub.send(&packets.Publish{Topic: "dev/data", QoS: packets.QoS2, PacketID: 77, Dup: true, Payload: []byte("payload")})
	pub.expect(packets.TypePubrec)
	sub.expectNothing(700 * time.Millisecond)

	pub.send(&packets.Pubrel{PacketID: 77})
	comp := pub.expect(packets.TypePubcomp).(*packets.Pubcomp)
	if comp.PacketID != 77 {
		t.Errorf("PUBCOMP id = %d, want 77", comp.PacketID)
	}

	// Now the subscriber sees exactly one copy and completes its own handshake.
	got := sub.expect(packets.TypePublish).(*packets.Publish)
	if got.QoS != packets.QoS2 || string(got.Payload) != "payload" {
		t.Fatalf("subscriber got qos=%d payload=%q", got.QoS, got.Payload)
	}
	sub.ackQoS2Outbound(got)
	sub.expectNothing(1200 * time.Millisecond)

	if m := b.Metrics(); m.Malformed != 0 {
		t.Errorf("malformed = %d, want 0", m.Malformed)
	}
}

// TestOfflineMessagesSurviveABrokerRestart is the core persistent-session
// promise: subscribe once, disappear, let messages pile up, restart the
// process, reconnect, and get everything exactly once.
func TestOfflineMessagesSurviveABrokerRestart(t *testing.T) {
	st := store.NewMemoryStore()

	b1 := startBroker(t, st, nil)
	sub := dial(t, b1)
	ack := sub.connect("durable", false)
	if ack.SessionPresent {
		t.Error("a brand new persistent session must not report stored state")
	}
	sub.subscribe(1, flt("dev/#", packets.QoS1))

	pub := dial(t, b1)
	pub.connect("pub", true)
	pub.publishQoS1(21, "dev/1", "one")
	pub.publishQoS1(22, "dev/2", "two")

	// Leave without a DISCONNECT so the session, and the messages queued
	// after it, are written to the store.
	_ = sub.conn.Close()
	waitUntil(t, func() bool {
		s, ok := st.Get("durable")
		return ok && len(s.Subscriptions) == 1
	})

	// Restart: a fresh broker, same store.
	if err := b1.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown b1: %v", err)
	}
	b2 := startBroker(t, st, nil)

	pub2 := dial(t, b2)
	pub2.connect("pub2", true)
	pub2.publishQoS1(23, "dev/3", "three")

	fresh := dial(t, b2)
	ack = fresh.connect("durable", false)
	if !ack.SessionPresent {
		t.Fatal("SessionPresent must be true: the broker has messages stored for this client")
	}

	// The reinstalled subscription must be live without a new SUBSCRIBE:
	// "dev/3" was published while this client had no connection at all.
	var got []string
	for range 3 {
		p := fresh.expect(packets.TypePublish).(*packets.Publish)
		if p.QoS != packets.QoS1 {
			t.Fatalf("replayed message %q arrived with QoS %d", p.Topic, p.QoS)
		}
		got = append(got, p.Topic+":"+string(p.Payload))
		fresh.send(&packets.Puback{PacketID: p.PacketID})
	}
	want := []string{"dev/1:one", "dev/2:two", "dev/3:three"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("replay order = %v, want %v", got, want)
		}
	}
	fresh.expectNothing(1 * time.Second)
}

func TestCleanSessionDiscardsStoredMessages(t *testing.T) {
	st := store.NewMemoryStore()
	b := startBroker(t, st, nil)

	sub := dial(t, b)
	sub.connect("temp", false)
	sub.subscribe(1, flt("q/1", packets.QoS1))
	_ = sub.conn.Close()
	waitUntil(t, func() bool { return b.Metrics().Online == 0 })

	pub := dial(t, b)
	pub.connect("pub", true)
	pub.publishQoS1(5, "q/1", "queued")

	back := dial(t, b)
	ack := back.connect("temp", true)
	if ack.SessionPresent {
		t.Error("clean session must report no stored session")
	}
	// The old queue and the old subscription are both gone, so nothing can
	// arrive unless this connection subscribes again.
	back.expectNothing(600 * time.Millisecond)
}

func TestOfflineQueueDropsTheOldestMessages(t *testing.T) {
	st := store.NewMemoryStore()
	b := startBroker(t, st, func(o *broker.Options) { o.QueueMax = 3 })

	sub := dial(t, b)
	sub.connect("slow", false)
	sub.subscribe(1, flt("burst/#", packets.QoS1))
	_ = sub.conn.Close()
	waitUntil(t, func() bool { return b.Metrics().Online == 0 })

	pub := dial(t, b)
	pub.connect("pub", true)
	for i := 1; i <= 6; i++ {
		pub.send(&packets.Publish{
			Topic: "burst/1", QoS: packets.QoS1,
			PacketID: uint16(i), Payload: []byte{byte('0' + i)},
		})
		pub.expect(packets.TypePuback)
	}

	if m := b.Metrics(); m.Dropped == 0 {
		t.Fatalf("dropped = %d, want the overflow to be counted", m.Dropped)
	}

	back := dial(t, b)
	back.connect("slow", false)
	var payloads []string
	for range 3 {
		p := back.expect(packets.TypePublish).(*packets.Publish)
		payloads = append(payloads, string(p.Payload))
		back.send(&packets.Puback{PacketID: p.PacketID})
	}
	if payloads[0] != "4" || payloads[2] != "6" {
		t.Errorf("replayed %v, want the newest three: [4 5 6]", payloads)
	}
	back.expectNothing(600 * time.Millisecond)
}

func TestSessionTakeoverClosesTheOlderConnection(t *testing.T) {
	b := startBroker(t, nil, nil)
	old := dial(t, b)
	old.connect("same-id", true)
	old.subscribe(1, flt("t/1", packets.QoS0))

	fresh := dial(t, b)
	fresh.connect("same-id", true)

	old.expectClosed()

	// The surviving session receives the traffic from here on.
	fresh.subscribe(2, flt("t/1", packets.QoS0))
	pub := dial(t, b)
	pub.connect("pub", true)
	pub.publishQoS0("t/1", "after-takeover")
	p := fresh.expect(packets.TypePublish).(*packets.Publish)
	if string(p.Payload) != "after-takeover" {
		t.Fatalf("payload = %q", p.Payload)
	}
	if m := b.Metrics(); m.Online != 2 {
		t.Errorf("online = %d, want 2 (pub plus the takeover)", m.Online)
	}
}

func TestMalformedPacketClosesTheConnection(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dial(t, b)
	c.connect("c1", true)

	// PUBLISH with the reserved QoS value 3.
	c.send(&packets.Publish{Topic: "a", QoS: packets.QoS0, Payload: []byte("x")})
	c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.conn.Write([]byte{0x3E, 0x02, 0x00, 0x01}); err != nil {
		t.Fatalf("raw write: %v", err)
	}
	c.expectClosed()
	if m := b.Metrics(); m.Malformed == 0 {
		t.Error("the malformed packet was not counted")
	}
}

func TestWillIsPublishedWhenTheConnectionVanishes(t *testing.T) {
	b := startBroker(t, nil, nil)
	watcher := dial(t, b)
	watcher.connect("watcher", true)
	watcher.subscribe(1, flt("node/1/status", packets.QoS1))

	node := dial(t, b)
	node.send(&packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: packets.ProtocolLevel,
		ClientID: "node-1", CleanSession: true, KeepAlive: 60,
		HasWill: true, WillTopic: "node/1/status", WillPayload: []byte("offline"), WillQoS: packets.QoS1,
	})
	node.expect(packets.TypeConnack)

	_ = node.conn.Close() // no DISCONNECT: this is the abnormal case

	p := watcher.expect(packets.TypePublish).(*packets.Publish)
	if p.Topic != "node/1/status" || string(p.Payload) != "offline" || p.QoS != packets.QoS1 {
		t.Fatalf("will arrived as %q/%q qos %d", p.Topic, p.Payload, p.QoS)
	}
	// Acknowledge it, otherwise the retry timer keeps re-sending the will and
	// the silence check below would report a false failure.
	watcher.send(&packets.Puback{PacketID: p.PacketID})

	// A graceful DISCONNECT must not fire the will.
	node2 := dial(t, b)
	node2.send(&packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: packets.ProtocolLevel,
		ClientID: "node-2", CleanSession: true, KeepAlive: 60,
		HasWill: true, WillTopic: "node/1/status", WillPayload: []byte("should-not-appear"), WillQoS: packets.QoS1,
	})
	node2.expect(packets.TypeConnack)
	node2.send(&packets.Disconnect{})
	_ = node2.conn.Close()
	watcher.expectNothing(800 * time.Millisecond)
}

func TestKeepaliveExpiryClosesIdleConnections(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dial(t, b)
	c.send(&packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: packets.ProtocolLevel,
		ClientID: "idle", CleanSession: true, KeepAlive: 1,
	})
	c.expect(packets.TypeConnack)

	// 1.5 x keepalive is the grace period the spec allows.
	c.expectClosed()
	waitUntil(t, func() bool { return b.Metrics().Online == 0 })
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dial(t, b)
	c.connect("c1", true)
	c.subscribe(1, flt("x/1", packets.QoS0))
	c.send(&packets.Unsubscribe{PacketID: 2, TopicFilters: []string{"x/1"}})
	ua := c.expect(packets.TypeUnsuback).(*packets.Unsuback)
	if ua.PacketID != 2 {
		t.Fatalf("UNSUBACK id = %d, want 2", ua.PacketID)
	}

	pub := dial(t, b)
	pub.connect("pub", true)
	pub.publishQoS0("x/1", "nope")
	c.expectNothing(600 * time.Millisecond)

	if m := b.Metrics(); m.Subscriptions != 0 {
		t.Errorf("subscriptions = %d, want 0", m.Subscriptions)
	}
}

func TestPingKeepsTheConnectionAlive(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dial(t, b)
	c.send(&packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: packets.ProtocolLevel,
		ClientID: "pinger", CleanSession: true, KeepAlive: 1,
	})
	c.expect(packets.TypeConnack)

	time.Sleep(1200 * time.Millisecond)
	c.send(&packets.Pingreq{})
	c.expect(packets.TypePingresp)
	c.expectNothing(900 * time.Millisecond)
}

func TestMaxConnectionsRejects(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) { o.MaxConns = 1 })
	first := dial(t, b)
	first.connect("one", true)

	second := dial(t, b)
	second.send(&packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: packets.ProtocolLevel,
		ClientID: "two", CleanSession: true, KeepAlive: 30,
	})
	refused := second.expect(packets.TypeConnack).(*packets.Connack)
	if refused.ReturnCode != packets.ConnUnavailable {
		t.Errorf("return code = %d, want %d", refused.ReturnCode, packets.ConnUnavailable)
	}
	if m := b.Metrics(); m.Rejected == 0 {
		t.Error("the rejection was not counted")
	}
}

func TestShutdownFlushesLiveSessionsToTheStore(t *testing.T) {
	st := store.NewMemoryStore()
	b := startBroker(t, st, nil)
	sub := dial(t, b)
	sub.connect("durable", false)
	sub.subscribe(1, flt("s/1", packets.QoS1))

	// The subscriber never acknowledges, so the message is still outstanding
	// when the broker stops: the queue must land in the store, not evaporate.
	pub := dial(t, b)
	pub.connect("pub", true)
	pub.publishQoS1(9, "s/1", "during-shutdown")

	if err := b.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	s, ok := st.Get("durable")
	if !ok {
		t.Fatal("session was not persisted on shutdown")
	}
	if len(s.Subscriptions) != 1 {
		t.Errorf("subscriptions = %v, want the filter to be kept", s.Subscriptions)
	}

	b2 := startBroker(t, st, nil)
	back := dial(t, b2)
	ack := back.connect("durable", false)
	if !ack.SessionPresent {
		t.Fatal("the restarted broker must report stored messages")
	}
	p := back.expect(packets.TypePublish).(*packets.Publish)
	if string(p.Payload) != "during-shutdown" {
		t.Fatalf("payload = %q", p.Payload)
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not reached within 3s")
}
