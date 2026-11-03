package broker_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/store"
)

// --- MQTT 5.0 helpers -------------------------------------------------------

// v5 connects a 5.0 client and insists it is accepted. expiry is the Session
// Expiry Interval in seconds; 0 leaves the property off, which means the same
// thing.
func (c *client) v5(id string, cleanStart bool, expiry uint32) *packets.Connack {
	c.t.Helper()
	p := &packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: byte(packets.V5),
		ClientID: id, CleanSession: cleanStart, KeepAlive: 120,
	}
	if expiry > 0 {
		p.Props = &packets.Properties{}
		p.Props.SetSessionExpiry(expiry)
	}
	return c.v5raw(p)
}

// v5raw sends a hand-built CONNECT and hands back whatever CONNACK arrives.
func (c *client) v5raw(p *packets.Connect) *packets.Connack {
	c.t.Helper()
	if p.ProtocolName == "" {
		p.ProtocolName = packets.ProtocolName
	}
	if p.ProtocolLevel == 0 {
		p.ProtocolLevel = byte(packets.V5)
	}
	c.id = p.ClientID
	c.send(p)
	ack, ok := c.expect(packets.TypeConnack).(*packets.Connack)
	if !ok {
		c.t.Fatalf("expected CONNACK")
	}
	return ack
}

// mustV5 connects and fails the test if the broker refused.
func (c *client) mustV5(id string, cleanStart bool, expiry uint32) *packets.Connack {
	c.t.Helper()
	ack := c.v5(id, cleanStart, expiry)
	if ack.ReasonCode != packets.RSuccess {
		c.t.Fatalf("%s: connect refused with %s (%#02x)", id,
			packets.ReasonName(ack.ReasonCode), ack.ReasonCode)
	}
	return ack
}

// mustV5As is mustV5 with a username, which an ACL keyed on users needs.
func (c *client) mustV5As(id, user string, cleanStart bool, expiry uint32) *packets.Connack {
	c.t.Helper()
	p := &packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: byte(packets.V5),
		ClientID: id, CleanSession: cleanStart, KeepAlive: 120,
		HasUsername: true, Username: user,
	}
	if expiry > 0 {
		p.Props = &packets.Properties{}
		p.Props.SetSessionExpiry(expiry)
	}
	ack := c.v5raw(p)
	if ack.ReasonCode != packets.RSuccess {
		c.t.Fatalf("%s: connect refused with %s (%#02x)", id,
			packets.ReasonName(ack.ReasonCode), ack.ReasonCode)
	}
	return ack
}

func (c *client) v5sub(packetID uint16, props *packets.Properties, want ...packets.Subscription) []byte {
	c.t.Helper()
	c.send(&packets.Subscribe{PacketID: packetID, Subscriptions: want, Props: props})
	ack := c.expect(packets.TypeSuback).(*packets.Suback)
	if ack.PacketID != packetID {
		c.t.Fatalf("SUBACK id = %d, want %d", ack.PacketID, packetID)
	}
	if len(ack.ReturnCodes) != len(want) {
		c.t.Fatalf("SUBACK has %d codes, want %d", len(ack.ReturnCodes), len(want))
	}
	return ack.ReturnCodes
}

// v5send publishes a hand-built PUBLISH and returns the reason code the broker
// answered with, so a test can set the RETAIN flag or add properties.
func (c *client) v5send(p *packets.Publish) byte {
	c.t.Helper()
	c.send(p)
	switch p.QoS {
	case packets.QoS0:
		// QoS 0 has no acknowledgement, so there is no code to report.
		return 0xFF
	case packets.QoS1:
		return c.expect(packets.TypePuback).(*packets.Puback).ReasonCode
	default:
		rec := c.expect(packets.TypePubrec).(*packets.Pubrec)
		c.send(&packets.Pubrel{PacketID: p.PacketID})
		comp := c.expect(packets.TypePubcomp).(*packets.Pubcomp)
		if rec.ReasonCode == packets.RSuccess && comp.ReasonCode != packets.RSuccess {
			c.t.Fatalf("accepted PUBREC (0x00) then rejected PUBREL (%#02x)", comp.ReasonCode)
		}
		return rec.ReasonCode
	}
}

// v5publish sends a PUBLISH and returns the reason code it was answered with.
// QoS 0 has no acknowledgement, so the code reported for it is 0xFF.
func (c *client) v5publish(topic, payload string, qos byte, id uint16, props *packets.Properties) byte {
	c.t.Helper()
	return c.v5send(&packets.Publish{
		Topic: topic, QoS: qos, PacketID: id,
		Payload: []byte(payload), Props: props,
	})
}

// v5will connects a client carrying a will, optionally delayed.
func (c *client) v5will(id, topic, payload string, delay uint32, expiry uint32) *packets.Connack {
	c.t.Helper()
	p := &packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: byte(packets.V5),
		ClientID: id, KeepAlive: 120,
		HasWill: true, WillTopic: topic, WillPayload: []byte(payload), WillQoS: packets.QoS1,
		WillProps: &packets.Properties{},
		Props:     &packets.Properties{},
	}
	if delay > 0 {
		p.WillProps.SetWillDelay(delay)
	}
	if expiry > 0 {
		p.Props.SetSessionExpiry(expiry)
	}
	return c.v5raw(p)
}

func (c *client) disconnect(reason byte, props *packets.Properties) {
	c.t.Helper()
	c.send(&packets.Disconnect{ReasonCode: reason, Props: props})
}

// firstPublish waits for one PUBLISH and returns it.
func (c *client) firstPublish() *packets.Publish {
	c.t.Helper()
	return c.expect(packets.TypePublish).(*packets.Publish)
}

// --- CONNACK capability advertisement ---------------------------------------

func TestV5ConnackAdvertisesOnlyWhatDiffers(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) {
		o.ReceiveMax = 7
		o.TopicAliasMax = 3
		o.MaxPacketSize = 4096
	})
	c := dialV5(t, b)
	ack := c.mustV5("cap", true, 0)

	p := ack.Props
	if p == nil {
		t.Fatal("a 5.0 CONNACK must carry a property area")
	}
	if !p.Has(packets.PropReceiveMaximum) || p.ReceiveMax != 7 {
		t.Errorf("receive maximum = %d, want 7", p.ReceiveMax)
	}
	if !p.Has(packets.PropTopicAliasMaximum) || p.TopicAliasMax != 3 {
		t.Errorf("topic alias maximum = %d, want 3", p.TopicAliasMax)
	}
	if !p.Has(packets.PropMaximumPacketSize) || p.MaxPacketSize != 4096 {
		t.Errorf("maximum packet size = %d, want 4096", p.MaxPacketSize)
	}
	if !p.Has(packets.PropSubIDAvailable) || p.SubIDAvail != 1 {
		t.Error("subscription identifiers must be advertised as available")
	}
	// Wildcards, retained and shared subscriptions are all supported, and QoS 2
	// is the default ceiling, so none of those properties may appear.
	for _, id := range []byte{packets.PropWildcardAvailable, packets.PropRetainAvailable,
		packets.PropSharedAvailable, packets.PropMaximumQoS} {
		if p.Has(id) {
			t.Errorf("property %#02x is a default and should be left off", id)
		}
	}
}

func TestV5MaxQoSCapsGrantsAndRejectsPublish(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) { o.MaxQoS = packets.QoS1 })
	c := dialV5(t, b)
	ack := c.mustV5("qos1", true, 0)
	if !ack.Props.Has(packets.PropMaximumQoS) || ack.Props.MaxQoS != packets.QoS1 {
		t.Fatalf("maximum QoS property = %d, want 1", ack.Props.MaxQoS)
	}

	// Asking above the ceiling is granted at the ceiling, not refused.
	if codes := c.v5sub(1, nil, flt("a/b", packets.QoS2)); codes[0] != packets.RGrantedQoS1 {
		t.Errorf("SUBACK code = %#02x, want Granted QoS 1", codes[0])
	}

	// Publishing above it is the client's error: the connection ends with 0x9B.
	c.send(&packets.Publish{Topic: "a/b", QoS: packets.QoS2, PacketID: 5, Payload: []byte("x")})
	d := c.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RQoSNotSupported {
		t.Errorf("disconnect reason = %#02x, want 0x9B", d.ReasonCode)
	}
}

func TestV5AssignsAClientIDWhenAskedFor(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dialV5(t, b)
	ack := c.v5raw(&packets.Connect{ProtocolLevel: byte(packets.V5), KeepAlive: 0})
	if ack.ReasonCode != packets.RSuccess {
		t.Fatalf("an empty client id must be answered with an assigned one, got %#02x", ack.ReasonCode)
	}
	if !ack.Props.Has(packets.PropAssignedClientID) || ack.Props.AssignedClientID == "" {
		t.Fatal("Assigned Client Identifier is missing")
	}
	assigned := ack.Props.AssignedClientID

	// The identifier it was given is the one the broker tracks it by.
	c.v5sub(1, nil, flt("anon/x", packets.QoS0))
	pub := dialV5(t, b)
	pub.mustV5("pub", true, 0)
	pub.send(&packets.Publish{Topic: "anon/x", Payload: []byte("hello")})
	if p := c.firstPublish(); string(p.Payload) != "hello" {
		t.Fatalf("payload = %q", p.Payload)
	}
	if m := b.Metrics(); m.Online != 2 {
		t.Errorf("online = %d, want 2", m.Online)
	}

	// Two anonymous clients must not be handed the same identifier, or the
	// second would take over the first's session.
	other := dialV5(t, b)
	second := other.v5raw(&packets.Connect{ProtocolLevel: byte(packets.V5), KeepAlive: 0})
	if second.ReasonCode != packets.RSuccess {
		t.Fatalf("second anonymous connect refused with %#02x", second.ReasonCode)
	}
	if second.Props.AssignedClientID == assigned {
		t.Errorf("two anonymous clients were both assigned %q", assigned)
	}
}

func TestV5UnsupportedProtocolLevelIsRefusedIn50Encoding(t *testing.T) {
	b := startBroker(t, nil, nil)
	// A client from the future sends a level this broker has never heard of.
	// Its CONNECT is written the old way, because a 5.0 property area would
	// only be invented by a client that can read the answer back.
	c := dial(t, b)
	frame, err := packets.EncodeBytes(&packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: 6, ClientID: "future", KeepAlive: 0,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := c.conn.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The refusal is written the way that client asked to be spoken to, so the
	// reason code and the reason string survive the round trip.
	c.ver = packets.V5
	ack := c.expect(packets.TypeConnack).(*packets.Connack)
	if ack.ReasonCode != packets.RUnsupportedProtocolVersion {
		t.Errorf("reason = %#02x, want 0x84", ack.ReasonCode)
	}
	if ack.Props == nil || ack.Props.ReasonString == "" {
		t.Error("the refusal should say which level was unusable")
	}
	c.expectClosed()
}

func TestV5AuthIsRefusedBecauseNoMethodIsOffered(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dialV5(t, b)
	c.mustV5("auth", true, 0)
	c.send(&packets.Auth{ReasonCode: packets.RReauthAuthenticate})
	d := c.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RBadAuthenticationMethod {
		t.Errorf("reason = %#02x, want 0x8C", d.ReasonCode)
	}
}

// --- session expiry ---------------------------------------------------------

func TestV5SessionExpiryKeepsStateThenTheReaperEndsIt(t *testing.T) {
	st := store.NewMemoryStore()
	b := startBroker(t, st, func(o *broker.Options) { o.ReapInterval = 50 * time.Millisecond })

	sub := dialV5(t, b)
	if ack := sub.v5("away", false, 1); ack.SessionPresent {
		t.Error("a brand new session must not report stored state")
	}
	sub.v5sub(1, nil, flt("q/1", packets.QoS1))
	_ = sub.conn.Close()
	waitUntil(t, func() bool {
		s, ok := st.Get("away")
		return ok && len(s.Subscriptions) == 1
	})

	pub := dialV5(t, b)
	pub.mustV5("pub", true, 0)
	if code := pub.v5publish("q/1", "queued", packets.QoS1, 1, nil); code != packets.RSuccess {
		t.Fatalf("PUBACK code = %#02x, want success", code)
	}

	back := dialV5(t, b)
	ack := back.v5("away", false, 1)
	if !ack.SessionPresent {
		t.Fatal("the session still existed, so the reconnect continues it")
	}
	msg := back.firstPublish()
	if string(msg.Payload) != "queued" {
		t.Fatalf("replayed %q", msg.Payload)
	}
	back.send(&packets.Puback{PacketID: msg.PacketID})
	_ = back.conn.Close()

	// One second of expiry plus a 50ms reap tick: the state has to disappear on
	// its own, without anyone reconnecting.
	waitUntil(t, func() bool {
		_, ok := st.Get("away")
		return !ok
	})
	if m := b.Metrics(); m.ExpiredSessions == 0 {
		t.Error("expired sessions were not counted")
	}
	if n := b.Metrics().Subscriptions; n != 0 {
		t.Errorf("subscriptions = %d, want the expired session's filter withdrawn", n)
	}
}

func TestV5ZeroSessionExpiryEndsTheSessionAtDisconnect(t *testing.T) {
	st := store.NewMemoryStore()
	b := startBroker(t, st, nil)
	c := dialV5(t, b)
	c.mustV5("brief", false, 0) // no Session Expiry property at all
	c.v5sub(1, nil, flt("b/1", packets.QoS1))
	c.disconnect(packets.RNormalDisconnection, nil)
	_ = c.conn.Close()

	waitUntil(t, func() bool { return b.Metrics().Online == 0 })
	if _, ok := st.Get("brief"); ok {
		t.Error("a session with no expiry must not outlive its connection")
	}
	if n := b.Metrics().Subscriptions; n != 0 {
		t.Errorf("subscriptions = %d, want 0", n)
	}
}

func TestV5SessionExpiryIsClampedByTheOperator(t *testing.T) {
	st := store.NewMemoryStore()
	b := startBroker(t, st, func(o *broker.Options) {
		o.SessionExpiryMax = time.Second
		o.ReapInterval = 50 * time.Millisecond
	})
	c := dialV5(t, b)
	c.mustV5("clamped", false, 3600) // asks for an hour
	c.v5sub(1, nil, flt("c/1", packets.QoS1))
	_ = c.conn.Close()

	waitUntil(t, func() bool {
		s, ok := st.Get("clamped")
		return ok && !s.Expiry.IsZero() && time.Until(s.Expiry) < 5*time.Second
	})
	waitUntil(t, func() bool { _, ok := st.Get("clamped"); return !ok })
}

func TestV5CleanStartDiscardsTheStoredSession(t *testing.T) {
	st := store.NewMemoryStore()
	b := startBroker(t, st, nil)

	sub := dialV5(t, b)
	sub.mustV5("temp", false, 600)
	sub.v5sub(1, nil, flt("t/1", packets.QoS1))
	_ = sub.conn.Close()
	waitUntil(t, func() bool { return b.Metrics().Online == 0 })

	pub := dialV5(t, b)
	pub.mustV5("pub", true, 0)
	pub.v5publish("t/1", "waiting", packets.QoS1, 7, nil)

	back := dialV5(t, b)
	ack := back.v5("temp", true, 600)
	if ack.SessionPresent {
		t.Error("Clean Start 1 always reports no session [MQTT-3.1.2-4]")
	}
	back.expectNothing(500 * time.Millisecond)
}

// --- reason codes -----------------------------------------------------------

func TestV5NoMatchingSubscribersIsToldNotSent(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dialV5(t, b)
	c.mustV5("pub", true, 0)

	if code := c.v5publish("nobody/here", "x", packets.QoS1, 1, nil); code != packets.RNoMatchingSubscribers {
		t.Errorf("PUBACK code = %#02x, want 0x10 (no matching subscribers)", code)
	}
	sub := dialV5(t, b)
	sub.mustV5("watch", true, 0)
	sub.v5sub(1, nil, flt("nobody/#", packets.QoS1))
	if code := c.v5publish("nobody/here", "y", packets.QoS1, 2, nil); code != packets.RSuccess {
		t.Errorf("PUBACK code = %#02x, want 0x00 once somebody listens", code)
	}
	// Both messages now reach the subscriber. A QoS 0 publish has no
	// acknowledgement, so the publisher is told nothing about it either way.
	sub.receive("nobody/here", "y")
	c.send(&packets.Publish{Topic: "nobody/here", QoS: packets.QoS0, Payload: []byte("z")})
	sub.receive("nobody/here", "z")
	c.expectNothing(300 * time.Millisecond)
}

func TestV5RefusedPublishesCarryReasonCodes(t *testing.T) {
	acl := loadACL(t, `
{"effect":"deny","user":"dev","action":"publish","topics":["secret/#"]}
{"effect":"allow","user":"dev","action":"publish","topics":["#"]}
`)
	b := startBroker(t, nil, func(o *broker.Options) { o.ACL = acl })
	c := dialV5(t, b)
	c.mustV5As("d1", "dev", true, 0)

	if code := c.v5publish("secret/x", "nope", packets.QoS1, 11, nil); code != packets.RNotAuthorized {
		t.Errorf("QoS 1 PUBACK = %#02x, want 0x87 (not authorized)", code)
	}
	if code := c.v5publish("secret/y", "nope", packets.QoS2, 12, nil); code != packets.RNotAuthorized {
		t.Errorf("QoS 2 PUBREC = %#02x, want 0x87", code)
	}
	// A QoS 0 refusal stays silent: there is no packet to refuse with.
	c.send(&packets.Publish{Topic: "secret/z", Payload: []byte("nope")})

	// An unusable topic name is refused the same way, and the connection lives.
	if code := c.v5publish("bad/+/name", "nope", packets.QoS1, 13, nil); code != packets.RTopicNameInvalid {
		t.Errorf("invalid name PUBACK = %#02x, want 0x90", code)
	}
	if code := c.v5publish("ok/x", "yes", packets.QoS1, 14, nil); code == packets.RNotAuthorized {
		t.Fatal("the allowed channel was refused too")
	}
	if m := b.Metrics(); m.DeniedPublish < 3 {
		t.Errorf("acl_denied_publish = %d, want at least 3", m.DeniedPublish)
	}
}

func TestV5SubscribeAndUnsubscribeReasonCodes(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dialV5(t, b)
	c.mustV5("codes", true, 0)

	codes := c.v5sub(1, nil,
		flt("good/one", packets.QoS2),
		flt("bad##", packets.QoS0),
		flt("good/two", packets.QoS0),
	)
	if codes[0] != packets.RGrantedQoS2 {
		t.Errorf("granted code = %#02x, want 0x02", codes[0])
	}
	if codes[1] != packets.RTopicFilterInvalid {
		t.Errorf("invalid filter code = %#02x, want 0x8F", codes[1])
	}
	if codes[2] != packets.RGrantedQoS0 {
		t.Errorf("granted code = %#02x, want 0x00", codes[2])
	}

	c.send(&packets.Unsubscribe{PacketID: 2, TopicFilters: []string{"good/one", "never/ subscribed"}})
	ua := c.expect(packets.TypeUnsuback).(*packets.Unsuback)
	if ua.ReasonCodes[0] != packets.RSuccess {
		t.Errorf("unsubscribe code = %#02x, want 0x00", ua.ReasonCodes[0])
	}
	if ua.ReasonCodes[1] != packets.RNoSubscriptionExisted {
		t.Errorf("unsubscribe code = %#02x, want 0x11", ua.ReasonCodes[1])
	}
}

// --- wills ------------------------------------------------------------------

func TestV5DisconnectWithWillPublishesAndNormalDisconnectionDoesNot(t *testing.T) {
	b := startBroker(t, nil, nil)
	watch := dialV5(t, b)
	watch.mustV5("watch", true, 0)
	watch.v5sub(1, nil, flt("node/1/status", packets.QoS1))

	goodbye := dialV5(t, b)
	goodbye.v5will("n1", "node/1/status", "bye", 0, 0)
	goodbye.disconnect(packets.RDisconnectWithWill, nil)
	_ = goodbye.conn.Close()
	will := watch.firstPublish()
	if string(will.Payload) != "bye" {
		t.Fatalf("will payload = %q", will.Payload)
	}
	watch.send(&packets.Puback{PacketID: will.PacketID})

	silent := dialV5(t, b)
	silent.v5will("n2", "node/1/status", "should-not-appear", 0, 0)
	silent.disconnect(packets.RNormalDisconnection, nil)
	_ = silent.conn.Close()
	watch.expectNothing(700 * time.Millisecond)
}

func TestV5WillDelayHoldsTheWillBack(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) { o.ReapInterval = 50 * time.Millisecond })
	watch := dialV5(t, b)
	watch.mustV5("watch", true, 0)
	watch.v5sub(1, nil, flt("node/2/status", packets.QoS1))

	node := dialV5(t, b)
	// Will delay 1s, session outlives the connection for a minute.
	node.v5will("delayed", "node/2/status", "gone", 1, 60)
	_ = node.conn.Close()

	// The session survives, so nothing may appear yet.
	watch.expectNothing(300 * time.Millisecond)

	p := watch.firstPublish()
	if string(p.Payload) != "gone" {
		t.Fatalf("will payload = %q", p.Payload)
	}
	if p.QoS != packets.QoS1 {
		t.Errorf("will QoS = %d, want 1", p.QoS)
	}
}

func TestV5ReconnectInsideTheWillDelayWithdrawsIt(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) { o.ReapInterval = 50 * time.Millisecond })
	watch := dialV5(t, b)
	watch.mustV5("watch", true, 0)
	watch.v5sub(1, nil, flt("node/3/status", packets.QoS1))

	node := dialV5(t, b)
	node.v5will("flapping", "node/3/status", "should-not-appear", 2, 60)
	_ = node.conn.Close()

	// Reconnect well inside the delay, continuing the same session.
	back := dialV5(t, b)
	if ack := back.v5("flapping", false, 60); !ack.SessionPresent {
		t.Fatal("the session is still alive, so the reconnect must continue it")
	}
	_ = back.conn.Close()

	// Long after the original delay: the will was withdrawn, and the second
	// connection brought no new one.
	watch.expectNothing(3 * time.Second)
}

func TestV5CleanStartTakeoverPublishesThePendingWill(t *testing.T) {
	b := startBroker(t, nil, nil)
	watch := dialV5(t, b)
	watch.mustV5("watch", true, 0)
	watch.v5sub(1, nil, flt("node/4/status", packets.QoS1))

	first := dialV5(t, b)
	first.v5will("taker", "node/4/status", "old-session-ends", 60, 60)
	_ = first.conn.Close()
	watch.expectNothing(300 * time.Millisecond)

	// Same client id, Clean Start 1: the old Session ends, so its will goes out
	// now rather than waiting for a delay that no longer applies.
	second := dialV5(t, b)
	ack := second.v5("taker", true, 60)
	if ack.SessionPresent {
		t.Error("Clean Start 1 must report no session")
	}
	p := watch.firstPublish()
	if string(p.Payload) != "old-session-ends" {
		t.Fatalf("will payload = %q", p.Payload)
	}
}

// --- server-initiated disconnects -------------------------------------------

func TestV5KeepaliveTimeoutAnnounces0x8D(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dialV5(t, b)
	c.send(&packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: byte(packets.V5),
		ClientID: "idle", KeepAlive: 1,
	})
	c.expect(packets.TypeConnack)

	d := c.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RKeepAliveTimeout {
		t.Errorf("reason = %#02x, want 0x8D", d.ReasonCode)
	}
	c.expectClosed()
}

func TestV5TakeoverAnnounces0x8E(t *testing.T) {
	b := startBroker(t, nil, nil)
	old := dialV5(t, b)
	old.mustV5("same", true, 0)

	fresh := dialV5(t, b)
	fresh.mustV5("same", true, 0)

	d := old.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RSessionTakenOver {
		t.Errorf("reason = %#02x, want 0x8E", d.ReasonCode)
	}
	old.expectClosed()
}

func TestV5MalformedAndProtocolErrorsAreToldApart(t *testing.T) {
	b := startBroker(t, nil, nil)

	m := dialV5(t, b)
	m.mustV5("malformed", true, 0)
	if _, err := m.conn.Write([]byte{0x3E, 0x02, 0x00, 0x01}); err != nil { // PUBLISH with QoS 3
		t.Fatalf("raw write: %v", err)
	}
	d := m.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RMalformedPacket {
		t.Errorf("malformed reason = %#02x, want 0x81", d.ReasonCode)
	}

	p := dialV5(t, b)
	p.mustV5("protocol", true, 0)
	// A SUBSCRIBE whose option byte carries the reserved QoS value 3. These
	// bytes parse cleanly but break a rule the spec names, which is why the
	// encoder refuses to build them and the test has to write them out.
	raw := []byte{byte(packets.TypeSubscribe)<<4 | 0x02, 9, 0x00, 0x01, 0x00, 0x00, 0x03, 'a', '/', 'b', 0x03}
	if _, err := p.conn.Write(raw); err != nil {
		t.Fatalf("raw write: %v", err)
	}
	d = p.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RProtocolError {
		t.Errorf("reserved subscription QoS reason = %#02x, want 0x82", d.ReasonCode)
	}
}

func TestV5SecondConnectOnAnOpenSessionIsAProtocolError(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dialV5(t, b)
	c.mustV5("twice", true, 0)
	c.send(&packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: byte(packets.V5),
		ClientID: "twice", KeepAlive: 60,
	})
	d := c.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RProtocolError {
		t.Errorf("reason = %#02x, want 0x82", d.ReasonCode)
	}
}

func TestV5ShutdownTellsPeersWhy(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dialV5(t, b)
	c.mustV5("bye", true, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	d := c.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RServerShuttingDown {
		t.Errorf("reason = %#02x, want 0x8B", d.ReasonCode)
	}
}

// --- retained messages ------------------------------------------------------

// retained publishes with the RETAIN flag set in the fixed header, which is the
// only way to ask the broker to store a message for subscribers that arrive
// later.
func (c *client) v5retain(topic, payload string, qos byte, id uint16) byte {
	c.t.Helper()
	return c.v5send(&packets.Publish{
		Topic: topic, QoS: qos, PacketID: id,
		Payload: []byte(payload), Retain: true,
	})
}

func TestV5RetainedMessageLifecycle(t *testing.T) {
	b := startBroker(t, nil, nil)

	pub := dialV5(t, b)
	pub.mustV5("r-pub", true, 0)

	live := dialV5(t, b)
	live.mustV5("r-live", true, 0)
	live.subscribe(1, flt("device/1/state", packets.QoS1))

	if code := pub.v5retain("device/1/state", "on", packets.QoS1, 2); code != packets.RSuccess {
		t.Fatalf("retained publish answered %#02x (%s)", code, packets.ReasonName(code))
	}
	forwarded := live.firstPublish()
	if forwarded.Retain {
		t.Error("a forwarded publish clears RETAIN: the flag was a promise to the broker, not to the next subscriber")
	}
	live.send(&packets.Puback{PacketID: forwarded.PacketID})

	late := dialV5(t, b)
	late.mustV5("r-late", true, 0)
	late.subscribe(3, flt("device/+/state", packets.QoS1))
	replay := late.firstPublish()
	if !replay.Retain {
		t.Error("a replayed retained message arrives with RETAIN set [MQTT-3.3.1-3]")
	}
	if replay.Topic != "device/1/state" || string(replay.Payload) != "on" {
		t.Errorf("replay = %q/%q, want device/1/state/on", replay.Topic, replay.Payload)
	}
	if replay.QoS != packets.QoS1 {
		t.Errorf("replay qos = %d, want the QoS granted to this subscriber", replay.QoS)
	}
	late.send(&packets.Puback{PacketID: replay.PacketID})

	if m := b.Metrics(); m.Retained != 1 {
		t.Errorf("retained_messages = %d, want 1", m.Retained)
	}

	// An empty retained payload deletes the stored message [MQTT-3.3.1-8] but is
	// still an Application Message, so the subscribers present now do see it.
	pub.v5retain("device/1/state", "", packets.QoS0, 0)
	if p := live.firstPublish(); len(p.Payload) != 0 {
		t.Errorf("live subscriber got %q, want the empty publish itself", p.Payload)
	}
	if p := late.firstPublish(); len(p.Payload) != 0 {
		t.Errorf("late subscriber got %q, want the empty publish itself", p.Payload)
	}
	if m := b.Metrics(); m.Retained != 0 {
		t.Errorf("retained_messages = %d after the empty publish, want 0", m.Retained)
	}

	gone := dialV5(t, b)
	gone.mustV5("r-gone", true, 0)
	gone.subscribe(4, flt("device/#", packets.QoS1))
	gone.expectNothing(600 * time.Millisecond)
}

func TestV5RetainHandlingDecidesTheReplay(t *testing.T) {
	b := startBroker(t, nil, nil)
	pub := dialV5(t, b)
	pub.mustV5("h-pub", true, 0)
	pub.v5retain("h/1", "kept", packets.QoS0, 0)

	// Handling 2 never sends retained messages, even for a brand new
	// subscription.
	never := dialV5(t, b)
	never.mustV5("h-never", true, 0)
	never.v5sub(1, nil, packets.Subscription{TopicFilter: "h/#", MaxQoS: packets.QoS0, RetainHandling: 2})
	never.expectNothing(500 * time.Millisecond)

	// Handling 1 means "only when this subscription is new", so the repeat of an
	// existing filter is silent while the default handling 0 replays again
	// [MQTT-3.3.1-9, -10, -11].
	once := dialV5(t, b)
	once.mustV5("h-once", true, 0)
	once.v5sub(2, nil, packets.Subscription{TopicFilter: "h/#", MaxQoS: packets.QoS0, RetainHandling: 1})
	once.receive("h/1", "kept")
	once.v5sub(3, nil, packets.Subscription{TopicFilter: "h/#", MaxQoS: packets.QoS0, RetainHandling: 1})
	once.expectNothing(500 * time.Millisecond)
	once.v5sub(4, nil, packets.Subscription{TopicFilter: "h/#", MaxQoS: packets.QoS0})
	once.receive("h/1", "kept")
}

func TestV5NoLocalSkipsThePublisherItself(t *testing.T) {
	b := startBroker(t, nil, nil)

	echo := dialV5(t, b)
	echo.mustV5("nl-echo", true, 0)
	echo.v5sub(1, nil, packets.Subscription{TopicFilter: "nl/#", MaxQoS: packets.QoS0, NoLocal: true})

	other := dialV5(t, b)
	other.mustV5("nl-other", true, 0)
	other.v5sub(2, nil, packets.Subscription{TopicFilter: "nl/#", MaxQoS: packets.QoS0})

	// The subscription is installed and does work — it just does not echo.
	echo.publishQoS0("nl/mine", "hello")
	other.receive("nl/mine", "hello")
	echo.expectNothing(500 * time.Millisecond)

	other.publishQoS0("nl/yours", "reply")
	echo.receive("nl/yours", "reply")
}

func TestV5RetainAsPublishedKeepsTheFlagOnward(t *testing.T) {
	b := startBroker(t, nil, nil)
	pub := dialV5(t, b)
	pub.mustV5("rap-pub", true, 0)

	plain := dialV5(t, b)
	plain.mustV5("rap-plain", true, 0)
	plain.v5sub(1, nil, packets.Subscription{TopicFilter: "rap/#", MaxQoS: packets.QoS0})

	kept := dialV5(t, b)
	kept.mustV5("rap-kept", true, 0)
	kept.v5sub(2, nil, packets.Subscription{TopicFilter: "rap/#", MaxQoS: packets.QoS0, RetainAsPublished: true})

	pub.v5retain("rap/1", "x", packets.QoS0, 0)

	if p := plain.firstPublish(); p.Retain {
		t.Error("without Retain As Published the flag stops at this broker [MQTT-3.3.1-12]")
	}
	if p := kept.firstPublish(); !p.Retain {
		t.Error("Retain As Published asks that the flag survive forwarding [MQTT-3.3.1-13]")
	}
}

func TestV5SubscriptionIdentifierTravelsOnDeliveries(t *testing.T) {
	b := startBroker(t, nil, nil)

	asked := dialV5(t, b)
	asked.mustV5("sid-asked", true, 0)
	props := &packets.Properties{}
	props.AddSubscriptionID(7)
	asked.v5sub(1, props, packets.Subscription{TopicFilter: "sid/#", MaxQoS: packets.QoS0})

	quiet := dialV5(t, b)
	quiet.mustV5("sid-quiet", true, 0)
	quiet.v5sub(2, nil, packets.Subscription{TopicFilter: "sid/#", MaxQoS: packets.QoS0})

	quiet.publishQoS0("sid/1", "x")

	got := asked.firstPublish()
	if got.Props == nil || len(got.Props.SubscriptionIDs) != 1 || got.Props.SubscriptionIDs[0] != 7 {
		t.Errorf("delivered subscription identifiers = %v, want [7]", idsOf(got))
	}
	// A subscriber that did not ask for one is not stamped with it.
	other := quiet.firstPublish()
	if other.Props != nil && other.Props.Has(packets.PropSubscriptionID) {
		t.Error("a subscription identifier appeared for a subscriber that never asked")
	}
}

func idsOf(p *packets.Publish) []int {
	if p.Props == nil {
		return nil
	}
	return p.Props.SubscriptionIDs
}

// --- topic alias ------------------------------------------------------------

func aliased(n uint16, topic, payload string, qos byte, id uint16) *packets.Publish {
	p := &packets.Publish{
		Topic: topic, QoS: qos, PacketID: id,
		Payload: []byte(payload), Props: &packets.Properties{},
	}
	p.Props.SetTopicAlias(n)
	return p
}

func TestV5InboundTopicAliasIsScopedToTheConnection(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) { o.TopicAliasMax = 4 })

	sub := dialV5(t, b)
	sub.mustV5("ta-sub", true, 0)
	sub.subscribe(1, flt("ta/#", packets.QoS0))

	pub := dialV5(t, b)
	ack := pub.mustV5("ta-pub", true, 0)
	if ack.Props == nil || ack.Props.TopicAliasMax != 4 {
		t.Fatalf("CONNACK Maximum Topic Alias = %v, want 4", ack.Props)
	}

	// The first use of an alias travels with the name and teaches the broker it.
	pub.v5send(aliased(4, "ta/one", "first", packets.QoS0, 0))
	sub.receive("ta/one", "first")

	// After that the name may be dropped entirely, which is the point of the
	// alias: a mapping lives in the Network Connection, not in the Session.
	pub.v5send(aliased(4, "", "second", packets.QoS0, 0))
	sub.receive("ta/one", "second")

	// A replacement for the same alias is allowed and takes effect at once.
	pub.v5send(aliased(4, "ta/two", "renamed", packets.QoS0, 0))
	sub.receive("ta/two", "renamed")
	pub.v5send(aliased(4, "", "on-two", packets.QoS0, 0))
	sub.receive("ta/two", "on-two")

	// Above the advertised maximum is 0x94 Topic Alias invalid, not a guess at
	// what the client meant.
	pub.send(aliased(5, "ta/three", "nope", packets.QoS0, 0))
	d := pub.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RTopicAliasInvalid {
		t.Errorf("reason = %#02x, want 0x94", d.ReasonCode)
	}

	// Alias 0 is reserved.
	zero := dialV5(t, b)
	zero.mustV5("ta-zero", true, 0)
	zero.send(aliased(0, "ta/x", "nope", packets.QoS0, 0))
	d = zero.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RTopicAliasInvalid {
		t.Errorf("alias 0 reason = %#02x, want 0x94", d.ReasonCode)
	}

	// A brand new connection has no mappings to inherit, and a name-less packet
	// pointing at one is a protocol error rather than an invalid alias.
	fresh := dialV5(t, b)
	fresh.mustV5("ta-fresh", true, 0)
	fresh.send(aliased(4, "", "orphan", packets.QoS0, 0))
	d = fresh.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RProtocolError {
		t.Errorf("unknown alias reason = %#02x, want 0x82", d.ReasonCode)
	}

	// Every one of the three above decoded cleanly and then broke a rule, so all
	// three belong in the same counter as the ones the codec refused to build.
	if m := b.Metrics(); m.ProtocolErrors != 3 {
		t.Errorf("protocol errors = %d, want the 3 this test provoked", m.ProtocolErrors)
	}
}

func TestV5OutboundTopicAliasStopsAtTheClientsMaximum(t *testing.T) {
	b := startBroker(t, nil, nil)

	c := dialV5(t, b)
	ask := &packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: byte(packets.V5),
		ClientID: "ta-out", KeepAlive: 120, Props: &packets.Properties{},
	}
	// One alias slot, which the broker must not exceed.
	ask.Props.SetTopicAliasMax(1)
	c.v5raw(ask)
	c.subscribe(1, flt("out/#", packets.QoS0))

	pub := dialV5(t, b)
	pub.mustV5("ta-out-pub", true, 0)

	pub.publishQoS0("out/one", "a")
	first := c.firstPublish()
	if first.Topic != "out/one" {
		t.Fatalf("the message that establishes an alias must carry the name, got %q", first.Topic)
	}
	if first.Props == nil || !first.Props.Has(packets.PropTopicAlias) {
		t.Fatal("the broker advertised no alias mapping on first use")
	}
	alias := first.Props.TopicAlias

	pub.publishQoS0("out/one", "b")
	second := c.firstPublish()
	if second.Topic != "" {
		t.Errorf("repeat of an aliased topic should drop the name, got %q", second.Topic)
	}
	if second.Props.TopicAlias != alias {
		t.Errorf("alias = %d, want the same %d", second.Props.TopicAlias, alias)
	}
	if string(second.Payload) != "b" {
		t.Errorf("payload = %q", second.Payload)
	}

	// The single slot is taken, so a second topic name has to travel in full.
	pub.publishQoS0("out/two", "c")
	third := c.firstPublish()
	if third.Topic != "out/two" {
		t.Errorf("with the peer's alias budget used up, the name must be sent, got %q", third.Topic)
	}
	if third.Props != nil && third.Props.Has(packets.PropTopicAlias) {
		t.Error("the broker opened a second alias past the client's Maximum Topic Alias of 1")
	}
}

// --- receive maximum --------------------------------------------------------

func TestV5ReceiveMaximumStopsInboundQoS2(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) { o.ReceiveMax = 2 })

	c := dialV5(t, b)
	ack := c.mustV5("rx-in", true, 0)
	if ack.Props.ReceiveMax != 2 {
		t.Fatalf("CONNACK Receive Maximum = %d, want 2", ack.Props.ReceiveMax)
	}

	// Two QoS 2 messages may be outstanding; the third is refused before the
	// first two are committed with a PUBREL.
	for _, id := range []uint16{1, 2} {
		c.send(&packets.Publish{Topic: "rx/1", QoS: packets.QoS2, PacketID: id, Payload: []byte("x")})
		rec := c.expect(packets.TypePubrec).(*packets.Pubrec)
		if rec.ReasonCode != packets.RSuccess {
			t.Fatalf("PUBREC for id %d answered %#02x", id, rec.ReasonCode)
		}
	}
	c.send(&packets.Publish{Topic: "rx/1", QoS: packets.QoS2, PacketID: 3, Payload: []byte("x")})
	d := c.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RReceiveMaximumExceeded {
		t.Errorf("reason = %#02x, want 0x93", d.ReasonCode)
	}
}

func TestV5PeerReceiveMaximumBoundsOutboundWindow(t *testing.T) {
	// The harness inflight window is 4; the peer says it can only hold one
	// unacknowledged message, so that is the tighter promise and the broker
	// must keep it. The retry timer is slowed so the silence below measures the
	// window, not a DUP re-send.
	b := startBroker(t, nil, func(o *broker.Options) {
		o.InflightWindow = 4
		o.RetryInterval = 5 * time.Second
	})

	sub := dialV5(t, b)
	ask := &packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: byte(packets.V5),
		ClientID: "rx-out", KeepAlive: 120, Props: &packets.Properties{},
	}
	ask.Props.SetReceiveMax(1)
	sub.v5raw(ask)
	sub.subscribe(1, flt("rx/#", packets.QoS1))

	pub := dialV5(t, b)
	pub.mustV5("rx-pub", true, 0)
	pub.publishQoS1(7, "rx/1", "one")
	pub.publishQoS1(8, "rx/2", "two")

	first := sub.firstPublish()
	if string(first.Payload) != "one" {
		t.Fatalf("first delivery = %q", first.Payload)
	}
	// Nothing else may appear while the one slot is held.
	sub.expectNothing(600 * time.Millisecond)

	sub.send(&packets.Puback{PacketID: first.PacketID})
	sub.receive("rx/2", "two")
}

// --- maximum packet size ----------------------------------------------------

func TestV5MaximumPacketSizeIsAdvertisedAndEnforced(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) { o.MaxPacketSize = 64 })

	c := dialV5(t, b)
	ack := c.mustV5("size-in", true, 0)
	if ack.Props.MaxPacketSize != 64 {
		t.Fatalf("CONNACK Maximum Packet Size = %d, want 64", ack.Props.MaxPacketSize)
	}

	c.publishQoS0("small", "fits")
	c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	big := make([]byte, 300)
	for i := range big {
		big[i] = 'x'
	}
	frame, err := packets.EncodeBytesVersion(packets.V5, &packets.Publish{Topic: "big", QoS: packets.QoS0, Payload: big})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := c.conn.Write(frame); err != nil {
		t.Fatalf("raw write: %v", err)
	}
	d := c.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RPacketTooLarge {
		t.Errorf("reason = %#02x, want 0x95", d.ReasonCode)
	}
}

func TestV5MessagesTooBigForThePeerAreDropped(t *testing.T) {
	b := startBroker(t, nil, nil)

	sub := dialV5(t, b)
	ask := &packets.Connect{
		ProtocolName: packets.ProtocolName, ProtocolLevel: byte(packets.V5),
		ClientID: "size-out", KeepAlive: 120, Props: &packets.Properties{},
	}
	ask.Props.SetMaxPacketSize(64)
	sub.v5raw(ask)
	sub.subscribe(1, flt("big/#", packets.QoS1))

	pub := dialV5(t, b)
	pub.mustV5("size-pub", true, 0)

	pub.publishQoS1(9, "big/1", "small enough")
	sub.receive("big/1", "small enough")

	pub.publishQoS1(10, "big/2", string(make([]byte, 400)))
	// The oversized message is forgotten as if it had been delivered; the
	// connection stays up and the queue keeps moving.
	sub.expectNothing(700 * time.Millisecond)
	if m := b.Metrics(); m.TooLargeForPeer != 1 {
		t.Errorf("dropped_over_peer_max_packet_size = %d, want 1", m.TooLargeForPeer)
	}

	pub.publishQoS1(11, "big/3", "after the drop")
	sub.receive("big/3", "after the drop")
}

// --- message expiry ---------------------------------------------------------

func TestV5MessageExpiryCountsDownAcrossTheBroker(t *testing.T) {
	b := startBroker(t, nil, nil)

	sub := dialV5(t, b)
	sub.mustV5("exp-sub", true, 0)
	sub.subscribe(1, flt("exp/#", packets.QoS1))

	pub := dialV5(t, b)
	pub.mustV5("exp-pub", true, 0)

	props := &packets.Properties{}
	props.SetMessageExpiry(60)
	pub.v5publish("exp/1", "kept", packets.QoS1, 2, props)

	got := sub.firstPublish()
	if got.Props == nil || !got.Props.Has(packets.PropMessageExpiry) {
		t.Fatal("a message with an expiry must arrive with one")
	}
	// The peer is told what is left, not the publisher's original number: a
	// value handed on unchanged would restart the clock at every hop
	// [MQTT-3.3.2-6].
	if left := got.Props.MessageExpiry; left == 0 || left > 60 {
		t.Errorf("Message Expiry Interval = %d, want what is left of 60", left)
	}
	sub.send(&packets.Puback{PacketID: got.PacketID})

	// A message with no expiry gets no property, which is how a client learns
	// it will never time out.
	pub.publishQoS1(3, "exp/2", "forever")
	quiet := sub.firstPublish()
	if quiet.Props != nil && quiet.Props.Has(packets.PropMessageExpiry) {
		t.Error("the broker invented a Message Expiry Interval")
	}
	sub.send(&packets.Puback{PacketID: quiet.PacketID})
}

func TestV5ExpiredMessageNeverReachesASubscriber(t *testing.T) {
	st := store.NewMemoryStore()
	b := startBroker(t, st, func(o *broker.Options) { o.ReapInterval = 100 * time.Millisecond })

	// An offline persistent session is where a message waits, so this is the
	// case where the countdown actually matters. The Session Expiry Interval
	// has to be non-zero or there would be no session to queue into.
	away := dialV5(t, b)
	away.mustV5("gone", false, 3600)
	away.subscribe(1, flt("late/#", packets.QoS1))
	away.disconnect(packets.RNormalDisconnection, nil)
	waitUntil(t, func() bool { return b.Metrics().Online == 0 })

	pub := dialV5(t, b)
	pub.mustV5("late-pub", true, 0)
	props := &packets.Properties{}
	props.SetMessageExpiry(1)
	pub.v5publish("late/1", "too slow", packets.QoS1, 2, props)
	pub.publishQoS1(3, "late/2", "still valid")

	time.Sleep(1600 * time.Millisecond)

	back := dialV5(t, b)
	ack := back.mustV5("gone", false, 3600)
	if !ack.SessionPresent {
		t.Fatal("the session should still be waiting")
	}
	got := back.firstPublish()
	if got.Topic != "late/2" || string(got.Payload) != "still valid" {
		t.Errorf("replayed %q/%q, want only the unexpired message", got.Topic, got.Payload)
	}
	back.send(&packets.Puback{PacketID: got.PacketID})
	back.expectNothing(600 * time.Millisecond)
	if m := b.Metrics(); m.ExpiredMessages == 0 {
		t.Error("the expired message was not counted")
	}
}

func TestV5RetainedMessageAgesOut(t *testing.T) {
	b := startBroker(t, nil, func(o *broker.Options) { o.ReapInterval = 100 * time.Millisecond })

	pub := dialV5(t, b)
	pub.mustV5("re-pub", true, 0)
	props := &packets.Properties{}
	props.SetMessageExpiry(1)
	// Nothing is subscribed to re/1 yet, so 0x10 "no matching subscribers" is as
	// correct an answer as 0x00 — the retained store is not a subscriber.
	if code := pub.v5send(&packets.Publish{
		Topic: "re/1", QoS: packets.QoS1, PacketID: 1,
		Payload: []byte("brief"), Retain: true, Props: props,
	}); code != packets.RSuccess && code != packets.RNoMatchingSubscribers {
		t.Fatalf("retained publish answered %#02x (%s)", code, packets.ReasonName(code))
	}

	if m := b.Metrics(); m.Retained != 1 {
		t.Fatalf("retained_messages = %d, want 1", m.Retained)
	}

	// The reaper takes it off the shelf once its own interval has run out: the
	// topic simply holds nothing again.
	time.Sleep(1500 * time.Millisecond)
	if m := b.Metrics(); m.Retained != 0 {
		t.Fatalf("retained_messages = %d, want the reaper to have pruned it", m.Retained)
	}

	late := dialV5(t, b)
	late.mustV5("re-late", true, 0)
	late.subscribe(2, flt("re/#", packets.QoS0))
	late.expectNothing(500 * time.Millisecond)
}

// --- shared subscriptions ---------------------------------------------------

// drain reads n deliveries and returns their payloads, acknowledging as it goes
// so the retry timer stays quiet.
func (c *client) drain(n int) []string {
	c.t.Helper()
	out := make([]string, 0, n)
	for range n {
		p := c.firstPublish()
		if p.QoS == packets.QoS1 {
			c.send(&packets.Puback{PacketID: p.PacketID})
		}
		out = append(out, string(p.Payload))
	}
	return out
}

func shared(filter string, qos byte) packets.Subscription {
	return packets.Subscription{TopicFilter: "$share/g1/" + filter, MaxQoS: qos}
}

func TestV5SharedSubscriptionSplitsTheLoad(t *testing.T) {
	b := startBroker(t, nil, nil)

	a := dialV5(t, b)
	a.mustV5("sh-a", true, 0)
	a.v5sub(1, nil, shared("cmd/#", packets.QoS1))

	c := dialV5(t, b)
	c.mustV5("sh-c", true, 0)
	c.v5sub(2, nil, shared("cmd/#", packets.QoS1))

	// An ordinary subscription to the same topics is separate from the group and
	// is served every message.
	watch := dialV5(t, b)
	watch.mustV5("sh-watch", true, 0)
	watch.subscribe(3, flt("cmd/#", packets.QoS1))

	pub := dialV5(t, b)
	pub.mustV5("sh-pub", true, 0)
	for i := 1; i <= 4; i++ {
		pub.publishQoS1(uint16(10+i), "cmd/1", string(rune('0'+i)))
	}

	// One copy per message, shared between the group members, rotating between
	// them rather than piling on one consumer.
	gotA := a.drain(2)
	gotC := c.drain(2)
	if len(gotA) != 2 || len(gotC) != 2 {
		t.Fatalf("group members got %v and %v, want two each", gotA, gotC)
	}
	if strings.Join(gotA, "") != "13" || strings.Join(gotC, "") != "24" {
		t.Errorf("rotation = %v / %v, want [1 3] and [2 4]", gotA, gotC)
	}
	if all := watch.drain(4); strings.Join(all, "") != "1234" {
		t.Errorf("non-shared subscriber got %v, want every message", all)
	}

	// The delivery carries the topic it was published to, never the shared
	// filter: the "$share/g1" parts do not take part in matching.
	if m := b.Metrics(); m.Subscriptions != 3 {
		t.Errorf("subscriptions = %d, want 3", m.Subscriptions)
	}
}

func TestV5SharedMembersKeepTheirOwnGrantedQoS(t *testing.T) {
	b := startBroker(t, nil, nil)

	slow := dialV5(t, b)
	slow.mustV5("qos-slow", true, 0)
	slow.v5sub(1, nil, shared("q/#", packets.QoS0))

	fast := dialV5(t, b)
	fast.mustV5("qos-fast", true, 0)
	fast.v5sub(2, nil, shared("q/#", packets.QoS1))

	pub := dialV5(t, b)
	pub.mustV5("qos-pub", true, 0)

	// Two messages, one to each member: the group's choice is per message, the
	// QoS is per subscriber [MQTT-4.8.2-3].
	pub.publishQoS1(3, "q/1", "one")
	pub.publishQoS1(4, "q/2", "two")

	first := slow.firstPublish()
	if first.QoS != packets.QoS0 {
		t.Errorf("the QoS 0 member was served at %d", first.QoS)
	}
	second := fast.firstPublish()
	if second.QoS != packets.QoS1 {
		t.Errorf("the QoS 1 member was served at %d", second.QoS)
	}
	fast.send(&packets.Puback{PacketID: second.PacketID})
}

func TestV5SharedSubscriptionsAreAuthorizedByTheirFilter(t *testing.T) {
	// The shipped style of rule talks about topics, not about the "$share"
	// wrapper, so the wrapper is taken off before the file is consulted —
	// otherwise every shared subscription would be refused as an unknown topic
	// space.
	acl := loadACL(t, `
{"effect":"allow","user":"worker","action":"subscribe","topics":["jobs/#"]}
{"effect":"deny","user":"nose","action":"subscribe","topics":["jobs/#"]}
{"effect":"allow","user":"bot","action":"publish","topics":["jobs/#"]}
`)
	b := startBroker(t, nil, func(o *broker.Options) { o.ACL = acl })

	worker := dialV5(t, b)
	worker.mustV5As("w1", "worker", true, 0)
	if codes := worker.v5sub(1, nil, shared("jobs/#", packets.QoS1)); codes[0] != packets.QoS1 {
		t.Errorf("granted qos = %d, want 1", codes[0])
	}

	blocked := dialV5(t, b)
	blocked.mustV5As("n1", "nose", true, 0)
	if codes := blocked.v5sub(2, nil, shared("jobs/#", packets.QoS1)); codes[0] != packets.RNotAuthorized {
		t.Errorf("reason = %#02x, want 0x87 not authorized", codes[0])
	}

	// A shared subscription inherits the filter's matching, and a shared filter
	// is not a topic name: the message arrives under its published name.
	pub := dialV5(t, b)
	pub.mustV5As("p1", "bot", true, 0)
	pub.publishQoS1(3, "jobs/42", "work")
	worker.receive("jobs/42", "work")
}

func TestV5SharedSubscriptionsRejectMalformedFilters(t *testing.T) {
	b := startBroker(t, nil, nil)
	c := dialV5(t, b)
	c.mustV5("sh-bad", true, 0)

	codes := c.v5sub(1, nil,
		packets.Subscription{TopicFilter: "$share//cmd", MaxQoS: packets.QoS0},
		packets.Subscription{TopicFilter: "$share/g1", MaxQoS: packets.QoS0},
		packets.Subscription{TopicFilter: "$share/g+/cmd", MaxQoS: packets.QoS0},
	)
	for i, code := range codes {
		if code != packets.RTopicFilterInvalid {
			t.Errorf("malformed filter %d answered %#02x, want 0x8F", i, code)
		}
	}
	if m := b.Metrics(); m.Subscriptions != 0 {
		t.Errorf("subscriptions = %d, want none installed", m.Subscriptions)
	}

	// No Local on a shared subscription is not a bad request but a broken
	// conversation: the specification calls it a Protocol Error, so the whole
	// packet goes and the connection with it [MQTT-3.8.3-4].
	strict := dialV5(t, b)
	strict.mustV5("sh-nl", true, 0)
	strict.send(&packets.Subscribe{PacketID: 2, Subscriptions: []packets.Subscription{
		{TopicFilter: "$share/g1/cmd/#", MaxQoS: packets.QoS0, NoLocal: true},
	}})
	d := strict.expect(packets.TypeDisconnect).(*packets.Disconnect)
	if d.ReasonCode != packets.RProtocolError {
		t.Errorf("No Local on a shared filter answered %#02x, want 0x82", d.ReasonCode)
	}
	if m := b.Metrics(); m.ProtocolErrors == 0 {
		t.Error("the protocol error was not counted")
	}
}

func TestV5SharedSubscriptionReplayAndDetach(t *testing.T) {
	b := startBroker(t, nil, nil)

	pub := dialV5(t, b)
	pub.mustV5("sp-pub", true, 0)
	pub.v5retain("sp/1", "waiting", packets.QoS0, 0)

	// A shared subscription is sent no retained messages when it is first made.
	group := dialV5(t, b)
	group.mustV5("sp-group", true, 0)
	group.v5sub(1, nil, shared("sp/#", packets.QoS0))
	group.expectNothing(500 * time.Millisecond)

	// Messages published afterwards do reach it.
	pub.publishQoS0("sp/2", "live")
	group.receive("sp/2", "live")

	// Unsubscribing with the full shared filter detaches this session, and with
	// no member left the group holds nothing at all.
	group.send(&packets.Unsubscribe{PacketID: 2, TopicFilters: []string{"$share/g1/sp/#"}})
	group.expect(packets.TypeUnsuback)
	pub.publishQoS0("sp/3", "gone")
	group.expectNothing(500 * time.Millisecond)
	if m := b.Metrics(); m.Subscriptions != 0 {
		t.Errorf("subscriptions = %d after the unsubscribe, want 0", m.Subscriptions)
	}
}
