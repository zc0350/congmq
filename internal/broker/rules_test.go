package broker_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/rules"
	"github.com/zc0350/congmq/internal/store"
)

// Digests computed outside the Go code (Node's crypto).
const (
	dashboardSha256 = "c45c09aa5760a3562c35b01e8b6351b79bde1d51c3af408ddc92c9523328b9de" // sha256("c0ng-2026" + "dashboard")
	deviceMd5       = "c11fd454b6857cea90e41052b5f923e2"                                 // md5("aaaaabcde" + "d3v1c3")
	wrongDigest     = "0000000000000000000000000000000000000000000000000000000000000000"
)

// ruleFile writes a rule file, so a test can state its rules the way an
// operator would.
func ruleFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func loadAuth(t *testing.T, content string) *rules.Authenticator {
	t.Helper()
	a, err := rules.LoadAuth(ruleFile(t, "auth.jsonl", content))
	if err != nil {
		t.Fatalf("LoadAuth: %v", err)
	}
	return a
}

func loadACL(t *testing.T, content string) *rules.ACL {
	t.Helper()
	a, err := rules.LoadACL(ruleFile(t, "acl.jsonl", content))
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	return a
}

// connectAs sends a CONNECT with credentials and hands back whatever CONNACK
// arrives, including a refusal.
func (c *client) connectAs(id string, clean bool, username, password string) *packets.Connack {
	c.t.Helper()
	c.id = id
	c.send(&packets.Connect{
		ProtocolName:  packets.ProtocolName,
		ProtocolLevel: packets.ProtocolLevel,
		ClientID:      id,
		CleanSession:  clean,
		KeepAlive:     120,
		HasUsername:   username != "",
		Username:      username,
		HasPassword:   password != "",
		Password:      []byte(password),
	})
	ack, ok := c.expect(packets.TypeConnack).(*packets.Connack)
	if !ok {
		c.t.Fatalf("expected CONNACK")
	}
	return ack
}

// connectWill connects a client carrying a last will.
func (c *client) connectWill(id, username, willTopic, willPayload string) *packets.Connack {
	c.t.Helper()
	c.id = id
	c.send(&packets.Connect{
		ProtocolName:  packets.ProtocolName,
		ProtocolLevel: packets.ProtocolLevel,
		ClientID:      id,
		CleanSession:  true,
		KeepAlive:     120,
		HasUsername:   true,
		Username:      username,
		HasWill:       true,
		WillTopic:     willTopic,
		WillPayload:   []byte(willPayload),
		WillQoS:       packets.QoS0,
	})
	ack, ok := c.expect(packets.TypeConnack).(*packets.Connack)
	if !ok {
		c.t.Fatalf("expected CONNACK")
	}
	return ack
}

// ackQoS1 releases an outbound QoS 1 message, without which the retry ticker
// would send it again with DUP and upset a later silence check.
func (c *client) ackQoS1(p *packets.Publish) {
	c.t.Helper()
	c.send(&packets.Puback{PacketID: p.PacketID})
}

func (c *client) receive(topic, payload string) *packets.Publish {
	c.t.Helper()
	p := c.expect(packets.TypePublish).(*packets.Publish)
	if p.Topic != topic {
		c.t.Fatalf("received %q, want %q", p.Topic, topic)
	}
	if string(p.Payload) != payload {
		c.t.Fatalf("received %q on %q, want %q", p.Payload, p.Topic, payload)
	}
	if p.QoS == packets.QoS1 {
		c.ackQoS1(p)
	}
	return p
}

func TestConnectRejectsBadCredentials(t *testing.T) {
	auth := loadAuth(t, `{"username":"dashboard","salt":"c0ng-2026","alg":"sha256","scheme":"salt+username"}`)
	b := startBroker(t, nil, func(o *broker.Options) { o.Auth = auth })

	good := dial(t, b)
	if ack := good.connectAs("c1", true, "dashboard", dashboardSha256); ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("known credentials refused with code %d", ack.ReturnCode)
	}

	wrong := dial(t, b)
	if ack := wrong.connectAs("c2", true, "dashboard", wrongDigest); ack.ReturnCode != packets.ConnBadCredentials {
		t.Errorf("wrong password answered with code %d, want %d", ack.ReturnCode, packets.ConnBadCredentials)
	}
	wrong.expectClosed()

	// A client that offers no username is not accepted either: with an auth
	// file in force, silence is not a credential.
	quiet := dial(t, b)
	if ack := quiet.connectAs("c3", true, "", ""); ack.ReturnCode != packets.ConnBadCredentials {
		t.Errorf("missing credentials answered with code %d, want %d", ack.ReturnCode, packets.ConnBadCredentials)
	}
	quiet.expectClosed()

	if m := b.Metrics(); m.AuthRejected != 2 {
		t.Errorf("auth_rejected = %d, want 2", m.AuthRejected)
	}
}

func TestSubscribeRefusedByAcl(t *testing.T) {
	acl := loadACL(t, `
{"effect":"deny","action":"subscribe","topics":["$SYS/#"]}
{"effect":"allow","user":"dev","action":"subscribe","topics":["dev/+/telemetry"]}
{"effect":"allow","user":"pub","action":"publish","topics":["#"]}
`)
	b := startBroker(t, nil, func(o *broker.Options) { o.ACL = acl })

	dev := dial(t, b)
	dev.connectAs("dev1", true, "dev", "")
	codes := dev.subscribe(1, flt("dev/a/telemetry", packets.QoS1), flt("$SYS/#", packets.QoS0), flt("other/#", packets.QoS0))
	if codes[0] != packets.QoS1 {
		t.Errorf("granted qos for dev/a/telemetry = %d, want %d", codes[0], packets.QoS1)
	}
	for _, i := range []int{1, 2} {
		if codes[i] != packets.SubAckFailure {
			t.Errorf("code %d = %d, want the 0x80 failure", i, codes[i])
		}
	}

	// A refused filter must not be installed at all.
	if m := b.Metrics(); m.DeniedSubscribe != 2 || m.Subscriptions != 1 {
		t.Errorf("metrics = denied_subscribe %d, subscriptions %d; want 2 and 1", m.DeniedSubscribe, m.Subscriptions)
	}

	pub := dial(t, b)
	pub.connectAs("pub1", true, "pub", "")
	pub.publishQoS1(9, "dev/a/telemetry", "hello")
	dev.receive("dev/a/telemetry", "hello")

	// The refused channels stay empty even though messages flow through them.
	pub.publishQoS0("other/x", "ignored")
	pub.publishQoS0("$SYS/broker/load", "0.5")
	dev.expectNothing(600 * time.Millisecond)
}

func TestPublishRefusedStillAcknowledgesQoS(t *testing.T) {
	acl := loadACL(t, `
{"effect":"allow","user":"dev","action":"publish","topics":["ok/#"]}
{"effect":"deny","user":"dev","action":"publish","topics":["secret/#"]}
{"effect":"allow","user":"watch","action":"all","topics":["#"]}
`)
	b := startBroker(t, nil, func(o *broker.Options) { o.ACL = acl })

	watch := dial(t, b)
	watch.connectAs("w1", true, "watch", "")
	watch.subscribe(1, flt("secret/#", packets.QoS1), flt("ok/#", packets.QoS1))

	dev := dial(t, b)
	dev.connectAs("d1", true, "dev", "")

	// QoS 1: 3.1.1 has no "you may not publish that" code, so the message is
	// dropped and the PUBACK is sent anyway rather than letting the client
	// retry it forever.
	dev.send(&packets.Publish{Topic: "secret/x", QoS: packets.QoS1, PacketID: 11, Payload: []byte("nope")})
	if ack := dev.expect(packets.TypePuback).(*packets.Puback); ack.PacketID != 11 {
		t.Errorf("PUBACK id = %d, want 11", ack.PacketID)
	}

	// QoS 2: the whole handshake has to close.
	dev.publishQoS2Inbound(12, "secret/y", "nope")
	dev.send(&packets.Pubrel{PacketID: 12})
	if comp := dev.expect(packets.TypePubcomp).(*packets.Pubcomp); comp.PacketID != 12 {
		t.Errorf("PUBCOMP id = %d, want 12", comp.PacketID)
	}

	dev.publishQoS0("secret/z", "nope")

	watch.expectNothing(600 * time.Millisecond)
	if m := b.Metrics(); m.DeniedPublish != 3 {
		t.Errorf("acl_denied_publish = %d, want 3", m.DeniedPublish)
	}

	// The allowed channel still works.
	dev.publishQoS1(13, "ok/x", "yes")
	watch.receive("ok/x", "yes")
}

func TestDeliveryIsAuthorizedPerSubscriber(t *testing.T) {
	// The deny comes first, so it bites when a message arrives while the
	// broader filter is still something both clients may ask for: a filter is
	// not a topic, and "data/private/#" does not match the subscription
	// "data/#", so it cannot block the SUBSCRIBE itself.
	acl := loadACL(t, `
{"effect":"allow","user":"pub","action":"publish","topics":["data/#"]}
{"effect":"deny","user":"b","action":"subscribe","topics":["data/private/#"]}
{"effect":"allow","user":"b","action":"subscribe","topics":["data/#"]}
{"effect":"allow","user":"c","action":"subscribe","topics":["data/#"]}
`)
	b := startBroker(t, nil, func(o *broker.Options) { o.ACL = acl })

	bob := dial(t, b)
	bob.connectAs("b1", true, "b", "")
	bob.subscribe(1, flt("data/#", packets.QoS1))

	carol := dial(t, b)
	carol.connectAs("c1", true, "c", "")
	carol.subscribe(2, flt("data/#", packets.QoS1))

	pub := dial(t, b)
	pub.connectAs("p1", true, "pub", "")

	pub.publishQoS1(3, "data/public/y", "open")
	bob.receive("data/public/y", "open")
	carol.receive("data/public/y", "open")

	pub.publishQoS1(4, "data/private/x", "secret")
	carol.receive("data/private/x", "secret")
	bob.expectNothing(600 * time.Millisecond)

	if m := b.Metrics(); m.DeniedDelivery != 1 {
		t.Errorf("acl_denied_delivery = %d, want 1", m.DeniedDelivery)
	}
}

func TestOfflineQueueIsAuthorizedByStoredIdentity(t *testing.T) {
	acl := loadACL(t, `
{"effect":"allow","user":"pub","action":"publish","topics":["data/#"]}
{"effect":"deny","user":"b","action":"subscribe","topics":["data/private/#"]}
{"effect":"allow","user":"b","action":"subscribe","topics":["data/#"]}
`)
	st := store.NewMemoryStore()
	b := startBroker(t, st, func(o *broker.Options) { o.ACL = acl })

	bob := dial(t, b)
	bob.connectAs("away", false, "b", "")
	bob.subscribe(1, flt("data/#", packets.QoS1))
	bob.send(&packets.Disconnect{})

	// The session must survive with the credentials that made its
	// subscriptions, otherwise there is nothing to authorise an offline queue
	// against.
	waitUntil(t, func() bool {
		s, ok := st.Get("away")
		return ok && s.Username == "b"
	})

	pub := dial(t, b)
	pub.connectAs("p1", true, "pub", "")
	pub.publishQoS1(2, "data/private/x", "secret")
	pub.publishQoS1(3, "data/public/y", "open")
	if m := b.Metrics(); m.DeniedDelivery != 1 {
		t.Errorf("acl_denied_delivery = %d, want 1", m.DeniedDelivery)
	}

	// Reconnect: only what the rules allow was waiting.
	back := dial(t, b)
	ack := back.connectAs("away", false, "b", "")
	if !ack.SessionPresent {
		t.Error("reconnect did not report a stored session")
	}
	back.receive("data/public/y", "open")
	back.expectNothing(600 * time.Millisecond)
}

func TestWillIsDroppedWhenPublishIsRefused(t *testing.T) {
	acl := loadACL(t, `
{"effect":"allow","user":"w","action":"publish","topics":["live/#"]}
{"effect":"deny","user":"w","action":"publish","topics":["dead/#"]}
{"effect":"allow","user":"watch","action":"all","topics":["#"]}
`)
	b := startBroker(t, nil, func(o *broker.Options) { o.ACL = acl })

	watch := dial(t, b)
	watch.connectAs("w1", true, "watch", "")
	watch.subscribe(1, flt("dead/#", packets.QoS1), flt("live/#", packets.QoS1))

	// Control: an allowed will topic does fire.
	allowed := dial(t, b)
	allowed.connectWill("w-live", "w", "live/gone", "here")
	allowed.conn.Close()
	watch.receive("live/gone", "here")

	// The same client may not publish dead/#, so its will is dropped at CONNECT
	// rather than sneaking out when it dies.
	denied := dial(t, b)
	denied.connectWill("w-dead", "w", "dead/gone", "here")
	denied.conn.Close()
	watch.expectNothing(700 * time.Millisecond)

	if m := b.Metrics(); m.DeniedPublish < 1 {
		t.Errorf("acl_denied_publish = %d, want at least the refused will", m.DeniedPublish)
	}
}

// TestRepositoryRuleFilesDriveABroker starts the broker with the rules that
// ship in this repository, so the files themselves are under test. These
// connections all come from 127.0.0.1, which the acl file hands "all" on
// "$SYS/#" and "#", so the interesting part is the credential digests and the
// templated product channels rather than refusals.
func TestRepositoryRuleFilesDriveABroker(t *testing.T) {
	auth, err := rules.LoadAuth(filepath.Join("..", "..", "rules", "auth.jsonl"))
	if err != nil {
		t.Fatalf("LoadAuth: %v", err)
	}
	acl, err := rules.LoadACL(filepath.Join("..", "..", "rules", "acl.jsonl"))
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	b := startBroker(t, nil, func(o *broker.Options) { o.Auth, o.ACL = auth, acl })

	ops := dial(t, b)
	if ack := ops.connectAs("ops-1", true, "dashboard", dashboardSha256); ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("dashboard rejected with code %d", ack.ReturnCode)
	}
	ops.subscribe(1, flt("$SYS/#", packets.QoS0))

	// "aaaa_abcde" is the one username both the auth file's device regex and
	// the acl file's mirrored product-channel rule describe.
	dev := dial(t, b)
	if ack := dev.connectAs("dev-aaaa", false, "aaaa_abcde", deviceMd5); ack.ReturnCode != packets.ConnAccepted {
		t.Fatalf("device rejected with code %d", ack.ReturnCode)
	}
	dev.subscribe(2, flt("abcde/aaaa/cmd", packets.QoS1))

	bad := dial(t, b)
	if ack := bad.connectAs("dev-bbb", true, "aaaa_abcde", wrongDigest); ack.ReturnCode != packets.ConnBadCredentials {
		t.Errorf("a wrong device password answered with code %d, want %d", ack.ReturnCode, packets.ConnBadCredentials)
	}
	bad.expectClosed()

	// Cloud down to device, then device up to cloud.
	ops.publishQoS1(3, "abcde/aaaa/cmd", "reboot")
	dev.receive("abcde/aaaa/cmd", "reboot")

	dev.send(&packets.Publish{Topic: "abcde/aaaa/event", QoS: packets.QoS1, PacketID: 4, Payload: []byte(`{"temp":21}`)})
	dev.expect(packets.TypePuback)
	// ops subscribed only to $SYS/#, so the event is not for it.
	ops.expectNothing(600 * time.Millisecond)

	if m := b.Metrics(); m.AuthRejected != 1 {
		t.Errorf("auth_rejected = %d, want 1", m.AuthRejected)
	}
}
