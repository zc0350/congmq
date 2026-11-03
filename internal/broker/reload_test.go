package broker_test

import (
	"testing"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/store"
)

// A policy that can only change with a restart changes on the operator's worst
// day. These tests pin what a swap means for a broker that is already carrying
// traffic: what the next CONNECT sees, what the next publish of an open session
// sees, what must not be silently reset, and what a live subscription loses when
// the rules under it move.

// md5TwoSaltX is md5("two" + "x"), computed outside this package, so the
// password half of a reloaded rule is checked rather than restated.
const md5TwoSaltX = "48248bc91567bbc9a33ba9c5be3b5af9"

func TestReloadedRulesDecideTheNextConnect(t *testing.T) {
	auth := loadAuth(t, `{"username":"one","salt":"x","alg":"md5","scheme":"username+salt"}`)
	b := startBroker(t, store.NewMemoryStore(), func(o *broker.Options) { o.Auth = auth })

	before := dial(t, b)
	if ack := before.connectAs("c-1", true, "two", md5TwoSaltX); ack.ReturnCode != packets.ConnBadCredentials {
		t.Fatalf("user two was accepted before the reload (code %d)", ack.ReturnCode)
	}
	if m := b.Metrics(); m.RulesGeneration != 1 {
		t.Fatalf("rules_generation = %d, want 1 before any swap", m.RulesGeneration)
	}

	// The operator adds a user. Nothing is restarted, no listener is reopened.
	b.SetRules(loadAuth(t, `{"username":"one","salt":"x","alg":"md5","scheme":"username+salt"}
{"username":"two","salt":"x","alg":"md5","scheme":"username+salt"}`), nil)

	after := dial(t, b)
	if ack := after.connectAs("c-2", true, "two", md5TwoSaltX); ack.ReturnCode != packets.ConnAccepted {
		t.Errorf("user two was still refused after the reload (code %d)", ack.ReturnCode)
	}
	m := b.Metrics()
	if m.RulesGeneration != 2 {
		t.Errorf("rules_generation = %d, want 2 after one swap", m.RulesGeneration)
	}
	if m.RulesLoadedUnix == 0 {
		t.Error("rules_loaded_unix is zero, so a reload cannot be timed")
	}
}

func TestReloadDoesNotEvictAnOpenSessionButJudgesItsNextPublish(t *testing.T) {
	b := startBroker(t, store.NewMemoryStore(), func(o *broker.Options) {
		o.ACL = loadACL(t, `{"effect":"allow","action":"all","topics":["plant/#"]}`)
	})
	dev := dial(t, b)
	dev.connectAs("dev", true, "", "")
	dev.publishQoS1(1, "plant/row/1", "allowed")

	// The rule now covers a different tree. The session that is already open is
	// not a mistake to be corrected: it is a device that stays online and is
	// simply judged by the new policy from its next packet on.
	b.SetRules(nil, loadACL(t, `{"effect":"allow","action":"all","topics":["shop/#"]}`))

	dev.publishQoS1(2, "plant/row/2", "refused now")
	dev.publishQoS1(3, "shop/bin/1", "allowed now")

	m := b.Metrics()
	if m.DeniedPublish != 1 {
		t.Errorf("acl_denied_publish = %d, want 1", m.DeniedPublish)
	}
	if m.Online != 1 {
		t.Errorf("online = %d, want 1: a policy swap is not an eviction", m.Online)
	}
}

func TestReloadStopsFeedingASubscriptionTheNewRulesRefuse(t *testing.T) {
	b := startBroker(t, store.NewMemoryStore(), func(o *broker.Options) {
		o.ACL = loadACL(t, `{"effect":"allow","action":"all","topics":["plant/#","shop/#"]}`)
	})
	watch := dial(t, b)
	watch.connectAs("watch", true, "", "")
	watch.subscribe(1, flt("plant/#", packets.QoS1))

	pub := dial(t, b)
	pub.connectAs("pub", true, "", "")
	pub.publishQoS1(2, "plant/row/1", "first")
	watch.receive("plant/row/1", "first")

	// The subscriber's rules move; the publisher's do not. If the new policy
	// refused the publish as well there would be no delivery to refuse, and the
	// test would be proving the wrong gate.
	b.SetRules(nil, loadACL(t, `{"effect":"allow","clientid":"pub","action":"publish","topics":["plant/#"]}
{"effect":"allow","clientid":"watch","action":"all","topics":["shop/#"]}`))
	pub.publishQoS1(3, "plant/row/2", "now refused")
	watch.expectNothing(400 * time.Millisecond)

	if m := b.Metrics(); m.DeniedDelivery != 1 {
		t.Errorf("acl_denied_delivery = %d, want 1", m.DeniedDelivery)
	}
}

func TestUnsafeExpansionCountSurvivesAReload(t *testing.T) {
	// A client identifier or username carrying a wildcard would widen its own
	// rule; the broker counts every time it refused to. That number is the audit
	// trail for "someone tried to escape their lane", and a reload must not be
	// able to erase it.
	b := startBroker(t, store.NewMemoryStore(), func(o *broker.Options) {
		o.ACL = loadACL(t, `{"effect":"allow","action":"publish","topics":["u/%u/x"]}`)
	})
	escape := dial(t, b)
	escape.connectAs("c", true, "a/#", "")
	escape.publishQoS1(1, "u/whatever/x", "widened")
	if m := b.Metrics(); m.UnsafeExpansions != 1 {
		t.Fatalf("acl_unsafe_expansions = %d, want 1", m.UnsafeExpansions)
	}

	b.SetRules(nil, loadACL(t, `{"effect":"allow","action":"publish","topics":["other/#"]}`))
	if m := b.Metrics(); m.UnsafeExpansions != 1 {
		t.Errorf("acl_unsafe_expansions reset to %d across a reload, want 1", m.UnsafeExpansions)
	}

	// It keeps counting from the carried-forward total.
	next := dial(t, b)
	next.connectAs("c2", true, "b/+", "")
	next.publishQoS1(2, "other/x", "unrelated but the id is still sharp")
	if m := b.Metrics(); m.UnsafeExpansions != 1 {
		t.Errorf("acl_unsafe_expansions = %d, want it to stay 1 for a rule that does not expand", m.UnsafeExpansions)
	}
}

func TestSetRulesCanTurnAHalfOff(t *testing.T) {
	// A nil half means "this half is off", which is how a broker runs without
	// rules — so rewriting a file down to only comments has to be honoured rather
	// than read as "the operator broke the file, keep the old policy".
	b := startBroker(t, store.NewMemoryStore(), func(o *broker.Options) {
		o.Auth = loadAuth(t, `{"username":"one","salt":"x","alg":"md5","scheme":"username+salt"}`)
	})
	closed := dial(t, b)
	if ack := closed.connectAs("c-1", true, "anyone", "whatever"); ack.ReturnCode != packets.ConnBadCredentials {
		t.Fatalf("an account no rule describes was accepted (code %d)", ack.ReturnCode)
	}

	b.SetRules(nil, nil)

	open := dial(t, b)
	if ack := open.connectAs("c-2", true, "anyone", "whatever"); ack.ReturnCode != packets.ConnAccepted {
		t.Errorf("a broker with the auth half switched off refused a client (code %d)", ack.ReturnCode)
	}
}
