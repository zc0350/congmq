package broker_test

import (
	"context"
	"testing"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/store"
)

// openFileStore is the durable half of a restart: a directory on disk that a
// second FileStore can be built from after the first one is gone.
func openFileStore(t *testing.T, dir string) *store.FileStore {
	t.Helper()
	fs, err := store.NewFileStore(store.FileStoreOptions{
		Dir:           dir,
		Sync:          store.SyncAlways,
		FlushInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open the file store in %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return fs
}

// onDisk runs a broker against a FileStore that is also its durable store, with
// a reaper quick enough for a test to watch it work.
func onDisk(fs store.Durable) func(*broker.Options) {
	return func(o *broker.Options) {
		o.Durable = fs
		o.ReapInterval = 100 * time.Millisecond
	}
}

// ackDelivery takes one QoS 1 delivery off the wire and acknowledges it, so a
// message the test has already seen is not still in flight after the restart.
func ackDelivery(c *client) *packets.Publish {
	c.t.Helper()
	p := c.expect(packets.TypePublish).(*packets.Publish)
	if p.QoS != packets.QoS1 {
		c.t.Fatalf("delivery of %q arrived with QoS %d, want QoS 1", p.Topic, p.QoS)
	}
	c.send(&packets.Puback{PacketID: p.PacketID})
	return p
}

// TestRestartFromDiskRestoresSessionsRetainedAndWills is the claim the whole
// persistence layer exists for: a broker that dies comes back owing the same
// messages, subscriptions, retained readings and delayed wills it did before.
//
// It restarts the store as well as the broker, so nothing is handed over in
// memory - phase two reads a file.
func TestRestartFromDiskRestoresSessionsRetainedAndWills(t *testing.T) {
	dir := t.TempDir()

	fs1 := openFileStore(t, dir)
	b1 := startBroker(t, fs1, onDisk(fs1))

	sub := dial(t, b1)
	sub.connect("durable", false)
	sub.subscribe(1, flt("dev/#", packets.QoS1))
	sub.subscribe(2, flt("will/#", packets.QoS1))
	sub.subscribe(3, flt("sensor/#", packets.QoS1))

	// A retained reading belongs to the topic and to no session, so it has a
	// durable home of its own.
	pub := dial(t, b1)
	pub.connect("pub", true)
	pub.publishQoS1(21, "dev/live", "seen")
	if p := ackDelivery(sub); p.Topic != "dev/live" {
		t.Fatalf("subscriber got %q while it was connected, want dev/live", p.Topic)
	}

	retainer := dialV5(t, b1)
	retainer.mustV5("retainer", true, 0)
	if code := retainer.v5retain("sensor/temp", "21.5C", packets.QoS1, 9); code != packets.RSuccess {
		t.Fatalf("retained publish answered %#02x", code)
	}
	p := ackDelivery(sub)
	// The live forward has no RETAIN flag: Retain As Published is off, so the flag
	// only ever meant something to the broker that received it. What has to
	// survive is the copy in the store, which the subscriber after the restart
	// gets back with its flag on.
	if p.Topic != "sensor/temp" || string(p.Payload) != "21.5C" || p.Retain {
		t.Fatalf("retained delivery = %q %q retain=%v, want the reading forwarded without the flag", p.Topic, p.Payload, p.Retain)
	}

	// A client whose Will Message is held back for a second: long enough that the
	// restart below happens while the will is still owed, short enough to watch it
	// fire afterwards.
	gone := dialV5(t, b1)
	gone.v5will("gone", "will/state", "gone-dark", 1, 600)

	// Both die without a DISCONNECT, so the session, its queue and the pending
	// will all have to be written down rather than remembered.
	_ = gone.conn.Close()
	_ = sub.conn.Close()
	waitUntil(t, func() bool {
		s, ok := fs1.Get("durable")
		return ok && len(s.Subscriptions) == 3 && len(fs1.LoadWills()) == 1
	})

	// Published while "durable" is away, so it waits in the offline queue.
	pub.publishQoS1(31, "dev/offline", "waited")
	waitUntil(t, func() bool {
		s, ok := fs1.Get("durable")
		return ok && len(s.Queued) == 1
	})
	// The will is on disk with the deadline the old process wrote down, so a
	// restart inside the delay still owes it - and does not restart the countdown.
	if w := fs1.LoadWills(); len(w) != 1 || w[0].ClientID != "gone" || !w[0].FireAt.After(time.Now()) {
		t.Fatalf("pending wills before the restart = %+v, want the one still owed with its deadline", w)
	}

	if err := b1.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown b1: %v", err)
	}
	if err := fs1.Close(); err != nil {
		t.Fatalf("close the first store: %v", err)
	}

	// --- restart ---
	fs2 := openFileStore(t, dir)
	b2 := startBroker(t, fs2, onDisk(fs2))

	// Serve restores the durable state before it accepts a single connection, so
	// the first thing a restarted broker can answer for is the count it read off
	// disk.
	waitUntil(t, func() bool { return b2.Metrics().Retained == 1 })

	// A brand new subscriber inherits the retained reading from the file.
	late := dialV5(t, b2)
	late.mustV5("late", true, 0)
	if codes := late.v5sub(3, nil, flt("sensor/#", packets.QoS1)); codes[0] != packets.QoS1 {
		t.Fatalf("subscribe answered %#02x, want QoS 1", codes[0])
	}
	p = late.expect(packets.TypePublish).(*packets.Publish)
	if p.Topic != "sensor/temp" || string(p.Payload) != "21.5C" || !p.Retain {
		t.Fatalf("retained message after the restart = %q %q retain=%v, want it unchanged", p.Topic, p.Payload, p.Retain)
	}

	// The will was still owed, so it goes out once its delay ends - not restarted
	// from the beginning, and not forgotten with the process that armed it.
	waitUntil(t, func() bool {
		s, ok := fs2.Get("durable")
		return ok && len(s.Queued) == 2 && len(fs2.LoadWills()) == 0
	})

	back := dial(t, b2)
	ack := back.connect("durable", false)
	if !ack.SessionPresent {
		t.Fatal("SessionPresent must be true: the broker has messages stored for this client")
	}
	var got []string
	for range 2 {
		p := back.expect(packets.TypePublish).(*packets.Publish)
		if p.QoS != packets.QoS1 {
			t.Fatalf("replayed %q with QoS %d, want QoS 1", p.Topic, p.QoS)
		}
		got = append(got, p.Topic+":"+string(p.Payload))
		back.send(&packets.Puback{PacketID: p.PacketID})
	}
	want := []string{"dev/offline:waited", "will/state:gone-dark"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("replay after the restart = %v, want %v", got, want)
	}
	back.expectNothing(200 * time.Millisecond)

	// And the subscription the client made before the restart is live again: this
	// publish has no new SUBSCRIBE behind it.
	pub2 := dial(t, b2)
	pub2.connect("pub2", true)
	pub2.publishQoS1(41, "dev/after", "fresh")
	p = back.expect(packets.TypePublish).(*packets.Publish)
	if p.Topic != "dev/after" {
		t.Fatalf("restored subscription delivered %q, want dev/after", p.Topic)
	}
	back.send(&packets.Puback{PacketID: p.PacketID})
}

// TestRetainedExpiryIsDurableToo checks the other half of persistence: a
// retained message that ages out must not come back on the next start.
func TestRetainedExpiryIsDurableToo(t *testing.T) {
	dir := t.TempDir()
	fs1 := openFileStore(t, dir)
	b1 := startBroker(t, fs1, onDisk(fs1))

	pub := dialV5(t, b1)
	pub.mustV5("pub", true, 0)
	ages := &packets.Properties{}
	ages.SetMessageExpiry(1)
	code := pub.v5send(&packets.Publish{
		Topic: "sensor/flash", QoS: packets.QoS1, PacketID: 7, Retain: true,
		Payload: []byte("here briefly"), Props: ages,
	})
	// Nobody is subscribed, and 5.0 says that out loud with 0x10. The broker took
	// the message either way, which is what a retained message is for.
	if code != packets.RSuccess && code != packets.RNoMatchingSubscribers {
		t.Fatalf("retained publish answered %#02x, want it accepted", code)
	}
	if got := b1.Metrics().Retained; got != 1 {
		t.Fatalf("the broker holds %d retained messages, want 1", got)
	}

	// The reaper prunes it while this broker is still up, and the prune has to
	// reach the file: an expired message that is still on disk returns.
	waitUntil(t, func() bool { return b1.Metrics().Retained == 0 })

	if err := b1.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := fs1.Close(); err != nil {
		t.Fatalf("close the first store: %v", err)
	}

	fs2 := openFileStore(t, dir)
	b2 := startBroker(t, fs2, onDisk(fs2))
	if got := b2.Metrics().Retained; got != 0 {
		t.Fatalf("the restarted broker holds %d retained messages, want none", got)
	}
	if got := fs2.LoadRetained(); len(got) != 0 {
		t.Fatalf("the store still holds %d retained messages, want none: an expired one must not return", len(got))
	}

	late := dialV5(t, b2)
	late.mustV5("late", true, 0)
	late.v5sub(1, nil, flt("sensor/#", packets.QoS1))
	late.expectNothing(300 * time.Millisecond)
}

// TestDrainedQueueIsNotStoredAgain pins the claim that a continuing session's
// store record cannot outlive the messages it handed to the live runtime. The
// runtime owns them; the record keeps only what the router spilled while the
// client was away. Without that, mergeSession unions already-delivered messages
// back in at every disconnect, and each offline -> online cycle adds another copy
// until the queue is nothing but redelivery.
func TestDrainedQueueIsNotStoredAgain(t *testing.T) {
	st := store.NewMemoryStore()
	b := startBroker(t, st, nil)

	sub := dial(t, b)
	sub.connect("cycle", false)
	sub.subscribe(1, flt("dev/data", packets.QoS1))
	_ = sub.conn.Close()

	pub := dial(t, b)
	pub.connect("pub", true)
	pub.publishQoS1(7, "dev/data", "one")
	pub.publishQoS1(8, "dev/data", "two")
	waitUntil(t, func() bool {
		s, ok := st.Get("cycle")
		return ok && len(s.Queued) == 2
	})

	// It comes back, takes both and acknowledges them, then leaves again.
	back := dial(t, b)
	if ack := back.connect("cycle", false); !ack.SessionPresent {
		t.Fatal("two messages were waiting, so the session must still be there")
	}
	if p := ackDelivery(back); string(p.Payload) != "one" {
		t.Fatalf("first delivery = %q, want one", p.Payload)
	}
	if p := ackDelivery(back); string(p.Payload) != "two" {
		t.Fatalf("second delivery = %q, want two", p.Payload)
	}
	_ = back.conn.Close()

	if s, ok := st.Get("cycle"); ok && len(s.Queued) != 0 {
		t.Fatalf("the store kept %d messages that had already been delivered, want none", len(s.Queued))
	}

	// So the next cycle may only ever see what arrived after it went away.
	pub.publishQoS1(9, "dev/data", "three")
	waitUntil(t, func() bool {
		s, ok := st.Get("cycle")
		return ok && len(s.Queued) == 1
	})

	third := dial(t, b)
	if ack := third.connect("cycle", false); !ack.SessionPresent {
		t.Fatal("the session is still alive, so the reconnect must continue it")
	}
	if p := ackDelivery(third); string(p.Payload) != "three" {
		t.Fatalf("delivery = %q, want only the message queued while it was away", p.Payload)
	}
	third.expectNothing(300 * time.Millisecond)
}

// TestLiveSessionIsOnRecordWhileItIsConnected is the other half of a crash: a
// broker that dies with a device connected has to bring that device's
// subscriptions back with it. Clients that resubscribe on reconnect paper over
// the gap; the ones that do not - most embedded devices - would stop being served
// for good and nothing in the log would say so.
func TestLiveSessionIsOnRecordWhileItIsConnected(t *testing.T) {
	st := store.NewMemoryStore()
	b := startBroker(t, st, nil)

	sub := dial(t, b)
	sub.connect("live", false)
	sub.subscribe(1, flt("dev/#", packets.QoS1))

	s, ok := st.Get("live")
	if !ok {
		t.Fatal("a persistent session is not in the store while it is connected")
	}
	if !s.Live {
		t.Error("the record does not say the session was live, so its expiry would be read as already running")
	}
	if !s.Expiry.IsZero() {
		t.Errorf("a live record carries Expiry %s, want the zero time: nothing has ended yet", s.Expiry)
	}
	if len(s.Subscriptions) != 1 {
		t.Fatalf("the record has %d subscriptions, want the one still connected", len(s.Subscriptions))
	}
	// The subscription still reaches the client, so the store write has not taken
	// over the live path.
	pub := dial(t, b)
	pub.connect("pub", true)
	pub.publishQoS1(3, "dev/a", "hello")
	if p := ackDelivery(sub); p.Topic != "dev/a" {
		t.Fatalf("delivery on topic %q, want dev/a", p.Topic)
	}

	// An unsubscribe has to reach the record too, or the filter comes back at the
	// next reconnect from a union with the state the client threw away.
	sub.send(&packets.Unsubscribe{PacketID: 4, TopicFilters: []string{"dev/#"}})
	sub.expect(packets.TypeUnsuback)
	if s, ok := st.Get("live"); ok && len(s.Subscriptions) != 0 {
		t.Fatalf("the record still holds %d subscriptions after the unsubscribe", len(s.Subscriptions))
	}

	// A session that will be discarded at disconnect has nothing worth saving.
	clean := dial(t, b)
	clean.connect("throwaway", true)
	clean.subscribe(5, flt("other/#", packets.QoS1))
	if _, ok := st.Get("throwaway"); ok {
		t.Error("a clean session was written to the store; it will be deleted the moment it leaves")
	}

	// The interval a 5.0 client asked for is what a restored record re-arms, so it
	// belongs in the record while the client is still here.
	five := dialV5(t, b)
	five.mustV5("delayed", false, 600)
	five.v5sub(1, nil, flt("node/1/status", packets.QoS1))
	s, ok = st.Get("delayed")
	if !ok || !s.Live {
		t.Fatalf("a connected 5.0 session with an expiry of 600s is not on record as live (found %v)", ok)
	}
	if s.ExpiryInterval != 10*time.Minute {
		t.Errorf("recorded expiry interval = %s, want 10m0s", s.ExpiryInterval)
	}
}

// TestRestoringALiveSessionStartsItsClockNow is the crash's other side: a record
// written while the client was connected never started counting, so the restart
// is when its session went offline. A record left over from a longer outage is
// already counting, and "never expires" stays unarmed.
func TestRestoringALiveSessionStartsItsClockNow(t *testing.T) {
	st := store.NewMemoryStore()
	if err := st.Put(&store.Session{
		ClientID:       "due",
		Live:           true,
		ExpiryInterval: 200 * time.Millisecond,
		Subscriptions:  map[string]store.Sub{"dev/#": {QoS: packets.QoS1}},
		Proto:          packets.V311,
	}); err != nil {
		t.Fatalf("seed the live record: %v", err)
	}
	if err := st.Put(&store.Session{
		ClientID:      "forever",
		Live:          true,
		Subscriptions: map[string]store.Sub{"keep/#": {QoS: packets.QoS1}},
		Proto:         packets.V311,
	}); err != nil {
		t.Fatalf("seed the immortal record: %v", err)
	}

	b := startBroker(t, st, func(o *broker.Options) { o.ReapInterval = 25 * time.Millisecond })

	// Restored, counted from the restart, and then reaped in front of the test.
	waitUntil(t, func() bool {
		s, ok := st.Get("due")
		return !ok || (!s.Live && !s.Expiry.IsZero())
	})
	waitUntil(t, func() bool {
		_, ok := st.Get("due")
		return !ok
	})

	forever, ok := st.Get("forever")
	if !ok {
		t.Fatal("the session that never expires was reaped")
	}
	if forever.Live {
		t.Error("the restored record still claims a connection that ended with the old process")
	}
	if !forever.Expiry.IsZero() {
		t.Errorf("immortal session restored with Expiry %s, want the zero time", forever.Expiry)
	}

	// Its subscription came back with it, so a publisher reaches it without help.
	pub := dial(t, b)
	pub.connect("pub", true)
	pub.publishQoS1(9, "keep/1", "held")
	if s, ok := st.Get("forever"); !ok || len(s.Queued) != 1 {
		t.Fatalf("the restored subscription did not reach the session: %+v (found %v)", s, ok)
	}
}
