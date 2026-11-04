package broker_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/store"
)

// liveHeap reads the heap the way an operator's /metrics does, but only after a
// collection: runtime.MemStats.HeapAlloc is a snapshot taken at the last GC, so
// measured any other way it reports what was live the last time the runtime had
// a reason to look.
func liveHeap(t *testing.T) uint64 {
	t.Helper()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// waitLonger is waitUntil with a budget that can cover a session expiry window.
// The stock helper gives up in three seconds, which is shorter than the clock it
// is watching.
func waitLonger(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not reached within %v", timeout)
}

// TestOfflineBacklogIsReleasedWithTheSessionsThatHeldIt is the unit-level version
// of what the soak measures: a fleet goes away, the router fills their queues,
// the clock runs out, and the bytes have to come back.
//
// The soak can only ask this from outside the process, where an idle Go runtime
// has no reason to collect and HeapAlloc keeps saying whatever the last GC saw.
// Inside a test the collection is forced, so a number that stays high here is
// retention rather than timing.
func TestOfflineBacklogIsReleasedWithTheSessionsThatHeldIt(t *testing.T) {
	st := store.NewMemoryStore()
	const expiry = 2 * time.Second
	b := startBroker(t, st, func(o *broker.Options) {
		o.ReapInterval = 20 * time.Millisecond
		o.QueueMax = 5000
		// Every session is cut to two seconds whatever it asked for, so the reaper
		// is guaranteed to run while the test is still watching.
		o.SessionExpiryMax = expiry
	})

	const (
		sessions = 20
		each     = 1200 // messages per away session, 24k in total
	)
	base := liveHeap(t)

	// Every session holds the same filter, so one publication queues one message
	// into each of them — the shape a topic a hundred devices share produces.
	for i := 0; i < sessions; i++ {
		c := dialV5(t, b)
		c.mustV5(fmt.Sprintf("hoard-%d", i), false, 300)
		c.v5sub(1, nil, flt("flood/1", packets.QoS1))
		_ = c.conn.Close()
	}
	// Filling before the broker has written the away record would race it: the
	// live record carries no expiry instant, so a snapshot taken then and put back
	// after the disconnect would hand the store a session that never dies.
	waitLonger(t, 3*time.Second, func() bool {
		for i := 0; i < sessions; i++ {
			s, ok := st.Get(fmt.Sprintf("hoard-%d", i))
			if !ok || s.Live || s.Expiry.IsZero() {
				return false
			}
		}
		return true
	})

	// The backlog goes in through the store rather than a thousand publishes,
	// because a publish loop would be timed against the seconds these sessions
	// have left. This is the same state the router writes: a queue of payloads
	// sitting under a session nobody is connected to.
	backlog := store.Message{Topic: "flood/1", Payload: []byte(strings.Repeat("p", 256)), QoS: packets.QoS1}
	for i := 0; i < sessions; i++ {
		id := fmt.Sprintf("hoard-%d", i)
		s, ok := st.Get(id)
		if !ok {
			t.Fatalf("session %s was not stored by the time its peers were", id)
		}
		for n := 0; n < each; n++ {
			s.Queued = append(s.Queued, backlog)
		}
		if err := st.Put(s); err != nil {
			t.Fatalf("fill %s: %v", id, err)
		}
	}
	waitLonger(t, 3*time.Second, func() bool { return b.Metrics().StoreQueued == sessions*each })
	peak := liveHeap(t)

	// The expiry window plus a reaper tick: every session ends and its queue is
	// thrown away with nobody to read it.
	waitLonger(t, expiry+4*time.Second, func() bool {
		m := b.Metrics()
		return m.StoreSessions == 0 && m.StoreQueued == 0
	})
	after := liveHeap(t)
	t.Logf("heap base %.1fMB, with the backlog %.1fMB, after the reaper %.1fMB",
		float64(base)/(1<<20), float64(peak)/(1<<20), float64(after)/(1<<20))

	// The backlog itself is 6MB of payload plus a Message header each, so the test
	// would prove nothing if it asked for zero. It asks for the backlog to be gone:
	// what remains may be the baseline's own noise, not 24k messages.
	grew := int64(after) - int64(base)
	if grew > 4<<20 {
		t.Errorf("heap grew %.1fMB and stayed there after the reaper released %d queued messages (base %.1fMB, peak %.1fMB, now %.1fMB)",
			float64(grew)/(1<<20), sessions*each,
			float64(base)/(1<<20), float64(peak)/(1<<20), float64(after)/(1<<20))
	}
	if after > peak {
		t.Errorf("heap is %.1fMB after the release, larger than the %.1fMB it was while holding the backlog",
			float64(after)/(1<<20), float64(peak)/(1<<20))
	}
}
