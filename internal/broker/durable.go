package broker

import (
	"time"

	"github.com/zc0350/congmq/internal/store"
)

// The durable half of a broker that belongs to no session: the retained message
// of a topic, and a will still waiting out its delay. Both live in memory while
// the process runs, and Options.Durable is what makes them outlive it.
//
// Every write-through reports its failure and moves on. A disk that will not
// take a retained message is a reason to warn the operator, not a reason to
// disconnect the publisher whose message is already safely in memory.

// restoreDurable puts the state that belongs to no session back where a running
// broker can find it: retained messages in the topic-keyed store, delayed wills
// in the pending map with the deadline the previous process wrote down.
//
// A will whose delay ended while the broker was down is published immediately
// rather than waiting for the next reap. Nobody is going to withdraw it: the
// connection that owned it died with the process.
func (b *Broker) restoreDurable() {
	d := b.opt.Durable
	if d == nil {
		return
	}
	retained := d.LoadRetained()
	for _, m := range retained {
		// set rather than the broker's own write-through path: this message is
		// already on disk, and re-adding it would grow the log on every start.
		b.retain.set(m)
	}
	wills := d.LoadWills()
	now := time.Now()
	b.willMu.Lock()
	for _, w := range wills {
		b.wills[w.ClientID] = pendingWill{clientID: w.ClientID, msg: w.Msg, fireAt: w.FireAt}
	}
	b.willMu.Unlock()

	b.log.Info("durable state restored", "retained", len(retained), "delayed_wills", len(wills))
	b.fireDueWills(now)
}

// persistRetained records m as the retained message of its topic. An empty
// payload is a deletion and the store knows that too, so one path covers both.
func (b *Broker) persistRetained(m store.Message) {
	if b.opt.Durable == nil {
		return
	}
	if err := b.opt.Durable.Retain(m); err != nil {
		b.log.Error("cannot persist retained message", "topic", m.Topic, "err", err)
	}
}

// forgetRetained drops a topic's retained message from the durable store, which
// is what an expired one needs: the memory map already forgot it, and a restart
// must not resurrect it.
func (b *Broker) forgetRetained(topic string) {
	if b.opt.Durable == nil {
		return
	}
	if err := b.opt.Durable.ForgetRetained(topic); err != nil {
		b.log.Error("cannot persist the loss of a retained message", "topic", topic, "err", err)
	}
}

// persistWill parks a delayed will on disk with the deadline it was given. The
// deadline is written rather than recomputed, because a restart must not extend
// a delay the client asked for.
func (b *Broker) persistWill(w store.Will) {
	if b.opt.Durable == nil {
		return
	}
	if err := b.opt.Durable.DeferWill(w); err != nil {
		b.log.Error("cannot persist delayed will", "client", w.ClientID, "err", err)
	}
}

// forgetWill removes a delayed will for good: it has been published, or
// withdrawn by a reconnect that continued the session it came from.
func (b *Broker) forgetWill(clientID string) {
	if b.opt.Durable == nil {
		return
	}
	if err := b.opt.Durable.ForgetWill(clientID); err != nil {
		b.log.Error("cannot forget a delayed will", "client", clientID, "err", err)
	}
}

// diskSized is the part of a durable store that can report its own footprint.
// Only a file-backed store answers; a broker without -store then reports zero
// bytes on disk, which is the truth rather than a number that is missing.
type diskSized interface{ DiskBytes() int64 }

func storeDiskBytes(d store.Durable) int64 {
	if ds, ok := d.(diskSized); ok {
		return ds.DiskBytes()
	}
	return 0
}
