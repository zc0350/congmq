package broker

import (
	"sort"
	"sync"
	"time"

	"github.com/zc0350/congmq/internal/store"
	"github.com/zc0350/congmq/internal/topics"
)

// retainedStore holds the last retained message of every topic that asked to be
// retained. It is separate from the session store on purpose: retained messages
// are not part of any session and survive both disconnects and session expiry.
type retainedStore struct {
	mu   sync.RWMutex
	msgs map[string]store.Message
}

func newRetainedStore() *retainedStore {
	return &retainedStore{msgs: make(map[string]store.Message)}
}

// set records m as the retained message for its topic. An empty payload is how
// a publisher deletes a retained message, so it is removed rather than stored.
// It reports whether the topic now holds a retained message.
func (r *retainedStore) set(m store.Message) bool {
	c := m.Clone()
	c.Retain = true
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(c.Payload) == 0 {
		delete(r.msgs, c.Topic)
		return false
	}
	r.msgs[c.Topic] = c
	return true
}

// match returns the retained messages a new subscription should be sent, in
// topic order, skipping any that already expired.
func (r *retainedStore) match(filter string) []store.Message {
	now := time.Now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []store.Message
	for _, topic := range r.liveTopics(now) {
		m := r.msgs[topic]
		if topics.Match(filter, topic) {
			out = append(out, m.Clone())
		}
	}
	return out
}

// liveTopics lists the unexpired topics, sorted so a subscription replays its
// retained messages in a stable order instead of map order.
func (r *retainedStore) liveTopics(now time.Time) []string {
	out := make([]string, 0, len(r.msgs))
	for topic, m := range r.msgs {
		if !m.Expires.IsZero() && now.After(m.Expires) {
			continue
		}
		out = append(out, topic)
	}
	sort.Strings(out)
	return out
}

// prune drops the retained messages whose Message Expiry Interval has passed and
// returns the topics that lost one, so the durable store can be told as well. A
// retained message that dies of old age leaves no trace: the topic simply has no
// retained message again.
func (r *retainedStore) prune(now time.Time) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var gone []string
	for topic, m := range r.msgs {
		if !m.Expires.IsZero() && now.After(m.Expires) {
			delete(r.msgs, topic)
			gone = append(gone, topic)
		}
	}
	sort.Strings(gone)
	return gone
}

// Len is the number of topics currently holding a retained message.
func (r *retainedStore) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.msgs)
}
