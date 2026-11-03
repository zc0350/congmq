package broker

import (
	"fmt"
	"time"

	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/store"
)

// task is one message on its way to a client. The router creates it, the
// session goroutine owns it, and it survives a disconnect by being written
// into the store.
type task struct {
	msg      store.Message
	stage    store.Stage
	attempts int
	sentAt   time.Time
}

// sessionRuntime holds everything the session goroutine touches: the outbound
// queue, the unacknowledged window and the inbound QoS 2 handshakes. Nothing
// here is locked because exactly one goroutine may touch it.
type sessionRuntime struct {
	clientID string
	subs     map[string]store.Sub
	nextID   uint16

	queue    []*task
	inflight map[uint16]*task
	order    []uint16
	released []uint16

	// recv maps inbound QoS 2 identifiers awaiting their PUBREL. It is
	// per-connection on purpose: after a reconnect the client replays the
	// PUBLISH under a fresh identifier and dedup starts over.
	recv map[uint16]*task

	window   int
	queueMax int
}

func newRuntime(clientID string, window, queueMax int) *sessionRuntime {
	return &sessionRuntime{
		clientID: clientID,
		subs:     make(map[string]store.Sub),
		inflight: make(map[uint16]*task),
		recv:     make(map[uint16]*task),
		window:   window,
		queueMax: queueMax,
	}
}

// loadRuntime rebuilds a runtime from a stored session, which is how a
// persistent session resumes after a disconnect or a broker restart.
func loadRuntime(s *store.Session, window, queueMax int) *sessionRuntime {
	r := newRuntime(s.ClientID, window, queueMax)
	r.nextID = s.NextPacketID
	for f, sub := range s.Subscriptions {
		r.subs[f] = sub
	}
	for _, m := range s.Inflight {
		if m.Dir != store.Outbound || m.PacketID == 0 {
			continue
		}
		t := &task{msg: m, stage: m.Stage, attempts: m.Attempts}
		t.msg.Dup = true // the identifier is already known to the peer
		r.inflight[m.PacketID] = t
		r.order = append(r.order, m.PacketID)
	}
	for _, m := range s.Queued {
		m.Dup = false
		r.queue = append(r.queue, &task{msg: m})
	}
	return r
}

// push queues a message, dropping the oldest once the limit is passed, and
// reports how many were dropped.
func (r *sessionRuntime) push(msg store.Message) int {
	r.queue = append(r.queue, &task{msg: msg})
	if over := len(r.queue) - r.queueMax; over > 0 {
		r.queue = r.queue[over:]
		return over
	}
	return 0
}

func (r *sessionRuntime) depth() int { return len(r.queue) }

func (r *sessionRuntime) inflightCount() int { return len(r.inflight) }

func (r *sessionRuntime) windowFree() int { return r.window - len(r.inflight) }

// allocID hands out the next unused identifier in 1..65535, preferring one
// that a previous acknowledgement freed.
func (r *sessionRuntime) allocID() (uint16, bool) {
	for len(r.released) > 0 {
		id := r.released[len(r.released)-1]
		r.released = r.released[:len(r.released)-1]
		if _, used := r.inflight[id]; !used {
			return id, true
		}
	}
	for i := 1; i <= 0xFFFF; i++ {
		n := int(r.nextID) + i
		if n > 0xFFFF {
			n -= 0xFFFF
		}
		if _, used := r.inflight[uint16(n)]; !used {
			r.nextID = uint16(n)
			return uint16(n), true
		}
	}
	return 0, false
}

// take removes a task from the queue head, or nil when the queue is empty.
func (r *sessionRuntime) take() *task {
	if len(r.queue) == 0 {
		return nil
	}
	t := r.queue[0]
	r.queue = r.queue[1:]
	return t
}

func (r *sessionRuntime) requeueFront(t *task) {
	r.queue = append([]*task{t}, r.queue...)
}

// markInflight records a sent message until it is acknowledged.
func (r *sessionRuntime) markInflight(t *task) {
	r.inflight[t.msg.PacketID] = t
	r.order = append(r.order, t.msg.PacketID)
}

// release forgets an acknowledged message and returns its identifier to the
// reuse pool.
func (r *sessionRuntime) release(id uint16) *task {
	t := r.inflight[id]
	if t == nil {
		return nil
	}
	delete(r.inflight, id)
	for i, oid := range r.order {
		if oid == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	if len(r.released) < r.window {
		r.released = append(r.released, id)
	}
	return t
}

// due returns inflight messages that have waited longer than the retry
// interval, oldest first.
func (r *sessionRuntime) due(now time.Time, interval time.Duration) []*task {
	var out []*task
	for _, id := range r.order {
		t := r.inflight[id]
		if t == nil {
			continue
		}
		if now.Sub(t.sentAt) >= interval {
			out = append(out, t)
		}
	}
	return out
}

// snapshot serialises the session so it can be written to the store.
func (r *sessionRuntime) snapshot() *store.Session {
	s := &store.Session{
		ClientID:      r.clientID,
		NextPacketID:  r.nextID,
		Subscriptions: make(map[string]store.Sub, len(r.subs)),
	}
	for f, q := range r.subs {
		s.Subscriptions[f] = q
	}
	for _, id := range r.order {
		t := r.inflight[id]
		if t == nil {
			continue
		}
		m := t.msg
		m.Dir = store.Outbound
		m.Stage = t.stage
		m.Attempts = t.attempts
		s.Inflight = append(s.Inflight, m)
	}
	for _, t := range r.queue {
		m := t.msg
		m.Dir = store.Outbound
		m.Dup = false
		m.PacketID = 0
		s.Queued = append(s.Queued, m)
	}
	return s
}

// publishPacket builds the PUBLISH that carries a task, or nil when the message
// must not be sent at all because it expired while it waited. On a 5.0
// connection it also writes the property area: the Message Expiry Interval is
// rewritten to what is left of it, and a topic the peer already knows is
// replaced by its alias.
func (c *client) publishPacket(t *task) *packets.Publish {
	if !t.msg.Expires.IsZero() && !time.Now().Before(t.msg.Expires) {
		c.b.c.expired.Add(1)
		return nil
	}
	p := &packets.Publish{
		Topic:    t.msg.Topic,
		PacketID: t.msg.PacketID,
		QoS:      t.msg.QoS,
		Retain:   t.msg.Retain,
		Dup:      t.msg.Dup,
		Payload:  t.msg.Payload,
	}
	if !c.ver.Is5() {
		return p
	}
	props := t.msg.Props.Clone()
	if props == nil {
		props = &packets.Properties{}
	}
	props.Clear(packets.PropTopicAlias)
	if !t.msg.Expires.IsZero() {
		// The interval the peer sees is what is left of it, rounded up: passing
		// on the publisher's value would restart the clock at every hop.
		left := time.Until(t.msg.Expires)
		props.SetMessageExpiry(uint32((left + time.Second - 1) / time.Second))
	} else {
		props.Clear(packets.PropMessageExpiry)
	}
	if alias, fresh := c.aliasFor(t.msg.Topic); alias != 0 {
		props.SetTopicAlias(alias)
		if !fresh {
			// The peer learned this name when the alias was established.
			p.Topic = ""
		}
	}
	if props.IsEmpty() {
		props = nil
	}
	p.Props = props
	return p
}

// aliasFor maps a topic to this connection's outbound topic alias, taking a new
// number when the peer has room for one. A fresh mapping has to travel with the
// topic name, which is why the caller is told whether it may drop the name.
func (c *client) aliasFor(topic string) (uint16, bool) {
	if c.peerAliasMax == 0 {
		return 0, false
	}
	if alias, ok := c.aliasOut[topic]; ok {
		return alias, false
	}
	if c.aliasNext >= c.peerAliasMax {
		return 0, false
	}
	c.aliasNext++
	c.aliasOut[topic] = c.aliasNext
	return c.aliasNext, true
}

// resolveAlias is the inbound half of topic aliasing: a PUBLISH that carries a
// name establishes or replaces its mapping, and one that carries no name is
// decoded from the mapping the peer built earlier. The number of aliases a peer
// may open is bounded by the Topic Alias Maximum THIS broker advertised, which
// is the mirror image of c.peerAliasMax used on the way out.
//
// The two refusals are different errors, and the specification gives each its
// own reason code: an unusable alias number is 0x94, while a name-less packet
// pointing at a mapping that was never made is a plain protocol error.
func (c *client) resolveAlias(p *packets.Publish) (string, error) {
	limit := c.b.opt.TopicAliasMax
	if p.Topic != "" {
		if p.Props == nil || !p.Props.Has(packets.PropTopicAlias) {
			return p.Topic, nil
		}
		alias := p.Props.TopicAlias
		if alias == 0 || alias > limit {
			return "", reasonErr{packets.RTopicAliasInvalid,
				fmt.Errorf("%w: topic alias %d is outside 1..%d advertised by this broker",
					errProtocol, alias, limit)}
		}
		if c.aliasIn == nil {
			c.aliasIn = make(map[uint16]string)
		}
		c.aliasIn[alias] = p.Topic
		return p.Topic, nil
	}
	if p.Props == nil || !p.Props.Has(packets.PropTopicAlias) {
		return "", reasonErr{packets.RProtocolError,
			fmt.Errorf("%w: PUBLISH has neither a topic name nor a topic alias", errProtocol)}
	}
	topic, ok := c.aliasIn[p.Props.TopicAlias]
	if !ok {
		return "", reasonErr{packets.RProtocolError,
			fmt.Errorf("%w: topic alias %d was never mapped on this connection", errProtocol, p.Props.TopicAlias)}
	}
	return topic, nil
}
