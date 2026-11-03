package broker

import (
	"time"

	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/rules"
	"github.com/zc0350/congmq/internal/store"
	"github.com/zc0350/congmq/internal/topics"
)

// route fans one published application message out to every subscriber whose
// filter matches. A connected subscriber receives it through its mailbox; one
// that is away, or too slow to accept it, gets it written to the store so a
// later connect replays it. It reports how many recipients were served, which
// is what lets a 5.0 publisher be told "no matching subscribers".
func (b *Broker) route(m store.Message, origin string) int {
	if !m.Expires.IsZero() && !time.Now().Before(m.Expires) {
		b.c.expired.Add(1)
		return 0
	}
	// The retained store keeps the message exactly as published, with its RETAIN
	// flag set, so the next subscriber of that topic name inherits it.
	if m.Retain {
		b.retain.set(m)
		b.persistRetained(m)
	}

	sent := 0
	for _, sub := range b.tree.Match(m.Topic) {
		if sub.NoLocal && sub.ClientID == origin {
			// No Local is a per-subscription promise not to echo the client's
			// own publications back to it.
			continue
		}
		d := m
		d.QoS = min(sub.QoS, m.QoS)
		if !sub.RetainAsPublished {
			// Retain As Published is off, so the flag only ever meant something
			// to the broker that received it.
			d.Retain = false
		}
		if sub.ID > 0 {
			props := d.Props.Clone()
			if props == nil {
				props = &packets.Properties{}
			}
			props.AddSubscriptionID(sub.ID)
			d.Props = props
		}

		id := rules.Identity{ClientID: sub.ClientID}
		c := b.lookup(sub.ClientID)
		if c != nil {
			id = c.identity()
		} else if b.pol.load().acl != nil {
			// Offline: the queue is checked against the credentials that made
			// these subscriptions, not against the publisher's.
			id = b.identityOf(sub.ClientID)
		}
		if !b.allowDelivery(id, m.Topic) {
			continue
		}
		if c != nil && c.deliver(d) {
			sent++
			continue
		}
		b.queueOffline(sub.ClientID, d, id)
		sent++
	}
	return sent
}

// deliverRetained hands a subscriber the retained messages its new filter asks
// for. Retain Handling decided whether this happens at all; the messages keep
// their RETAIN flag because they are being replayed from the store, not
// forwarded from a publisher.
func (b *Broker) deliverRetained(c *client, filter string, sub store.Sub) {
	msgs := b.retain.match(filter)
	if len(msgs) == 0 {
		return
	}
	id := c.identity()
	sent := 0
	for _, m := range msgs {
		if !b.allowDelivery(id, m.Topic) {
			continue
		}
		d := m
		d.QoS = min(sub.QoS, m.QoS)
		d.Retain = true
		if sub.ID > 0 {
			props := d.Props.Clone()
			if props == nil {
				props = &packets.Properties{}
			}
			props.AddSubscriptionID(sub.ID)
			d.Props = props
		}
		if c.deliver(d) {
			sent++
		}
	}
	c.log.Debug("retained messages replayed", "filter", filter, "count", sent)
}

// fireWill publishes the last will of a client whose connection ended without a
// DISCONNECT packet.
func (b *Broker) fireWill(will *store.Message, origin string) {
	if err := topics.ValidName(will.Topic); err != nil {
		b.log.Warn("will topic is unusable", "client", origin, "err", err)
		return
	}
	b.log.Info("publishing will", "client", origin, "topic", will.Topic, "qos", will.QoS)
	b.route(*will, origin)
}
