// Package store keeps the durable half of a persistent MQTT session: its
// subscriptions, the messages still waiting for a reconnecting client, and
// the messages already sent but not yet acknowledged.
package store

import (
	"fmt"
	"sync"
	"time"

	"github.com/zc0350/congmq/internal/packets"
)

// Direction tells which way a stored message was travelling.
type Direction byte

const (
	// Outbound: the broker sent it and awaits PUBACK or PUBCOMP.
	Outbound Direction = iota
	// Inbound: the broker got a QoS 2 PUBLISH and awaits the PUBREL.
	Inbound
)

// Stage is the QoS 2 step a message is parked at.
type Stage byte

const (
	StageNone             Stage = iota
	StageAwaitPubRec      Stage = 1
	StageAwaitPubComp     Stage = 2
	StageAwaitPubRel      Stage = 3
	StageAwaitPubCompRecv Stage = 4
)

// Message is one application message inside a session.
type Message struct {
	Topic    string
	Payload  []byte
	QoS      byte
	Retain   bool
	Dup      bool
	PacketID uint16
	Dir      Direction
	Stage    Stage
	Attempts int

	// Props carries the MQTT 5.0 property area as the publisher sent it. It is
	// nil for 3.1.1 messages. The Subscription Identifier is not kept here: it
	// belongs to the subscription, not the message, and is added per recipient.
	Props *packets.Properties
	// Expires is the deadline set by the Message Expiry Interval, or the zero
	// time when the message never expires.
	Expires time.Time
}

// Clone deep-copies a message so a stored session shares no bytes with the
// caller that queued it.
func (m Message) Clone() Message {
	out := m
	out.Payload = cloneBytes(m.Payload)
	out.Props = m.Props.Clone()
	return out
}

// Sub is one subscription: the granted QoS plus the MQTT 5.0 options, which a
// persistent session must remember because a reconnect replays retained
// messages and forwards later ones under the same rules.
type Sub struct {
	QoS               byte
	NoLocal           bool
	RetainAsPublished bool
	RetainHandling    byte
	// ID is the Subscription Identifier the client asked to have stamped onto
	// messages delivered under this filter.
	ID int
}

// Session is the serialisable state of one client identifier.
type Session struct {
	ClientID string
	// Username and RemoteIP are the credentials the client presented at
	// CONNECT. An authorization file can key on either, so an offline queue
	// has to be checked against the same identity that made the subscription.
	Username     string
	RemoteIP     string
	NextPacketID uint16
	// Subscriptions maps topic filter to its grant and options.
	Subscriptions map[string]Sub
	Inflight      []Message
	Queued        []Message

	// Expiry is the instant this offline session dies and is reaped. The zero
	// time means it never expires, which is how 3.1.1 sessions behave.
	Expiry time.Time
	// Live marks the record of a session that was still connected when it was
	// written. Its Session Expiry Interval has not started, because that clock
	// runs from the end of the connection - which for a broker killed
	// mid-connection is the moment it comes back.
	Live bool
	// ExpiryInterval is the lifetime a Live record asked for, so restoring one
	// can start the clock rather than read an Expiry that was never armed. Zero
	// alongside Live means never, which covers 3.1.1 cleanSession=false and the
	// all-ones interval alike.
	ExpiryInterval time.Duration
	// Proto is the negotiated protocol version, so a restored session knows
	// whether to write property areas.
	Proto packets.Version
}

func (s *Session) clone() *Session {
	out := &Session{
		ClientID:       s.ClientID,
		Username:       s.Username,
		RemoteIP:       s.RemoteIP,
		NextPacketID:   s.NextPacketID,
		Expiry:         s.Expiry,
		Live:           s.Live,
		ExpiryInterval: s.ExpiryInterval,
		Proto:          s.Proto,
		Subscriptions:  make(map[string]Sub, len(s.Subscriptions)),
		Inflight:       make([]Message, 0, len(s.Inflight)),
		Queued:         make([]Message, 0, len(s.Queued)),
	}
	for f, q := range s.Subscriptions {
		out.Subscriptions[f] = q
	}
	for _, m := range s.Inflight {
		out.Inflight = append(out.Inflight, m.Clone())
	}
	for _, m := range s.Queued {
		out.Queued = append(out.Queued, m.Clone())
	}
	return out
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Store holds sessions by client identifier. Implementations must be safe for
// concurrent use and must not share byte slices with the caller.
type Store interface {
	Get(clientID string) (*Session, bool)
	Put(s *Session) error
	// Delete reports whether the removal reached whatever backs the store, so a
	// file implementation can honour the same sync promise Put does.
	Delete(clientID string) error
	Sessions() []*Session
	Close() error
}

// MemoryStore keeps sessions in a map. It survives a client disconnect but
// not a broker restart; FileStore replaces it without touching the broker.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{sessions: make(map[string]*Session)}
}

// Get returns a detached copy of a session.
func (m *MemoryStore) Get(clientID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[clientID]
	if !ok {
		return nil, false
	}
	return s.clone(), true
}

// Put replaces a session with a detached copy.
func (m *MemoryStore) Put(s *Session) error {
	if s == nil || s.ClientID == "" {
		return fmt.Errorf("store: session needs a client identifier")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ClientID] = s.clone()
	return nil
}

// Delete forgets a session, discarding its queued messages.
func (m *MemoryStore) Delete(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, clientID)
	return nil
}

// Sessions lists every stored session, detached.
func (m *MemoryStore) Sessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s.clone())
	}
	return out
}

// Close is a no-op.
func (m *MemoryStore) Close() error { return nil }
