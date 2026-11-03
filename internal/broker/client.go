package broker

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/rules"
	"github.com/zc0350/congmq/internal/store"
	"github.com/zc0350/congmq/internal/topics"
)

// preConnectTimeout bounds how long a socket may stay open without sending a
// CONNECT packet.
const preConnectTimeout = 30 * time.Second

// defaultReceiveMax is the Receive Maximum a 5.0 peer applies when it sends no
// such property: the protocol's own ceiling, which is to say no limit at all.
const defaultReceiveMax = 65535

var (
	errProtocol = errors.New("congmq: protocol violation")
	errNormal   = errors.New("congmq: client disconnected")
	errTakeover = errors.New("congmq: taken over by a newer connection")
	errExpired  = errors.New("congmq: message expired before it could be sent")
	errTooLarge = errors.New("congmq: message is larger than the peer will accept")
)

// fault is a problem noticed by someone other than stateLoop - the reader, or
// the broker itself - that has to end this session. It travels through a
// channel because only stateLoop may write the closing frames, and a DISCONNECT
// that jumps the queue behind a PUBLISH would be a lie about what was sent.
type fault struct {
	reason byte
	err    error
	// noWill is set when the closure is the broker's own doing, as with a
	// shutdown, rather than the peer vanishing.
	noWill bool
}

// reasonErr pins the DISCONNECT reason code to an error for the cases the
// specification names individually, where the error alone would only justify
// the generic 0x82.
type reasonErr struct {
	reason byte
	err    error
}

func (e reasonErr) Error() string { return e.err.Error() }
func (e reasonErr) Unwrap() error { return e.err }

// client is one MQTT session bound to one network connection.
//
// Three goroutines serve a connection: readLoop decodes packets into in,
// stateLoop owns all session state, and writeLoop drains out to the socket.
// Because only stateLoop touches sessionRuntime, the QoS bookkeeping needs no
// locks at any traffic level.
type client struct {
	b    *Broker
	conn net.Conn
	ip   net.IP
	// certCN is the CommonName of a client certificate this broker verified
	// during the handshake, or "" for a plain connection and for one where no
	// chain was checked. It never changes after accept.
	certCN string
	log    *slog.Logger

	in      chan packets.Packet
	out     chan []byte
	mailbox chan *task
	faults  chan fault

	// connMu serialises socket writes with writeLoop, so a final DISCONNECT
	// written by stateLoop cannot interleave with a frame being flushed.
	connMu sync.Mutex

	// Owned by stateLoop.
	id             string
	ver            packets.Version
	rt             *sessionRuntime
	will           *store.Message
	cause          error
	registered     bool
	hadSession     bool
	graceful       bool
	willRequested  bool
	lastActivity   time.Time
	keepAliveValue time.Duration

	// Session shape, negotiated in CONNECT and applied when the connection ends.
	discard        bool
	persist        bool
	sessionExpiry  time.Duration
	sessionForever bool
	willDelay      time.Duration

	// The peer's own limits, learned from its CONNECT properties.
	peerReceiveMax int
	peerAliasMax   uint16
	peerMaxPacket  uint32

	// Topic alias maps live as long as the connection does: the specification
	// ties them to the Network Connection, not to the Session.
	aliasIn   map[uint16]string
	aliasOut  map[string]uint16
	aliasNext uint16

	done     chan struct{}
	finished chan struct{}
	once     sync.Once

	// subject is the identity this connection presented at CONNECT. The router
	// reads it to authorise deliveries, so it is handed over atomically rather
	// than living with the rest of the stateLoop-owned fields.
	subject atomic.Pointer[rules.Identity]
}

func newClient(b *Broker, conn net.Conn) *client {
	size := b.opt.MailboxSize
	return &client{
		b:              b,
		conn:           conn,
		ip:             peerIP(conn),
		certCN:         peerCertCN(conn),
		log:            b.log.With("remote", conn.RemoteAddr().String()),
		in:             make(chan packets.Packet, size),
		out:            make(chan []byte, size),
		mailbox:        make(chan *task, size),
		faults:         make(chan fault, 4),
		ver:            packets.V311,
		peerReceiveMax: defaultReceiveMax,
		aliasIn:        make(map[uint16]string),
		aliasOut:       make(map[string]uint16),
		done:           make(chan struct{}),
		finished:       make(chan struct{}),
	}
}

// fail ends the connection once, recording why.
func (c *client) fail(err error) {
	c.once.Do(func() {
		c.cause = err
		close(c.done)
		_ = c.conn.Close()
	})
}

// kick asks a session to close itself, giving it the reason code to announce.
// A session that is already finished or wedged shuts down without the courtesy.
func (c *client) kick(reason byte, err error, noWill bool) {
	select {
	case c.faults <- fault{reason: reason, err: err, noWill: noWill}:
	case <-c.done:
	default:
		c.fail(err)
	}
}

// idTimeout implements the "1.5 x keep alive" rule of section 3.1.2.10.
func (c *client) idTimeout() time.Duration {
	if c.rt == nil {
		return preConnectTimeout
	}
	if c.keepAlive() == 0 {
		// The client asked never to be timed out.
		return 1 << 62
	}
	ka := c.keepAlive()
	return ka + ka/2
}

func (c *client) keepAlive() time.Duration { return c.keepAliveValue }

// countReader tallies bytes so the metrics reflect real wire traffic.
type countReader struct {
	r io.Reader
	n *atomic.Int64
}

func (r *countReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n.Add(int64(n))
	return n, err
}

func (c *client) readLoop() {
	br := bufio.NewReaderSize(&countReader{r: c.conn, n: &c.b.c.bytesIn}, 4096)
	// The reader tracks the negotiated version itself: CONNECT names it, and the
	// packets after that one are encoded with it. stateLoop keeps its own copy
	// for writing, and both see the same CONNECT.
	ver := packets.V311
	maxIn := c.b.opt.MaxPacketSize
	for {
		p, _, err := packets.DecodeFrameLimited(br, ver, int(maxIn))
		if err != nil {
			switch {
			case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
				c.fail(errNormal)
			case errors.Is(err, packets.ErrFrameTooLarge):
				// Answered before the body was read, which is the whole point:
				// the peer announced a size, and this connection cost the broker
				// a header.
				c.log.Warn("packet exceeds the advertised maximum size", "err", err)
				c.kick(packets.RPacketTooLarge, err, false)
			case errors.Is(err, packets.ErrTopicAlias):
				// Wraps ErrProtocol, so it has to be recognised first: the
				// specification wants 0x94 here rather than the generic 0x82.
				c.b.c.protoErr.Add(1)
				c.log.Warn("unusable topic alias, closing", "err", err)
				c.kick(packets.RTopicAliasInvalid, err, false)
			case errors.Is(err, packets.ErrMalformed):
				c.b.c.malformed.Add(1)
				c.log.Warn("malformed packet, closing", "err", err)
				c.kick(packets.RMalformedPacket, err, false)
			case errors.Is(err, packets.ErrProtocol):
				c.b.c.protoErr.Add(1)
				c.log.Warn("protocol error, closing", "err", err)
				c.kick(packets.RProtocolError, err, false)
			default:
				c.fail(err)
			}
			return
		}
		if conn, ok := p.(*packets.Connect); ok {
			if v := packets.Version(conn.ProtocolLevel); v == packets.V5 {
				ver = v
			}
		}
		select {
		case c.in <- p:
		case <-c.done:
			return
		}
	}
}

// writeLoop owns the socket's buffered side. It ends when the session ends,
// which is the only honest signal it has: closing on the broker's shutdown
// context instead would race stateLoop, whose last act is to write the
// DISCONNECT that tells the peer why the broker went away.
func (c *client) writeLoop() {
	bw := bufio.NewWriterSize(c.conn, 4096)
	for {
		select {
		case <-c.done:
			c.flushOut(bw)
			_ = c.conn.Close()
			return
		case frame := <-c.out:
			c.connMu.Lock()
			_ = c.conn.SetWriteDeadline(time.Now().Add(c.b.opt.WriteTimeout))
			n, err := bw.Write(frame)
			if err == nil {
				// MQTT is latency sensitive, so every frame is flushed rather
				// than waiting for the buffer to fill.
				err = bw.Flush()
			}
			c.connMu.Unlock()
			c.b.c.bytesOut.Add(int64(n))
			if err != nil {
				c.log.Debug("write failed", "err", err)
				c.fail(err)
				_ = c.conn.Close()
				return
			}
		}
	}
}

// flushOut hands the peer the frames that were already accepted when the
// session ended. It holds connMu for the same reason writeLoop does: stateLoop
// may be writing a final DISCONNECT straight to the socket, and buffered bytes
// must not land after it.
func (c *client) flushOut(bw *bufio.Writer) {
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.b.opt.WriteTimeout))
	for {
		select {
		case frame := <-c.out:
			c.connMu.Lock()
			n, err := bw.Write(frame)
			if err == nil {
				err = bw.Flush()
			}
			c.connMu.Unlock()
			c.b.c.bytesOut.Add(int64(n))
			if err != nil {
				return
			}
		default:
			c.connMu.Lock()
			_ = bw.Flush()
			c.connMu.Unlock()
			return
		}
	}
}

func (c *client) stateLoop() {
	defer c.cleanup()

	retry := time.NewTicker(c.b.opt.RetryInterval)
	defer retry.Stop()
	idle := time.NewTimer(c.idTimeout())
	defer idle.Stop()

	for {
		select {
		case p := <-c.in:
			c.lastActivity = time.Now()
			if err := c.handle(p); err != nil {
				if !errors.Is(err, errNormal) {
					c.log.Info("session ended", "client", c.id, "err", err)
				}
				c.fail(c.endWith(err))
				return
			}
			// Re-armed after handling, so a CONNECT that changes the keep alive
			// takes effect immediately rather than at the next packet.
			// Go 1.23+ timers discard pending values on Reset.
			idle.Stop()
			idle.Reset(c.idTimeout())

		case f := <-c.faults:
			c.endFault(f)
			return

		case t := <-c.mailbox:
			if dropped := c.rt.push(t.msg); dropped > 0 {
				c.b.c.dropped.Add(int64(dropped))
				c.log.Warn("session queue overflow", "client", c.id, "dropped", dropped)
			}
			c.pump()

		case <-retry.C:
			c.resend()

		case <-idle.C:
			c.log.Warn("keepalive expired", "client", c.id, "keepalive", c.keepAlive())
			c.fail(c.endWith(ErrIdle))
			return

		case <-c.b.ctx.Done():
			// Shutdown tells every session why first, and that fault is usually
			// already queued by the time this arm wakes up. A select chooses
			// between ready arms at random, so look for it rather than letting
			// the peer's goodbye depend on a coin toss.
			if !c.drainFault() {
				// A session that was never registered gets no kick at all, so
				// it says the same thing here.
				c.graceful = true
				c.fail(c.endWith(ErrShuttingDown))
			}
			return

		case <-c.done:
			return
		}
	}
}

// endFault closes the session on someone else's decision: tell the peer why if
// the socket can still hear it, then stop.
func (c *client) endFault(f fault) {
	if f.noWill {
		c.graceful = true
	}
	c.log.Info("closing connection", "client", c.id, "err", f.err)
	c.announce(f.reason)
	c.fail(f.err)
}

// drainFault handles a queued fault that the select handed to another arm. It
// reports whether there was one.
func (c *client) drainFault() bool {
	select {
	case f := <-c.faults:
		c.endFault(f)
		return true
	default:
		return false
	}
}

// endWith explains an abrupt end to a 5.0 peer with a DISCONNECT packet before
// the caller closes the socket, then hands back the same error. 3.1.1 has no
// such packet, and a session that never got a CONNACK must not send one
// [MQTT-3.14.0-1], so both cases just return.
func (c *client) endWith(err error) error {
	// The read loop counts the protocol errors a frame cannot even be built
	// from; this is the other half, a packet that decoded cleanly and then broke
	// a rule the specification itself names a Protocol Error.
	if errors.Is(err, errProtocol) {
		c.b.c.protoErr.Add(1)
	}
	c.announce(disconnectReason(err))
	return err
}

// announce writes one DISCONNECT carrying the given reason code.
func (c *client) announce(reason byte) {
	if reason == 0 || c.rt == nil || !c.ver.Is5() {
		return
	}
	p := &packets.Disconnect{ReasonCode: reason}
	if c.b.pol.load().acl != nil && reason == packets.RNotAuthorized {
		p.Props = &packets.Properties{}
		p.Props.SetReasonString("not authorized")
	}
	if err := c.sendNow(p); err != nil {
		c.log.Debug("cannot send DISCONNECT", "err", err)
		return
	}
	c.b.c.kicked.Add(1)
}

func disconnectReason(err error) byte {
	var re reasonErr
	if errors.As(err, &re) {
		return re.reason
	}
	switch {
	case errors.Is(err, errNormal), errors.Is(err, errTakeover):
		return 0
	case errors.Is(err, ErrIdle):
		return packets.RKeepAliveTimeout
	case errors.Is(err, ErrSlowConsumer):
		return packets.RQuotaExceeded
	case errors.Is(err, ErrShuttingDown):
		return packets.RServerShuttingDown
	case errors.Is(err, ErrNotAuthorized):
		return packets.RNotAuthorized
	case errors.Is(err, packets.ErrMalformed):
		return packets.RMalformedPacket
	default:
		return packets.RProtocolError
	}
}

// sessionForStore lifts the live runtime into a store record. live says whether
// the connection is still up, which is the whole difference between an expiry
// clock that has started and one that has not.
func (c *client) sessionForStore(live bool) *store.Session {
	s := c.rt.snapshot()
	s.Proto = c.ver
	s.ExpiryInterval = c.sessionExpiry
	s.Live = live
	if live {
		// The runtime owns these until the connection ends, and the record's
		// share of them is filled back in by whoever writes the queue there.
		s.Queued = nil
		s.Inflight = nil
	} else if !c.sessionForever {
		s.Expiry = time.Now().Add(c.sessionExpiry)
	}
	if id := c.subject.Load(); id != nil {
		s.Username = id.Username
		if id.IP != nil {
			s.RemoteIP = id.IP.String()
		}
	}
	return s
}

// persistLive files this session while its connection is still up. Two things
// depend on it: the subscriptions have to outlive a broker that dies with a
// client connected - a device that does not resubscribe on reconnect would
// otherwise go deaf for good - and the record has to say the session was live, so
// its Session Expiry Interval counts from the restart instead of from a
// disconnect that never happened.
func (c *client) persistLive() {
	if !c.persist || c.rt == nil {
		return
	}
	c.b.saveLiveSession(c.sessionForStore(true))
}

// cleanup persists or discards the session, in that order: the connection is
// removed from the live map first, so any message the router spills afterwards
// goes to the store and merges with this snapshot instead of racing it.
func (c *client) cleanup() {
	if c.registered {
		c.b.unregister(c)
		c.registered = false
	}
	if c.rt != nil {
		if !c.persist {
			c.b.tree.UnsubscribeAll(c.id)
			c.b.dropSession(c.id)
		} else {
			c.b.mergeSession(c.sessionForStore(false))
		}
	}
	c.endWill()
	close(c.finished)
}

// endWill decides what becomes of the Will Message now that this connection is
// over. A normal DISCONNECT deletes it; an abrupt close publishes it at once,
// unless the session lives on and the client asked for a delay [MQTT-3.1.2-7].
func (c *client) endWill() {
	if c.will == nil || !c.hadSession {
		return
	}
	switch {
	case c.willRequested:
		c.b.fireWill(c.will, c.id)
	case c.graceful:
		// The client said goodbye, so its will is withdrawn.
	case !c.persist || c.willDelay <= 0:
		c.b.fireWill(c.will, c.id)
	default:
		c.b.scheduleWill(c.id, *c.will, c.willDelay)
	}
}

func (c *client) handle(p packets.Packet) error {
	if conn, ok := p.(*packets.Connect); ok {
		if c.rt != nil {
			return fmt.Errorf("%w: a second CONNECT on an open session", errProtocol)
		}
		return c.onConnect(conn)
	}
	if c.rt == nil {
		return fmt.Errorf("%w: %s before CONNECT", errProtocol, p.Type())
	}
	switch p := p.(type) {
	case *packets.Publish:
		return c.onPublish(p)
	case *packets.Puback:
		return c.onPuback(p)
	case *packets.Pubrec:
		return c.onPubrec(p)
	case *packets.Pubrel:
		return c.onPubrel(p)
	case *packets.Pubcomp:
		return c.onPubcomp(p)
	case *packets.Subscribe:
		return c.onSubscribe(p)
	case *packets.Unsubscribe:
		return c.onUnsubscribe(p)
	case *packets.Pingreq:
		return c.send(&packets.Pingresp{})
	case *packets.Disconnect:
		c.graceful = true
		if c.ver.Is5() {
			c.readDisconnect(p)
		}
		return errNormal
	case *packets.Auth:
		// Extended authentication is a handshake this broker does not offer; its
		// rules files decide a CONNECT in one exchange.
		return reasonErr{packets.RBadAuthenticationMethod,
			fmt.Errorf("%w: AUTH is not supported, connect with credentials", errProtocol)}
	case *packets.Connack, *packets.Suback, *packets.Unsuback, *packets.Pingresp:
		return fmt.Errorf("%w: client sent %s, which only a server may send", errProtocol, p.Type())
	default:
		return fmt.Errorf("%w: %s", errProtocol, p.Type())
	}
}

// readDisconnect applies the two things a 5.0 DISCONNECT can carry that change
// the session: a request to publish the will anyway, and a new expiry.
func (c *client) readDisconnect(p *packets.Disconnect) {
	if p.ReasonCode == packets.RDisconnectWithWill {
		c.willRequested = true
	}
	if p.Props != nil && p.Props.Has(packets.PropSessionExpiry) {
		c.applySessionExpiry(p.Props.SessionExpiry)
	}
}

// sendNow writes one frame straight to the socket.
func (c *client) sendNow(p packets.Packet) error {
	frame, err := packets.EncodeBytesVersion(c.ver, p)
	if err != nil {
		return err
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.b.opt.WriteTimeout))
	n, err := c.conn.Write(frame)
	c.b.c.bytesOut.Add(int64(n))
	return err
}

// refuse answers a CONNECT with a verdict and ends the handshake. The reply is
// written here rather than handed to writeLoop because the caller closes the
// socket as soon as this returns, and that close would race the frame away.
// Only pre-session refusals use it, when nothing else can be on its way.
func (c *client) refuse(code byte, reason string, cause error) error {
	ack := &packets.Connack{ReturnCode: code}
	if c.ver.Is5() && reason != "" {
		ack.Props = &packets.Properties{}
		ack.Props.SetReasonString(reason)
	}
	if err := c.sendNow(ack); err != nil {
		c.log.Debug("cannot send CONNACK", "err", err)
	}
	return cause
}

func (c *client) onConnect(p *packets.Connect) error {
	ver := packets.Version(p.ProtocolLevel)
	// A refusal has to be written in an encoding the client can read, so a peer
	// that claims 5.0 or newer gets a 5.0 CONNACK even when its name or level
	// was unusable [MQTT-3.1.2-1].
	if p.ProtocolName != packets.ProtocolName {
		if ver >= packets.V5 {
			c.ver = packets.V5
		}
		return c.refuse(packets.ConnBadProtocol, fmt.Sprintf("protocol name %q is not MQTT", p.ProtocolName),
			fmt.Errorf("%w: protocol %q is not MQTT", errProtocol, p.ProtocolName))
	}
	if ver != packets.V311 && ver != packets.V5 {
		if ver > packets.V5 {
			c.ver = packets.V5
		}
		return c.refuse(packets.ConnBadProtocol, fmt.Sprintf("level %d is neither 3.1.1 nor 5.0", p.ProtocolLevel),
			fmt.Errorf("%w: protocol level %d is not supported", errProtocol, p.ProtocolLevel))
	}
	c.ver = ver

	if err := c.negotiate(p); err != nil {
		return err
	}

	clientID := p.ClientID
	assigned := ""
	if clientID == "" {
		if !ver.Is5() {
			// 3.1.1 gives the server no way to report an assigned identifier
			// back, so an empty one cannot be honoured.
			return c.refuse(packets.ConnIDRejected, "3.1.1 has no way to assign a client identifier",
				fmt.Errorf("%w: empty client identifier", errProtocol))
		}
		clientID = newClientID()
		assigned = clientID
	}
	// The limit is checked here rather than at accept so a refused client
	// learns why instead of watching the socket disappear mid-handshake.
	if max := c.b.opt.MaxConns; max > 0 && int(c.b.c.online.Load()) >= max {
		c.b.c.rejected.Add(1)
		return c.refuse(packets.ConnUnavailable, "this broker is at capacity",
			fmt.Errorf("%w: at capacity (%d connections)", errProtocol, max))
	}

	c.id = clientID
	c.keepAliveValue = time.Duration(p.KeepAlive) * time.Second

	id := subjectOf(p, c.ip, c.certCN)
	c.subject.Store(&id)
	if !c.b.authenticate(id, string(p.Password)) {
		// 0x04 is what a client expects for a credential failure; the reason
		// stays in the log so the wire never reveals whether the username or
		// the password was the wrong half.
		return c.refuse(packets.ConnBadCredentials, "bad user name or password",
			fmt.Errorf("%w: credentials for client %q user %q rejected", ErrNotAuthorized, clientID, p.Username))
	}

	c.armWill(p)

	// A takeover must finish before this session reads the store, otherwise the
	// old connection would flush over the messages being loaded here.
	if old := c.b.lookup(c.id); old != nil {
		old.kick(packets.RSessionTakenOver, errTakeover, false)
		select {
		case <-old.finished:
		case <-time.After(c.b.opt.WriteTimeout + c.b.opt.DeliverTimeout):
			c.log.Warn("previous session did not finish in time", "client", c.id)
		}
	}
	// A delayed will of the session we continue is withdrawn; one of the session
	// we are discarding is published, because discarding ends it [MQTT-3.1.3-9].
	c.b.resolvePendingWill(c.id, !c.discard)

	sessionPresent := c.startSession()

	// Registering before the tree is reinstalled matters: while the session is
	// live the router hands it messages directly, so nothing published in this
	// window can be spilled to the store and left there until the next connect.
	prev := c.b.register(c)
	if prev != nil && prev != c {
		// Only reachable if two CONNECTs raced; the newer one wins.
		prev.kick(packets.RSessionTakenOver, errTakeover, false)
	}
	c.registered = true
	c.hadSession = true
	c.reinstallSubs()

	ack := &packets.Connack{
		SessionPresent: sessionPresent,
		ReturnCode:     packets.ConnAccepted,
		Props:          c.connackProps(assigned),
	}
	if err := c.send(ack); err != nil {
		return err
	}
	c.log.Info("client connected",
		"client", c.id, "proto", c.ver.String(), "clean", c.discard, "persist", c.persist,
		"keepalive", c.keepAlive(), "session_present", sessionPresent,
		"queued", c.rt.depth(), "inflight", c.rt.inflightCount(),
		"peer_receive_max", c.peerReceiveMax, "peer_alias_max", c.peerAliasMax)
	c.restream()
	c.pump()
	return nil
}

// negotiate reads the CONNECT properties that shape this connection: the peer's
// own limits and how long its session should outlive the socket.
func (c *client) negotiate(p *packets.Connect) error {
	c.peerReceiveMax = defaultReceiveMax
	c.discard = p.CleanSession
	if !c.ver.Is5() {
		c.persist = !p.CleanSession
		// A 3.1.1 session has no expiry: it waits forever for its client.
		c.sessionForever = c.persist
		return nil
	}
	props := p.Props
	if props == nil {
		props = &packets.Properties{}
	}
	if props.Has(packets.PropReceiveMaximum) {
		c.peerReceiveMax = int(props.ReceiveMax)
	}
	c.peerAliasMax = props.TopicAliasMax
	c.peerMaxPacket = props.MaxPacketSize
	c.applySessionExpiry(props.SessionExpiry)
	c.persist = c.sessionForever || c.sessionExpiry > 0
	return nil
}

// applySessionExpiry turns a requested Session Expiry Interval into this
// session's lifetime, clamped by whatever the operator allows. The all-ones
// value means the session is never reaped.
func (c *client) applySessionExpiry(seconds uint32) {
	switch {
	case seconds == 0xFFFFFFFF:
		c.sessionExpiry = 0
		c.sessionForever = true
	case c.b.opt.SessionExpiryMax > 0 && time.Duration(seconds)*time.Second > c.b.opt.SessionExpiryMax:
		c.sessionExpiry = c.b.opt.SessionExpiryMax
		c.sessionForever = false
	default:
		c.sessionExpiry = time.Duration(seconds) * time.Second
		c.sessionForever = false
	}
}

// connackProps advertises what this broker will do for a 5.0 client. Anything a
// client may assume by default is left out to keep the packet small; the
// properties that change the client's behaviour are always sent.
func (c *client) connackProps(assigned string) *packets.Properties {
	if !c.ver.Is5() {
		return nil
	}
	p := &packets.Properties{}
	p.SetReceiveMax(clamp16(c.b.opt.ReceiveMax))
	if c.b.opt.MaxQoS < packets.QoS2 {
		p.SetMaxQoS(c.b.opt.MaxQoS)
	}
	if c.b.opt.MaxPacketSize > 0 {
		p.SetMaxPacketSize(c.b.opt.MaxPacketSize)
	}
	if c.b.opt.TopicAliasMax > 0 {
		p.SetTopicAliasMax(c.b.opt.TopicAliasMax)
	}
	// Wildcards, retained messages and shared subscriptions are all supported,
	// which is the default, so only the subscription identifier is asserted.
	p.SetSubIDAvail(1)
	if assigned != "" {
		p.SetAssignedClientID(assigned)
	}
	return p
}

// clamp16 fits a count into the two-byte field the protocol advertises it in.
func clamp16(n int) uint16 {
	switch {
	case n > 0xFFFF:
		return 0xFFFF
	case n < 0:
		return 0
	default:
		return uint16(n)
	}
}

// newClientID mints an identifier for a 5.0 client that connected without one.
// The peer learns it from the Assigned Client Identifier CONNACK property.
func newClientID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("anon-%d", time.Now().UnixNano())
	}
	return "anon-" + hex.EncodeToString(b[:])
}

// armWill stores this connection's will, honouring the will properties a 5.0
// client can attach to it. An unusable will is dropped rather than refusing the
// connection, because a client that cannot publish a topic while connected must
// certainly not get to publish it by dying.
func (c *client) armWill(p *packets.Connect) {
	if !p.HasWill {
		return
	}
	if err := topics.ValidName(p.WillTopic); err != nil {
		c.log.Warn("will topic is unusable, dropping will", "client", c.id, "err", err)
		return
	}
	if !c.b.allowPublish(c.identity(), p.WillTopic) {
		c.log.Warn("client may not publish its will topic, dropping will", "client", c.id, "topic", p.WillTopic)
		return
	}
	msg := store.Message{
		Topic:   p.WillTopic,
		Payload: p.WillPayload,
		QoS:     min(p.WillQoS, c.b.opt.MaxQoS),
		Retain:  p.WillRetain,
		Dir:     store.Outbound,
	}
	if c.ver.Is5() && p.WillProps != nil {
		if p.WillProps.Has(packets.PropWillDelay) {
			c.willDelay = time.Duration(p.WillProps.WillDelay) * time.Second
		}
		if p.WillProps.Has(packets.PropMessageExpiry) {
			msg.Expires = time.Now().Add(time.Duration(p.WillProps.MessageExpiry) * time.Second)
		}
		props := p.WillProps.Clone()
		props.Clear(packets.PropWillDelay)
		props.Clear(packets.PropMessageExpiry)
		if props.IsEmpty() {
			props = nil
		}
		msg.Props = props
	}
	c.will = &msg
}

// startSession builds the runtime, either fresh or from the stored session, and
// reports whether the broker is continuing a session it already had.
func (c *client) startSession() bool {
	window := c.b.opt.InflightWindow
	if c.ver.Is5() {
		// Our own outbound window must respect the peer's Receive Maximum, which
		// counts the QoS 1 and 2 messages still awaiting acknowledgement.
		window = min(window, c.peerReceiveMax)
	}
	queueMax := c.b.opt.QueueMax

	if c.discard {
		c.b.dropSession(c.id)
		c.b.tree.UnsubscribeAll(c.id)
		c.rt = newRuntime(c.id, window, queueMax)
		return false
	}
	stored, ok := c.b.store.Get(c.id)
	if ok && !c.expiredSession(stored) {
		c.rt = loadRuntime(stored, window, queueMax)
		// Everything the record held is now in the runtime, so the record is
		// brought down to what only a record can hold.
		c.b.takeOverStoredSession(c.sessionForStore(true))
		if c.ver.Is5() {
			// A Session exists even when the rest of its state is empty.
			return true
		}
		return len(c.rt.inflight) > 0 || len(c.rt.queue) > 0
	}
	if ok {
		// The reaper had not got to it yet; treat it as gone.
		c.b.dropSession(c.id)
		c.b.tree.UnsubscribeAll(c.id)
	}
	c.rt = newRuntime(c.id, window, queueMax)
	return false
}

// reinstallSubs points the topic tree at the subscriptions a continuing session
// already had, so a publisher reaches this client without it sending a SUBSCRIBE.
func (c *client) reinstallSubs() {
	if c.rt == nil {
		return
	}
	for filter, sub := range c.rt.subs {
		if err := c.b.tree.Subscribe(filter, c.id, subOptions(sub)); err != nil {
			c.log.Warn("cannot reinstall subscription", "client", c.id, "filter", filter, "err", err)
		}
	}
}

func (c *client) expiredSession(s *store.Session) bool {
	return !s.Expiry.IsZero() && !time.Now().Before(s.Expiry)
}

// restream re-sends everything still awaiting acknowledgement, oldest first,
// as soon as a session comes back. Those messages were published before the
// queued ones, so letting the queue overtake them would reorder the stream.
func (c *client) restream() {
	if c.rt == nil {
		return
	}
	now := time.Now()
	for _, id := range append([]uint16(nil), c.rt.order...) {
		t := c.rt.inflight[id]
		if t == nil {
			continue
		}
		t.attempts++
		t.sentAt = now
		t.msg.Dup = true
		switch {
		case t.msg.QoS == packets.QoS1, t.stage == store.StageAwaitPubRec:
			if err := c.sendFrame(t); err != nil {
				c.dropUnsendable(t, err)
			}
		case t.stage == store.StageAwaitPubComp:
			_ = c.send(&packets.Pubrel{PacketID: id})
		}
	}
}

func (c *client) onSubscribe(p *packets.Subscribe) error {
	codes := make([]byte, len(p.Subscriptions))
	subID := 0
	if c.ver.Is5() && p.Props != nil && len(p.Props.SubscriptionIDs) > 0 {
		// A client may send more than one Subscription Identifier; section 3.3.4
		// asks the Server to use the last one.
		subID = p.Props.SubscriptionIDs[len(p.Props.SubscriptionIDs)-1]
	}
	for i, sub := range p.Subscriptions {
		existed := c.subscribed(sub.TopicFilter)
		code, ok := c.grant(sub, subID)
		codes[i] = code
		if ok {
			c.sendRetained(sub, existed)
		}
	}
	// The subscriptions are on record before the client is told they exist: a
	// SUBACK that promises a durable session must not be answered from memory the
	// broker is about to lose.
	c.persistLive()
	// SUBACK carries the verdicts in the same field for both versions: 3.1.1
	// return codes and 5.0 reason codes share the payload, and 0x00..0x02 mean
	// "granted at this QoS" in each.
	return c.send(&packets.Suback{PacketID: p.PacketID, ReturnCodes: codes})
}

// subscribed reports whether the session already held this filter, which is the
// question Retain Handling 1 asks.
func (c *client) subscribed(filter string) bool {
	_, ok := c.rt.subs[filter]
	return ok
}

// grant validates one requested subscription and files it, returning the reason
// code the client is told and whether the subscription was actually made.
func (c *client) grant(sub packets.Subscription, subID int) (byte, bool) {
	if err := topics.ValidFilter(sub.TopicFilter); err != nil {
		c.log.Warn("subscription rejected", "client", c.id, "filter", sub.TopicFilter, "err", err)
		return c.refuseCode(packets.RTopicFilterInvalid), false
	}
	// A shared subscription is authorized for the filter it actually covers;
	// the "$share/{group}" wrapper is a delivery detail, not a new topic space
	// an operator would write a rule about.
	_, wanted, _ := topics.SplitShared(sub.TopicFilter)
	if !c.b.allowSubscribe(c.identity(), wanted) {
		c.log.Warn("subscription refused by acl", "client", c.id, "filter", sub.TopicFilter)
		return c.refuseCode(packets.RNotAuthorized), false
	}
	granted := min(sub.MaxQoS, c.b.opt.MaxQoS)
	stored := store.Sub{
		QoS:               granted,
		NoLocal:           sub.NoLocal,
		RetainAsPublished: sub.RetainAsPublished,
		RetainHandling:    sub.RetainHandling,
		ID:                subID,
	}
	if err := c.b.tree.Subscribe(sub.TopicFilter, c.id, subOptions(stored)); err != nil {
		c.log.Warn("subscription rejected", "client", c.id, "filter", sub.TopicFilter, "err", err)
		return c.refuseCode(packets.RTopicFilterInvalid), false
	}
	c.rt.subs[sub.TopicFilter] = stored
	return granted, true
}

// refuseCode translates a 5.0 reason code into the one thing a 3.1.1 subscriber
// can be told: that the subscription failed.
func (c *client) refuseCode(five byte) byte {
	if !c.ver.Is5() {
		return packets.SubAckFailure
	}
	return five
}

// sendRetained replays the stored messages a new subscription asks for. Retain
// Handling 0 always sends them, 1 only when the subscription is new, 2 never
// [MQTT-3.3.1-9, -10, -11].
func (c *client) sendRetained(sub packets.Subscription, existed bool) {
	// A shared subscription inherits the {filter} component's matching but is
	// sent no retained messages when it is first made, so this stops here
	// rather than relying on "$share" never matching a topic name.
	if _, _, shared := topics.SplitShared(sub.TopicFilter); shared {
		return
	}
	switch sub.RetainHandling {
	case 2:
		return
	case 1:
		if existed {
			return
		}
	}
	stored, ok := c.rt.subs[sub.TopicFilter]
	if !ok {
		return
	}
	c.b.deliverRetained(c, sub.TopicFilter, stored)
}

func (c *client) onUnsubscribe(p *packets.Unsubscribe) error {
	codes := make([]byte, 0, len(p.TopicFilters))
	for _, filter := range p.TopicFilters {
		removed := c.b.tree.Unsubscribe(filter, c.id)
		if removed {
			delete(c.rt.subs, filter)
		}
		if c.ver.Is5() {
			if removed {
				codes = append(codes, packets.RSuccess)
			} else {
				codes = append(codes, packets.RNoSubscriptionExisted)
			}
		}
	}
	// An unsubscribe has to reach the record too: unioning subscriptions back in
	// from it is how a filter the client removed comes back after a reconnect.
	c.persistLive()
	ack := &packets.Unsuback{PacketID: p.PacketID}
	if c.ver.Is5() {
		ack.ReasonCodes = codes
	}
	return c.send(ack)
}

func (c *client) onPublish(p *packets.Publish) error {
	topic := p.Topic
	if c.ver.Is5() {
		resolved, err := c.resolveAlias(p)
		if err != nil {
			return err
		}
		topic = resolved
	}
	if err := topics.ValidName(topic); err != nil {
		if !c.ver.Is5() {
			return fmt.Errorf("%w: %v", errProtocol, err)
		}
		// A 5.0 publisher is told its name was useless and the message is
		// discarded, which keeps the connection alive for everything else it
		// was doing.
		c.log.Warn("topic name rejected", "client", c.id, "topic", topic, "err", err)
		return c.ackRefused(p, packets.RTopicNameInvalid)
	}
	if p.QoS > c.b.opt.MaxQoS {
		return reasonErr{packets.RQoSNotSupported,
			fmt.Errorf("%w: QoS %d is above this broker's maximum %d", errProtocol, p.QoS, c.b.opt.MaxQoS)}
	}
	c.b.c.msgsIn.Add(1)

	// A refused PUBLISH is dropped, but its handshake still completes: 3.1.1 has
	// no "you may not publish that" code, and leaving a QoS 1 or 2 message
	// unacknowledged would make the client retry it forever.
	if !c.b.allowPublish(c.identity(), topic) {
		c.log.Debug("publish refused by acl", "client", c.id, "topic", topic)
		return c.ackRefused(p, packets.RNotAuthorized)
	}

	msg := c.incomingMessage(p, topic)

	switch p.QoS {
	case packets.QoS0:
		c.b.route(msg, c.id)
		return nil

	case packets.QoS1:
		sent := c.b.route(msg, c.id)
		return c.ackPublish(p, packets.RSuccess, sent == 0)

	case packets.QoS2:
		if _, seen := c.rt.recv[p.PacketID]; seen {
			// Replayed PUBLISH (DUP) for a handshake already in progress: the
			// message is stored but must not be delivered twice.
			return c.send(&packets.Pubrec{PacketID: p.PacketID})
		}
		// Receive Maximum is the count of our own outstanding handshakes, so it
		// is measured against the window this CONNACK advertised, not the peer's.
		if len(c.rt.recv) >= c.b.opt.ReceiveMax {
			return reasonErr{packets.RReceiveMaximumExceeded,
				fmt.Errorf("%w: more than %d QoS 1 and 2 messages await acknowledgement", errProtocol, c.b.opt.ReceiveMax)}
		}
		c.rt.recv[p.PacketID] = &task{msg: msg, stage: store.StageAwaitPubRel}
		return c.send(&packets.Pubrec{PacketID: p.PacketID, ReasonCode: c.wireCode(packets.RSuccess)})
	}
	return fmt.Errorf("%w: reserved QoS %d", errProtocol, p.QoS)
}

// incomingMessage turns a PUBLISH into the stored form the router forwards. The
// publisher's own view of its message does not travel: its alias, its expiry
// countdown and any subscription identifier it tried to smuggle in are stripped,
// and the expiry becomes a deadline this broker owns.
func (c *client) incomingMessage(p *packets.Publish, topic string) store.Message {
	msg := store.Message{
		Topic:   topic,
		Payload: p.Payload,
		QoS:     p.QoS,
		Retain:  p.Retain,
	}
	if !c.ver.Is5() || p.Props == nil {
		return msg
	}
	if p.Props.Has(packets.PropMessageExpiry) {
		msg.Expires = time.Now().Add(time.Duration(p.Props.MessageExpiry) * time.Second)
	}
	props := p.Props.Clone()
	props.Clear(packets.PropTopicAlias)
	props.Clear(packets.PropMessageExpiry)
	props.Clear(packets.PropSubscriptionID)
	if props.IsEmpty() {
		props = nil
	}
	msg.Props = props
	return msg
}

// ackPublish answers a QoS 1 or 2 PUBLISH. A 3.1.1 client gets a bare
// acknowledgement; a 5.0 one gets the reason code, which is how it learns that
// nothing wanted its message or that the broker refused to carry it.
func (c *client) ackPublish(p *packets.Publish, code byte, noSubscribers bool) error {
	if noSubscribers && code == packets.RSuccess {
		code = packets.RNoMatchingSubscribers
	}
	if p.QoS == packets.QoS1 {
		return c.send(&packets.Puback{PacketID: p.PacketID, ReasonCode: c.wireCode(code)})
	}
	return c.send(&packets.Pubrec{PacketID: p.PacketID, ReasonCode: c.wireCode(code)})
}

// ackRefused closes the handshake of a message this broker will not carry. A
// QoS 0 PUBLISH has no acknowledgement, so the drop is silent for both
// versions - only a refused QoS 1 or 2 needs a reply.
func (c *client) ackRefused(p *packets.Publish, code byte) error {
	if p.QoS == packets.QoS0 {
		return nil
	}
	return c.ackPublish(p, code, false)
}

// wireCode keeps the reason code off a 3.1.1 acknowledgement, where the encoder
// would otherwise be asked to write a byte that has no place in the packet.
func (c *client) wireCode(code byte) byte {
	if !c.ver.Is5() {
		return 0
	}
	return code
}

func (c *client) onPubrel(p *packets.Pubrel) error {
	code := c.wireCode(packets.RSuccess)
	t, ok := c.rt.recv[p.PacketID]
	if ok {
		c.b.route(t.msg, c.id)
		delete(c.rt.recv, p.PacketID)
	} else {
		c.log.Debug("PUBREL for an unknown identifier", "client", c.id, "packet_id", p.PacketID)
		code = c.wireCode(packets.RPacketIdentifierNotFound)
	}
	// The PUBCOMP is sent either way so a client that lost our PUBREC can move on.
	return c.send(&packets.Pubcomp{PacketID: p.PacketID, ReasonCode: code})
}

func (c *client) onPuback(p *packets.Puback) error {
	if t := c.rt.release(p.PacketID); t == nil {
		c.log.Debug("PUBACK for an unknown identifier", "client", c.id, "packet_id", p.PacketID)
		return nil
	}
	c.pump()
	return nil
}

func (c *client) onPubcomp(p *packets.Pubcomp) error {
	if t := c.rt.release(p.PacketID); t == nil {
		c.log.Debug("PUBCOMP for an unknown identifier", "client", c.id, "packet_id", p.PacketID)
		return nil
	}
	c.pump()
	return nil
}

func (c *client) onPubrec(p *packets.Pubrec) error {
	t := c.rt.inflight[p.PacketID]
	if t == nil {
		c.log.Debug("PUBREC for an unknown identifier", "client", c.id, "packet_id", p.PacketID)
		return nil
	}
	if t.msg.QoS != packets.QoS2 {
		return fmt.Errorf("%w: PUBREC for a QoS %d message", errProtocol, t.msg.QoS)
	}
	t.stage = store.StageAwaitPubComp
	t.sentAt = time.Now()
	t.attempts++
	return c.send(&packets.Pubrel{PacketID: p.PacketID})
}

// pump moves queued messages into the unacknowledged window and onto the
// socket, oldest first.
func (c *client) pump() {
	for {
		if c.rt.windowFree() <= 0 {
			return
		}
		t := c.rt.take()
		if t == nil {
			return
		}

		if t.msg.QoS == packets.QoS0 {
			if err := c.sendFrame(t); err != nil && !unsendable(err) {
				// Losing a QoS 0 message is what QoS 0 means.
				c.b.c.dropped.Add(1)
				c.log.Debug("dropped QoS 0 message", "client", c.id, "err", err)
			}
			continue
		}

		if t.msg.PacketID == 0 {
			id, ok := c.rt.allocID()
			if !ok {
				c.rt.requeueFront(t)
				return
			}
			t.msg.PacketID = id
		}
		t.msg.Dup = t.attempts > 0
		if t.msg.QoS == packets.QoS2 {
			t.stage = store.StageAwaitPubRec
		}
		c.rt.markInflight(t)
		t.sentAt = time.Now()

		if err := c.sendFrame(t); err != nil {
			if unsendable(err) {
				// The peer can never take this one, so forget it and let the
				// messages behind it through.
				c.dropUnsendable(t, err)
				continue
			}
			// The task stays in the window; cleanup flushes it to the store so
			// the next connect resends it.
			c.log.Warn("cannot queue outbound message", "client", c.id, "err", err)
			return
		}
	}
}

// unsendable reports an error that means this message must be forgotten rather
// than retried: it died while it waited, or it is bigger than the peer allows.
func unsendable(err error) bool {
	return errors.Is(err, errExpired) || errors.Is(err, errTooLarge)
}

// dropUnsendable frees the window slot a message that cannot be sent was
// holding. MQTT-3.1.2-25 asks a server to behave as if it had completed sending
// such a message, which is exactly a release and a move along the queue.
func (c *client) dropUnsendable(t *task, err error) {
	c.rt.release(t.msg.PacketID)
	if errors.Is(err, errTooLarge) {
		c.b.c.tooBig.Add(1)
		c.b.c.dropped.Add(1)
		c.log.Info("dropped a message larger than the peer accepts",
			"client", c.id, "topic", t.msg.Topic, "max", c.peerMaxPacket)
	}
}

// resend re-sends messages the peer has not acknowledged.
func (c *client) resend() {
	if c.rt == nil {
		return
	}
	now := time.Now()
	due := c.rt.due(now, c.b.opt.RetryInterval)
	if len(due) == 0 {
		return
	}
	for _, t := range due {
		t.attempts++
		t.sentAt = now
		t.msg.Dup = true
		switch {
		case t.msg.QoS == packets.QoS1:
			if err := c.sendFrame(t); err != nil {
				c.dropUnsendable(t, err)
			}
		case t.msg.QoS == packets.QoS2 && t.stage == store.StageAwaitPubRec:
			if err := c.sendFrame(t); err != nil {
				c.dropUnsendable(t, err)
			}
		case t.msg.QoS == packets.QoS2 && t.stage == store.StageAwaitPubComp:
			_ = c.send(&packets.Pubrel{PacketID: t.msg.PacketID})
		}
		c.log.Debug("resending unacknowledged message",
			"client", c.id, "packet_id", t.msg.PacketID, "attempts", t.attempts)
	}
	// Messages the peer never acknowledges are retried until it reconnects, so
	// the queue behind them waits too.
	c.pump()
}

func (c *client) sendFrame(t *task) error {
	p := c.publishPacket(t)
	if p == nil {
		return errExpired
	}
	frame, err := packets.EncodeBytesVersion(c.ver, p)
	if err != nil {
		return err
	}
	if c.peerMaxPacket > 0 && uint64(len(frame)) > uint64(c.peerMaxPacket) {
		return errTooLarge
	}
	c.b.c.msgsOut.Add(1)
	return c.push(frame)
}

func (c *client) send(p packets.Packet) error {
	frame, err := packets.EncodeBytesVersion(c.ver, p)
	if err != nil {
		return err
	}
	return c.push(frame)
}

// push hands a frame to writeLoop. It blocks when the socket is stalled, which
// is the intended backpressure: writeLoop gives up after WriteTimeout, closes
// the connection and unblocks this call through c.done.
func (c *client) push(frame []byte) error {
	select {
	case c.out <- frame:
		return nil
	case <-c.done:
		return c.connError()
	case <-c.b.ctx.Done():
		return errors.New("congmq: broker is shutting down")
	}
}

func (c *client) connError() error {
	if c.cause != nil {
		return c.cause
	}
	return errNormal
}

// deliver is the router's entry point into this session. It returns false when
// the message could not be handed over, and the caller must then store it.
//
// It never watches c.faults: a fault is stateLoop's to read, and picking it off
// the channel here would leave the session to close without its DISCONNECT.
func (c *client) deliver(msg store.Message) bool {
	t := &task{msg: msg}
	select {
	case c.mailbox <- t:
		return true
	case <-c.done:
		return false
	default:
	}

	// Mailbox full: give the session goroutine a bounded chance to catch up.
	deadline := time.NewTimer(c.b.opt.DeliverTimeout)
	defer deadline.Stop()
	select {
	case c.mailbox <- t:
		return true
	case <-c.done:
		return false
	case <-deadline.C:
		c.log.Warn("disconnecting a subscriber that stopped reading", "client", c.id)
		c.kick(packets.RQuotaExceeded, ErrSlowConsumer, false)
		return false
	}
}
