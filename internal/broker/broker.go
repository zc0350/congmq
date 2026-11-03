// Package broker wires the packet codec, the topic tree and the session store
// into a single-machine MQTT 3.1.1 server.
package broker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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

// Options configures a Broker.
type Options struct {
	// ID names this broker in logs.
	ID string
	// Store keeps persistent sessions. Defaults to an in-memory store.
	Store store.Store
	// Durable keeps what belongs to no session: the retained message of a topic
	// and a will still waiting out its delay. With nil both live only as long as
	// the process does, and a restart loses them. A store.FileStore is both.
	Durable store.Durable
	// Auth, when set, must accept a client's credentials before its CONNECT is
	// honoured. With nil, every client is taken at its word. This is the boot-time
	// copy: decisions read the generation SetRules installs.
	Auth *rules.Authenticator
	// ACL, when set, decides every publish, subscribe and delivery. With nil,
	// everything the client asked for is granted.
	ACL *rules.ACL
	// QueueMax caps queued messages per offline session. Oldest are dropped
	// once the cap is reached.
	QueueMax int
	// InflightWindow is how many unacknowledged QoS 1/2 messages the broker
	// keeps outstanding per client before holding the rest in its queue.
	InflightWindow int
	// MailboxSize is the per-connection channel depth between the router and
	// the session goroutine.
	MailboxSize int
	// MaxConns caps open connections; 0 means unlimited.
	MaxConns int
	// RetryInterval is how often unacknowledged outbound messages are resent.
	RetryInterval time.Duration
	// WriteTimeout bounds a single frame write before the peer is considered
	// stuck.
	WriteTimeout time.Duration
	// DeliverTimeout bounds how long the router waits for a slow subscriber's
	// mailbox before disconnecting it.
	DeliverTimeout time.Duration
	// Logger receives broker events. Defaults to slog.Default().
	Logger *slog.Logger

	// --- MQTT 5.0 capabilities ---

	// ReceiveMax is advertised in CONNACK: how many QoS 1 and QoS 2 PUBLISH
	// packets this broker processes concurrently from one client. A client that
	// exceeds it is disconnected with 0x93.
	ReceiveMax int
	// TopicAliasMax is advertised in CONNACK: the highest alias number a client
	// may use on a connection. 0 turns inbound aliases off.
	TopicAliasMax uint16
	// MaxPacketSize is advertised in CONNACK and enforced on every incoming
	// packet. 0 means only the protocol's own 256MB limit applies.
	MaxPacketSize uint32
	// MaxQoS caps the quality of service this broker grants and advertises in
	// CONNACK. Zero means the default of 2; set 1 to run a broker that does not
	// accept QoS 2.
	MaxQoS byte
	// SessionExpiryMax clamps the Session Expiry Interval a client may ask for.
	// 0 honours any value, including "never expires".
	SessionExpiryMax time.Duration
	// ReapInterval is how often the broker looks for offline sessions whose
	// Session Expiry Interval has passed and delayed wills that are due.
	ReapInterval time.Duration

	// --- transport security ---

	// TLSConfig turns the TLS listener on. It must carry a certificate: a config
	// without one fails every handshake, so ListenTLS refuses it at bind time
	// instead of letting a broker that accepts no connections start.
	TLSConfig *tls.Config
	// HandshakeTimeout bounds one TLS handshake. A peer that only completes the
	// TCP part would otherwise hold a goroutine and a socket for as long as it
	// liked, which is the cheapest denial of service there is.
	HandshakeTimeout time.Duration
}

func (o *Options) withDefaults() {
	if o.ID == "" {
		o.ID = "congmq"
	}
	if o.Store == nil {
		o.Store = store.NewMemoryStore()
	}
	if o.QueueMax <= 0 {
		o.QueueMax = 1000
	}
	if o.InflightWindow <= 0 {
		o.InflightWindow = 100
	}
	if o.MailboxSize <= 0 {
		o.MailboxSize = 256
	}
	if o.RetryInterval <= 0 {
		o.RetryInterval = 5 * time.Second
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = 10 * time.Second
	}
	if o.DeliverTimeout <= 0 {
		o.DeliverTimeout = 5 * time.Second
	}
	if o.ReceiveMax <= 0 {
		o.ReceiveMax = 100
	}
	if o.MaxQoS == 0 || o.MaxQoS > packets.QoS2 {
		o.MaxQoS = packets.QoS2
	}
	if o.ReapInterval <= 0 {
		o.ReapInterval = 10 * time.Second
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 10 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// Errors that end a connection.
var (
	// ErrSlowConsumer is returned when a subscriber stops reading from its
	// socket. MQTT 3.1.1 defines no flow control, so the broker protects the
	// publisher by dropping the subscriber; its session is persisted first.
	ErrSlowConsumer  = errors.New("congmq: subscriber is too slow")
	ErrIdle          = errors.New("congmq: keepalive expired")
	ErrNotAuthorized = errors.New("congmq: not authorized")
	ErrShuttingDown  = errors.New("congmq: broker is shutting down")
)

// Broker accepts MQTT connections.
type Broker struct {
	opt Options
	log *slog.Logger

	tree   *topics.Tree
	store  store.Store
	retain *retainedStore

	mu sync.RWMutex
	// live maps a client identifier to its connected session.
	live map[string]*client

	// offlineMu serialises read-modify-write of a stored session, so a
	// message spilled by the router and a session flushed by its goroutine
	// cannot clobber each other.
	offlineMu sync.Mutex

	// willMu guards the delayed wills of clients that set a Will Delay
	// Interval. A pending will survives the session it came from.
	willMu sync.Mutex
	wills  map[string]pendingWill

	listener net.Listener
	// tlsListener and tlsCfg belong to the secure port. They are set by
	// ListenTLS before Serve, exactly as listener is set by Listen.
	tlsListener net.Listener
	tlsCfg      *tls.Config
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	started     atomic.Bool
	// stopping is set the moment Shutdown begins draining: the listeners are
	// going away and sessions are being flushed, which is exactly the window a
	// load balancer must stop routing to.
	stopping atomic.Bool

	// pol is the rule set decisions are made against. Options.Auth and
	// Options.ACL only seed it; SetRules replaces it.
	pol policy

	c counters
}

// pendingWill is a Will Message waiting for its Will Delay Interval to pass.
type pendingWill struct {
	clientID string
	msg      store.Message
	fireAt   time.Time
}

type counters struct {
	totalConns atomic.Int64
	online     atomic.Int64
	msgsIn     atomic.Int64
	msgsOut    atomic.Int64
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
	spills     atomic.Int64
	malformed  atomic.Int64
	protoErr   atomic.Int64
	rejected   atomic.Int64
	dropped    atomic.Int64
	expired    atomic.Int64
	sessGone   atomic.Int64
	tooBig     atomic.Int64
	kicked     atomic.Int64

	authRejected  atomic.Int64
	denyPublish   atomic.Int64
	denySubscribe atomic.Int64
	denyDelivery  atomic.Int64

	tlsConns          atomic.Int64
	tlsHandshakeFails atomic.Int64
}

// Metrics is a snapshot of broker counters.
type Metrics struct {
	ID               string `json:"id"`
	TotalConns       int64  `json:"total_connections"`
	Online           int64  `json:"online"`
	MessagesIn       int64  `json:"messages_in"`
	MessagesOut      int64  `json:"messages_out"`
	BytesIn          int64  `json:"bytes_in"`
	BytesOut         int64  `json:"bytes_out"`
	Subscriptions    int    `json:"subscriptions"`
	Retained         int    `json:"retained_messages"`
	QueueSpills      int64  `json:"queue_spills"`
	Malformed        int64  `json:"malformed_packets"`
	ProtocolErrors   int64  `json:"protocol_errors"`
	Rejected         int64  `json:"rejected_connections"`
	Dropped          int64  `json:"dropped_messages"`
	ExpiredMessages  int64  `json:"expired_messages"`
	ExpiredSessions  int64  `json:"expired_sessions"`
	TooLargeForPeer  int64  `json:"dropped_over_peer_max_packet_size"`
	DisconnectsSent  int64  `json:"server_disconnects"`
	AuthRejected     int64  `json:"auth_rejected"`
	DeniedPublish    int64  `json:"acl_denied_publish"`
	DeniedSubscribe  int64  `json:"acl_denied_subscribe"`
	DeniedDelivery   int64  `json:"acl_denied_delivery"`
	UnsafeExpansions int64  `json:"acl_unsafe_expansions"`
	ConnectionsTLS   int64  `json:"connections_tls"`
	// TLSHandshakeFailures counts handshakes that never became a session: a
	// wrong CA, a client certificate this broker does not trust, a peer that
	// connected and went silent. Every one is a device that could not connect,
	// so a growing number here with a flat connections_tls is the signal.
	TLSHandshakeFailures int64 `json:"tls_handshake_failures"`
	// RulesGeneration starts at 1 and rises once per policy swap, so an operator
	// reloading a rule file can tell which copy a decision was made against.
	// RulesLoadedUnix is when that generation became the live one.
	RulesGeneration int64 `json:"rules_generation"`
	RulesLoadedUnix int64 `json:"rules_loaded_unix"`
}

// Serving reports the window in which this broker takes and keeps connections:
// Serve has started and no Shutdown has begun draining. A readiness probe reads
// it, because "the process is up" and "the process will hold your session" are
// different questions during a restart.
func (b *Broker) Serving() bool { return b.started.Load() && !b.stopping.Load() }

// Metrics returns the current counters.
func (b *Broker) Metrics() Metrics {
	rs := b.pol.load()
	m := Metrics{
		ID:              b.opt.ID,
		TotalConns:      b.c.totalConns.Load(),
		Online:          b.c.online.Load(),
		MessagesIn:      b.c.msgsIn.Load(),
		MessagesOut:     b.c.msgsOut.Load(),
		BytesIn:         b.c.bytesIn.Load(),
		BytesOut:        b.c.bytesOut.Load(),
		Subscriptions:   b.tree.Count(),
		Retained:        b.retain.Len(),
		QueueSpills:     b.c.spills.Load(),
		Malformed:       b.c.malformed.Load(),
		ProtocolErrors:  b.c.protoErr.Load(),
		Rejected:        b.c.rejected.Load(),
		Dropped:         b.c.dropped.Load(),
		ExpiredMessages: b.c.expired.Load(),
		ExpiredSessions: b.c.sessGone.Load(),
		TooLargeForPeer: b.c.tooBig.Load(),
		DisconnectsSent: b.c.kicked.Load(),
		AuthRejected:    b.c.authRejected.Load(),
		DeniedPublish:   b.c.denyPublish.Load(),
		DeniedSubscribe: b.c.denySubscribe.Load(),
		DeniedDelivery:  b.c.denyDelivery.Load(),
		ConnectionsTLS:  b.c.tlsConns.Load(),

		TLSHandshakeFailures: b.c.tlsHandshakeFails.Load(),
		RulesGeneration:      rs.generation,
		RulesLoadedUnix:      rs.loadedUnix,
	}
	if rs.acl != nil {
		m.UnsafeExpansions = rs.unsafeBase + rs.acl.UnsafeExpansions()
	} else {
		m.UnsafeExpansions = rs.unsafeBase
	}
	return m
}

// New builds a Broker but does not listen.
func New(opt Options) *Broker {
	opt.withDefaults()
	ctx, cancel := context.WithCancel(context.Background())
	b := &Broker{
		opt:    opt,
		log:    opt.Logger.With("component", "broker", "id", opt.ID),
		tree:   topics.NewTree(),
		store:  opt.Store,
		retain: newRetainedStore(),
		live:   make(map[string]*client),
		wills:  make(map[string]pendingWill),
		ctx:    ctx,
		cancel: cancel,
	}
	b.pol.init(opt.Auth, opt.ACL)
	return b
}

// Listen binds a TCP listener on addr. Passing port 0 lets the OS choose, and
// Addr then reports the real address. An empty addr binds nothing, which is how
// a broker that only speaks TLS is started.
func (b *Broker) Listen(addr string) error {
	if addr == "" {
		return nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("congmq: listen %s: %w", addr, err)
	}
	b.listener = l
	return nil
}

// ListenTLS binds a second TCP listener that wraps every connection in TLS using
// Options.TLSConfig. Like Listen, port 0 is fine and an empty addr binds nothing.
//
// The handshake happens after accept, on its own goroutine, rather than inside a
// tls.Listener: the broker needs to bound it by a deadline, count what fails, and
// hold the peer's verified certificates before a session exists.
func (b *Broker) ListenTLS(addr string) error {
	if addr == "" {
		return nil
	}
	if b.opt.TLSConfig == nil {
		return errors.New("congmq: ListenTLS needs Options.TLSConfig")
	}
	cfg := b.opt.TLSConfig.Clone()
	if len(cfg.Certificates) == 0 && cfg.GetCertificate == nil {
		return fmt.Errorf("congmq: TLS config for %s has no certificate", addr)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("congmq: listen tls %s: %w", addr, err)
	}
	b.tlsListener = l
	b.tlsCfg = cfg
	return nil
}

// Addr is the bound listener address, or "" before Listen.
func (b *Broker) Addr() string {
	if b.listener == nil {
		return ""
	}
	return b.listener.Addr().String()
}

// TLSAddr is the bound TLS listener address, or "" when TLS is off.
func (b *Broker) TLSAddr() string {
	if b.tlsListener == nil {
		return ""
	}
	return b.tlsListener.Addr().String()
}

// Serve restores persistent sessions and accepts connections until Shutdown
// is called. It returns net.ErrClosed-style errors as nil.
func (b *Broker) Serve() error {
	if b.listener == nil && b.tlsListener == nil {
		return errors.New("congmq: Listen was not called")
	}
	if !b.started.CompareAndSwap(false, true) {
		return errors.New("congmq: Serve already running")
	}
	b.restoreDurable()
	b.restoreSessions()
	b.log.Info("listening", "addr", b.Addr(), "tls_addr", b.TLSAddr(), "rules", b.ruleSummary(),
		"receive_max", b.opt.ReceiveMax, "topic_alias_max", b.opt.TopicAliasMax,
		"max_packet_size", b.opt.MaxPacketSize, "max_qos", b.opt.MaxQoS)

	b.wg.Add(1)
	go func() { defer b.wg.Done(); b.reap() }()

	one := make(chan error, 2)
	loops := 0
	if b.listener != nil {
		loops++
		go func() { one <- b.acceptLoop(b.listener, false) }()
	}
	if b.tlsListener != nil {
		loops++
		go func() { one <- b.acceptLoop(b.tlsListener, true) }()
	}
	// Returning is the operator's notice that this broker stopped accepting, so
	// the listener still serving must not be left open behind it.
	err := <-one
	if loops > 1 {
		b.closeListeners()
		// The first listener to report a real failure owns the exit code; the
		// other one closing cleanly afterwards is not news.
		if other := <-one; err == nil {
			err = other
		}
	}
	return err
}

// acceptLoop takes connections off one listener until it is closed. A second
// listener is only ever closed by Shutdown, and both loops exit the same way.
func (b *Broker) acceptLoop(l net.Listener, secure bool) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			// Closing the listener is how Shutdown unblocks this loop, so a
			// closed listener is a clean exit rather than a failure.
			if errors.Is(err, net.ErrClosed) || b.ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if secure {
			b.acceptTLS(conn)
		} else {
			b.accept(conn)
		}
	}
}

func (b *Broker) accept(conn net.Conn) {
	b.c.totalConns.Add(1)
	b.noDelay(conn)
	c := newClient(b, conn)
	b.wg.Add(3)
	go func() { defer b.wg.Done(); c.readLoop() }()
	go func() { defer b.wg.Done(); c.writeLoop() }()
	go func() { defer b.wg.Done(); c.stateLoop() }()
}

// acceptTLS negotiates TLS before a session exists, so a peer that never finishes
// the handshake costs one short-lived goroutine and nothing else. The handshake
// cannot run on the accept loop: a peer that opens the socket and goes silent
// would then stop the broker from accepting anyone else for the full timeout.
//
// HandshakeContext returning here also means a required client certificate made
// it through verification. TLS 1.3 sends that certificate after the server's own
// flight, so a client with nothing to show completes the handshake on its side and
// fails on this one: measured, the failure is counted here, the socket closes, and
// total_connections never moves. So when TLSConfig asks for a client certificate, a
// secure session that reaches CONNECT already holds a chain that verified against
// ClientCAs, and the certificate rules can rely on that rather than re-checking it.
func (b *Broker) acceptTLS(conn net.Conn) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		sc := tls.Server(conn, b.tlsCfg)
		ctx, cancel := context.WithTimeout(b.ctx, b.opt.HandshakeTimeout)
		defer cancel()
		if err := sc.HandshakeContext(ctx); err != nil {
			b.c.tlsHandshakeFails.Add(1)
			// Warn, not debug: every one of these is a device that could not
			// connect, and "unknown certificate authority" is the answer to the
			// operator's question, not a detail to bury.
			b.log.Warn("tls handshake failed", "remote", conn.RemoteAddr().String(),
				"err", err, "timeout", b.opt.HandshakeTimeout.String())
			_ = conn.Close()
			return
		}
		b.c.tlsConns.Add(1)
		b.accept(sc)
	}()
}

// noDelay switches Nagle off on an accepted connection. MQTT's steady traffic is
// small packets — PUBACK, SUBACK, PINGRESP — and Nagle withholds a small segment
// while the peer still has unacknowledged data, which pairs with that peer's
// delayed-ACK timer into a stall of tens to hundreds of milliseconds per round
// trip. It is not a tuning knob: a broker that leaves it on measures the two
// timers, not itself. Measured with cmd/congmq-load on loopback, eight QoS 1
// publishers went from about 1.2k to about 90k messages per second.
func (b *Broker) noDelay(conn net.Conn) {
	tc := tcpConn(conn)
	if tc == nil {
		return // a listener that hands out something else owns its own options
	}
	if err := tc.SetNoDelay(true); err != nil {
		b.log.Warn("cannot disable Nagle on an accepted connection", "remote", conn.RemoteAddr().String(), "err", err)
	}
}

// tcpConn finds the TCP connection underneath conn, unwrapping a TLS conn: the
// deadline that matters is the socket's, and a TLS record is just bytes on it.
// Without this, every secure connection would run with Nagle enabled.
func tcpConn(conn net.Conn) *net.TCPConn {
	for {
		switch c := conn.(type) {
		case *net.TCPConn:
			return c
		case *tls.Conn:
			conn = c.NetConn()
		default:
			return nil
		}
	}
}

// closeListeners stops both accept loops. Closing is idempotent from the
// broker's point of view: a listener Shutdown already closed returns an error
// this ignores, and a nil one was never bound.
func (b *Broker) closeListeners() {
	if b.listener != nil {
		_ = b.listener.Close()
	}
	if b.tlsListener != nil {
		_ = b.tlsListener.Close()
	}
}

// Shutdown stops accepting, tells 5.0 peers why, asks every session to persist
// itself, and waits up to the context deadline for connections to drain.
func (b *Broker) Shutdown(ctx context.Context) error {
	b.stopping.Store(true)
	b.closeListeners()
	// A graceful shutdown is not the client's fault, so its Will Message stays
	// unpublished and its session is written to the store.
	b.kickAll(packets.RServerShuttingDown, ErrShuttingDown)
	b.cancel()

	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		b.log.Info("shutdown complete", "metrics", b.Metrics())
		return nil
	case <-ctx.Done():
		return fmt.Errorf("congmq: shutdown waited: %w", ctx.Err())
	}
}

// restoreSessions re-installs the subscriptions of offline clients so that
// messages published while they are away still reach their queue. Sessions whose
// Session Expiry Interval elapsed while the broker was down are discarded here
// rather than revived, and a will that was still delayed gets published.
func (b *Broker) restoreSessions() {
	now := time.Now()
	for _, s := range b.store.Sessions() {
		if s.Live {
			// The connection was up when this was written, so no clock had
			// started: this crash is when the session went offline. Arm it from
			// now, or leave it unarmed for the sessions that never expire.
			s.Live = false
			if s.ExpiryInterval > 0 {
				s.Expiry = now.Add(s.ExpiryInterval)
			}
			if err := b.store.Put(s); err != nil {
				b.log.Error("cannot re-arm session expiry", "client", s.ClientID, "err", err)
			}
		}
		if !s.Expiry.IsZero() && now.After(s.Expiry) {
			b.expireSession(s.ClientID)
			continue
		}
		for filter, sub := range s.Subscriptions {
			if err := b.tree.Subscribe(filter, s.ClientID, subOptions(sub)); err != nil {
				b.log.Warn("restored subscription rejected", "client", s.ClientID, "filter", filter, "err", err)
			}
		}
		b.log.Info("session restored", "client", s.ClientID, "proto", s.Proto.String(),
			"queued", len(s.Queued), "inflight", len(s.Inflight), "subs", len(s.Subscriptions),
			"session_expires", s.Expiry)
	}
}

// subOptions lifts a stored subscription into what the topic tree needs to
// forward a message. Retain Handling is deliberately left out: it only ever
// applies at the moment the subscription is made.
func subOptions(sub store.Sub) topics.Options {
	return topics.Options{
		QoS:               sub.QoS,
		NoLocal:           sub.NoLocal,
		RetainAsPublished: sub.RetainAsPublished,
		ID:                sub.ID,
	}
}

// lookup returns the live connection for a client identifier.
func (b *Broker) lookup(clientID string) *client {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.live[clientID]
}

// liveClients snapshots the connected sessions so a caller can act on them
// without holding the broker lock.
func (b *Broker) liveClients() []*client {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]*client, 0, len(b.live))
	for _, c := range b.live {
		out = append(out, c)
	}
	return out
}

// kickAll hands every live session a server-initiated DISCONNECT reason.
func (b *Broker) kickAll(reason byte, err error) {
	for _, c := range b.liveClients() {
		c.kick(reason, err, true)
	}
}

func (b *Broker) register(c *client) *client {
	b.mu.Lock()
	defer b.mu.Unlock()
	prev := b.live[c.id]
	b.live[c.id] = c
	if prev == nil {
		b.c.online.Add(1)
	}
	return prev
}

func (b *Broker) unregister(c *client) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cur, ok := b.live[c.id]; ok && cur == c {
		delete(b.live, c.id)
		b.c.online.Add(-1)
	}
}

// queueOffline appends a message to a disconnected client's stored session.
// The identity that authorised the delivery is recorded so a later delivery to
// the same client id is checked against it too.
func (b *Broker) queueOffline(clientID string, msg store.Message, id rules.Identity) {
	b.offlineMu.Lock()
	defer b.offlineMu.Unlock()

	s, ok := b.store.Get(clientID)
	if !ok {
		remote := ""
		if id.IP != nil {
			remote = id.IP.String()
		}
		s = &store.Session{
			ClientID:      clientID,
			Username:      id.Username,
			RemoteIP:      remote,
			Subscriptions: map[string]store.Sub{},
		}
	}
	s.Queued = append(s.Queued, msg)
	if over := len(s.Queued) - b.opt.QueueMax; over > 0 {
		s.Queued = s.Queued[over:]
		b.c.dropped.Add(int64(over))
		b.c.spills.Add(1)
		b.log.Warn("offline queue overflow, oldest dropped",
			"client", clientID, "queue_max", b.opt.QueueMax)
	}
	if err := b.store.Put(s); err != nil {
		b.log.Error("cannot persist offline queue", "client", clientID, "err", err)
	}
}

// mergeSession writes a runtime snapshot back to the store without losing
// messages the router spilled while the session was being torn down. The two
// queues are disjoint: the spill path only runs when the push failed, so the
// snapshot never contains the same message.
func (b *Broker) mergeSession(s *store.Session) {
	b.offlineMu.Lock()
	defer b.offlineMu.Unlock()

	if cur, ok := b.store.Get(s.ClientID); ok {
		s.Subscriptions = unionSubs(cur.Subscriptions, s.Subscriptions)
		s.Queued = append(cur.Queued, s.Queued...)
	}
	if over := len(s.Queued) - b.opt.QueueMax; over > 0 {
		s.Queued = s.Queued[over:]
		b.c.dropped.Add(int64(over))
		b.c.spills.Add(1)
	}
	if err := b.store.Put(s); err != nil {
		b.log.Error("cannot persist session", "client", s.ClientID, "err", err)
	}
}

// saveLiveSession refreshes the record of a session that is still connected. The
// runtime owns its subscriptions, so they come from the snapshot; the queue
// already in the store stays there, because those are the messages the router
// spilled when this client's mailbox was full and the snapshot has never seen
// them.
func (b *Broker) saveLiveSession(s *store.Session) {
	b.offlineMu.Lock()
	defer b.offlineMu.Unlock()
	if cur, ok := b.store.Get(s.ClientID); ok {
		s.Queued = cur.Queued
	}
	if err := b.store.Put(s); err != nil {
		b.log.Error("cannot persist session", "client", s.ClientID, "err", err)
	}
}

// takeOverStoredSession is the store's half of continuing a session: everything
// the record held has just been loaded into the live runtime, so the record is
// reduced to what only a record can hold. Leaving the queue in place would have
// mergeSession union it again at the next disconnect and hand the client messages
// it has already been sent, every cycle, until the queue hit its cap.
//
// It runs before the session is registered, so no spill can be racing the write.
func (b *Broker) takeOverStoredSession(s *store.Session) {
	b.offlineMu.Lock()
	defer b.offlineMu.Unlock()
	s.Queued = nil
	s.Inflight = nil
	if err := b.store.Put(s); err != nil {
		b.log.Error("cannot persist session", "client", s.ClientID, "err", err)
	}
}

// dropSession forgets a session for good. A store that refused the deletion
// would resurrect the queue on the next restart, so it is logged rather than
// ignored; neither outcome may disconnect the client that is already gone.
func (b *Broker) dropSession(clientID string) {
	if err := b.store.Delete(clientID); err != nil {
		b.log.Error("cannot delete session", "client", clientID, "err", err)
	}
}

func unionSubs(a, b map[string]store.Sub) map[string]store.Sub {
	out := make(map[string]store.Sub, len(a)+len(b))
	for f, s := range a {
		out[f] = s
	}
	for f, s := range b {
		out[f] = s
	}
	return out
}

// --- session expiry and delayed wills ---

// scheduleWill holds a Will Message back for its Will Delay Interval. A client
// that set no delay has its will published by the caller straight away, so this
// is only reached with a positive delay and a session worth keeping.
func (b *Broker) scheduleWill(clientID string, msg store.Message, delay time.Duration) {
	fireAt := time.Now().Add(delay)
	b.willMu.Lock()
	b.wills[clientID] = pendingWill{clientID: clientID, msg: msg, fireAt: fireAt}
	b.willMu.Unlock()
	b.persistWill(store.Will{ClientID: clientID, Msg: msg, FireAt: fireAt})
	b.log.Debug("will delayed", "client", clientID, "delay", delay)
}

// takeWill removes and returns the will waiting on this client, if any. It is
// gone from the durable store as well: once it has been published, or withdrawn
// by a reconnect that continued the session, nobody owes it any more.
func (b *Broker) takeWill(clientID string) (store.Message, bool) {
	b.willMu.Lock()
	w, ok := b.wills[clientID]
	if !ok {
		b.willMu.Unlock()
		return store.Message{}, false
	}
	delete(b.wills, clientID)
	b.willMu.Unlock()

	b.forgetWill(clientID)
	return w.msg, true
}

// resolvePendingWill decides what happens to a delayed will when the client it
// belongs to connects again. A new connection that continues the Session
// withdraws it [MQTT-3.1.3-9]; one that discards the Session ends it, so the
// will goes out now rather than waiting for a delay that has already been paid.
func (b *Broker) resolvePendingWill(clientID string, continues bool) {
	msg, ok := b.takeWill(clientID)
	if !ok {
		return
	}
	if continues {
		b.log.Info("reconnect within the will delay, will withdrawn", "client", clientID)
		return
	}
	b.log.Info("will published because the session was discarded", "client", clientID, "topic", msg.Topic)
	b.fireWill(&msg, clientID)
}

// reap is the broker's clock: it publishes wills whose delay has elapsed,
// expires offline sessions and prunes retained messages that ran out.
func (b *Broker) reap() {
	tick := time.NewTicker(b.opt.ReapInterval)
	defer tick.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return
		case now := <-tick.C:
			b.fireDueWills(now)
			b.expireOfflineSessions(now)
			gone := b.retain.prune(now)
			if len(gone) > 0 {
				b.c.expired.Add(int64(len(gone)))
				for _, topic := range gone {
					b.forgetRetained(topic)
				}
				b.log.Debug("retained messages expired", "count", len(gone))
			}
		}
	}
}

// fireDueWills publishes every will whose delay has run out. Each one goes
// through takeWill rather than the map directly, so a client that reconnected
// between this scan and the publish has already withdrawn its own will.
func (b *Broker) fireDueWills(now time.Time) {
	b.willMu.Lock()
	var due []string
	for id, w := range b.wills {
		if !now.Before(w.fireAt) {
			due = append(due, id)
		}
	}
	b.willMu.Unlock()

	for _, id := range due {
		msg, ok := b.takeWill(id)
		if !ok {
			continue
		}
		b.log.Info("delayed will published", "client", id, "topic", msg.Topic)
		b.route(msg, id)
	}
}

// expireOfflineSessions ends the sessions whose Session Expiry Interval has
// passed. A client that is connected again owns its own session, so it is never
// expired underneath itself.
func (b *Broker) expireOfflineSessions(now time.Time) {
	for _, s := range b.store.Sessions() {
		if s.Expiry.IsZero() || now.Before(s.Expiry) {
			continue
		}
		if b.lookup(s.ClientID) != nil {
			continue
		}
		b.expireSession(s.ClientID)
	}
}

// expireSession ends an offline session for good: its subscriptions are
// withdrawn, its queued messages thrown away and a will that was still delayed
// finally published.
func (b *Broker) expireSession(clientID string) {
	b.tree.UnsubscribeAll(clientID)
	b.dropSession(clientID)
	// The Session ended, so a will that was still waiting is published now: the
	// delay never outlives the session it belongs to.
	if msg, ok := b.takeWill(clientID); ok {
		b.log.Info("will published with the expired session", "client", clientID, "topic", msg.Topic)
		b.fireWill(&msg, clientID)
	}
	b.c.sessGone.Add(1)
	b.log.Info("session expired", "client", clientID)
}
