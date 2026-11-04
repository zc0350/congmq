package broker

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// gateIdleWindow is how long a bucket with nothing in it may sit in the table
// before prune drops it. The table is keyed by source address, so without a
// deadline the attack the gate exists to stop becomes the thing that exhausts
// the broker: keep introducing new addresses and the map grows forever.
const gateIdleWindow = 10 * time.Minute

// gateWarnEvery caps the refusal log line per address. One line per refused
// socket is the same flood the gate is here to stop — and the count is the
// number an operator graphs, so the log only has to prove the gate is what
// answered.
const gateWarnEvery = time.Minute

// gateRefusal says why a socket was closed before it was ever read.
type gateRefusal byte

const (
	refusedNone gateRefusal = iota
	refusedConns
	refusedRate
)

func (r gateRefusal) String() string {
	switch r {
	case refusedConns:
		return "connection limit"
	case refusedRate:
		return "connect rate"
	}
	return "none"
}

// bucket is one source address's share of the gate: what it is holding right now,
// what it has spent, and — with the credential limit armed — how close it is to
// being locked out.
type bucket struct {
	conns    int     // sockets held right now, including one still handshaking
	tokens   float64 // the rate window's remaining budget
	refilled time.Time
	seen     time.Time // any activity, for pruning
	warned   time.Time // the last time this bucket produced a refusal log line

	// Credential failures. authFails counts the ones inside the current window;
	// windowStart is when that window began, and is cleared along with the count
	// whenever a device proves it knows its password.
	authFails   int
	windowStart time.Time
	lockedUntil time.Time
}

// gate meters what one source address may do. It has two independent features,
// each off until asked for:
//   - connection metering, decided on a socket that has not sent a byte, which is
//     the only place a connect storm is visible (see gate.acquire);
//   - credential lockout, decided at CONNECT, where an address that keeps failing
//     the auth rules stops being able to try (see gate.locked).
//
// They share one table because they share one keying question — what counts as
// "the same address" — and one pruning problem: an attacker who can make the
// broker remember things can exhaust it.
//
// The whole table sits behind one mutex. It is held for a handful of field
// updates on the accept and CONNECT paths, both of which already do far more
// expensive work; nothing here is on the message path.
type gate struct {
	maxConns int
	rate     float64 // new connections per second, 0 for unmetered
	burst    float64 // the most a bucket may spend at once

	auth *gateAuth // nil until the credential limit is asked for

	// on means the table exists; connMetered means the connection limits are in
	// it. Both are decided once by newGate and read without a lock afterwards.
	on, connMetered bool

	counters *counters
	log      *slog.Logger

	mu   sync.Mutex
	byIP map[string]*bucket
	now  func() time.Time
}

// gateAuth is the credential-failure policy: limit failures in a window, then
// refuse the address for a while.
type gateAuth struct {
	limit  int
	window time.Duration
	locked time.Duration
}

func newGate(maxConns int, rate, burst float64, auth *gateAuth, c *counters, log *slog.Logger) *gate {
	g := &gate{
		maxConns: maxConns, rate: rate, burst: burst, counters: c, log: log, now: time.Now,
		connMetered: maxConns > 0 || rate > 0,
		on:          maxConns > 0 || rate > 0 || auth != nil,
	}
	if !g.on {
		return g
	}
	if g.connMetered {
		if g.burst <= 0 {
			g.burst = g.rate
		}
		// A bucket that never holds a whole token could never let anything through:
		// the price of a connection is one token, so the floor of a
		// sub-one-per-second rate is still one spare connection, not a permanently
		// locked address.
		if g.burst < 1 {
			g.burst = 1
		}
	}
	if auth != nil && auth.locked <= 0 {
		// Nothing was asked for beyond the window, so the penalty is a whole window
		// of quiet: the address has to stay well enough behaved to have filled one.
		auth.locked = auth.window
	}
	g.auth = auth
	g.byIP = make(map[string]*bucket)
	// Say what is armed. A limit that only shows up as a refused connection looks
	// like a broken device to whoever wrote the rules file, and "which numbers are
	// live" is the first question an operator asks after an outage.
	g.log.Info("per-address gate armed",
		"max_conns_per_ip", g.maxConns, "connect_rate_per_second", g.rate, "burst", g.burst,
		"auth_fail_limit", g.authLimit(), "auth_fail_window", g.authWindow(), "auth_lockout", g.authLockout(),
		"ipv6_prefix", "/64", "idle_pruned_after", gateIdleWindow.String())
	return g
}

func (g *gate) authLimit() int {
	if g.auth == nil {
		return 0
	}
	return g.auth.limit
}

func (g *gate) authWindow() time.Duration {
	if g.auth == nil {
		return 0
	}
	return g.auth.window
}

func (g *gate) authLockout() time.Duration {
	if g.auth == nil {
		return 0
	}
	return g.auth.locked
}

// offPermit stands for "the gate is not metering your connections". It is shared,
// and safe to share, because release only touches the map when the permit has a
// gate.
var offPermit = &permit{}

// permit is the reason a counted connection is still counted. Releasing it is
// idempotent because two owners are expected: the client's cleanup path and, on
// a TLS listener, the handshake failure that never produced a client at all.
type permit struct {
	g    *gate
	key  string
	held atomic.Bool
}

// release gives the address's slot back. Exactly once, whoever gets here first.
func (p *permit) release() {
	if p == nil || p.g == nil {
		return
	}
	if p.held.CompareAndSwap(true, false) {
		p.g.leave(p.key)
	}
}

// acquire charges the address for one more connection and returns the permit
// that owes it back, or nil plus why the socket should be closed now.
//
// This is called before the connection is read, not at CONNECT, and the
// difference is what the gate is for. A limit checked at CONNECT bounds
// sessions; a peer that opens sockets and sends nothing never reaches a CONNECT,
// so each attempt still costs a socket, a read deadline and three goroutines
// for the full preConnectTimeout. Metering the socket is the only place that
// can see that shape of load.
func (g *gate) acquire(ip net.IP) (*permit, gateRefusal) {
	if g == nil || !g.connMetered {
		return offPermit, refusedNone
	}
	key := gateKey(ip)

	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	b := g.bucketLocked(key, now)
	b.seen = now

	if g.rate > 0 {
		if elapsed := now.Sub(b.refilled).Seconds(); elapsed > 0 {
			b.tokens += elapsed * g.rate
			if b.tokens > g.burst {
				b.tokens = g.burst
			}
			b.refilled = now
		}
		if b.tokens < 1 {
			return nil, g.refuseLocked(b, key, ip, refusedRate)
		}
		b.tokens--
	}
	if g.maxConns > 0 && b.conns >= g.maxConns {
		return nil, g.refuseLocked(b, key, ip, refusedConns)
	}
	b.conns++
	p := &permit{g: g, key: key}
	p.held.Store(true)
	return p, refusedNone
}

// bucketLocked returns the address's bucket, making it if this is the first
// sight of the address. The caller holds g.mu.
func (g *gate) bucketLocked(key string, now time.Time) *bucket {
	b := g.byIP[key]
	if b == nil {
		// refilled is stamped now rather than left at the zero time. An untouched
		// bucket would otherwise be credited with every second since year 0001
		// before being capped at the burst — the right number, arrived at by a
		// route nobody would defend in review.
		b = &bucket{tokens: g.burst, refilled: now}
		g.byIP[key] = b
	}
	return b
}

// refuseLocked counts a refusal and logs it on the address's own throttle. The
// caller holds g.mu.
func (g *gate) refuseLocked(b *bucket, key string, ip net.IP, why gateRefusal) gateRefusal {
	switch why {
	case refusedRate:
		g.counters.gateRate.Add(1)
	case refusedConns:
		g.counters.gateConns.Add(1)
	}
	if b.warned.IsZero() || !g.now().Before(b.warned.Add(gateWarnEvery)) {
		b.warned = g.now()
		g.log.Warn("connection refused by the per-address gate",
			"remote", key, "ip", ip.String(), "reason", why.String(),
			"conns", b.conns, "max_conns", g.maxConns,
			"rate_per_second", g.rate, "burst", g.burst)
	}
	return why
}

// locked reports whether this address is serving a credential lockout, and
// forgets one that has run its term.
//
// Nothing about the answer is visible to the client. The caller refuses the
// CONNECT with the same code a wrong password gets, because a lockout that a
// script can recognise is a lockout a script can time around — and an operator
// with a NAT'd floor of devices does not want to be told which one mistyped.
func (g *gate) locked(ip net.IP) bool {
	if g == nil || g.auth == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.byIP[gateKey(ip)]
	if b == nil || b.lockedUntil.IsZero() {
		return false
	}
	if g.now().Before(b.lockedUntil) {
		return true
	}
	b.lockedUntil = time.Time{}
	return false
}

// noteAuthFailure records a CONNECT that the auth rules refused. Reaching the
// limit inside the window locks the address for the lockout period, which starts
// from nothing: the failures that earned it are not also held against the next
// attempt after it ends.
func (g *gate) noteAuthFailure(ip net.IP) {
	if g == nil || g.auth == nil {
		return
	}
	key := gateKey(ip)
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	b := g.bucketLocked(key, now)
	b.seen = now

	// Already serving a lockout. A second failure must not extend it: an attacker
	// that keeps trying would then never be allowed back, and the penalty would
	// have become a ban nobody configured.
	if !b.lockedUntil.IsZero() && now.Before(b.lockedUntil) {
		return
	}
	// A window that has run out is not held against the address any more, so this
	// failure starts a new one rather than topping up an old count.
	if b.windowStart.IsZero() || !now.Before(b.windowStart.Add(g.auth.window)) {
		b.windowStart, b.authFails = now, 0
	}
	b.authFails++
	if b.authFails < g.auth.limit {
		return
	}
	b.lockedUntil = now.Add(g.auth.locked)
	b.windowStart = time.Time{}
	b.authFails = 0
	// One line per lockout, not per failure: the lockout is the event, and the
	// failures leading up to it are already in auth_rejected. This is the moment an
	// operator needs to see, because from here a correct password is refused too.
	g.log.Warn("address locked out after too many credential failures",
		"remote", key, "ip", ip.String(), "failures", g.auth.limit,
		"window", g.auth.window.String(), "locked_for", g.auth.locked.String())
}

// noteAuthSuccess clears the address's standing. A device that knows its password
// has earned a clean window, and an expired lockout is dropped from the record so
// prune can forget the bucket entirely.
func (g *gate) noteAuthSuccess(ip net.IP) {
	if g == nil || g.auth == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.byIP[gateKey(ip)]
	if b == nil {
		return
	}
	b.seen = g.now()
	b.authFails = 0
	b.windowStart = time.Time{}
	if !b.lockedUntil.IsZero() && !g.now().Before(b.lockedUntil) {
		b.lockedUntil = time.Time{}
	}
}

func (g *gate) leave(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if b := g.byIP[key]; b != nil && b.conns > 0 {
		b.conns--
		b.seen = g.now()
	}
}

// tracked is how many addresses the table holds. It is the number that proves
// prune is working: under load it should look like the fleet, not like the
// attack.
func (g *gate) tracked() int {
	if g == nil || !g.on {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.byIP)
}

// held is how many sockets the gate is counting across every address. The
// refusal counters only know what already happened; this one says whether a limit
// is about to bite, which is the number worth alerting on.
func (g *gate) held() int64 {
	if g == nil || !g.connMetered {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	var n int64
	for _, b := range g.byIP {
		n += int64(b.conns)
	}
	return n
}

// lockedCount is how many addresses are serving a credential lockout right now.
// Without it, an operator debugging "the devices say bad credentials" has only the
// history counter to read, and cannot tell whether the lockout is still in force.
func (g *gate) lockedCount() int {
	if g == nil || g.auth == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	var n int
	for _, b := range g.byIP {
		if !b.lockedUntil.IsZero() && now.Before(b.lockedUntil) {
			n++
		}
	}
	return n
}

// prune drops buckets that hold nothing and have been idle past gateIdleWindow.
// Called from the reaper, so it inherits that loop's interval and stops with the
// broker.
//
// A live lockout is never dropped: it is a debt the address still owes, and
// forgetting it would let the attack resume simply by staying quiet for a while.
// Anything else is fair game — an address that comes back after being dropped
// starts from a full burst, which is the honest reading of "quiet for ten
// minutes": the gate is a window, not a record of history.
func (g *gate) prune() {
	if g == nil || !g.on {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	cutoff := now.Add(-gateIdleWindow)
	for key, b := range g.byIP {
		if b.conns > 0 {
			continue
		}
		if !b.lockedUntil.IsZero() && now.Before(b.lockedUntil) {
			continue
		}
		if b.seen.Before(cutoff) {
			delete(g.byIP, key)
		}
	}
}

// gateKey is the address the gate actually meters.
//
// IPv4 is keyed exactly. IPv6 is keyed on its /64, because that is what an
// interface is handed: a hostile host can source a fresh address per attempt
// from its own prefix at no cost, so a per-address limit there limits nothing.
// The other side of that is a building full of devices behind one /64 sharing a
// bucket, which is why the limit is off until an operator asks for it.
//
// A connection with no IP at all — a transport this broker never creates, since
// both listeners are TCP — gets one shared bucket rather than a free pass.
func gateKey(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if masked := ip.Mask(net.CIDRMask(64, 128)); masked != nil {
		return masked.String()
	}
	return ip.String()
}
