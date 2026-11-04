package broker

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// The gate is metered in nanoseconds and refills in seconds, so these tests own
// the clock: a real one would make the rate assertions either flaky or slow.

type fakeClock struct{ at time.Time }

func (f *fakeClock) now() time.Time          { return f.at }
func (f *fakeClock) advance(d time.Duration) { f.at = f.at.Add(d) }

func newTestGate(maxConns int, rate, burst float64) (*gate, *counters, *bytes.Buffer, *fakeClock) {
	return newGateTest(maxConns, rate, burst, nil)
}

// newGateTest builds a gate with a clock the test owns. Passing an auth policy
// arms the credential half; passing nil leaves it off, which is what the
// connection-limit and rate tests above both use.
func newGateTest(maxConns int, rate, burst float64, auth *gateAuth) (*gate, *counters, *bytes.Buffer, *fakeClock) {
	var c counters
	logBuf := &bytes.Buffer{}
	clock := &fakeClock{at: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}
	g := newGate(maxConns, rate, burst, auth, &c, slog.New(slog.NewTextHandler(logBuf, nil)))
	g.now = clock.now
	return g, &c, logBuf, clock
}

func refusals(buf *bytes.Buffer) int {
	return strings.Count(buf.String(), "refused by the per-address gate")
}

func bucketOf(g *gate, ip net.IP) *bucket {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.byIP[gateKey(ip)]
}

// An off gate has to be unobservable. Every existing deployment runs with these
// switches untouched, so "off" means no accounting, no log line and no bucket for
// anyone — not a limit set high enough to look like none.
func TestGateOffIsInvisible(t *testing.T) {
	g, c, buf, _ := newTestGate(0, 0, 0)
	if g.on {
		t.Fatal("a gate with every knob at 0 reports itself armed")
	}
	for i := 0; i < 100; i++ {
		p, why := g.acquire(net.ParseIP("192.0.2.1"))
		if p == nil || why != refusedNone {
			t.Fatalf("attempt %d refused with %v while the gate is off", i, why)
		}
	}
	if n := g.tracked(); n != 0 {
		t.Errorf("an off gate tracks %d addresses, want 0", n)
	}
	if c.gateConns.Load() != 0 || c.gateRate.Load() != 0 {
		t.Errorf("an off gate counted %d/%d refusals", c.gateConns.Load(), c.gateRate.Load())
	}
	if buf.Len() != 0 {
		t.Errorf("an off gate logged %q", buf.String())
	}
	// The off path shares one permit object between every connection, so a release
	// must not find a gate to decrement.
	g.acquire(net.ParseIP("198.51.100.7"))
	(&permit{}).release()
	if n := g.tracked(); n != 0 {
		t.Errorf("after releasing a bare permit the gate tracks %d addresses", n)
	}
}

func TestConnectionLimitIsPerAddress(t *testing.T) {
	g, c, _, _ := newTestGate(2, 0, 0)
	a, other := net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.2")

	p1, _ := g.acquire(a)
	p2, _ := g.acquire(a)
	if p1 == nil || p2 == nil {
		t.Fatal("the first two connections of an address with a limit of 2 were refused")
	}
	if p3, why := g.acquire(a); p3 != nil || why != refusedConns {
		t.Fatalf("a third connection from the same address returned %v/%v, want nil/refusedConns", p3, why)
	}
	// One noisy address must not be able to spend another's room.
	if p, why := g.acquire(other); p == nil || why != refusedNone {
		t.Fatalf("a different address got %v/%v, want a permit", p, why)
	}
	if got := c.gateConns.Load(); got != 1 {
		t.Errorf("gate_conns refusals = %d, want 1", got)
	}

	// The slot comes back when the connection ends, and only then.
	p1.release()
	if p, why := g.acquire(a); p == nil || why != refusedNone {
		t.Fatalf("after one release the address still could not connect (%v)", why)
	}
}

// Two owners are expected to release the same permit: the client's cleanup path
// and the TLS handshake that produced no client. A double decrement would let an
// address hold more than its limit, which is the failure this gate exists to
// prevent — so the check is that a third connection is still refused.
func TestReleaseIsIdempotent(t *testing.T) {
	g, _, _, _ := newTestGate(1, 0, 0)
	ip := net.ParseIP("203.0.113.9")

	p := mustAcquire(t, g, ip)
	p.release()
	p.release()
	p.release()

	if b := bucketOf(g, ip); b.conns != 0 {
		t.Fatalf("bucket holds %d connections after three releases of one permit, want 0", b.conns)
	}
	p2 := mustAcquire(t, g, ip)
	if b := bucketOf(g, ip); b.conns != 1 {
		t.Fatalf("bucket holds %d connections, want 1", b.conns)
	}
	if p3, why := g.acquire(ip); p3 != nil || why != refusedConns {
		t.Fatal("an address at its limit of 1 got a second connection: release went negative")
	}
	p2.release()
	if b := bucketOf(g, ip); b.conns != 0 {
		t.Fatalf("bucket holds %d after the second release, want 0", b.conns)
	}
	// Releasing a permit whose bucket has already been pruned must not panic.
	g.mu.Lock()
	delete(g.byIP, gateKey(ip))
	g.mu.Unlock()
	(&permit{g: g, key: gateKey(ip)}).release()
}

func TestRateIsATokenBucket(t *testing.T) {
	ip := net.ParseIP("192.0.2.7")
	g, c, _, clock := newTestGate(0, 1, 3)

	for i := 0; i < 3; i++ {
		if p, why := g.acquire(ip); p == nil {
			t.Fatalf("burst attempt %d refused (%v): a fresh bucket should hold 3", i, why)
		}
	}
	if p, why := g.acquire(ip); p != nil || why != refusedRate {
		t.Fatalf("the 4th attempt in one burst returned %v/%v, want nil/refusedRate", p, why)
	}

	// Two and a half seconds at one per second is two more connections, not three:
	// a fractional token does not pay for a whole one.
	clock.advance(2500 * time.Millisecond)
	mustAcquire(t, g, ip)
	mustAcquire(t, g, ip)
	if p, why := g.acquire(ip); p != nil || why != refusedRate {
		t.Fatalf("a half token let a connection through (%v)", why)
	}

	// Time that passed while nobody was connecting is not owed to them: the bucket
	// tops up at burst and no higher, or one quiet week buys an unlimited sprint.
	clock.advance(time.Hour)
	for i := 0; i < 3; i++ {
		mustAcquire(t, g, ip)
	}
	if p, why := g.acquire(ip); p != nil || why != refusedRate {
		t.Fatalf("tokens stacked to more than the burst (4th attempt returned %v/%v)", p, why)
	}
	if got := c.gateRate.Load(); got != 3 {
		t.Errorf("gate rate refusals = %d, want 3", got)
	}
}

// A rate below one per second is the setting an operator reaches for when they
// mean "this address may reconnect, slowly". If the bucket were allowed to hold
// less than one token, the limit would refuse everything forever, including the
// first device that ever asks.
func TestSlowRateStillAdmitsOne(t *testing.T) {
	ip := net.ParseIP("192.0.2.9")
	g, _, _, clock := newTestGate(0, 0.2, 0) // one connection every five seconds

	if g.burst < 1 {
		t.Fatalf("burst = %v, want floored to 1: nothing could ever connect", g.burst)
	}
	mustAcquire(t, g, ip)
	if p, why := g.acquire(ip); p != nil || why != refusedRate {
		t.Fatalf("the second immediate attempt returned %v/%v, want a rate refusal", p, why)
	}
	clock.advance(5 * time.Second)
	mustAcquire(t, g, ip)
}

func TestGateKeyGroupsIPv6ByPrefix(t *testing.T) {
	one := []string{"2001:db8:1:2::1", "2001:db8:1:2:dead:beef::9"}
	base := gateKey(net.ParseIP(one[0]))
	for _, s := range one[1:] {
		if got := gateKey(net.ParseIP(s)); got != base {
			t.Errorf("gateKey(%s) = %q, want the same /64 bucket %q", s, got, base)
		}
	}
	if gateKey(net.ParseIP("2001:db8:1:3::1")) == base {
		t.Error("a different /64 shared the bucket: only the last 64 bits should be dropped")
	}
	if got := gateKey(net.ParseIP("192.0.2.5")); got != "192.0.2.5" {
		t.Errorf("gateKey(v4) = %q, want the address itself", got)
	}
	// An IPv4-mapped v6 address is that v4 host arriving; two names for one bucket
	// would double its allowance.
	if got := gateKey(net.ParseIP("::ffff:192.0.2.5")); got != "192.0.2.5" {
		t.Errorf("gateKey(v4-mapped) = %q, want it folded onto the v4 key", got)
	}
	if got := gateKey(nil); got != "" {
		t.Errorf("gateKey(nil) = %q, want the one shared bucket for a transport with no address", got)
	}

	// What the keying buys: a host minting addresses inside its own prefix does not
	// get a fresh allowance each time.
	g, _, _, _ := newTestGate(1, 0, 0)
	mustAcquire(t, g, net.ParseIP("2001:db8:7::1"))
	if p, why := g.acquire(net.ParseIP("2001:db8:7:0:1234::1")); p != nil || why != refusedConns {
		t.Fatalf("a second address in the same /64 got %v/%v, want refusal", p, why)
	}
	// A separate /64 is a separate tenant of the network, and stays unmetered by
	// the first one.
	mustAcquire(t, g, net.ParseIP("2001:db8:8::1"))
}

func TestPruneForgetsIdleAddresses(t *testing.T) {
	g, _, _, clock := newTestGate(1, 0, 0)

	held := make([]*permit, 0, 20)
	ips := make([]net.IP, 0, 20)
	for i := 0; i < 20; i++ {
		ip := net.IPv4(10, 0, byte(i), 1).To4()
		ips = append(ips, ip)
		held = append(held, mustAcquire(t, g, ip))
	}
	if n := g.tracked(); n != 20 {
		t.Fatalf("gate tracks %d addresses after 20 connections, want 20", n)
	}
	for _, p := range held[:19] {
		p.release()
	}

	clock.advance(gateIdleWindow + time.Minute)
	g.prune()
	// Only the address still holding a connection survives; the rest of the table
	// is an attack's footprint, not the broker's.
	if n := g.tracked(); n != 1 {
		t.Fatalf("after pruning %d addresses, %d remain: want the one still connected", 20, n)
	}
	if p, why := g.acquire(ips[19]); p != nil || why != refusedConns {
		t.Fatalf("the live address was pruned too (%v/%v)", p, why)
	}

	// Releasing it leaves an idle bucket, which the next sweep takes.
	held[19].release()
	clock.advance(gateIdleWindow + time.Minute)
	g.prune()
	if n := g.tracked(); n != 0 {
		t.Fatalf("after everything went quiet, %d entries remain", n)
	}
	// The pruned address starts from a full burst again: the gate is a rate window,
	// not a grudge.
	mustAcquire(t, g, ips[19])
}

// A refusal is worth a log line exactly once per address. One per socket turns
// the defence into the flood it is here to stop, and the counters already say how
// many were refused.
func TestRefusalsAreLoggedOncePerWindow(t *testing.T) {
	g, c, buf, clock := newTestGate(1, 0, 0)
	ip := net.ParseIP("192.0.2.44")
	other := net.ParseIP("198.51.100.44")

	p := mustAcquire(t, g, ip)
	for i := 0; i < 50; i++ {
		if p2, why := g.acquire(ip); p2 != nil || why != refusedConns {
			t.Fatalf("attempt %d returned %v/%v", i, p2, why)
		}
	}
	if got := c.gateConns.Load(); got != 50 {
		t.Errorf("refusals counted = %d, want 50", got)
	}
	if n := refusals(buf); n != 1 {
		t.Fatalf("%d refusal lines for 50 refusals, want 1", n)
	}
	// A different address is not silenced by this one's throttle.
	mustAcquire(t, g, other)
	if p2, _ := g.acquire(other); p2 != nil {
		t.Fatal("the second address got past its own limit")
	}
	if n := refusals(buf); n != 2 {
		t.Fatalf("%d refusal lines with two addresses stuck, want one each", n)
	}
	// The throttle expires, so a problem still happening an hour later is still
	// worth telling the operator about.
	before := refusals(buf)
	clock.advance(gateWarnEvery + time.Second)
	g.acquire(ip)
	if refusals(buf) != before+1 {
		t.Fatal("the address stayed silent after the warning window passed")
	}
	// What returns the room is the release, not the clock.
	if p2, why := g.acquire(ip); p2 != nil || why != refusedConns {
		t.Fatalf("time passing alone returned a slot (%v/%v)", p2, why)
	}
	p.release()
	mustAcquire(t, g, ip)
}

func mustAcquire(t *testing.T, g *gate, ip net.IP) *permit {
	t.Helper()
	p, why := g.acquire(ip)
	if p == nil {
		t.Fatalf("acquire(%s) refused: %v", ip, why)
	}
	return p
}

// --- the credential half ---

func newAuthGate(limit int, window, locked time.Duration) (*gate, *counters, *bytes.Buffer, *fakeClock) {
	return newGateTest(0, 0, 0, &gateAuth{limit: limit, window: window, locked: locked})
}

func lockouts(buf *bytes.Buffer) int {
	return strings.Count(buf.String(), "address locked out")
}

func authIP(n byte) net.IP { return net.IPv4(192, 0, 2, n).To4() }

// Arming the lockout must not cost anything to the connection half, and leaving
// it off must cost nothing at all: the default deployment sets no auth flags, and
// "no buckets, no counting, nobody locked" is the whole promise.
func TestAuthLockoutOffIsInvisible(t *testing.T) {
	g, _, buf, _ := newTestGate(0, 0, 0) // every knob at 0, auth policy nil
	ip := authIP(1)

	for i := 0; i < 20; i++ {
		g.noteAuthFailure(ip)
	}
	if g.locked(ip) {
		t.Fatal("an address is locked out with no auth policy armed")
	}
	if n := g.lockedCount(); n != 0 {
		t.Errorf("locked addresses = %d with the feature off, want 0", n)
	}
	if n := g.tracked(); n != 0 {
		t.Errorf("the off gate recorded %d buckets for failed credentials, want 0", n)
	}
	if buf.Len() != 0 {
		t.Errorf("the off gate logged %q", buf.String())
	}
	// noteAuthSuccess on a gate that never made a bucket must not create one.
	g.noteAuthSuccess(ip)
	if n := g.tracked(); n != 0 {
		t.Errorf("a success on the off gate created %d buckets", n)
	}
}

// With only the credential half armed, the accept path stays exactly as cheap as
// it was: acquire hands back the shared off-permit, holds nothing, and releasing
// it must not touch the bucket the lockout counting lives in.
func TestAuthOnlyGateLeavesAcceptUnmetered(t *testing.T) {
	g, _, _, _ := newAuthGate(3, time.Minute, time.Minute)
	ip := authIP(2)

	g.noteAuthFailure(ip) // the address now has a bucket
	if g.connMetered {
		t.Fatal("arming only the credential limit also armed connection metering")
	}
	p, why := g.acquire(ip)
	if p != offPermit || why != refusedNone {
		t.Fatalf("acquire on an auth-only gate returned %v/%v, want the shared off permit", p, why)
	}
	if n := g.held(); n != 0 {
		t.Errorf("gate_held_sockets = %d while only credentials are metered, want 0", n)
	}
	p.release()
	if b := bucketOf(g, ip); b.conns != 0 {
		t.Errorf("releasing the off permit moved the bucket to %d connections", b.conns)
	}
}

func TestCredentialFailuresLockAtTheLimit(t *testing.T) {
	g, _, buf, _ := newAuthGate(3, time.Minute, 5*time.Minute)
	ip, other := authIP(3), authIP(4)

	for i := 0; i < 2; i++ {
		g.noteAuthFailure(ip)
		if g.locked(ip) {
			t.Fatalf("the address was locked after %d failures of an allowed 3", i+1)
		}
	}
	g.noteAuthFailure(ip)
	if !g.locked(ip) {
		t.Fatal("three failures in the window left the address free to try again")
	}
	if n := g.lockedCount(); n != 1 {
		t.Errorf("locked addresses = %d, want 1", n)
	}
	// The answer is per address: one device mistyping does not lock the subnet.
	if g.locked(other) {
		t.Fatal("a neighbour was locked out for another address's failures")
	}
	if n := lockouts(buf); n != 1 {
		t.Errorf("%d lockout lines for one lockout, want 1", n)
	}
	// The lockout outlives the failures that earned it: the count is reset at the
	// moment the lock starts, so the released address is not a failure from being
	// refused again back into another penalty.
	b := bucketOf(g, ip)
	if b.authFails != 0 {
		t.Errorf("failures still counted = %d after locking, want the window cleared", b.authFails)
	}
}

// Reaching the limit with no lockout duration asked for means the operator named
// a window and nothing else. The honest penalty is a whole window of quiet: the
// address has to behave well long enough to have filled one.
func TestDefaultLockoutIsAWindowOfQuiet(t *testing.T) {
	g, _, _, clock := newAuthGate(2, 90*time.Second, 0)
	ip := authIP(5)

	if got := g.authLockout(); got != 90*time.Second {
		t.Fatalf("lockout = %v, want it to default to the fail window", got)
	}
	g.noteAuthFailure(ip)
	g.noteAuthFailure(ip)
	if !g.locked(ip) {
		t.Fatal("two failures did not reach a limit of 2")
	}
	clock.advance(89 * time.Second)
	if !g.locked(ip) {
		t.Fatal("the lockout ended before its window of quiet was served")
	}
	clock.advance(2 * time.Second)
	if g.locked(ip) {
		t.Fatal("the lockout outlasted the window it defaults to")
	}
}

// Trying harder during a lockout must not extend it, and must not add to the next
// one either. A penalty that an attacker can grow by continuing the attack has
// become a ban that nobody configured, and the attack pays nothing for it.
func TestLockoutIsNotExtendedByTryingHarder(t *testing.T) {
	g, _, buf, clock := newAuthGate(3, time.Minute, 10*time.Minute)
	ip := authIP(6)

	for i := 0; i < 3; i++ {
		g.noteAuthFailure(ip)
	}
	first := bucketOf(g, ip).lockedUntil

	for i := 0; i < 100; i++ {
		clock.advance(time.Millisecond)
		g.noteAuthFailure(ip)
	}
	b := bucketOf(g, ip)
	if !b.lockedUntil.Equal(first) {
		t.Fatalf("lockout grew from %v to %v: the attack bought itself a longer penalty", first, b.lockedUntil)
	}
	if b.authFails != 0 {
		t.Errorf("failures during the lock were counted (%d), want them thrown away", b.authFails)
	}
	if n := lockouts(buf); n != 1 {
		t.Errorf("%d lockout lines for one address stuck in a lockout, want 1", n)
	}
	// And when it expires, the hundred refused attempts are not held against the
	// address: it needs a full set of fresh failures to be locked again.
	clock.advance(10*time.Minute + time.Second)
	if g.locked(ip) {
		t.Fatal("the lockout did not expire")
	}
	for i := 0; i < 2; i++ {
		g.noteAuthFailure(ip)
		if g.locked(ip) {
			t.Fatalf("the address was re-locked after only %d fresh failures", i+1)
		}
	}
	g.noteAuthFailure(ip)
	if !g.locked(ip) {
		t.Fatal("a full set of failures after the lockout did not lock again")
	}
}

// Asking whether an address is locked both frees it and forgets the term. The
// record should not keep claiming a debt that has been paid: it is what prune
// protects from the sweep, and the next failure has to land in a fresh window
// rather than in the "already serving a lockout" branch.
func TestExpiredLockoutIsForgotten(t *testing.T) {
	g, _, _, clock := newAuthGate(1, time.Minute, time.Minute)
	ip := authIP(7)

	g.noteAuthFailure(ip)
	if !g.locked(ip) {
		t.Fatal("one failure did not reach a limit of 1")
	}
	clock.advance(2 * time.Minute)
	if g.locked(ip) {
		t.Fatal("an address stayed locked past its term")
	}
	if b := bucketOf(g, ip); !b.lockedUntil.IsZero() {
		t.Fatalf("the expired term is still on record as %v, want it forgotten", b.lockedUntil)
	}
	if n := g.lockedCount(); n != 0 {
		t.Errorf("locked addresses = %d after the term expired, want 0", n)
	}
	// The next failure counts on its own, not as a continuation of the old run.
	g.noteAuthFailure(ip)
	if !g.locked(ip) {
		t.Fatal("a fresh failure after an expired term did not lock at a limit of 1")
	}
}

// A device that knows its password has earned a clean window. Without this, two
// mistypes on Monday plus one on Friday would lock an address for a week's worth
// of stray keystrokes.
//
// The clock is never advanced here: with a one-hour window, the only way the count
// can reach 3 is the success clearing it, not a window rolling over.
func TestAuthSuccessClearsTheCount(t *testing.T) {
	g, _, _, _ := newAuthGate(3, time.Hour, time.Hour)
	ip := authIP(8)

	g.noteAuthFailure(ip)
	g.noteAuthFailure(ip)
	g.noteAuthSuccess(ip)
	if b := bucketOf(g, ip); b.authFails != 0 || !b.windowStart.IsZero() {
		t.Fatalf("after a success the bucket holds %d failures from %v", b.authFails, b.windowStart)
	}
	// A full limit again, from zero.
	g.noteAuthFailure(ip)
	g.noteAuthFailure(ip)
	if g.locked(ip) {
		t.Fatal("two failures locked an address whose earlier ones were cleared")
	}
	g.noteAuthFailure(ip)
	if !g.locked(ip) {
		t.Fatal("the third failure after a success did not lock")
	}

	// A live lockout is not bought off. authenticate checks the lock before it
	// checks the password, so this is unreachable today; it is the ordering that
	// would have to break for a locked address to talk its way back in, and the
	// invariant is worth pinning in case anyone ever reorders those two lines.
	g.noteAuthSuccess(ip)
	if !g.locked(ip) {
		t.Fatal("a success cleared a lockout that was still being served")
	}
}

// Failures only stack inside the window. Three mistypes spread over an afternoon
// are a flaky device, not a brute-force run, and the limit means "in a row".
func TestFailuresOutsideTheWindowDoNotStack(t *testing.T) {
	g, _, _, clock := newAuthGate(3, time.Minute, 10*time.Minute)
	ip := authIP(9)

	g.noteAuthFailure(ip)
	clock.advance(40 * time.Second)
	g.noteAuthFailure(ip)
	clock.advance(40 * time.Second) // 80s from the first failure: the window has run out
	g.noteAuthFailure(ip)
	if g.locked(ip) {
		t.Fatal("three failures across two windows locked the address: the window did not roll over")
	}
	if b := bucketOf(g, ip); b.authFails != 1 {
		t.Errorf("counted failures = %d after the rollover, want the new window holding 1", b.authFails)
	}
	clock.advance(20 * time.Second)
	g.noteAuthFailure(ip)
	if g.locked(ip) {
		t.Fatal("the rolled window failed to accumulate")
	}
	clock.advance(20 * time.Second)
	g.noteAuthFailure(ip)
	if !g.locked(ip) {
		t.Fatal("three failures inside one rolled window did not lock")
	}
}

// The lockout is a debt, so it is the one thing prune may not collect. Forgetting
// a live lock is an evasion the attacker does not have to work at: stay quiet for
// the idle window and the broker has pardoned the attempt count for free.
func TestPruneKeepsALiveLockout(t *testing.T) {
	g, _, _, clock := newAuthGate(2, time.Minute, gateIdleWindow+30*time.Minute)
	locked, idle := authIP(10), authIP(11)

	g.noteAuthFailure(locked)
	g.noteAuthFailure(locked) // the limit
	g.noteAuthFailure(idle)   // one failure short of the limit, then nothing
	if !g.locked(locked) {
		t.Fatal("the address did not lock at the limit of 2")
	}
	if g.locked(idle) {
		t.Fatal("an address one failure short of the limit was locked")
	}

	// Both go quiet for longer than the idle window, holding no sockets.
	clock.advance(gateIdleWindow + time.Minute)
	g.prune()

	if n := g.lockedCount(); n != 1 {
		t.Fatalf("locked addresses after prune = %d, want the one still serving its term", n)
	}
	if !g.locked(locked) {
		t.Fatal("prune cancelled a lockout by forgetting its bucket")
	}
	// The merely-imperfect address is footprint, not a debt, and goes.
	if n := g.tracked(); n != 1 {
		t.Fatalf("gate tracks %d addresses after prune, want only the locked-out one", n)
	}
	if bucketOf(g, idle) != nil {
		t.Fatal("the idle bucket survived the sweep")
	}
	// Which is a reset, not a pardon of the live lock: the pruned address's single
	// earlier failure is gone, while the locked one still owes the rest of its term.
	g.noteAuthFailure(idle)
	if g.locked(idle) {
		t.Fatal("a pruned address kept its old count")
	}
}
