package broker

import (
	"sync/atomic"
	"time"

	"github.com/zc0350/congmq/internal/rules"
)

// ruleSet is one immutable pair of policies: the credential check and the
// authoriser that a decision must be made against together. It is never mutated
// after it is built, which is what lets a running broker swap it mid-decision.
type ruleSet struct {
	auth *rules.Authenticator
	acl  *rules.ACL

	// unsafeBase is the total every discarded rule set had already counted. A
	// freshly loaded ACL starts at zero, so without this fold
	// acl_unsafe_expansions would restart on every reload and a scraper reading
	// it as a counter would see the series go backwards.
	unsafeBase int64

	generation int64
	loadedUnix int64
}

// policy keeps the rule set in force, so an operator rewriting a rule file can
// be obeyed without dropping a connection. Every decision loads the pointer once
// and reads both halves from that snapshot: a CONNECT being answered now is
// answered by one generation, never by a new authoriser glued to an old
// credential check.
type policy struct {
	current atomic.Pointer[ruleSet]
}

func (p *policy) init(auth *rules.Authenticator, acl *rules.ACL) {
	p.current.Store(&ruleSet{auth: auth, acl: acl, generation: 1, loadedUnix: time.Now().Unix()})
}

func (p *policy) load() *ruleSet { return p.current.Load() }

// set installs the next generation and returns it.
func (p *policy) set(auth *rules.Authenticator, acl *rules.ACL) *ruleSet {
	prev := p.current.Load()
	next := &ruleSet{
		auth:       auth,
		acl:        acl,
		unsafeBase: prev.unsafeBase,
		generation: prev.generation + 1,
		loadedUnix: time.Now().Unix(),
	}
	if prev.acl != nil {
		// Folded at the moment this set stops being the one in force. A delivery
		// already inside the old ACL may still add its own count afterwards, which
		// then goes uncounted — a reload loses at most one expansion notice, and
		// pretending otherwise would mean a lock on the routing path.
		next.unsafeBase += prev.acl.UnsafeExpansions()
	}
	p.current.Store(next)
	return next
}

// SetRules replaces the policy in force and returns the generation now live.
//
// A nil half means "this half is off" — which is how a broker runs without rules
// — so a reload that empties a file is honoured rather than silently ignored.
// Loading is the caller's job: nothing is swapped until both halves parsed.
func (b *Broker) SetRules(auth *rules.Authenticator, acl *rules.ACL) int64 {
	return b.pol.set(auth, acl).generation
}
