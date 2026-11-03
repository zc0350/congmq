// Package topics holds the topic-name grammar and the prefix tree that maps
// subscriptions to published topics.
package topics

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Separator divides topic levels.
const Separator = '/'

const (
	singleLevel  = "+"
	multiLevel   = "#"
	systemPrefix = "$"
)

// SharePrefix marks a 5.0 shared subscription: $share/{Group}/{Filter}.
const SharePrefix = "$share/"

// ErrInvalidTopic reports a topic name or filter that cannot be used.
var ErrInvalidTopic = errors.New("invalid topic")

// Options are the delivery settings a broker needs when a message matches this
// subscription, so they travel with it instead of being looked up again.
type Options struct {
	QoS               byte
	NoLocal           bool
	RetainAsPublished bool
	// ID is the Subscription Identifier echoed on every delivery made through
	// this filter. 0 means the subscriber did not ask for one.
	ID int
}

// Subscription is one client's interest in a filter.
type Subscription struct {
	ClientID string
	// Filter is exactly what the client subscribed to, including any
	// $share/{Group}/ prefix.
	Filter string
	// Group is the shared-subscription name, or "" for an ordinary filter.
	Group string
	Options
}

// key identifies a subscription inside one trie node. A client may hold both
// "a/b" and "$share/g1/a/b", which resolve to the same node, so the group is
// part of the identity.
func (s Subscription) key() string { return s.Group + "\x00" + s.ClientID }

// ValidName checks a topic name carried by a PUBLISH: no wildcards, no
// control characters, no empty levels.
func ValidName(topic string) error {
	if topic == "" {
		return fmt.Errorf("%w: empty topic name", ErrInvalidTopic)
	}
	if strings.ContainsAny(topic, singleLevel+multiLevel) {
		return fmt.Errorf("%w: topic name %q contains a wildcard", ErrInvalidTopic, topic)
	}
	return validChars(topic)
}

// ValidFilter checks a topic filter carried by a SUBSCRIBE, shared
// subscriptions included.
func ValidFilter(filter string) error {
	group, rest, shared := SplitShared(filter)
	if shared {
		if group == "" {
			return fmt.Errorf("%w: shared subscription %q has an empty group", ErrInvalidTopic, filter)
		}
		if strings.ContainsAny(group, singleLevel+multiLevel) {
			return fmt.Errorf("%w: shared group %q contains a wildcard", ErrInvalidTopic, group)
		}
		return ValidFilter(rest)
	}
	if filter == "" {
		return fmt.Errorf("%w: empty topic filter", ErrInvalidTopic)
	}
	if err := validChars(filter); err != nil {
		return err
	}
	levels := strings.Split(filter, string(Separator))
	for i, lvl := range levels {
		switch lvl {
		case multiLevel:
			if i != len(levels)-1 {
				return fmt.Errorf("%w: '#' must be the last level of %q", ErrInvalidTopic, filter)
			}
		case singleLevel:
		default:
			if strings.ContainsAny(lvl, singleLevel+multiLevel) {
				return fmt.Errorf("%w: wildcard must occupy a whole level in %q", ErrInvalidTopic, filter)
			}
		}
	}
	return nil
}

// SplitShared takes "$share/g/a/b" apart into its group and its filter. The
// boolean says whether the filter claimed to be shared. A malformed claim is
// reported with its halves empty so the caller rejects it rather than quietly
// filing it as an ordinary filter.
//
// The specification says the "$share" and {ShareName} portions are not taken
// into account when matching, so anything that reasons about what a filter
// covers works on the filter this returns.
func SplitShared(filter string) (group, rest string, shared bool) {
	if !strings.HasPrefix(filter, SharePrefix) {
		return "", filter, false
	}
	tail := filter[len(SharePrefix):]
	slash := strings.IndexByte(tail, Separator)
	if slash < 0 {
		return tail, "", true
	}
	return tail[:slash], tail[slash+1:], true
}

// filterLevels is the path this filter occupies in the trie. A shared
// subscription is filed under its plain filter, so one walk of the tree finds
// both ordinary and shared interest in a topic.
func filterLevels(filter string) []string {
	_, rest, shared := SplitShared(filter)
	if shared {
		return strings.Split(rest, string(Separator))
	}
	return strings.Split(filter, string(Separator))
}

func validChars(s string) error {
	for _, r := range s {
		if r == 0 || r == utf8RuneReplacement || r < 0x20 || r == 0x7F {
			return fmt.Errorf("%w: %q contains control character U+%04X", ErrInvalidTopic, s, r)
		}
	}
	return nil
}

const utf8RuneReplacement = 0xFFFD

// Tree is an in-memory prefix tree of subscriptions. It is safe for
// concurrent use.
type Tree struct {
	root *node
	n    int
	mu   sync.RWMutex

	// rrMu guards the round-robin counters, which Match advances while holding
	// only the read lock, so shared delivery can rotate without blocking
	// subscribers on a write lock.
	rrMu sync.Mutex
	rr   map[string]*atomic.Uint64
}

type node struct {
	children map[string]*node
	subs     map[string]Subscription
}

func newNode() *node {
	return &node{children: make(map[string]*node), subs: make(map[string]Subscription)}
}

// NewTree returns an empty tree.
func NewTree() *Tree { return &Tree{root: newNode(), rr: make(map[string]*atomic.Uint64)} }

// Count is the number of live subscriptions.
func (t *Tree) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.n
}

// Subscribe records interest and replaces any existing grant for the same
// client, filter and share group.
func (t *Tree) Subscribe(filter, clientID string, o Options) error {
	if err := ValidFilter(filter); err != nil {
		return err
	}
	group, _, shared := SplitShared(filter)
	sub := Subscription{ClientID: clientID, Filter: filter, Group: group, Options: o}
	if shared && o.NoLocal {
		return fmt.Errorf("%w: a shared subscription cannot set No Local", ErrInvalidTopic)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.root
	for _, lvl := range filterLevels(filter) {
		child := n.children[lvl]
		if child == nil {
			child = newNode()
			n.children[lvl] = child
		}
		n = child
	}
	if _, ok := n.subs[sub.key()]; !ok {
		t.n++
	}
	n.subs[sub.key()] = sub
	return nil
}

// Unsubscribe drops one filter for one client.
func (t *Tree) Unsubscribe(filter, clientID string) bool {
	group, _, shared := SplitShared(filter)
	return t.remove(filterLevels(filter), clientID, group, shared)
}

func (t *Tree) remove(levels []string, clientID, group string, shared bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.root
	for _, lvl := range levels {
		child := n.children[lvl]
		if child == nil {
			return false
		}
		n = child
	}
	key := group + "\x00" + clientID
	if _, ok := n.subs[key]; !ok {
		return false
	}
	delete(n.subs, key)
	t.n--
	return true
}

// UnsubscribeAll removes every subscription of a client and reports how many
// were dropped.
func (t *Tree) UnsubscribeAll(clientID string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	removed := 0
	var walk func(*node)
	walk = func(n *node) {
		for key, s := range n.subs {
			if s.ClientID == clientID {
				delete(n.subs, key)
				removed++
			}
		}
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(t.root)
	t.n -= removed
	return removed
}

// Subscriptions lists everything a client currently holds.
func (t *Tree) Subscriptions(clientID string) []Subscription {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []Subscription
	var walk func(*node)
	walk = func(n *node) {
		for _, s := range n.subs {
			if s.ClientID == clientID {
				out = append(out, s)
			}
		}
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(t.root)
	return out
}

// Match returns one entry per subscriber whose filter matches topic. When a
// client has several matching filters the highest granted QoS wins, which is
// what MQTT requires the receiver to see. Members of a shared subscription
// group are not all returned: one of them is chosen, and the choice rotates
// across calls so a queue-front of consumers splits the load.
func (t *Tree) Match(topic string) []Subscription {
	levels := strings.Split(topic, string(Separator))
	t.mu.RLock()
	cands := make(map[string]Subscription)
	// Only a filter whose *first* level is a wildcard is barred from matching a
	// $-prefixed topic, so "$SYS/#" still works while "#" does not.
	walk(t.root, levels, 0, cands, levels[0] == "" || levels[0][0] != systemPrefix[0])
	t.mu.RUnlock()

	return t.subscribers(cands)
}

// subscribers collapses the candidates into the deliveries to make: every ordinary
// subscription group of one client becomes a single best-QoS entry, and every
// shared group becomes exactly one entry, rotated round-robin. A client that
// holds both a plain and a shared filter matching the topic is in both sets and
// is served twice, which is what the specification's two rules together ask for.
func (t *Tree) subscribers(cands map[string]Subscription) []Subscription {
	plain := make(map[string]Subscription)
	groups := make(map[string][]Subscription)
	for _, s := range cands {
		if s.Group == "" {
			if cur, ok := plain[s.ClientID]; !ok || s.QoS > cur.QoS {
				plain[s.ClientID] = s
			}
			continue
		}
		groups[s.Group] = append(groups[s.Group], s)
	}

	out := make([]Subscription, 0, len(plain)+len(groups))
	for _, s := range plain {
		out = append(out, s)
	}
	for name, members := range groups {
		sort.Slice(members, func(i, j int) bool { return members[i].ClientID < members[j].ClientID })
		out = append(out, t.rotate(name, members))
	}
	return out
}

// rotate picks one member of a shared group, advancing that group's counter.
// Sorting the members first makes the rotation stable even though the trie is
// walked in map order.
func (t *Tree) rotate(group string, members []Subscription) Subscription {
	t.rrMu.Lock()
	ctr := t.rr[group]
	if ctr == nil {
		ctr = new(atomic.Uint64)
		t.rr[group] = ctr
	}
	t.rrMu.Unlock()
	n := ctr.Add(1) - 1
	return members[int(n%uint64(len(members)))]
}

func walk(n *node, levels []string, i int, found map[string]Subscription, allowWild bool) {
	if i == len(levels) {
		merge(found, n.subs)
		if child, ok := n.children[multiLevel]; ok && allowWild {
			merge(found, child.subs)
		}
		return
	}
	if child, ok := n.children[levels[i]]; ok {
		// Below the first level a leading-wildcard ban no longer applies.
		walk(child, levels, i+1, found, true)
	}
	if !allowWild {
		return
	}
	if child, ok := n.children[singleLevel]; ok {
		walk(child, levels, i+1, found, true)
	}
	if child, ok := n.children[multiLevel]; ok {
		merge(found, child.subs)
	}
}

func merge(dst, src map[string]Subscription) {
	for key, s := range src {
		// One client, one group: several filters of the same subscriber can land
		// on the same key while the walk descends, and the receiver must see the
		// highest QoS that was granted.
		if cur, ok := dst[key]; !ok || s.QoS > cur.QoS {
			dst[key] = s
		}
	}
}
