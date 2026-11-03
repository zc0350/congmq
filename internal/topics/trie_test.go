package topics

import (
	"sort"
	"testing"
)

func TestValidFilter(t *testing.T) {
	ok := []string{"a", "a/b", "a/+/c", "+", "#", "a/#", "$SYS/#", "sport/tennis/player1/#"}
	bad := []string{"", "a/#/b", "a/+b", "a/b#", "a\x00b"}
	for _, f := range ok {
		if err := ValidFilter(f); err != nil {
			t.Errorf("ValidFilter(%q) = %v, want nil", f, err)
		}
	}
	for _, f := range bad {
		if err := ValidFilter(f); err == nil {
			t.Errorf("ValidFilter(%q) = nil, want an error", f)
		}
	}
}

func TestValidName(t *testing.T) {
	ok := []string{"a", "a/b", "a//b", "$SYS/x"}
	bad := []string{"", "a/+", "a/#", "a\x7fb"}
	for _, n := range ok {
		if err := ValidName(n); err != nil {
			t.Errorf("ValidName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range bad {
		if err := ValidName(n); err == nil {
			t.Errorf("ValidName(%q) = nil, want an error", n)
		}
	}
}

// qos is shorthand for the only option most of these tests care about.
func qos(q byte) Options { return Options{QoS: q} }

func matchIDs(tr *Tree, topic string) []string {
	subs := tr.Match(topic)
	out := make([]string, 0, len(subs))
	for _, s := range subs {
		out = append(out, s.ClientID)
	}
	sort.Strings(out)
	return out
}

func TestMatch(t *testing.T) {
	tr := NewTree()
	add := func(filter, id string, o Options) {
		if err := tr.Subscribe(filter, id, o); err != nil {
			t.Fatalf("Subscribe(%q): %v", filter, err)
		}
	}
	add("a/b/c", "exact", qos(0))
	add("a/+/c", "plus", qos(1))
	add("a/#", "hash", qos(2))
	add("#", "all", qos(0))
	add("a/b", "parent", qos(0))

	cases := []struct {
		topic string
		want  []string
	}{
		{"a/b/c", []string{"all", "exact", "hash", "plus"}},
		{"a", []string{"all", "hash"}},
		// "a/#" matches a/b and even a, because # covers zero or more levels.
		{"a/b", []string{"all", "hash", "parent"}},
		{"a/b/c/d", []string{"all", "hash"}},
		{"x/y", []string{"all"}},
		{"a/xx/c", []string{"all", "hash", "plus"}},
	}
	for _, tc := range cases {
		got := matchIDs(tr, tc.topic)
		if len(got) != len(tc.want) {
			t.Errorf("Match(%q) = %v, want %v", tc.topic, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("Match(%q) = %v, want %v", tc.topic, got, tc.want)
				break
			}
		}
	}
}

func TestSystemTopicsAreNotMatchedByLeadingWildcards(t *testing.T) {
	tr := NewTree()
	_ = tr.Subscribe("#", "everything", qos(0))
	_ = tr.Subscribe("+/x", "plus", qos(0))
	_ = tr.Subscribe("$SYS/#", "broker", qos(0))

	if got := matchIDs(tr, "$SYS/broker/uptime"); len(got) != 1 || got[0] != "broker" {
		t.Errorf("Match($SYS) = %v, want [broker]", got)
	}
	if got := matchIDs(tr, "a/x"); len(got) != 2 {
		t.Errorf("Match(a/x) = %v, want two subscribers", got)
	}
}

func TestHighestQoSWinsForOneClient(t *testing.T) {
	tr := NewTree()
	_ = tr.Subscribe("a/#", "c1", qos(1))
	_ = tr.Subscribe("a/b", "c1", qos(2))
	_ = tr.Subscribe("a/+", "c1", qos(0))

	subs := tr.Match("a/b")
	if len(subs) != 1 {
		t.Fatalf("a client with three matching filters must get one copy, got %d", len(subs))
	}
	if subs[0].QoS != 2 {
		t.Errorf("granted QoS = %d, want 2", subs[0].QoS)
	}
}

func TestUnsubscribe(t *testing.T) {
	tr := NewTree()
	_ = tr.Subscribe("a/b", "c1", qos(1))
	_ = tr.Subscribe("a/#", "c2", qos(1))
	if tr.Count() != 2 {
		t.Fatalf("Count = %d, want 2", tr.Count())
	}
	if !tr.Unsubscribe("a/b", "c1") {
		t.Fatal("Unsubscribe reported nothing removed")
	}
	if tr.Unsubscribe("a/b", "c1") {
		t.Fatal("Unsubscribe must be false when the filter is already gone")
	}
	if got := matchIDs(tr, "a/b"); len(got) != 1 || got[0] != "c2" {
		t.Errorf("Match = %v, want [c2]", got)
	}
	if n := tr.UnsubscribeAll("c2"); n != 1 {
		t.Errorf("UnsubscribeAll = %d, want 1", n)
	}
	if tr.Count() != 0 {
		t.Errorf("Count after UnsubscribeAll = %d, want 0", tr.Count())
	}
	if list := tr.Subscriptions("c1"); len(list) != 0 {
		t.Errorf("Subscriptions = %v, want none", list)
	}
}

func TestSubscribeReplacesGrant(t *testing.T) {
	tr := NewTree()
	_ = tr.Subscribe("a/b", "c1", qos(2))
	_ = tr.Subscribe("a/b", "c1", qos(0))
	if tr.Count() != 1 {
		t.Fatalf("Count = %d, want 1", tr.Count())
	}
	if subs := tr.Subscriptions("c1"); subs[0].QoS != 0 {
		t.Errorf("QoS = %d, want the re-subscribe value 0", subs[0].QoS)
	}
}

func TestValidSharedFilter(t *testing.T) {
	ok := []string{"$share/g1/a/b", "$share/consumers/#", "$share/g1/+/x"}
	bad := []string{"$share/", "$share//a", "$share/g1", "$share/g/a/#/b", "$share/g+/a"}
	for _, f := range ok {
		if err := ValidFilter(f); err != nil {
			t.Errorf("ValidFilter(%q) = %v, want nil", f, err)
		}
	}
	for _, f := range bad {
		if err := ValidFilter(f); err == nil {
			t.Errorf("ValidFilter(%q) = nil, want an error", f)
		}
	}
}

func TestSharedSubscriptionRotates(t *testing.T) {
	tr := NewTree()
	for _, id := range []string{"w1", "w2", "w3"} {
		if err := tr.Subscribe("$share/workers/jobs", id, qos(1)); err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
	}
	if tr.Count() != 3 {
		t.Fatalf("Count = %d, want three members", tr.Count())
	}

	seen := make(map[string]int)
	for i := 0; i < 9; i++ {
		subs := tr.Match("jobs")
		if len(subs) != 1 {
			t.Fatalf("a shared group must take one copy, got %d", len(subs))
		}
		if subs[0].QoS != 1 {
			t.Errorf("granted QoS = %d, want 1", subs[0].QoS)
		}
		seen[subs[0].ClientID]++
	}
	if len(seen) != 3 {
		t.Fatalf("only %v delivered, want all three workers", seen)
	}
	for id, n := range seen {
		if n != 3 {
			t.Errorf("worker %s took %d of 9, want an even spread", id, n)
		}
	}
}

func TestSharedAndPlainSubscriptionDeliverTwice(t *testing.T) {
	tr := NewTree()
	_ = tr.Subscribe("jobs", "c1", qos(0))
	_ = tr.Subscribe("$share/g/jobs", "c1", qos(2))
	_ = tr.Subscribe("$share/g/jobs", "c2", qos(1))

	subs := tr.Match("jobs")
	if len(subs) != 2 {
		t.Fatalf("Match = %d entries, want one plain and one shared", len(subs))
	}
	var plain, shared *Subscription
	for i := range subs {
		if subs[i].Group == "" {
			plain = &subs[i]
		} else {
			shared = &subs[i]
		}
	}
	if plain == nil || plain.Filter != "jobs" || plain.QoS != 0 {
		t.Errorf("plain delivery = %+v, want the zero-QoS filter", plain)
	}
	if shared == nil || shared.Filter != "$share/g/jobs" {
		t.Fatalf("shared delivery = %+v", shared)
	}

	if !tr.Unsubscribe("$share/g/jobs", "c1") {
		t.Error("Unsubscribe must find the shared filter")
	}
	if got := matchIDs(tr, "jobs"); len(got) != 2 || got[0] != "c1" || got[1] != "c2" {
		t.Errorf("Match after one member left = %v, want the plain copy and the remaining worker", got)
	}
}

func TestSharedGroupPerClientIsDistinct(t *testing.T) {
	tr := NewTree()
	_ = tr.Subscribe("$share/g1/a/b", "c1", qos(0))
	_ = tr.Subscribe("$share/g2/a/b", "c1", qos(0))
	_ = tr.Subscribe("a/b", "c1", qos(0))
	if tr.Count() != 3 {
		t.Fatalf("Count = %d, want one entry per group", tr.Count())
	}
	// Two groups and one plain filter: three deliveries, even though they all
	// belong to the same client and the same node.
	if got := tr.Match("a/b"); len(got) != 3 {
		t.Errorf("Match = %d, want 3", len(got))
	}
	if n := tr.UnsubscribeAll("c1"); n != 3 {
		t.Errorf("UnsubscribeAll = %d, want 3", n)
	}
}

func TestNoLocalRejectsShared(t *testing.T) {
	tr := NewTree()
	if err := tr.Subscribe("$share/g/a", "c1", Options{NoLocal: true}); err == nil {
		t.Error("a shared subscription cannot set No Local")
	}
}
