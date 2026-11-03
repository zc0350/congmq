package topics

import "testing"

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pattern string
		subject string
		want    bool
	}{
		{"a/b", "a/b", true},
		{"a/b", "a/c", false},
		{"a/+", "a/b", true},
		{"a/+", "a/b/c", false},
		{"+/+", "a/b", true},
		{"a/#", "a/b/c", true},
		// '#' also covers the level above it, same as the trie.
		{"a/#", "a", true},
		{"#", "a", true},
		{"#", "a/b/c", true},

		// $SYS stays out of a leading wildcard.
		{"#", "$SYS/broker/load", false},
		{"+/#", "$SYS/broker/load", false},
		{"$SYS/#", "$SYS/broker/load", true},
		{"$SYS/+/load", "$SYS/broker/load", true},
		{"+", "$SYS", false},
		{"$SYS", "$SYS", true},

		// The subject may itself be a filter: an ACL asks "may this client
		// subscribe to #?" and then the wildcards are ordinary characters, so
		// "#" swallows "+" the same way it swallows any topic name. Matching
		// stays as loose as MQTT wildcard matching, which is why the rule file
		// uses a literal comparison for exact refusals.
		{"#", "#", true},
		{"#", "+", true},
		{"+", "#", true},
		{"a/+", "a/#", true},
		{"sport+/tennis#", "sport+/tennis#", true},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.subject); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.subject, got, c.want)
		}
	}
}

func TestMatchAgreesWithTrie(t *testing.T) {
	// The router and the ACL engine must not disagree about a concrete topic.
	patterns := []string{"a/b", "a/+", "a/#", "#", "+/+", "$SYS/#", "sensor/+/temp", "sport/tennis/#"}
	subjects := []string{"a/b", "a/c", "a/b/c", "a", "sensor/x/temp", "sensor/x/hum", "$SYS/broker/load", "sport/tennis/player1"}

	for _, p := range patterns {
		tree := NewTree()
		if err := tree.Subscribe(p, "c1", Options{QoS: 1}); err != nil {
			t.Fatalf("subscribe %q: %v", p, err)
		}
		for _, s := range subjects {
			trieGot := len(tree.Match(s)) > 0
			if matchGot := Match(p, s); matchGot != trieGot {
				t.Errorf("pattern %q, topic %q: Match=%v but trie=%v", p, s, matchGot, trieGot)
			}
		}
	}
}
