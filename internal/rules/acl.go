package rules

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/zc0350/congmq/internal/topics"
)

// Action is the operation an ACL rule speaks about.
type Action string

const (
	// ActionPublish is a client sending a message.
	ActionPublish Action = "publish"
	// ActionSubscribe covers both asking for a filter and receiving messages.
	ActionSubscribe Action = "subscribe"
	// ActionAll matches either operation.
	ActionAll Action = "all"
)

const (
	effectAllow = "allow"
	effectDeny  = "deny"
	probeLevel  = "congmqprobe"
)

// topicPattern is one entry of a rule's "topics" list: either a plain string,
// matched as an MQTT wildcard pattern after template expansion, or
// {"eq": "..."} compared literally so that "#" means the two characters.
type topicPattern struct {
	filter   string
	eq       string
	maxGroup int
}

func (p topicPattern) String() string {
	if p.eq != "" {
		return `{"eq":` + p.eq + `}`
	}
	return p.filter
}

// ACLRule is one compiled line of acl.jsonl.
type ACLRule struct {
	Effect     string
	User       string
	ClientID   string
	IP         string
	CertCN     string
	Action     Action
	Topics     []topicPattern
	LineNumber int

	userRE   *regexp.Regexp
	clientRE *regexp.Regexp
	certRE   *regexp.Regexp
	ipNet    *ipConstraint
}

func (r *ACLRule) String() string {
	return fmt.Sprintf("line %d: %s %s user=%q clientid=%q ip=%s cert_cn=%q topics=%v",
		r.LineNumber, r.Effect, r.Action, r.User, r.ClientID, r.ipNet, r.CertCN, r.Topics)
}

// UsesCertificate reports a rule that asks for a client certificate. Such a rule
// can never match a plain connection, so a broker without TLS is not enforcing
// what this file describes.
func (r *ACLRule) UsesCertificate() bool { return r.CertCN != "" || r.certRE != nil }

type aclJSON struct {
	Effect        string            `json:"effect"`
	User          string            `json:"user"`
	Match         string            `json:"match"`
	ClientID      string            `json:"clientid"`
	ClientIDMatch string            `json:"clientid_match"`
	IP            string            `json:"ip"`
	CertCN        string            `json:"cert_cn"`
	CertCNMatch   string            `json:"cert_cn_match"`
	Action        string            `json:"action"`
	Topics        []json.RawMessage `json:"topics"`
}

// ACL evaluates publish and subscribe authorization.
type ACL struct {
	path  string
	rules []ACLRule

	// unsafe counts template expansions refused because the identity carried
	// a wildcard; a client id of "a/#" must never enlarge its own rule.
	unsafe atomic.Int64
}

// LoadACL compiles acl.jsonl. Rules are kept in strict file order: the first
// rule that matches subject, action and topic decides.
func LoadACL(path string) (*ACL, error) {
	a := &ACL{path: path}
	err := readJSONL(path, func(line int, raw []byte) error {
		var j aclJSON
		if err := strictObject(raw, &j); err != nil {
			return err
		}
		r, err := compileACLRule(j, line)
		if err != nil {
			return err
		}
		a.rules = append(a.rules, *r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

func compileACLRule(j aclJSON, line int) (*ACLRule, error) {
	switch j.Effect {
	case effectAllow, effectDeny:
	default:
		return nil, fmt.Errorf("%w: effect must be allow or deny, got %q", ErrInvalidRule, j.Effect)
	}
	action := ActionAll
	switch j.Action {
	case "":
	case string(ActionPublish), string(ActionSubscribe), string(ActionAll):
		action = Action(j.Action)
	default:
		return nil, fmt.Errorf("%w: unknown action %q", ErrInvalidRule, j.Action)
	}
	if j.Match != "" && j.Match != regexKind {
		return nil, fmt.Errorf("%w: unknown match %q", ErrInvalidRule, j.Match)
	}
	if j.ClientIDMatch != "" && j.ClientIDMatch != regexKind {
		return nil, fmt.Errorf("%w: unknown clientid_match %q", ErrInvalidRule, j.ClientIDMatch)
	}
	if j.CertCNMatch != "" && j.CertCNMatch != regexKind {
		return nil, fmt.Errorf("%w: unknown cert_cn_match %q", ErrInvalidRule, j.CertCNMatch)
	}
	if j.CertCNMatch == regexKind && j.CertCN == "" {
		return nil, fmt.Errorf("%w: cert_cn_match needs cert_cn to hold the pattern", ErrInvalidRule)
	}

	r := &ACLRule{
		Effect:     j.Effect,
		User:       j.User,
		ClientID:   j.ClientID,
		IP:         j.IP,
		CertCN:     j.CertCN,
		Action:     action,
		LineNumber: line,
	}
	if j.Match == regexKind {
		re, err := compileRegex(j.User, "user")
		if err != nil {
			return nil, err
		}
		r.userRE = re
	}
	if j.ClientIDMatch == regexKind {
		re, err := compileRegex(j.ClientID, "clientid")
		if err != nil {
			return nil, err
		}
		r.clientRE = re
	}
	if j.CertCNMatch == regexKind {
		re, err := compileRegex(j.CertCN, "cert_cn")
		if err != nil {
			return nil, err
		}
		r.certRE = re
	}
	ip, err := parseIPConstraint(j.IP)
	if err != nil {
		return nil, err
	}
	r.ipNet = ip

	for _, raw := range j.Topics {
		p, err := compileTopicPattern(raw, r.userRE)
		if err != nil {
			return nil, err
		}
		r.Topics = append(r.Topics, p)
	}
	return r, nil
}

func compileTopicPattern(raw json.RawMessage, userRE *regexp.Regexp) (topicPattern, error) {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "{") {
		var eq struct {
			Eq string `json:"eq"`
		}
		d := json.NewDecoder(strings.NewReader(trimmed))
		d.DisallowUnknownFields()
		if err := d.Decode(&eq); err != nil {
			return topicPattern{}, fmt.Errorf("%w: topics entry: %v", ErrInvalidRule, err)
		}
		if eq.Eq == "" {
			return topicPattern{}, fmt.Errorf("%w: topics entry {\"eq\": \"\"} is empty", ErrInvalidRule)
		}
		return topicPattern{eq: eq.Eq}, nil
	}

	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return topicPattern{}, fmt.Errorf("%w: topics entry must be a string or {\"eq\": ...}: %v", ErrInvalidRule, err)
	}
	if s == "" {
		return topicPattern{}, fmt.Errorf("%w: empty topic pattern", ErrInvalidRule)
	}
	p := topicPattern{filter: s}

	// "%1" can only be filled from the user regex, and only if it has the
	// group: catch both mistakes while loading the file.
	max, err := checkTemplates(s, userRE)
	if err != nil {
		return p, err
	}
	p.maxGroup = max
	if err := topics.ValidFilter(replaceTemplates(s, probeLevel)); err != nil {
		return p, fmt.Errorf("%w: topic pattern %q: %v", ErrInvalidRule, s, err)
	}
	return p, nil
}

// checkTemplates validates every percent token and returns the highest group
// number used.
func checkTemplates(s string, userRE *regexp.Regexp) (int, error) {
	max := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if i+1 >= len(s) {
			return 0, fmt.Errorf("%w: topic pattern %q ends with a bare '%%'", ErrInvalidRule, s)
		}
		c := s[i+1]
		i++
		switch {
		case c == '%' || c == 'c' || c == 'u':
		case c >= '0' && c <= '9':
			n := int(c - '0')
			if n > max {
				max = n
			}
			if userRE == nil {
				return 0, fmt.Errorf("%w: topic pattern %q uses %%%d but the rule has no \"match\": \"regex\" user", ErrInvalidRule, s, n)
			}
			if n > userRE.NumSubexp() {
				return 0, fmt.Errorf("%w: topic pattern %q uses %%%d but the user regex has only %d group(s)",
					ErrInvalidRule, s, n, userRE.NumSubexp())
			}
		default:
			// Anything else is an ordinary percent, kept as written.
		}
	}
	return max, nil
}

// replaceTemplates swaps every token for a fixed probe level so the rest of
// the pattern can be grammar-checked.
func replaceTemplates(s, probe string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '%' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		c := s[i+1]
		switch {
		case c == 'c' || c == 'u' || c >= '0' && c <= '9':
			b.WriteString(probe)
			i += 2
		case c == '%':
			b.WriteByte('%')
			i += 2
		default:
			b.WriteByte('%')
			b.WriteByte(c)
			i += 2
		}
	}
	return b.String()
}

// expand fills the identity tokens of a pattern. It reports unsafe when a
// substituted value contains a wildcard.
func expand(pattern string, id Identity, groups []string) (string, bool) {
	var b strings.Builder
	b.Grow(len(pattern) + 8)
	for i := 0; i < len(pattern); {
		if pattern[i] != '%' || i+1 >= len(pattern) {
			b.WriteByte(pattern[i])
			i++
			continue
		}
		c := pattern[i+1]
		i += 2
		var value string
		switch {
		case c == '%':
			b.WriteByte('%')
			continue
		case c == 'c':
			value = id.ClientID
		case c == 'u':
			value = id.Username
		case c >= '0' && c <= '9':
			if n := int(c - '0'); n < len(groups) {
				value = groups[n]
			}
		default:
			b.WriteByte('%')
			b.WriteByte(c)
			continue
		}
		if strings.ContainsAny(value, "+#") {
			return "", false
		}
		b.WriteString(value)
	}
	return b.String(), true
}

// Rules exposes the compiled rules for start-up logging.
func (a *ACL) Rules() []ACLRule { return a.rules }

// Count is the number of loaded rules.
func (a *ACL) Count() int { return len(a.rules) }

// String names the file this ACL was loaded from.
func (a *ACL) String() string { return a.path }

// UnsafeExpansions counts expansions refused because an identity contained a
// wildcard.
func (a *ACL) UnsafeExpansions() int64 { return a.unsafe.Load() }

// UsesCertificates reports a rule that asks for a client certificate. A broker
// started without TLS can load such a file but can never match one of those
// lines, so the operator is told at start-up rather than left to wonder why
// every device is refused.
func (a *ACL) UsesCertificates() bool {
	for i := range a.rules {
		if a.rules[i].UsesCertificate() {
			return true
		}
	}
	return false
}

// Decision evaluates the file in order. It returns the verdict and the rule
// that produced it; a nil rule means nothing matched, which this implementation
// treats as a refusal.
func (a *ACL) Decision(action Action, id Identity, resource string) (bool, *ACLRule) {
	for i := range a.rules {
		r := &a.rules[i]
		groups, ok := r.matchesSubject(id)
		if !ok {
			continue
		}
		if r.Action != ActionAll && r.Action != action {
			continue
		}
		if len(r.Topics) == 0 {
			return r.Effect == effectAllow, r
		}
		for _, p := range r.Topics {
			matched, unsafe := p.matches(id, groups, resource)
			if unsafe {
				a.unsafe.Add(1)
				continue
			}
			if matched {
				return r.Effect == effectAllow, r
			}
		}
	}
	return false, nil
}

// matchesSubject tests user, client id and source address. When the user is a
// regex, its capture groups come back for template expansion.
func (r *ACLRule) matchesSubject(id Identity) (groups []string, ok bool) {
	if r.UsesCertificate() && id.CertCN == "" {
		// No certificate on the connection, so a certificate line says nothing.
		return nil, false
	}
	if !matchText(r.certRE, r.CertCN, id.CertCN) {
		return nil, false
	}
	if r.userRE != nil {
		groups = r.userRE.FindStringSubmatch(id.Username)
		if groups == nil {
			return nil, false
		}
	} else if !matchText(nil, r.User, id.Username) {
		return nil, false
	}
	if !matchText(r.clientRE, r.ClientID, id.ClientID) {
		return nil, false
	}
	if !r.ipNet.contains(id.IP) {
		return nil, false
	}
	return groups, true
}

func (p topicPattern) matches(id Identity, groups []string, resource string) (matched, unsafe bool) {
	if p.eq != "" {
		return p.eq == resource, false
	}
	expanded, ok := expand(p.filter, id, groups)
	if !ok {
		return false, true
	}
	return topics.Match(expanded, resource), false
}
