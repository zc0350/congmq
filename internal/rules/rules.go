// Package rules implements the operator's JSONL rule files: auth.jsonl for
// credential checking and acl.jsonl for publish/subscribe authorization.
//
// Both files are one JSON object per line, with '#' lines and blank lines
// skipped. Unknown fields reject the whole file rather than being ignored, so
// a typo can never quietly weaken a rule.
package rules

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

// ErrInvalidRule reports a rule file that cannot be loaded.
var ErrInvalidRule = errors.New("rules: invalid rule file")

// Identity is everything the broker knows about a connection when it asks a
// question of the rule files.
type Identity struct {
	Username string
	ClientID string
	IP       net.IP
	// CertCN is the CommonName of the client certificate the peer presented and
	// this broker verified. It is empty for a plain connection and for a TLS
	// connection whose chain was not checked, so a rule that asks for a
	// certificate can never be satisfied by an identity that has none.
	CertCN string
}

// readJSONL hands every non-comment line to parse, which reports the problem
// with its file and line number.
func readJSONL(path string, parse func(line int, raw []byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 || raw[0] == '#' {
			continue
		}
		if err := parse(n, raw); err != nil {
			return fmt.Errorf("%s:%d: %w", path, n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%w: reading %s: %v", ErrInvalidRule, path, err)
	}
	return nil
}

// strictObject decodes one JSON object and refuses unknown keys.
func strictObject(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	if d.More() {
		return fmt.Errorf("%w: more than one JSON value on the line", ErrInvalidRule)
	}
	return nil
}

// ipConstraint matches a single address or a prefix, IPv4 and IPv6 alike.
type ipConstraint struct {
	exact net.IP
	net   *net.IPNet
	raw   string
}

func parseIPConstraint(s string) (*ipConstraint, error) {
	if s == "" {
		return nil, nil
	}
	if strings.Contains(s, "/") {
		_, network, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("%w: bad ip %q: %v", ErrInvalidRule, s, err)
		}
		return &ipConstraint{net: network, raw: s}, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("%w: bad ip %q", ErrInvalidRule, s)
	}
	return &ipConstraint{exact: ip, raw: s}, nil
}

func (c *ipConstraint) contains(ip net.IP) bool {
	if c == nil {
		return true
	}
	if ip == nil {
		return false
	}
	if c.net != nil {
		return c.net.Contains(ip)
	}
	return c.exact.Equal(ip)
}

func (c *ipConstraint) String() string {
	if c == nil {
		return "*"
	}
	return c.raw
}

// matchKind selects between a literal comparison and a regular expression.
// The rule files ask for POSIX extended regex; Go's regexp is RE2, which
// accepts every ERE pattern these files use.
const regexKind = "regex"

func compileRegex(pattern, field string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("%w: %s pattern %q: %v", ErrInvalidRule, field, pattern, err)
	}
	return re, nil
}

// matchText compares one field, either literally or through its regex.
func matchText(re *regexp.Regexp, literal, value string) bool {
	if literal == "" || literal == "*" {
		return true
	}
	if re != nil {
		return re.MatchString(value)
	}
	return literal == value
}

// sanitize strips everything but [A-Za-z0-9] from the username that feeds a
// password digest, which is what the rule file's "sanitize" switch controls.
// Matching itself always sees the original username.
func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b.WriteByte(c)
		}
	}
	return b.String()
}
