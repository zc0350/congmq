package rules

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"hash"
	"regexp"
	"strings"
)

// Password digest schemes.
const (
	SchemeUsernameSalt     = "username+salt"
	SchemeSaltUsername     = "salt+username"
	SchemeSaltUsernameSalt = "salt+username+salt"
)

// AuthRule is one compiled line of auth.jsonl.
type AuthRule struct {
	Username   string
	ClientID   string
	IP         string
	CertCN     string
	Salt       string
	Alg        string
	Scheme     string
	Sanitize   bool
	LineNumber int

	userRE   *regexp.Regexp
	clientRE *regexp.Regexp
	certRE   *regexp.Regexp
	ipNet    *ipConstraint
}

// Literal reports a rule that names an exact username or an exact certificate
// CommonName. Literal rules are tried before any wildcard or regex rule, so a
// specific account is never shadowed by a permissive catch-all further down the
// file.
func (r *AuthRule) Literal() bool {
	return (r.Username != "" && r.Username != "*" && r.userRE == nil) ||
		(r.CertCN != "" && r.CertCN != "*" && r.certRE == nil)
}

// certRequired reports a rule that only a presented certificate can answer to.
// "cert_cn": "*" counts: it asks for any certificate, which is a certificate
// requirement even though it names no one.
func (r *AuthRule) certRequired() bool {
	return r.CertCN != "" || r.certRE != nil
}

// ByCertificate reports a rule whose credential IS the certificate: it names a
// client certificate and asks for no password digest. Such a rule is satisfied
// by the handshake alone, because TLS already proved the peer holds the private
// key, and there is no secret left to check.
func (r *AuthRule) ByCertificate() bool {
	return r.certRequired() && r.Alg == "" && r.Scheme == ""
}

func (r *AuthRule) String() string {
	return fmt.Sprintf("username=%q clientid=%q ip=%s cert_cn=%s alg=%s scheme=%s",
		r.Username, r.ClientID, r.ipNet, certField(r), r.Alg, r.Scheme)
}

func certField(r *AuthRule) string {
	switch {
	case r.certRE != nil:
		return r.certRE.String()
	case r.CertCN == "":
		return "-"
	default:
		return `"` + r.CertCN + `"`
	}
}

type authJSON struct {
	Username      string `json:"username"`
	Match         string `json:"match"`
	ClientID      string `json:"clientid"`
	ClientIDMatch string `json:"clientid_match"`
	IP            string `json:"ip"`
	CertCN        string `json:"cert_cn"`
	CertCNMatch   string `json:"cert_cn_match"`
	Salt          string `json:"salt"`
	Alg           string `json:"alg"`
	Scheme        string `json:"scheme"`
	Sanitize      *bool  `json:"sanitize"`
}

// Authenticator checks client credentials against a loaded rule file.
type Authenticator struct {
	path  string
	rules []AuthRule
}

// LoadAuth compiles auth.jsonl. Every password rule needs a digest algorithm and
// a scheme: a rule that can never be satisfied is a load error, not a silent
// hole. The exception is a rule that names a client certificate and asks for no
// password at all — there the handshake is the credential.
func LoadAuth(path string) (*Authenticator, error) {
	a := &Authenticator{path: path}
	err := readJSONL(path, func(line int, raw []byte) error {
		var j authJSON
		if err := strictObject(raw, &j); err != nil {
			return err
		}
		r, err := compileAuthRule(j, line)
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

func compileAuthRule(j authJSON, line int) (*AuthRule, error) {
	if j.Match != "" && j.Match != regexKind {
		return nil, fmt.Errorf("%w: unknown match %q (want %q)", ErrInvalidRule, j.Match, regexKind)
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

	// A certificate may stand in for a password, but only for the whole line: a
	// rule with both a certificate and a digest would let a device in on whichever
	// half its operator remembered to configure.
	certAsked := j.CertCN != ""
	hasDigest := j.Alg != "" || j.Scheme != ""
	if certAsked && !hasDigest {
		if j.Salt != "" {
			return nil, fmt.Errorf("%w: a certificate rule checks no password, so it takes no salt", ErrInvalidRule)
		}
	} else {
		switch j.Alg {
		case "md5", "sha1", "sha256", "sha512":
		default:
			return nil, fmt.Errorf("%w: rule needs alg md5|sha1|sha256|sha512, got %q", ErrInvalidRule, j.Alg)
		}
		switch j.Scheme {
		case SchemeUsernameSalt, SchemeSaltUsername, SchemeSaltUsernameSalt:
		default:
			return nil, fmt.Errorf("%w: rule needs scheme %q, %q or %q, got %q",
				ErrInvalidRule, SchemeUsernameSalt, SchemeSaltUsername, SchemeSaltUsernameSalt, j.Scheme)
		}
	}

	r := &AuthRule{
		Username:   j.Username,
		ClientID:   j.ClientID,
		IP:         j.IP,
		CertCN:     j.CertCN,
		Salt:       j.Salt,
		Alg:        j.Alg,
		Scheme:     j.Scheme,
		Sanitize:   true,
		LineNumber: line,
	}
	if j.Sanitize != nil {
		r.Sanitize = *j.Sanitize
	}
	if j.Match == regexKind {
		re, err := compileRegex(j.Username, "username")
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
	return r, nil
}

// Rules exposes the compiled rules, mainly for start-up logging.
func (a *Authenticator) Rules() []AuthRule { return a.rules }

// Count is the number of loaded rules.
func (a *Authenticator) Count() int { return len(a.rules) }

// String names the file this authenticator was loaded from.
func (a *Authenticator) String() string { return a.path }

// UsesCertificates reports a rule that only a verified client certificate can
// answer to. A broker started without TLS can load such a file but can never
// satisfy it, which is worth refusing out loud instead of locking every device
// out quietly.
func (a *Authenticator) UsesCertificates() bool {
	for i := range a.rules {
		if a.rules[i].certRequired() {
			return true
		}
	}
	return false
}

// Authenticate reports whether the presented credentials satisfy a rule. Rules
// with a literal username or certificate name are tried first, then the rest in
// file order; an empty rule set accepts nobody.
func (a *Authenticator) Authenticate(id Identity, password string) bool {
	for _, pass := range [2]func(*AuthRule) bool{
		func(r *AuthRule) bool { return r.Literal() },
		func(r *AuthRule) bool { return !r.Literal() },
	} {
		for i := range a.rules {
			r := &a.rules[i]
			if !pass(r) {
				continue
			}
			if !r.matches(id) {
				continue
			}
			if r.ByCertificate() {
				// The handshake proved the peer holds this certificate's private
				// key, so there is no secret left to compare.
				return true
			}
			if matchesSecret(r.expected(id.Username), password) {
				return true
			}
			// A subject-matching rule with the wrong password stops nothing:
			// another rule may still accept this identity, so keep trying.
		}
	}
	return false
}

func (r *AuthRule) matches(id Identity) bool {
	if r.certRequired() && id.CertCN == "" {
		// A plain connection answers no certificate question, not even
		// "cert_cn": "*". Turning TLS on is what makes this rule reachable.
		return false
	}
	if !matchText(r.certRE, r.CertCN, id.CertCN) {
		return false
	}
	if !matchText(r.userRE, r.Username, id.Username) {
		return false
	}
	if !matchText(r.clientRE, r.ClientID, id.ClientID) {
		return false
	}
	return r.ipNet.contains(id.IP)
}

// expected is the password this rule demands for the given username.
func (r *AuthRule) expected(username string) string {
	name := username
	if r.Sanitize {
		name = sanitize(name)
	}
	var h hash.Hash
	switch r.Alg {
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		h = md5.New()
	}
	switch r.Scheme {
	case SchemeSaltUsername:
		fmt.Fprintf(h, "%s%s", r.Salt, name)
	case SchemeSaltUsernameSalt:
		fmt.Fprintf(h, "%s%s%s", r.Salt, name, r.Salt)
	default:
		fmt.Fprintf(h, "%s%s", name, r.Salt)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// matchesSecret compares digests without leaking their contents and without
// caring about hex case.
func matchesSecret(want, got string) bool {
	got = strings.ToLower(strings.TrimSpace(got))
	if len(want) != len(got) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}
