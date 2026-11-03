package rules

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRuleFile puts a rule file on disk and returns its path.
func writeRuleFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	return path
}

// The digests below are computed outside this package (with Node's crypto), so
// they check the implementation instead of restating it.
const (
	dashboardSha256 = "c45c09aa5760a3562c35b01e8b6351b79bde1d51c3af408ddc92c9523328b9de" // sha256("c0ng-2026" + "dashboard")
	deviceMd5       = "67b1d9a71df8f6b6aaf0a6e0a99e58eb"                                 // md5("aaaabbbb" + "d3v1c3")
	deviceMd5Raw    = "2d849493d724d4a144846605bff3cb57"                                 // md5("aaaa_bbbb" + "d3v1c3")
	gatewaySha512   = "dfe57ba1506f59ddf0dac05fb7d54cf248c7af37459b75bb148aaa6d12113341" +
		"5bf9fcb0e90a2a414bd7d8238212d658ff6e31fd3268b7fc23d7d4fe965184af" // sha512("gtw" + "gwparis" + "gtw")
	legacySha1          = "3f7a5dbd0e6174171dc78456b90ed7b0793e1410" // sha1("legacy_x" + "old")
	legacySha1Sanitized = "ad604fde6186d76c6c0ef533ae09ef0b34713acb" // sha1("legacyx" + "old")

	wildcardSha   = "043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89" // sha256("s")
	anyoneSha     = "d1863465463f64dd7bf1e68811d9222515a8d61a1ae0354df75f2ee6bfa613ea" // sha256("s" + "anyone")
	commaStripped = "ebecac3dbb3428c344df1b9e9656e0648db6b480513e8c763a69b5f0675465d3" // sha256("s" + "ab") from username "a,b"
	commaKeptSha  = "2facb73c6e15f35d94ee32638f8a4f38d3807c700a3966ef08405837a6e07b33" // sha256("s" + "a,b")
	opsSha        = "0d949547fe3ff85c480aae8e07aff43d2bbf5fc29baf5308a38c1de3a971d91e" // sha256("c0ng" + "ops")
	v6Sha         = "a47b854fe14f2ebeb54a2ec3f5455e61bda6b3733bf2600dd932f80cec9ec59e" // sha256("c0ng" + "v6")
	broadSha      = "1a9f4ee16814b048cef70d26b0c7a2ae2c94b4e9f6aa7433e5d122653a58ca06" // sha256("broad" + "dashboard")

	wrongDigest = "0000000000000000000000000000000000000000000000000000000000000000"
)

func identity(user, client, ip string) Identity {
	id := Identity{Username: user, ClientID: client}
	if ip != "" {
		id.IP = net.ParseIP(ip)
	}
	return id
}

func TestAuthenticateAgainstRepositoryRuleFile(t *testing.T) {
	a, err := LoadAuth(filepath.Join("..", "..", "rules", "auth.jsonl"))
	if err != nil {
		t.Fatalf("LoadAuth(../../rules/auth.jsonl): %v", err)
	}
	if a.Count() != 4 {
		t.Fatalf("loaded %d rules, want 4", a.Count())
	}

	cases := []struct {
		name string
		id   Identity
		pass string
		want bool
	}{
		{"dashboard sha256(salt+username)", identity("dashboard", "d1", "10.9.9.9"), dashboardSha256, true},
		{"dashboard wrong password", identity("dashboard", "d1", "10.9.9.9"), wrongDigest, false},
		{"dashboard uppercase hex accepted", identity("dashboard", "d1", "10.9.9.9"), strings.ToUpper(dashboardSha256), true},
		{"device digest uses the sanitized name", identity("aaaa_bbbb", "any", "192.168.0.1"), deviceMd5, true},
		{"device digest of the raw name refused", identity("aaaa_bbbb", "any", "192.168.0.1"), deviceMd5Raw, false},
		{"device name outside the regex", identity("aaaa_BBBB", "any", "192.168.0.1"), deviceMd5, false},
		// The regex matches the raw username, the digest uses the sanitized one.
		{"gateway needs all three constraints", identity("gw_paris", "gw-DEADBEEF", "10.1.2.3"), gatewaySha512, true},
		{"gateway outside its network", identity("gw_paris", "gw-DEADBEEF", "11.1.2.3"), gatewaySha512, false},
		{"gateway with another client id", identity("gw_paris", "gw-deadbeef", "10.1.2.3"), gatewaySha512, false},
		{"gateway username without the prefix", identity("gwparis", "gw-DEADBEEF", "10.1.2.3"), gatewaySha512, false},
		{"legacy rule keeps the underscore", identity("legacy_x", "l1", "10.0.0.1"), legacySha1, true},
		{"legacy sanitized digest refused", identity("legacy_x", "l1", "10.0.0.1"), legacySha1Sanitized, false},
		{"unknown user matches no rule", identity("nobody", "n1", "127.0.0.1"), deviceMd5, false},
	}
	for _, c := range cases {
		if got := a.Authenticate(c.id, c.pass); got != c.want {
			t.Errorf("%s: Authenticate = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAuthNoEarlyDecisionOnWrongPassword(t *testing.T) {
	// A broad regex rule listed first, the specific literal account after it.
	// The spec says literal rules go first and every rule gets its try, so
	// neither an earlier match nor a wrong password can shadow the other.
	path := writeRuleFile(t, `
{"username":"^d.*","match":"regex","salt":"broad","alg":"sha256","scheme":"salt+username"}
{"username":"dashboard","salt":"c0ng-2026","alg":"sha256","scheme":"salt+username"}
`)
	a, err := LoadAuth(path)
	if err != nil {
		t.Fatalf("LoadAuth: %v", err)
	}
	if a.rules[0].Literal() {
		t.Error("the regex rule must not count as literal")
	}
	if a.rules[1].Literal() != true {
		t.Error("the exact-username rule must count as literal")
	}
	id := identity("dashboard", "d1", "")
	if !a.Authenticate(id, dashboardSha256) {
		t.Error("the later literal rule was shadowed by the earlier regex rule")
	}
	if !a.Authenticate(id, broadSha) {
		t.Error("the first matching rule refused a wrong password and stopped the scan")
	}
	if a.Authenticate(id, wrongDigest) {
		t.Error("a password that matches no rule was accepted")
	}
}

func TestAuthEmptyFileAcceptsNobody(t *testing.T) {
	path := writeRuleFile(t, "# nothing but comments\n\n")
	a, err := LoadAuth(path)
	if err != nil {
		t.Fatalf("LoadAuth: %v", err)
	}
	if a.Count() != 0 {
		t.Fatalf("count = %d, want 0", a.Count())
	}
	if a.Authenticate(identity("dashboard", "c", ""), dashboardSha256) {
		t.Error("an empty rule set must refuse everyone")
	}
}

func TestAuthLoadErrors(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"unknown field", `{"username":"u","salt":"s","alg":"md5","scheme":"username+salt","a1g":"md5"}`, "unknown field"},
		{"missing alg", `{"username":"u","salt":"s","scheme":"username+salt"}`, "alg"},
		{"missing scheme", `{"username":"u","salt":"s","alg":"md5"}`, "scheme"},
		{"unknown alg", `{"username":"u","salt":"s","alg":"md9","scheme":"username+salt"}`, "md9"},
		{"unknown scheme", `{"username":"u","salt":"s","alg":"md5","scheme":"salt+salt"}`, "salt+salt"},
		{"unknown match kind", `{"username":"u","match":"glob","salt":"s","alg":"md5","scheme":"username+salt"}`, "match"},
		{"bad regex", `{"username":"u(","match":"regex","salt":"s","alg":"md5","scheme":"username+salt"}`, "username pattern"},
		{"bad clientid regex", `{"username":"u","clientid":"u(","clientid_match":"regex","salt":"s","alg":"md5","scheme":"username+salt"}`, "clientid pattern"},
		{"bad ip", `{"username":"u","ip":"10.0.0.300","salt":"s","alg":"md5","scheme":"username+salt"}`, "bad ip"},
		{"two objects on a line", `{"username":"a","salt":"s","alg":"md5","scheme":"username+salt"} {"username":"b"}`, "more than one JSON value"},
		{"not an object", `[{"username":"a"}]`, "json"},
		{"line number reported", "\n\n" + `{"username":"u","salt":"s","alg":"sha0","scheme":"username+salt"}`, ":3:"},
	}
	for _, c := range cases {
		_, err := LoadAuth(writeRuleFile(t, c.content))
		if err == nil {
			t.Errorf("%s: LoadAuth succeeded, want an error", c.name)
			continue
		}
		if !errors.Is(err, ErrInvalidRule) {
			t.Errorf("%s: error %v does not wrap ErrInvalidRule", c.name, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

func TestAuthMissingFile(t *testing.T) {
	if _, err := LoadAuth(filepath.Join(t.TempDir(), "absent.jsonl")); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("LoadAuth of a missing file = %v, want ErrInvalidRule", err)
	}
}

func TestAuthWildcardAndSanitize(t *testing.T) {
	path := writeRuleFile(t, `{"username":"*","salt":"s","alg":"sha256","scheme":"salt+username"}`)
	a, err := LoadAuth(path)
	if err != nil {
		t.Fatalf("LoadAuth: %v", err)
	}
	cases := []struct {
		user string
		pass string
		want bool
	}{
		{"", wildcardSha, true},
		{"anyone", anyoneSha, true},
		// sanitize strips the comma before hashing.
		{"a,b", commaStripped, true},
		{"a,b", commaKeptSha, false},
		{"anyone", wrongDigest, false},
	}
	for _, c := range cases {
		if got := a.Authenticate(identity(c.user, "c", ""), c.pass); got != c.want {
			t.Errorf("username %q, password %s…: got %v, want %v", c.user, c.pass[:8], got, c.want)
		}
	}
}

func TestAuthClientIDAndIPLiteralConstraints(t *testing.T) {
	path := writeRuleFile(t, `
{"username":"ops","clientid":"ops-1","ip":"10.0.0.0/8","salt":"c0ng","alg":"sha256","scheme":"salt+username"}
{"username":"v6","ip":"fd00::/64","salt":"c0ng","alg":"sha256","scheme":"salt+username"}
`)
	a, err := LoadAuth(path)
	if err != nil {
		t.Fatalf("LoadAuth: %v", err)
	}
	if !a.Authenticate(identity("ops", "ops-1", "10.1.2.3"), opsSha) {
		t.Error("client inside 10/8 with the right client id was refused")
	}
	if a.Authenticate(identity("ops", "ops-2", "10.1.2.3"), opsSha) {
		t.Error("a different client id was accepted")
	}
	if a.Authenticate(identity("ops", "ops-1", "9.1.2.3"), opsSha) {
		t.Error("an address outside the prefix was accepted")
	}
	if a.Authenticate(identity("ops", "ops-1", ""), opsSha) {
		t.Error("a rule with an ip constraint accepted a connection with no address")
	}
	if !a.Authenticate(identity("v6", "x", "fd00::42"), v6Sha) {
		t.Error("an address inside the ipv6 prefix was refused")
	}
	if a.Authenticate(identity("v6", "x", "fd01::42"), v6Sha) {
		t.Error("an address outside the ipv6 prefix was accepted")
	}
}

// meterCert is sha256("s" + "meter"), the salt+username digest of the rule that
// pins a password to a certificate.
const meterCert = "66e6048a25131b2c4b8ab2165b3439ef1a6a260cecfa9a82da8f30075b5fa6e6"

func TestAuthCertificateIsTheCredential(t *testing.T) {
	a, err := LoadAuth(writeRuleFile(t, `
{"cert_cn":"congmq-device-1"}
{"cert_cn_match":"regex","cert_cn":"^plant-[0-9]+$"}
`))
	if err != nil {
		t.Fatalf("LoadAuth: %v", err)
	}
	if !a.UsesCertificates() {
		t.Error("UsesCertificates is false for a file that only asks for certificates")
	}
	cases := []struct {
		cn   string
		pass string
		want bool
	}{
		{"congmq-device-1", "", true},
		// A password cannot undo a certificate: the handshake already decided.
		{"congmq-device-1", wrongDigest, true},
		{"plant-7", "", true},
		{"plant-x", "", false},
		{"plant-77-something", "", false},
		{"congmq-device-2", "", false},
		// The empty CN is what a plain connection carries, and no certificate
		// rule accepts it — not even a name that matches everything.
		{"", "", false},
	}
	for _, c := range cases {
		id := Identity{CertCN: c.cn}
		if got := a.Authenticate(id, c.pass); got != c.want {
			t.Errorf("cert_cn=%q password=%q: got %v, want %v", c.cn, c.pass, got, c.want)
		}
	}
}

func TestAuthCertificateAnysStillRequiresTLS(t *testing.T) {
	a, err := LoadAuth(writeRuleFile(t, `{"cert_cn":"*"}`))
	if err != nil {
		t.Fatalf("LoadAuth: %v", err)
	}
	if !a.UsesCertificates() {
		t.Error(`"cert_cn": "*" is a certificate requirement, so UsesCertificates must be true`)
	}
	if !a.Authenticate(Identity{CertCN: "whoever"}, "") {
		t.Error("a verified certificate with an unexpected name was refused by a * rule")
	}
	if a.Authenticate(identity("whoever", "c1", "127.0.0.1"), "") {
		t.Error("a plain connection satisfied a certificate rule")
	}
}

func TestAuthCertificatePinsAPasswordRule(t *testing.T) {
	a, err := LoadAuth(writeRuleFile(t,
		`{"cert_cn":"congmq-device-1","username":"meter","salt":"s","alg":"sha256","scheme":"salt+username"}`))
	if err != nil {
		t.Fatalf("LoadAuth: %v", err)
	}
	wrong := Identity{Username: "meter", CertCN: "congmq-device-2"}
	if a.Authenticate(wrong, meterCert) {
		t.Error("the right password from a different certificate was accepted")
	}
	right := Identity{Username: "meter", CertCN: "congmq-device-1"}
	if a.Authenticate(right, wrongDigest) {
		t.Error("the right certificate with the wrong password was accepted")
	}
	if !a.Authenticate(right, meterCert) {
		t.Error("the right certificate and the right password were refused")
	}
	// The password half is still a password rule: it is reachable without TLS
	// only if the rule asks for nothing else, which this one does.
	if a.Authenticate(identity("meter", "c1", ""), meterCert) {
		t.Error("a plain connection met a rule that names a certificate")
	}
}

func TestAuthCertificateRuleLoadErrors(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"salt with no password to salt", `{"cert_cn":"dev-1","salt":"s"}`, "takes no salt"},
		{"regex without a pattern", `{"cert_cn_match":"regex"}`, "cert_cn_match needs cert_cn"},
		{"unknown match kind", `{"cert_cn":"dev-1","cert_cn_match":"glob"}`, "unknown cert_cn_match"},
		{"bad pattern", `{"cert_cn":"(","cert_cn_match":"regex"}`, "cert_cn pattern"},
		{"half a digest", `{"cert_cn":"dev-1","alg":"sha256"}`, "needs scheme"},
	}
	for _, c := range cases {
		_, err := LoadAuth(writeRuleFile(t, c.content))
		if err == nil {
			t.Errorf("%s: LoadAuth succeeded, want an error", c.name)
			continue
		}
		if !errors.Is(err, ErrInvalidRule) {
			t.Errorf("%s: error %v does not wrap ErrInvalidRule", c.name, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

func TestAuthPasswordOnlyFileDoesNotUseCertificates(t *testing.T) {
	a, err := LoadAuth(writeRuleFile(t,
		`{"username":"meter","salt":"s","alg":"sha256","scheme":"salt+username"}`))
	if err != nil {
		t.Fatalf("LoadAuth: %v", err)
	}
	if a.UsesCertificates() {
		t.Error("UsesCertificates is true for a file that never mentions a certificate")
	}
	if !a.Authenticate(identity("meter", "c1", ""), meterCert) {
		t.Error("the password rule refused its own digest")
	}
}
