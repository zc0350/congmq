package rules

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// decide is a shorthand for the allowed half of Decision.
func decide(a *ACL, action Action, user, client, ip, resource string) bool {
	ok, _ := a.Decision(action, identity(user, client, ip), resource)
	return ok
}

func TestACLAgainstRepositoryRuleFile(t *testing.T) {
	a, err := LoadACL(filepath.Join("..", "..", "rules", "acl.jsonl"))
	if err != nil {
		t.Fatalf("LoadACL(../../rules/acl.jsonl): %v", err)
	}
	if a.Count() != 8 {
		t.Fatalf("loaded %d rules, want 8", a.Count())
	}

	cases := []struct {
		name     string
		action   Action
		user     string
		client   string
		ip       string
		resource string
		want     bool
	}{
		{"dashboard may watch $SYS", ActionSubscribe, "dashboard", "d1", "10.9.9.9", "$SYS/#", true},
		{"dashboard publish of $SYS is left to the catch-all", ActionPublish, "dashboard", "d1", "10.9.9.9", "$SYS/broker/load", true},
		{"localhost may do anything on $SYS", ActionPublish, "whoever", "c1", "127.0.0.1", "$SYS/broker/load", true},
		{"localhost may subscribe to the whole tree", ActionSubscribe, "whoever", "c1", "127.0.0.1", "#", true},
		{"others may not subscribe to $SYS", ActionSubscribe, "guest", "c2", "10.9.9.9", "$SYS/#", false},
		{"others may not subscribe to #", ActionSubscribe, "guest", "c2", "10.9.9.9", "#", false},
		{"others may not subscribe to +/#", ActionSubscribe, "guest", "c2", "10.9.9.9", "+/#", false},
		// The deny rule is subscribe-only, so a publish reaches the catch-all.
		{"publishing # is not caught by the subscribe deny", ActionPublish, "guest", "c2", "10.9.9.9", "#", true},
		{"device publishes its own event channel", ActionPublish, "abcde_aaaa", "d1", "10.9.9.9", "abcde/aaaa/event", true},
		{"device in the mirrored order", ActionPublish, "aaaa_abcde", "d2", "10.9.9.9", "abcde/aaaa/event", true},
		{"device subscribes its own cmd channel", ActionSubscribe, "abcde_aaaa", "d1", "10.9.9.9", "abcde/aaaa/cmd", true},
		{"device subscribes its cmd channel mirrored", ActionSubscribe, "aaaa_abcde", "d2", "10.9.9.9", "abcde/aaaa/cmd", true},
		{"device event digest is not a cmd channel", ActionPublish, "abcde_aaaa", "d1", "10.9.9.9", "abcde/aaaa/cmd", true},
	}
	for _, c := range cases {
		got := decide(a, c.action, c.user, c.client, c.ip, c.resource)
		if got != c.want {
			t.Errorf("%s: %s %q by user=%q client=%q ip=%q = %v, want %v",
				c.name, c.action, c.resource, c.user, c.client, c.ip, got, c.want)
		}
	}

	// Anything the product-channel rules miss falls to the file's catch-all,
	// which is exactly why its comment says to change it for production.
	ok, rule := a.Decision(ActionPublish, identity("abcde_aaaa", "d1", ""), "abcde/bbbb/event")
	if !ok || rule == nil {
		t.Fatalf("cross-device publish = %v/%v, want the catch-all to allow it", ok, rule)
	}
	if !strings.Contains(rule.String(), `user=""`) {
		t.Errorf("cross-device publish decided by %v, want the catch-all rule", rule)
	}
}

func TestACLOrderDecides(t *testing.T) {
	path := writeRuleFile(t, `
{"effect":"deny","user":"guest","action":"publish","topics":["secret/#"]}
{"effect":"allow","user":"guest","action":"publish","topics":["public/#"]}
{"effect":"allow","user":"admin","action":"all"}
`)
	a, err := LoadACL(path)
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	ok, rule := a.Decision(ActionPublish, identity("guest", "c1", ""), "secret/keys")
	if ok {
		t.Error("a later allow overrode the earlier deny")
	}
	if rule == nil || rule.LineNumber != 2 {
		t.Errorf("guest publish of secret/keys decided by %v, want the deny rule on line 2", rule)
	}
	if !decide(a, ActionPublish, "guest", "c1", "", "public/notes") {
		t.Error("guest could not publish its own public channel")
	}
	if decide(a, ActionSubscribe, "guest", "c1", "", "public/#") {
		t.Error("a publish-only allow granted a subscribe")
	}
	if !decide(a, ActionPublish, "admin", "c2", "", "secret/keys") {
		t.Error("the guest deny leaked onto another user")
	}
	if !decide(a, ActionSubscribe, "admin", "c2", "", "$SYS/#") {
		t.Error("admin's all-action rule did not cover $SYS")
	}
}

func TestACLNoMatchDenies(t *testing.T) {
	path := writeRuleFile(t, `{"effect":"allow","user":"ops","action":"publish","topics":["a/b"]}`)
	a, err := LoadACL(path)
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	ok, rule := a.Decision(ActionPublish, identity("ops", "c1", ""), "a/c")
	if ok || rule != nil {
		t.Errorf("no rule matched: got allowed=%v rule=%v, want false and no deciding rule", ok, rule)
	}
	if !decide(a, ActionPublish, "ops", "c1", "", "a/b") {
		t.Error("the matching rule did not allow")
	}
}

func TestACLOmittedTopicsMeanAnyTopic(t *testing.T) {
	path := writeRuleFile(t, `{"effect":"deny","user":"blocked"}`)
	a, err := LoadACL(path)
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	for _, topic := range []string{"a", "$SYS/broker/load", "any/thing/else"} {
		ok, rule := a.Decision(ActionPublish, identity("blocked", "c1", ""), topic)
		if ok || rule == nil || rule.LineNumber != 1 {
			t.Errorf("blocked user published %q: allowed=%v decided by %v", topic, ok, rule)
		}
		// Nobody else is described by this file, so no rule matches them and
		// no_match = deny applies.
		if ok, rule := a.Decision(ActionPublish, identity("other", "c2", ""), topic); ok || rule != nil {
			t.Errorf("topic %q: allowed=%v decided by %v, want denial with no deciding rule", topic, ok, rule)
		}
	}
}

func TestACLActionFiltering(t *testing.T) {
	path := writeRuleFile(t, `
{"effect":"allow","user":"pub","action":"publish","topics":["t/#"]}
{"effect":"allow","user":"sub","action":"subscribe","topics":["t/#"]}
{"effect":"allow","user":"both","topics":["t/#"]}
`)
	a, err := LoadACL(path)
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	cases := []struct {
		user   string
		action Action
		topic  string
		want   bool
	}{
		{"pub", ActionPublish, "t/a", true},
		{"pub", ActionSubscribe, "t/a", false},
		{"sub", ActionSubscribe, "t/a", true},
		{"sub", ActionPublish, "t/a", false},
		{"both", ActionPublish, "t/a", true},
		{"both", ActionSubscribe, "t/a", true},
		{"pub", ActionPublish, "u/a", false},
	}
	for _, c := range cases {
		if got := decide(a, c.action, c.user, "c1", "", c.topic); got != c.want {
			t.Errorf("user=%q action=%s topic=%q: got %v, want %v", c.user, c.action, c.topic, got, c.want)
		}
	}
}

func TestACLTemplates(t *testing.T) {
	path := writeRuleFile(t, `
{"effect":"allow","user":"^d_([a-z0-9]+)$","match":"regex","action":"publish","topics":["p/%1/event"]}
{"effect":"allow","action":"publish","topics":["sensor/%c/data"]}
{"effect":"allow","action":"all","topics":["tenants/%u/#"]}
{"effect":"allow","action":"publish","topics":["sales/50%%off"]}
{"effect":"allow","action":"publish","topics":["sales/50%xoff"]}
`)
	a, err := LoadACL(path)
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	cases := []struct {
		name   string
		user   string
		client string
		topic  string
		want   bool
	}{
		{"capture group fills one level", "d_ab12", "c1", "p/ab12/event", true},
		{"capture group cannot be reused for another device", "d_ab12", "c1", "p/cd34/event", false},
		{"client id template", "who", "dev-9", "sensor/dev-9/data", true},
		{"client id template refuses a neighbour", "who", "dev-9", "sensor/dev-8/data", false},
		{"username template keeps the underscore", "acme_x", "c1", "tenants/acme_x/a/b", true},
		{"double percent becomes one", "who", "c1", "sales/50%off", true},
		{"double percent does not match two", "who", "c1", "sales/50%%off", false},
		{"unknown percent token is literal", "who", "c1", "sales/50%xoff", true},
	}
	for _, c := range cases {
		got := decide(a, ActionPublish, c.user, c.client, "", c.topic)
		if got != c.want {
			t.Errorf("%s: publish %q as user=%q client=%q = %v, want %v", c.name, c.topic, c.user, c.client, got, c.want)
		}
	}
}

// A client id holding a wildcard must not widen its own rule into "#".
func TestACLUnsafeIdentity(t *testing.T) {
	path := writeRuleFile(t, `{"effect":"allow","action":"publish","topics":["sensor/%c/data"]}`)
	a, err := LoadACL(path)
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	if decide(a, ActionPublish, "who", "a/#", "", "sensor/anything/here") {
		t.Error("client id \"a/#\" widened its own rule to every topic")
	}
	if decide(a, ActionPublish, "who", "a/+", "", "sensor/x/data") {
		t.Error("client id \"a/+\" widened its own rule to a whole level")
	}
	if got := a.UnsafeExpansions(); got != 2 {
		t.Errorf("UnsafeExpansions = %d, want 2", got)
	}
	if !decide(a, ActionPublish, "who", "dev-1", "", "sensor/dev-1/data") {
		t.Error("an ordinary client id was refused")
	}
	if got := a.UnsafeExpansions(); got != 2 {
		t.Errorf("UnsafeExpansions grew to %d on a safe expansion", got)
	}
}

func TestACLLoadErrors(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"unknown field", `{"effect":"allow","user":"u","topic":["a"]}`, "unknown field"},
		{"missing effect", `{"user":"u"}`, "effect"},
		{"unknown effect", `{"effect":"permit","user":"u"}`, "permit"},
		{"unknown action", `{"effect":"allow","action":"write"}`, "write"},
		{"unknown match kind", `{"effect":"allow","user":"u","match":"glob"}`, "match"},
		{"group without a regex user", `{"effect":"allow","user":"u","action":"publish","topics":["a/%1/b"]}`, `no "match": "regex" user`},
		{"group beyond the regex", `{"effect":"allow","user":"^u_([a-z]+)$","match":"regex","action":"publish","topics":["a/%2/b"]}`, "only 1 group"},
		{"eq without a value", `{"effect":"allow","topics":[{"eqx":"a"}]}`, "unknown field"},
		{"eq empty", `{"effect":"allow","topics":[{"eq":""}]}`, "empty"},
		{"empty pattern", `{"effect":"allow","topics":[""]}`, "empty topic pattern"},
		{"pattern is neither string nor eq", `{"effect":"allow","topics":[7]}`, "must be a string"},
		{"illegal filter", `{"effect":"allow","topics":["a/#/b"]}`, "a/#/b"},
		{"trailing percent", `{"effect":"allow","topics":["a/%"]}`, "bare '%'"},
		{"line number reported", "\n" + `{"effect":"maybe"}`, ":2:"},
	}
	for _, c := range cases {
		_, err := LoadACL(writeRuleFile(t, c.content))
		if err == nil {
			t.Errorf("%s: LoadACL succeeded, want an error", c.name)
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

func TestACLClientIDAndIPConstraints(t *testing.T) {
	path := writeRuleFile(t, `
{"effect":"allow","clientid":"^gw-[0-9A-F]{8}$","clientid_match":"regex","ip":"10.0.0.0/8","action":"all","topics":["gw/#"]}
`)
	a, err := LoadACL(path)
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	if !decide(a, ActionPublish, "", "gw-DEADBEEF", "10.1.2.3", "gw/a/b") {
		t.Error("gateway inside its network was refused")
	}
	if decide(a, ActionPublish, "", "gw-deadbeef", "10.1.2.3", "gw/a/b") {
		t.Error("lower-case client id matched a case-sensitive regex")
	}
	if decide(a, ActionPublish, "", "gw-DEADBEEF", "11.1.2.3", "gw/a/b") {
		t.Error("gateway outside its network was allowed")
	}
}

func TestACLEmptyFileDeniesEverything(t *testing.T) {
	a, err := LoadACL(writeRuleFile(t, "# no rules\n"))
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	if ok, rule := a.Decision(ActionAll, identity("u", "c", ""), "a/b"); ok || rule != nil {
		t.Errorf("empty file: got allowed=%v rule=%v, want denial with no deciding rule", ok, rule)
	}
}

// decideCert is the certificate half of Decision: the identity carries nothing
// but a verified common name, which is what a device on an mTLS port presents.
func decideCert(a *ACL, action Action, cn, resource string) bool {
	ok, _ := a.Decision(action, Identity{CertCN: cn}, resource)
	return ok
}

func TestACLCertificateScopesTopics(t *testing.T) {
	a, err := LoadACL(writeRuleFile(t, `
{"effect":"allow","action":"all","cert_cn":"congmq-device-1","topics":["plant/#"]}
{"effect":"deny","action":"publish","cert_cn_match":"regex","cert_cn":"^bot-","topics":["cmd/#"]}
{"effect":"allow","action":"all","cert_cn_match":"regex","cert_cn":"^bot-","topics":["plant/#","cmd/#"]}
`))
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	if !a.UsesCertificates() {
		t.Error("UsesCertificates is false for a file that only asks for certificates")
	}
	cases := []struct {
		name     string
		action   Action
		cn       string
		resource string
		want     bool
	}{
		{"named device publishes under its tree", ActionPublish, "congmq-device-1", "plant/a/1", true},
		{"named device subscribes under its tree", ActionSubscribe, "congmq-device-1", "plant/a", true},
		{"named device is not a bot", ActionPublish, "congmq-device-1", "cmd/1", false},
		{"named device cannot escape its tree", ActionPublish, "congmq-device-1", "other/a", false},
		{"bot may read commands", ActionSubscribe, "bot-9", "cmd/1", true},
		{"bot may not send them", ActionPublish, "bot-9", "cmd/1", false},
		{"bot publishes sensors", ActionPublish, "bot-9", "plant/1", true},
		{"a name outside every pattern is refused", ActionPublish, "whoever", "plant/1", false},
		// The empty CN is what a plain connection or an unverified certificate
		// carries, and it answers no certificate rule.
		{"plain connection asks for a topic", ActionPublish, "", "plant/1", false},
	}
	for _, c := range cases {
		if got := decideCert(a, c.action, c.cn, c.resource); got != c.want {
			t.Errorf("%s: %s %q by cert_cn=%q = %v, want %v",
				c.name, c.action, c.resource, c.cn, got, c.want)
		}
	}
}

func TestACLCertificateAndSubjectBothBind(t *testing.T) {
	a, err := LoadACL(writeRuleFile(t,
		`{"effect":"allow","action":"all","cert_cn":"congmq-device-1","user":"meter","topics":["plant/#"]}`))
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	if ok, _ := a.Decision(ActionPublish, Identity{CertCN: "congmq-device-1", Username: "meter"}, "plant/1"); !ok {
		t.Error("the certificate and the username it was bound to were refused")
	}
	if ok, _ := a.Decision(ActionPublish, Identity{CertCN: "congmq-device-1"}, "plant/1"); ok {
		t.Error("the right certificate alone overrode the username the rule binds it to")
	}
	if ok, _ := a.Decision(ActionPublish, Identity{Username: "meter"}, "plant/1"); ok {
		t.Error("a plain connection met a rule that names a certificate")
	}
}

func TestACLActionAllRuleCoversBothActions(t *testing.T) {
	a, err := LoadACL(writeRuleFile(t, `{"effect":"allow","action":"all","cert_cn":"*","topics":["#"]}`))
	if err != nil {
		t.Fatalf("LoadACL: %v", err)
	}
	if !decideCert(a, ActionPublish, "anything", "a/b") || !decideCert(a, ActionSubscribe, "anything", "a/b") {
		t.Error(`"cert_cn": "*" with action all did not cover both operations`)
	}
	if decideCert(a, ActionPublish, "", "a/b") {
		t.Error("a plain connection was allowed by a rule that asks for any certificate")
	}
}

func TestACLLoadCertificateErrors(t *testing.T) {
	cases := []struct {
		content string
		want    string
	}{
		{`{"effect":"allow","cert_cn":"^dev-","cert_cn_match":"regex","topics":["a/#/b"]}`, "topic pattern"},
		{`{"effect":"allow","cert_cn_match":"regex"}`, "cert_cn_match needs cert_cn"},
		{`{"effect":"allow","cert_cn":"dev-1","topics":["plant/#"],"unknown":1}`, "unknown field"},
	}
	for _, c := range cases {
		if _, err := LoadACL(writeRuleFile(t, c.content)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v does not mention %q", c.content, err, c.want)
		}
	}
}
