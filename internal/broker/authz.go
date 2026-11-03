package broker

import (
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"

	"github.com/zc0350/congmq/internal/packets"
	"github.com/zc0350/congmq/internal/rules"
)

// peerIP extracts the address of the connecting socket. Anything that is not a
// plain IP endpoint (a unix socket, say) yields nil, which every "ip" rule
// refuses: a constraint that cannot be checked is not a constraint that passes.
func peerIP(conn net.Conn) net.IP {
	switch a := conn.RemoteAddr().(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	}
	if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// peerCertCN is the CommonName a rule file may key on: the client certificate
// this broker actually verified. Two things keep it empty on purpose. A plain
// connection has no certificate at all. And a TLS connection negotiated with
// ClientAuth below RequireAndVerifyClientCert — including RequireAnyClientCert,
// which accepts a self-signed certificate nobody vouches for — has a chain of
// trust this broker did not check, so it is not an identity. Rules read the name
// only when the handshake finished the job.
func peerCertCN(conn net.Conn) string {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return ""
	}
	st := tc.ConnectionState()
	if len(st.VerifiedChains) == 0 || len(st.PeerCertificates) == 0 {
		return ""
	}
	return st.PeerCertificates[0].Subject.CommonName
}

// identity is this connection's view of itself as the rule files see it. Before
// CONNECT there is no client identifier yet, only the socket address.
func (c *client) identity() rules.Identity {
	if id := c.subject.Load(); id != nil {
		return *id
	}
	return rules.Identity{ClientID: c.id, IP: c.ip, CertCN: c.certCN}
}

// subjectOf is the identity a CONNECT presented, as the rule files see it.
func subjectOf(p *packets.Connect, ip net.IP, certCN string) rules.Identity {
	return rules.Identity{Username: p.Username, ClientID: p.ClientID, IP: ip, CertCN: certCN}
}

// authenticate runs the credential check. With no auth file loaded the broker
// stays open, which is how it behaved before rules existed. A client that
// offers no username is still passed through: an empty name simply matches the
// rules the operator wrote for it.
func (b *Broker) authenticate(id rules.Identity, password string) bool {
	rs := b.pol.load()
	if rs.auth == nil {
		return true
	}
	if rs.auth.Authenticate(id, password) {
		return true
	}
	b.c.authRejected.Add(1)
	return false
}

// identityOf is the identity stored for a client identifier that is not
// currently connected, so an offline queue is authorised with the same
// credentials that made its subscriptions. A session persisted by a broker
// running without rules carries an empty identity, and username-keyed rules
// then refuse it; failing closed is the safer direction.
//
// The same applies to a certificate-scoped rule: what was verified belongs to a
// connection that no longer exists, so a stored session carries no CertCN and a
// "cert_cn" rule refuses it until the device connects again with its certificate.
func (b *Broker) identityOf(clientID string) rules.Identity {
	s, ok := b.store.Get(clientID)
	if !ok {
		return rules.Identity{ClientID: clientID}
	}
	return rules.Identity{Username: s.Username, ClientID: s.ClientID, IP: net.ParseIP(s.RemoteIP)}
}

func (b *Broker) decide(action rules.Action, id rules.Identity, resource string, denied *atomic.Int64) bool {
	acl := b.pol.load().acl
	if acl == nil {
		return true
	}
	ok, rule := acl.Decision(action, id, resource)
	if ok {
		return true
	}
	denied.Add(1)
	if rule == nil {
		b.log.Debug("acl refused: no rule matched",
			"action", action, "client", id.ClientID, "user", id.Username, "resource", resource)
		return false
	}
	b.log.Debug("acl refused by rule",
		"action", action, "client", id.ClientID, "user", id.Username,
		"resource", resource, "rule", rule.String(), "effect", rule.Effect)
	return false
}

// allowPublish guards a PUBLISH a client is sending.
func (b *Broker) allowPublish(id rules.Identity, topic string) bool {
	return b.decide(rules.ActionPublish, id, topic, &b.c.denyPublish)
}

// allowSubscribe guards a subscription request.
func (b *Broker) allowSubscribe(id rules.Identity, filter string) bool {
	return b.decide(rules.ActionSubscribe, id, filter, &b.c.denySubscribe)
}

// allowDelivery guards a message arriving for a subscriber. The rule file says
// "subscribe" covers both the filter and the messages under it, so the check
// runs again on every delivery rather than only at SUBSCRIBE time — an identity
// whose rules changed, or that subscribed through a broader filter than it is
// allowed, stops receiving here.
func (b *Broker) allowDelivery(id rules.Identity, topic string) bool {
	return b.decide(rules.ActionSubscribe, id, topic, &b.c.denyDelivery)
}

// ruleSummary is what the operator sees at start-up: which files are in force.
func (b *Broker) ruleSummary() string {
	rs := b.pol.load()
	auth := "off"
	if rs.auth != nil {
		auth = fmt.Sprintf("%s (%d rules)", filepath.Base(rs.auth.String()), rs.auth.Count())
	}
	acl := "off"
	if rs.acl != nil {
		acl = fmt.Sprintf("%s (%d rules)", filepath.Base(rs.acl.String()), rs.acl.Count())
	}
	return "auth=" + auth + " acl=" + acl
}
