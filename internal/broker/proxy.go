package broker

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/zc0350/congmq/internal/proxyproto"
)

// ProxyMode says what to make of a PROXY protocol transport header: the bytes a
// load balancer writes in front of the payload to say whose connection it is
// forwarding.
type ProxyMode uint8

const (
	// ProxyOff reads no header. Every device behind a balancer then arrives
	// wearing the balancer's address, which is the right default for a broker on
	// a flat network and the wrong one for everything else.
	ProxyOff ProxyMode = iota
	// ProxyRequire refuses any connection that does not open with a valid header.
	// It is the shape of a dedicated listener behind one known balancer: nothing
	// reaches the broker except through it, so a connection without a header is
	// not a client, it is someone who found the port.
	ProxyRequire
	// ProxyTrusted honours a header only from TrustedProxies, and expects one from
	// exactly those addresses. A peer outside the list that sends no header is a
	// direct client and keeps its socket address; one that sends a header is
	// refused rather than ignored, because the only reason to write a header you
	// know will not be believed is to find out whether it will be.
	ProxyTrusted
)

func (m ProxyMode) String() string {
	switch m {
	case ProxyRequire:
		return "require"
	case ProxyTrusted:
		return "trusted"
	default:
		return "off"
	}
}

// proxyConf is the transport-header policy, built once by New and read without a
// lock on every connection. A nil *proxyConf means ProxyOff, and the accept path
// then does no reading, no buffering and no extra goroutine: a broker that never
// asked for this feature pays nothing for it.
type proxyConf struct {
	mode    ProxyMode
	trusted []netip.Prefix
	timeout time.Duration
}

func newProxyConf(opt Options, log *slog.Logger) *proxyConf {
	if opt.Proxy == ProxyOff {
		return nil
	}
	p := &proxyConf{mode: opt.Proxy, trusted: opt.TrustedProxies, timeout: opt.ProxyHeaderTimeout}
	// Same rule as the gate: a limit that only shows up as a refused connection
	// looks like a broken client, so say what is armed before anyone is refused.
	log.Info("transport header armed", "mode", p.mode.String(),
		"trusted_proxies", len(p.trusted), "header_timeout", p.timeout.String())
	return p
}

// mayReport answers whether a peer at this socket address is allowed to name
// somebody else's address. In require mode the answer is everyone, because the
// header is what the listener speaks; there is no list to consult.
func (p *proxyConf) mayReport(socket net.Addr) bool {
	if p.mode == ProxyRequire {
		return true
	}
	addr := addrOf(socket)
	if !addr.IsValid() {
		// A peer with no IP at all — a unix socket, say — cannot be matched against
		// a network, so it cannot be trusted with somebody else's identity.
		return false
	}
	for _, prefix := range p.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// attach resolves the transport header and returns the connection to build a
// session on, or reports that this socket ends here. On success the returned
// conn may be a wrapper that reports the header's source address as RemoteAddr;
// when no header was involved the original connection comes back.
//
// This is a read, so it happens off the accept loop — see handleOne. A peer that
// connects and says nothing costs one goroutine for the header timeout rather
// than three for the pre-connect window, which is cheaper than what it is
// protecting, not free.
func (b *Broker) attach(conn net.Conn) (net.Conn, bool) {
	p := b.proxy
	w := &proxyConn{Conn: conn, r: bufio.NewReaderSize(conn, headerBufferSize), socket: conn.RemoteAddr()}
	if err := conn.SetReadDeadline(time.Now().Add(p.timeout)); err != nil {
		b.refuseProxy(w, "cannot arm the header deadline", err)
		return nil, false
	}
	h, err := proxyproto.Read(w.r)
	// Whatever the deadline was for, it is over: the session that follows sets its
	// own read deadlines, and a five second one left dangling here would cut short
	// every keepalive on the connection.
	_ = conn.SetReadDeadline(time.Time{})

	if err != nil {
		if p.mode == ProxyTrusted && !p.mayReport(w.socket) && !isHeaderAttempt(err) {
			// A direct client on a listener that also serves a balancer: nothing was
			// expected from this address and nothing arrived, so the socket's own
			// address is the whole story. The bytes the parser did read are still
			// buffered inside w and reach the decoder in order.
			return w, true
		}
		b.refuseProxy(w, "no usable transport header", err)
		return nil, false
	}
	if !p.mayReport(w.socket) {
		b.refuseProxy(w, "transport header from an address that may not report one", nil)
		return nil, false
	}
	if h.Command != proxyproto.CommandProxy || !h.Source.Addr().IsValid() {
		// LOCAL and UNKNOWN are well formed and name nobody: a health check from
		// the balancer itself, or a sender that could not say. The socket is the
		// truth, and that is the right answer for a probe.
		return w, true
	}
	w.source = h.Source
	b.c.proxyHeader.Add(1)
	return w, true
}

// refuseProxy closes a socket that never became anything and counts it. The count
// is exact; the log is throttled, because an address probing the header path is
// precisely the load that would otherwise fill a disk with warnings. One line per
// hundred, with the running total in it, says both that it is happening and how
// much of it there is.
func (b *Broker) refuseProxy(conn net.Conn, reason string, err error) {
	// Counted before the socket closes, so an operator scraping the endpoint the
	// moment a client reports a refusal sees the refusal. After the close there is a
	// window where the peer knows and the broker's own numbers do not.
	n := b.c.proxyRefused.Add(1)
	_ = conn.Close()
	if n == 1 || n%proxyRefuseLogEvery == 0 {
		b.log.Warn("connection refused at the transport header",
			"remote", conn.RemoteAddr().String(), "reason", reason, "err", err,
			"refused_total", n, "mode", b.proxy.mode.String())
	}
}

// isHeaderAttempt tells "this peer is speaking the protocol badly" from "this
// peer is not speaking it, or said nothing at all". On a listener that mixes
// direct clients with a balancer, only the first is a refusal: a CONNECT that
// happens to start with the letter P is not an imitation of a header.
func isHeaderAttempt(err error) bool {
	return errors.Is(err, proxyproto.ErrMalformed) || errors.Is(err, proxyproto.ErrTooLong)
}

const (
	// headerBufferSize is what the parser reads at a time. A transport header is
	// at most 108 bytes of text or 16 plus its own declared length, so the buffer
	// is never emptied into the payload's way, and one per connection is the whole
	// memory cost of this feature.
	headerBufferSize = 128
	// proxyRefuseLogEvery throttles the refusal warning, not the counter.
	proxyRefuseLogEvery = 100
)

// proxyConn is the socket plus the transport header in front of it. Two things
// change for everyone downstream, and both matter.
//
// RemoteAddr reports the address the header named, so every decision keyed on the
// peer — the gate, the ip rules, the credential lockout, the identity stored with
// an offline queue, the logs — is made about the device rather than about the
// machine that forwarded it.
//
// Read hands back whatever the parser buffered past the header, so the bytes
// behind it still reach the decoder in order. A wrapper that forgot this would
// swallow the first bytes of any CONNECT that arrived in the same segment.
type proxyConn struct {
	net.Conn
	r      *bufio.Reader
	socket net.Addr
	source netip.AddrPort
}

// SocketAddr is the machine that actually connected. It is kept because "the
// balancer's address" is the other half of the answer an operator needs when a
// decision looks wrong.
func (c *proxyConn) SocketAddr() net.Addr { return c.socket }

// NetConn exposes the socket underneath. tcpConn unwraps through it, so wrapping
// a connection cannot quietly leave Nagle switched on.
func (c *proxyConn) NetConn() net.Conn { return c.Conn }

func (c *proxyConn) RemoteAddr() net.Addr {
	if !c.source.IsValid() {
		return c.socket
	}
	return tcpAddr(c.source)
}

func (c *proxyConn) Read(p []byte) (int, error) {
	if c.r.Buffered() > 0 {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}

// connLog is the pair of addresses every line about this connection carries.
// "remote" is the one the decisions were made about — which behind a balancer is
// the device, not the machine that forwarded it — and "via" is the socket the
// connection actually arrived on. An operator asking "why did the gate shut my
// fleet out" needs both, in the order that explains the difference.
func connLog(base *slog.Logger, conn net.Conn) *slog.Logger {
	if pc, ok := conn.(*proxyConn); ok && pc.source.IsValid() {
		return base.With("remote", conn.RemoteAddr().String(), "via", pc.socket.String())
	}
	return base.With("remote", conn.RemoteAddr().String())
}

func tcpAddr(ap netip.AddrPort) *net.TCPAddr {
	a := &net.TCPAddr{IP: ap.Addr().AsSlice(), Port: int(ap.Port())}
	if z := ap.Addr().Zone(); z != "" {
		a.Zone = z
	}
	return a
}

// addrOf turns a socket peer into an address that can be matched against a
// network. Anything without an IP — the string form not parsing, a unix socket —
// comes back invalid, and an invalid address is trusted by nothing: a constraint
// that cannot be checked is not a constraint that passes.
func addrOf(a net.Addr) netip.Addr {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

// ParsePrefixes reads a comma separated list of networks for
// -trusted-proxy-cidr. A v4-mapped prefix is normalised to the family it means,
// so /104 on ::ffff:10.0.0.0 becomes /8 on 10.0.0.0 rather than matching nothing.
func ParsePrefixes(list string) ([]netip.Prefix, error) {
	if list == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("empty entry in the list")
		}
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", item, err)
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if !p.Addr().IsValid() || p.Bits() < 0 {
			return nil, fmt.Errorf("%q: not a network", item)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
