package broker

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// The wrapper is the whole trick, so these check the two obligations it takes on
// and the reading of the list that decides when it is used. Both obligations are
// easy to forget and neither shows up as a refused connection: a wrapper that
// hides the socket leaves Nagle switched on, and one that does not hand back what
// the parser over-read eats the client's first bytes.

// socketPair gives one end of a real TCP connection, because what is worth
// asserting here is the socket underneath a wrapper rather than a stand-in for it.
func socketPair(t *testing.T) *net.TCPConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		t.Fatalf("a tcp dial returned %T, want *net.TCPConn", c)
	}
	peer := <-accepted
	if peer == nil {
		t.Fatalf("accept failed")
	}
	t.Cleanup(func() {
		_ = peer.Close()
		_ = ln.Close()
		_ = tc.Close()
	})
	return tc
}

// tcpSocket is what a listener would report for a peer, so mayReport is asked
// about the kind of value it is handed in production rather than a text one.
func tcpSocket(addr string) net.Addr {
	return tcpAddr(netip.MustParseAddrPort(addr))
}

// listed parses a -trusted-proxy-cidr value or stops the test.
func listed(t *testing.T, list string) []netip.Prefix {
	t.Helper()
	p, err := ParsePrefixes(list)
	if err != nil {
		t.Fatalf("ParsePrefixes(%q): %v", list, err)
	}
	return p
}

// TestTcpConnFindsTheSocketThroughEveryWrapper is the Nagle test. noDelay can only
// switch it off if it can reach the socket, and it has to reach it through the
// transport wrapper, through TLS, and through both at once — which is the shape of
// a secure listener behind a balancer.
func TestTcpConnFindsTheSocketThroughEveryWrapper(t *testing.T) {
	tc := socketPair(t)

	pc := &proxyConn{
		Conn:   tc,
		r:      bufio.NewReaderSize(tc, headerBufferSize),
		socket: tc.RemoteAddr(),
		source: netip.MustParseAddrPort("203.0.113.7:49101"),
	}
	cfg := &tls.Config{InsecureSkipVerify: true}

	if got := tcpConn(tc); got != tc {
		t.Errorf("tcpConn on a bare socket gave %v, want the socket itself", got)
	}
	if got := tcpConn(pc); got != tc {
		t.Errorf("tcpConn through the transport wrapper gave %v, want the socket: wrapping would otherwise leave Nagle on", got)
	}
	if got := tcpConn(tls.Client(pc, cfg)); got != tc {
		t.Errorf("tcpConn through tls over the wrapper gave %v, want the socket", got)
	}
}

// TestProxyConnReportsTheAddressItWasGiven pins the two faces of the wrapper: the
// address every decision is made about, and the one that wrote the header.
func TestProxyConnReportsTheAddressItWasGiven(t *testing.T) {
	tc := socketPair(t)
	socket := tc.RemoteAddr().String()
	pc := &proxyConn{Conn: tc, r: bufio.NewReaderSize(tc, headerBufferSize), socket: tc.RemoteAddr()}

	if got := pc.RemoteAddr().String(); got != socket {
		t.Errorf("with nothing claimed, RemoteAddr = %s, want the socket's own %s", got, socket)
	}
	pc.source = netip.MustParseAddrPort("203.0.113.7:49101")
	if got := pc.RemoteAddr().String(); got != "203.0.113.7:49101" {
		t.Errorf("RemoteAddr = %s, want the address the header named", got)
	}
	if pc.SocketAddr().String() != socket {
		t.Errorf("SocketAddr = %s, want %s: who wrote the header is the other half of the answer",
			pc.SocketAddr(), socket)
	}
	// A v6 source keeps its port, and neither is something to lose on the way
	// through netip.
	pc.source = netip.MustParseAddrPort("[2001:db8::7]:49101")
	if got := pc.RemoteAddr().String(); got != "[2001:db8::7]:49101" {
		t.Errorf("RemoteAddr = %s, want the v6 form with its port", got)
	}
}

// TestConnLogCarriesTheBalancerWhenThereIsOne is the log contract: a line about a
// proxied session says both addresses, and a line about a direct one says only the
// one there is.
func TestConnLogCarriesTheBalancerWhenThereIsOne(t *testing.T) {
	tc := socketPair(t)
	socket := tc.RemoteAddr().String()

	var buf bytes.Buffer
	line := func(conn net.Conn) string {
		buf.Reset()
		log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		connLog(log, conn).Debug("x")
		return buf.String()
	}

	if got := line(tc); strings.Contains(got, "via=") {
		t.Errorf("a direct connection logged %q; via= belongs to a proxied one only", got)
	}

	pc := &proxyConn{Conn: tc, r: bufio.NewReaderSize(tc, headerBufferSize), socket: tc.RemoteAddr()}
	if got := line(pc); strings.Contains(got, "via=") {
		t.Errorf("a wrapper that claims nothing logged %q, want no via=", got)
	}

	pc.source = netip.MustParseAddrPort("203.0.113.7:49101")
	got := line(pc)
	if want := "remote=203.0.113.7:49101"; !strings.Contains(got, want) {
		t.Errorf("proxied line %q, want it to carry %s", got, want)
	}
	if want := "via=" + socket; !strings.Contains(got, want) {
		t.Errorf("proxied line %q, want it to carry %s", got, want)
	}
}

// TestParsePrefixesReadsWhatAnOperatorTypes covers the two ways a list written for
// a v4 balancer stops meaning anything: an address form that matches no socket, and
// a host with bits outside its own mask.
func TestParsePrefixesReadsWhatAnOperatorTypes(t *testing.T) {
	cases := []struct {
		list string
		want []string
		err  bool
	}{
		{list: "", want: nil},
		{list: "10.0.0.0/8", want: []string{"10.0.0.0/8"}},
		{list: " 10.0.0.0/8 , 192.168.1.0/24 ", want: []string{"10.0.0.0/8", "192.168.1.0/24"}},
		// A host address is masked rather than rejected: 203.0.113.7/24 plainly means
		// the /24 it sits in, and refusing it would only teach operators to type /32.
		{list: "203.0.113.7/24", want: []string{"203.0.113.0/24"}},
		// The v4-mapped form is what a v6-shaped socket reports a v4 peer as. Left
		// alone it would be a /112 that contains no v4 address at all.
		{list: "::ffff:192.168.0.0/112", want: []string{"192.168.0.0/16"}},
		{list: "2001:db8::/32", want: []string{"2001:db8::/32"}},
		{list: "10.0.0.0", err: true},
		{list: "10.0.0.0/8,192.168", err: true},
		{list: "10.0.0.0/8,", err: true},
		{list: "10.0.0.0/33", err: true},
	}
	for _, tc := range cases {
		got, err := ParsePrefixes(tc.list)
		if tc.err {
			if err == nil {
				t.Errorf("ParsePrefixes(%q) accepted, want an error", tc.list)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePrefixes(%q): %v", tc.list, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("ParsePrefixes(%q) gave %d prefixes, want %d", tc.list, len(got), len(tc.want))
			continue
		}
		for i, p := range got {
			if p.String() != tc.want[i] {
				t.Errorf("ParsePrefixes(%q)[%d] = %s, want %s", tc.list, i, p, tc.want[i])
			}
		}
	}
}

// TestMayReportIsAboutTheSocketNotTheClaim: the address inside a header is never
// consulted for whether the header may be believed, or a peer could whitelist
// itself by naming a whitelisted address.
func TestMayReportIsAboutTheSocketNotTheClaim(t *testing.T) {
	p := &proxyConf{mode: ProxyTrusted, trusted: listed(t, "10.0.0.0/8,2001:db8::/32")}

	cases := []struct {
		name   string
		socket string
		want   bool
	}{
		{"inside the v4 list", "10.1.2.3:49101", true},
		{"outside it", "11.1.2.3:49101", false},
		{"the v6 list", "[2001:db8::1]:49101", true},
		{"loopback is not a balancer by default", "127.0.0.1:49101", false},
		// A v4 peer seen through a v6-shaped socket is the same machine, and a list
		// written in v4 has to say so.
		{"the mapped form of a listed address", "[::ffff:10.1.2.3]:49101", true},
	}
	for _, tc := range cases {
		if got := p.mayReport(tcpSocket(tc.socket)); got != tc.want {
			t.Errorf("mayReport(%s) = %v, want %v: %s", tc.socket, got, tc.want, tc.name)
		}
	}

	// require has no list to consult: the header is what the listener speaks.
	if !(&proxyConf{mode: ProxyRequire}).mayReport(tcpSocket("203.0.113.7:1")) {
		t.Error("require mode refused to believe an address, which is the opposite of what require means")
	}

	// A peer with no address to match cannot be trusted with somebody else's.
	if p.mayReport(&net.UnixAddr{Net: "unix", Name: "/run/congmq.sock"}) {
		t.Error("a unix socket was allowed to report an address")
	}
}
