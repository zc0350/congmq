// Package proxyproto parses the PROXY protocol transport header: the small
// block of bytes a load balancer writes before the first payload byte to say
// whose connection it is forwarding. Without it every device behind an LB
// arrives wearing the LB's address, and any decision keyed on the source —
// admission limits, lockouts, ip-scoped rules — is then made about the proxy
// rather than about the fleet.
//
// Only the header is this package's business. It parses both wire forms, tells
// the caller whether the header actually named a source, and consumes exactly
// its own bytes so the connection behind it can be read normally.
package proxyproto

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Command is what the sender meant by the header.
type Command byte

const (
	// CommandLocal carries no usable source. It is a health check, a Unix socket,
	// or an UNKNOWN family, and a caller that keyed a decision on it would be
	// keying it on nothing. It is the zero value on purpose: a Header nobody
	// filled in — every error path — then claims no source rather than asserting
	// one.
	CommandLocal Command = iota
	// CommandProxy asserts a source address: the bytes behind this header come
	// from someone the sender is reporting on behalf of. Trusting it is the
	// caller's decision, and it is the one this whole protocol exists for.
	CommandProxy
)

// Header is the answer. Source is only meaningful when Command is CommandProxy.
type Header struct {
	Version int
	Command Command
	Source  netip.AddrPort
	Dest    netip.AddrPort
}

// Errors a caller has to be able to tell apart in its log. All of them are
// fatal for the connection: there is no "keep reading and hope" here, because
// the bytes we could not make sense of may be the payload of a client that is
// not who the header claimed.
var (
	// ErrNotProxy means the connection did not start with a header at all.
	ErrNotProxy = errors.New("proxyproto: not a PROXY header")
	// ErrMalformed means a header started but did not hold together.
	ErrMalformed = errors.New("proxyproto: malformed PROXY header")
	// ErrTooLong means a header claimed more bytes than this package will buffer.
	ErrTooLong = errors.New("proxyproto: PROXY header too long")
)

const (
	// v1MaxLine is the specification's own cap on the whole text header,
	// including "PROXY " and the CRLF. A longer line is either a broken sender or
	// someone discovering how much memory a broker will buffer for a prefix.
	v1MaxLine = 108
	// v2MaxBody bounds the address block plus the TLVs after it. The length field
	// is 16 bits, so without a cap one 65KiB prefix per connection is free memory
	// for the asking; everything the broker needs lives in the first 36 bytes.
	v2MaxBody = 512

	v1Token = "PROXY "
	v2Sig   = "\r\n\r\n\x00\r\nQUIT\n"

	// The low nibble of the v2 ver_cmd byte. The specification's own values, and
	// the reason they are written out rather than derived: a header whose command
	// nibble is 0x1 is a PROXY header, and one that reads it as LOCAL turns every
	// device behind a balancer into a health check. That failure is invisible — the
	// connection is accepted, the address is the balancer's, and every limit keyed
	// on the source is quietly about the wrong machine.
	v2Local = 0x0
	v2Proxy = 0x1

	famUnspec = 0x0
	famInet4  = 0x1
	famInet6  = 0x2
	famUnix   = 0x3
	transTCP  = 0x1
)

// Read parses one header from r. It consumes exactly the header's bytes, so the
// same reader can be handed to whatever protocol follows.
//
// The first byte picks the form: 'P' for the text header, CR for the binary one.
// Anything else, including a connection that says nothing, is an error rather than
// a header with no source — the caller has to be able to tell "this peer does not
// speak the protocol" from "this peer spoke it and meant LOCAL".
//
// ErrNotProxy consumes nothing. That is not tidiness: a listener that serves both a
// balancer and direct clients has to hand the same reader to the MQTT decoder after
// a refused prefix, and a parser that had already eaten the first byte would deliver
// a payload missing its packet type. Every other error may consume, because those
// connections are being closed anyway.
func Read(r *bufio.Reader) (Header, error) {
	first, err := r.Peek(1)
	if err != nil {
		return Header{}, err
	}
	switch first[0] {
	case 'P':
		return readV1(r)
	case '\r':
		return readV2(r)
	}
	return Header{}, fmt.Errorf("%w: starts with 0x%02x", ErrNotProxy, first[0])
}

func readV1(r *bufio.Reader) (Header, error) {
	// The whole token is checked before any of it is taken, so a payload that
	// merely starts with the letter P leaves the stream as it was found.
	head, err := r.Peek(len(v1Token))
	if err != nil {
		return Header{}, err
	}
	if string(head) != v1Token {
		return Header{}, fmt.Errorf("%w: %q", ErrNotProxy, head)
	}
	if _, err := r.Discard(len(head)); err != nil {
		return Header{}, err
	}
	line, err := readV1Line(r)
	if err != nil {
		return Header{}, err
	}
	return parseV1(line)
}

// readV1Line takes the remainder of the text header one byte at a time. Byte-wise
// reads go through the caller's buffer, so the cost is one fill rather than one
// syscall per byte, and the bound is enforced without ever letting a sender decide
// how much to buffer.
func readV1Line(r *bufio.Reader) (string, error) {
	buf := make([]byte, 0, v1MaxLine-len(v1Token))
	for {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			return strings.TrimSuffix(string(buf), "\r"), nil
		}
		// The prefix and CRLF are part of the 108 bytes the spec allows.
		if len(buf) >= v1MaxLine-len(v1Token)-2 {
			return "", fmt.Errorf("%w: v1 line over %d bytes", ErrTooLong, v1MaxLine)
		}
		buf = append(buf, c)
	}
}

func parseV1(line string) (Header, error) {
	parts := strings.Split(line, " ")
	switch {
	case parts[0] == "UNKNOWN":
		// Sent both as "UNKNOWN" alone and as "UNKNOWN" plus zero placeholders.
		// Either way there is no address to believe.
		return Header{Version: 1, Command: CommandLocal}, nil
	case parts[0] == "UDP4" || parts[0] == "UDP6":
		// A datagram family on a stream connection names no source we can meter.
		return Header{Version: 1, Command: CommandLocal}, nil
	case parts[0] == "TCP4" || parts[0] == "TCP6":
	default:
		return Header{}, fmt.Errorf("%w: unknown v1 family %q", ErrMalformed, parts[0])
	}
	if len(parts) != 5 {
		return Header{}, fmt.Errorf("%w: v1 %s wants 4 fields, got %d", ErrMalformed, parts[0], len(parts)-1)
	}
	src, err := parseV1AddrPort(parts[1], parts[3])
	if err != nil {
		return Header{}, err
	}
	dst, err := parseV1AddrPort(parts[2], parts[4])
	if err != nil {
		return Header{}, err
	}
	// The declared family has to match what was written. A TCP4 line carrying an
	// IPv6 address is not a typo to be forgiving about: it is a sender that does
	// not know what it is reporting.
	if parts[0] == "TCP4" && !src.Addr().Is4() {
		return Header{}, fmt.Errorf("%w: TCP4 with address %s", ErrMalformed, src)
	}
	if parts[0] == "TCP6" && !src.Addr().Is6() {
		return Header{}, fmt.Errorf("%w: TCP6 with address %s", ErrMalformed, src)
	}
	return Header{Version: 1, Command: CommandProxy, Source: src, Dest: dst}, nil
}

func parseV1AddrPort(ip, port string) (netip.AddrPort, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: address %q", ErrMalformed, ip)
	}
	p, err := parseV1Port(port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	// Unmap first: a sender that writes ::ffff:203.0.113.7 on a TCP4 line means
	// that address, and the broker keys its limits on the plain v4 form anyway.
	// Leaving the mapped form in place would let one device arrive under two
	// different keys depending on which parenthesis its load balancer used.
	return netip.AddrPortFrom(addr.Unmap(), p), nil
}

// parseV1Port is deliberately narrower than the port parsers in the standard
// library: net.ParsePort would accept a service name, and strconv would accept a
// leading "+". A transport header carries digits.
func parseV1Port(s string) (uint16, error) {
	if s == "" {
		return 0, fmt.Errorf("%w: empty port", ErrMalformed)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%w: port %q", ErrMalformed, s)
		}
	}
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%w: port %q", ErrMalformed, s)
	}
	return uint16(p), nil
}

func readV2(r *bufio.Reader) (Header, error) {
	// The leading CRLF is what a client's own first bytes could plausibly look
	// like, so the full twelve-byte signature is the check that decides whether this
	// connection is speaking the protocol at all. It is peeked rather than read for
	// the same reason as the v1 token: a mismatch has to leave the payload whole.
	head, err := r.Peek(len(v2Sig))
	if err != nil {
		return Header{}, err
	}
	if string(head) != v2Sig {
		return Header{}, fmt.Errorf("%w: %q", ErrNotProxy, head)
	}
	if _, err := r.Discard(len(head)); err != nil {
		return Header{}, err
	}

	var fixed [4]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return Header{}, err
	}
	ver, cmd := fixed[0]>>4, fixed[0]&0x0f
	fam, trans := fixed[1]>>4, fixed[1]&0x0f
	body := int(binary.BigEndian.Uint16(fixed[2:]))
	if ver != 2 {
		return Header{}, fmt.Errorf("%w: v2 version %d", ErrMalformed, ver)
	}
	if cmd != v2Local && cmd != v2Proxy {
		return Header{}, fmt.Errorf("%w: v2 command 0x%x", ErrMalformed, cmd)
	}
	if body > v2MaxBody {
		return Header{}, fmt.Errorf("%w: v2 body %d bytes", ErrTooLong, body)
	}
	buf := make([]byte, body)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Header{}, err
	}
	// LOCAL is what a sender writes for its own health checks: the bytes are read
	// and thrown away, and the connection is attributed to the socket it came on.
	if cmd == v2Local {
		return Header{Version: 2, Command: CommandLocal}, nil
	}
	h := Header{Version: 2, Command: CommandProxy}
	// A datagram transport on a stream connection names no source we would meter,
	// whichever family it claims.
	if trans != transTCP {
		return Header{Version: 2, Command: CommandLocal}, nil
	}
	switch {
	case fam == famInet4:
		if body < 12 {
			return Header{}, fmt.Errorf("%w: v2 INET4 body is %d bytes", ErrMalformed, body)
		}
		// src addr, dst addr, src port, dst port — in that order, which the
		// specification fixes and a reader cannot infer. Reading the ports where the
		// destination address lives is silent: the source IP still comes out right,
		// so every address-keyed decision keeps working, while the port the session
		// reports is a piece of somebody else's address.
		h.Source = netip.AddrPortFrom(netip.AddrFrom4([4]byte(buf[0:4])), binary.BigEndian.Uint16(buf[8:10]))
		h.Dest = netip.AddrPortFrom(netip.AddrFrom4([4]byte(buf[4:8])), binary.BigEndian.Uint16(buf[10:12]))
	case fam == famInet6:
		if body < 36 {
			return Header{}, fmt.Errorf("%w: v2 INET6 body is %d bytes", ErrMalformed, body)
		}
		h.Source = netip.AddrPortFrom(netip.AddrFrom16([16]byte(buf[0:16])), binary.BigEndian.Uint16(buf[32:34]))
		h.Dest = netip.AddrPortFrom(netip.AddrFrom16([16]byte(buf[16:32])), binary.BigEndian.Uint16(buf[34:36]))
	default:
		// AF_UNSPEC and AF_UNIX: the header is well formed and says nothing about
		// an IP source, which is a LOCAL answer delivered under another command.
		return Header{Version: 2, Command: CommandLocal}, nil
	}
	return h, nil
}
