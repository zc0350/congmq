package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestReadV1(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    string
		want  Header
		wantE error
	}{
		{
			name: "tcp4",
			in:   "PROXY TCP4 203.0.113.7 198.51.100.1 41330 1883\r\n",
			want: Header{Version: 1, Command: CommandProxy,
				Source: addrPort("203.0.113.7", 41330), Dest: addrPort("198.51.100.1", 1883)},
		},
		{
			name: "tcp6",
			in:   "PROXY TCP6 2001:db8::ff:1 2001:db8::2 41330 1883\r\n",
			want: Header{Version: 1, Command: CommandProxy,
				Source: addrPort("2001:db8::ff:1", 41330), Dest: addrPort("2001:db8::2", 1883)},
		},
		{
			name: "a v4-mapped address on a TCP4 line means that v4 address",
			in:   "PROXY TCP4 ::ffff:203.0.113.7 ::ffff:198.51.100.1 41330 1883\r\n",
			want: Header{Version: 1, Command: CommandProxy,
				Source: addrPort("203.0.113.7", 41330), Dest: addrPort("198.51.100.1", 1883)},
		},
		{
			name: "unknown means no source",
			in:   "PROXY UNKNOWN\r\n",
			want: Header{Version: 1, Command: CommandLocal},
		},
		{
			name: "unknown with placeholders",
			in:   "PROXY UNKNOWN :: 0.0.0.0 0 0\r\n",
			want: Header{Version: 1, Command: CommandLocal},
		},
		{
			name: "a datagram family on a stream connection names nobody",
			in:   "PROXY UDP4 203.0.113.7 198.51.100.1 41330 1883\r\n",
			want: Header{Version: 1, Command: CommandLocal},
		},
		{
			name: "a bare LF terminates the line",
			in:   "PROXY TCP4 10.0.0.1 10.0.0.2 1 2\n",
			want: Header{Version: 1, Command: CommandProxy,
				Source: addrPort("10.0.0.1", 1), Dest: addrPort("10.0.0.2", 2)},
		},
		{name: "not a header", in: "CONNECT\r\n", wantE: ErrNotProxy},
		{name: "half the token", in: "PROX TCP4 10.0.0.1 10.0.0.2 1 2\r\n", wantE: ErrNotProxy},
		{name: "unknown family", in: "PROXY TCP9 10.0.0.1 10.0.0.2 1 2\r\n", wantE: ErrMalformed},
		{name: "no fields", in: "PROXY \r\n", wantE: ErrMalformed},
		{name: "one field short", in: "PROXY TCP4 10.0.0.1 10.0.0.2 1\r\n", wantE: ErrMalformed},
		{name: "not an address", in: "PROXY TCP4 10.0.0.999 10.0.0.2 1 2\r\n", wantE: ErrMalformed},
		{name: "not a port", in: "PROXY TCP4 10.0.0.1 10.0.0.2 99999 2\r\n", wantE: ErrMalformed},
		{name: "a v6 address on a TCP4 line", in: "PROXY TCP4 2001:db8::1 10.0.0.2 1 2\r\n", wantE: ErrMalformed},
		{name: "a v4 address on a TCP6 line", in: "PROXY TCP6 10.0.0.1 2001:db8::2 1 2\r\n", wantE: ErrMalformed},
		{
			name:  "a line past the specification's own cap is refused",
			in:    "PROXY TCP4 203.0.113.7 203.0.113.7 41330 1883" + strings.Repeat(" ", 200) + "\r\n",
			wantE: ErrTooLong,
		},
		{
			name:  "the line never ended: the peer stopped talking",
			in:    "PROXY TCP4 10.0.0.1 10",
			wantE: io.EOF,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Read(bufio.NewReader(strings.NewReader(tc.in)))
			if check(t, tc.name, got, err, tc.want, tc.wantE) {
				return
			}
			if got.Command != tc.want.Command || got.Version != tc.want.Version ||
				got.Source != tc.want.Source || got.Dest != tc.want.Dest {
				t.Fatalf("%s: header = %+v, want %+v", tc.name, got, tc.want)
			}
		})
	}
}

func TestReadV2(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    []byte
		want  Header
		wantE error
	}{
		{
			name: "inet4",
			in:   v2(v2Proxy, famInet4, transTCP, inet4("203.0.113.7", 41330, "198.51.100.1", 1883)),
			want: Header{Version: 2, Command: CommandProxy,
				Source: addrPort("203.0.113.7", 41330), Dest: addrPort("198.51.100.1", 1883)},
		},
		{
			name: "inet6",
			in:   v2(v2Proxy, famInet6, transTCP, inet6("2001:db8::ff:1", 41330, "2001:db8::2", 1883)),
			want: Header{Version: 2, Command: CommandProxy,
				Source: addrPort("2001:db8::ff:1", 41330), Dest: addrPort("2001:db8::2", 1883)},
		},
		{
			name: "TLVs after the addresses are skipped, not parsed as addresses",
			in: v2(v2Proxy, famInet4, transTCP, append(
				inet4("203.0.113.7", 41330, "198.51.100.1", 1883),
				0x02, 0x00, 0x05, 'a', 'l', 'i', 'c', 'e',
				0x04, 0x00, 0x01, 0x01,
			)),
			want: Header{Version: 2, Command: CommandProxy,
				Source: addrPort("203.0.113.7", 41330), Dest: addrPort("198.51.100.1", 1883)},
		},
		{
			name: "local is a health check: bytes consumed, no source",
			in:   v2(v2Local, famUnspec, 0, make([]byte, 16)),
			want: Header{Version: 2, Command: CommandLocal},
		},
		{
			name: "unix names no IP",
			in:   v2(v2Proxy, famUnix, transTCP, make([]byte, 216)),
			want: Header{Version: 2, Command: CommandLocal},
		},
		{
			name: "unspec under the proxy command still names no IP",
			in:   v2(v2Proxy, famUnspec, 0, nil),
			want: Header{Version: 2, Command: CommandLocal},
		},
		{
			name: "a datagram transport on this stream names no source",
			in:   v2(v2Proxy, famInet4, 0x2, inet4("203.0.113.7", 1, "198.51.100.1", 2)),
			want: Header{Version: 2, Command: CommandLocal},
		},
		{
			name:  "short body for an inet4 pair",
			in:    v2(v2Proxy, famInet4, transTCP, []byte{192, 0, 2, 1, 0, 1}),
			wantE: ErrMalformed,
		},
		{
			name:  "short body for an inet6 pair",
			in:    v2(v2Proxy, famInet6, transTCP, make([]byte, 20)),
			wantE: ErrMalformed,
		},
		{
			name:  "a declared length over what will be buffered",
			in:    append(v2(v2Proxy, famInet4, transTCP, nil)[:14], 0x03, 0x00),
			wantE: ErrTooLong,
		},
		{
			name:  "wrong version nibble",
			in:    v2Bad(0x1, v2Proxy, famInet4, transTCP, inet4("1.2.3.4", 1, "5.6.7.8", 2)),
			wantE: ErrMalformed,
		},
		{
			name:  "unknown command",
			in:    v2Bad(0x2, 0x9, famInet4, transTCP, inet4("1.2.3.4", 1, "5.6.7.8", 2)),
			wantE: ErrMalformed,
		},
		{
			name:  "signature but no fixed header",
			in:    []byte("\r\n\r\n\x00\r\nQUIT\n\r"),
			wantE: io.ErrUnexpectedEOF,
		},
		{
			name:  "the first twelve bytes of something else",
			in:    []byte("\r\n\r\n\x00\r\nQUIT\r\n"),
			wantE: ErrNotProxy,
		},
		{
			name:  "body promised, body missing",
			in:    v2Truncated(v2Proxy, famInet4, transTCP, inet4("1.2.3.4", 1, "5.6.7.8", 2), 6),
			wantE: io.ErrUnexpectedEOF,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Read(bufio.NewReader(strings.NewReader(string(tc.in))))
			if check(t, tc.name, got, err, tc.want, tc.wantE) {
				return
			}
			if got.Command != tc.want.Command || got.Version != tc.want.Version ||
				got.Source != tc.want.Source || got.Dest != tc.want.Dest {
				t.Fatalf("%s: header = %+v, want %+v", tc.name, got, tc.want)
			}
		})
	}
}

// TestReadConsumesOnlyTheHeader is the property the broker depends on: whatever
// follows the header has to still be sitting on the connection, byte for byte. A
// parser that read one byte too many would eat the first byte of every CONNECT.
func TestReadConsumesOnlyTheHeader(t *testing.T) {
	cases := []string{
		"PROXY TCP4 203.0.113.7 198.51.100.1 41330 1883\r\n",
		string(v2(v2Proxy, famInet4, transTCP, inet4("203.0.113.7", 41330, "198.51.100.1", 1883))),
		string(v2(v2Local, famUnspec, 0, make([]byte, 4))),
	}
	payload := "\x10\x0e\x00\x04MQTT\x05\x02\x00\x00\x00\x01a"
	for _, in := range cases {
		r := bufio.NewReader(strings.NewReader(in + payload))
		if _, err := Read(r); err != nil {
			t.Fatalf("Read(%q…): %v", in[:min(20, len(in))], err)
		}
		rest, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
		if string(rest) != payload {
			t.Fatalf("leftover = %q, want the untouched payload %q", rest, payload)
		}
	}
}

// TestV2CommandNibblesAreTheSpecification'sOwn is written from literal bytes on
// purpose. This package's constants are the thing a wrong reading corrupts, and a
// table built from those same constants keeps passing: the header a balancer
// actually puts on the wire is 0x21 for PROXY and 0x20 for LOCAL, and reading the
// two the other way round accepts the connection, believes no address, and looks
// exactly like success. That is the one failure mode this whole feature exists to
// prevent, arriving as a green test suite.
func TestV2CommandNibblesAreTheSpecificationOwn(t *testing.T) {
	canonical := []byte{
		0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, // signature
		0x21, 0x11, 0x00, 0x0c, // ver 2 + PROXY, AF_INET + STREAM, length 12
		203, 0, 113, 7, // source address
		198, 51, 100, 1, // destination address
		0xa1, 0x72, // source port 41330
		0x07, 0x5b, // destination port 1883
	}
	h, err := Read(bufio.NewReader(bytes.NewReader(canonical)))
	if err != nil {
		t.Fatalf("the specification's own header did not parse: %v", err)
	}
	if h.Command != CommandProxy {
		t.Errorf("command = %v, want PROXY: 0x21 is what a balancer sends for a real source", h.Command)
	}
	if h.Source != addrPort("203.0.113.7", 41330) || h.Dest != addrPort("198.51.100.1", 1883) {
		t.Errorf("source/dest = %s / %s, want 203.0.113.7:41330 / 198.51.100.1:1883", h.Source, h.Dest)
	}

	// 0x20 is the health check: well formed, and naming nobody.
	probe := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x20, 0x00, 0x00, 0x04)
	probe = append(probe, make([]byte, 4)...)
	h, err = Read(bufio.NewReader(bytes.NewReader(probe)))
	if err != nil {
		t.Fatalf("a LOCAL header is not an error: %v", err)
	}
	if h.Command != CommandLocal || h.Source.IsValid() {
		t.Errorf("LOCAL parsed as %+v, want no source claimed", h)
	}
}

// TestNotAHeaderConsumesNothing is the other half of the property above, and the
// one the broker's mixed listener depends on: a peer that is not sending a header
// has to be handed to the protocol decoder whole, including the first byte. A
// parser that read the dispatch byte before deciding would deliver every direct
// client a CONNECT missing its packet type.
func TestNotAHeaderConsumesNothing(t *testing.T) {
	cases := []struct {
		in    string
		wantE error
	}{
		{"\x10\x0e\x00\x04MQTT", ErrNotProxy},                 // a real CONNECT, byte for byte
		{"Proxy TCP4 10.0.0.1 10.0.0.2 1 2\r\n", ErrNotProxy}, // the right letters, the wrong case
		{"\r\n\r\n\x00\r\nQUIT\r\n", ErrNotProxy},             // the signature's shape, not its bytes
		{"\x00\x00", ErrNotProxy},                             // neither opener
		// One byte of the signature is not a decision yet, so this is the read
		// running out rather than the stream being refused. It consumes nothing
		// either, which is what the caller downstream needs.
		{"\r", io.EOF},
	}
	for _, tc := range cases {
		r := bufio.NewReader(strings.NewReader(tc.in))
		if _, err := Read(r); !errors.Is(err, tc.wantE) {
			t.Errorf("Read(%q) = %v, want %v", tc.in, err, tc.wantE)
		}
		rest, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("drain %q: %v", tc.in, err)
		}
		if string(rest) != tc.in {
			t.Errorf("after a refused prefix the stream held %q, want all of %q", rest, tc.in)
		}
	}
}

// TestReadV1LineBound: the text header is capped by the specification, and a
// parser that trusted the sender's newline would buffer a whole connection as
// "the prefix".
func TestReadV1LineBound(t *testing.T) {
	long := "PROXY TCP4 203.0.113.7 198.51.100.1 41330 1883" + strings.Repeat("x", v1MaxLine)
	if _, err := Read(bufio.NewReader(strings.NewReader(long))); !errors.Is(err, ErrTooLong) {
		t.Fatalf("err = %v, want ErrTooLong", err)
	}
}

// TestReadEmptyConnection: a peer that opens the socket and says nothing is the
// abuse case the whole gate exists for. The header read has to report the silence
// rather than hang once its own deadline is up.
func TestReadEmptyConnection(t *testing.T) {
	if _, err := Read(bufio.NewReader(strings.NewReader(""))); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

// TestReadFromASocket proves the reader works against a real connection, where
// the header and the payload can arrive in one segment or in three.
func TestReadFromASocket(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		_, _ = b.Write([]byte("PROXY TCP4 203.0.113.7 198.51.100.1 41330 1883\r\n\x10"))
		_, _ = b.Write([]byte("\x0e\x00\x04"))
		_, _ = b.Write([]byte("MQTT"))
	}()
	defer a.Close()
	r := bufio.NewReader(a)
	h, err := Read(r)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if h.Source != addrPort("203.0.113.7", 41330) {
		t.Fatalf("source = %s", h.Source)
	}
	rest := make([]byte, 8)
	if _, err := io.ReadFull(r, rest); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if string(rest) != "\x10\x0e\x00\x04MQTT" {
		t.Fatalf("payload = %q", rest)
	}
}

func check(t *testing.T, name string, got Header, err error, want Header, wantE error) bool {
	t.Helper()
	if wantE == nil {
		if err != nil {
			t.Fatalf("%s: Read: %v", name, err)
		}
		return false
	}
	if !errors.Is(err, wantE) {
		t.Fatalf("%s: err = %v (%T), want something matching %v", name, err, err, wantE)
	}
	if got != (Header{}) {
		t.Fatalf("%s: a refused header must report nothing, got %+v", name, got)
	}
	return true
}

func addrPort(ip string, port uint16) netip.AddrPort {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		panic(err)
	}
	return netip.AddrPortFrom(a.Unmap(), port)
}

// v2 builds a well-formed version 2 header.
func v2(cmd, fam, trans byte, body []byte) []byte {
	return v2Bad(0x2, cmd, fam, trans, body)
}

// v2Bad builds a header with chosen version and command nibbles, for the cases
// where one of the two is supposed to be wrong.
func v2Bad(ver, cmd, fam, trans byte, body []byte) []byte {
	b := []byte("\r\n\r\n\x00\r\nQUIT\n")
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(body)))
	b = append(b, ver<<4|cmd, fam<<4|trans, l[0], l[1])
	return append(b, body...)
}

func v2Truncated(cmd, fam, trans byte, body []byte, drop int) []byte {
	full := v2(cmd, fam, trans, body)
	return full[:len(full)-drop]
}

// inet4 and inet6 lay out a v2 address body the way the specification does: both
// addresses first, then both ports. Written to match the wire rather than the parser,
// so a test that reads the ports out of the destination address fails on both sides
// instead of agreeing with itself.
func inet4(src string, sp uint16, dst string, dp uint16) []byte {
	b := append([]byte{}, v4bytes(src)...)
	b = append(b, v4bytes(dst)...)
	b = append(b, byte(sp>>8), byte(sp))
	return append(b, byte(dp>>8), byte(dp))
}

func inet6(src string, sp uint16, dst string, dp uint16) []byte {
	b := append([]byte{}, v16bytes(src)...)
	b = append(b, v16bytes(dst)...)
	b = append(b, byte(sp>>8), byte(sp))
	return append(b, byte(dp>>8), byte(dp))
}

func v4bytes(ip string) []byte {
	a := net.ParseIP(ip).To4()
	if a == nil {
		panic("not v4: " + ip)
	}
	return a
}

func v16bytes(ip string) []byte {
	a := net.ParseIP(ip)
	if a == nil {
		panic("not an address: " + ip)
	}
	return a.To16()
}
