package packets

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"testing"
)

func TestRemainingLengthBoundaries(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7F}},
		{128, []byte{0x80, 0x01}},
		{16383, []byte{0xFF, 0x7F}},
		{16384, []byte{0x80, 0x80, 0x01}},
		{2097151, []byte{0xFF, 0xFF, 0x7F}},
		{2097152, []byte{0x80, 0x80, 0x80, 0x01}},
		{MaxRemainingLength, []byte{0xFF, 0xFF, 0xFF, 0x7F}},
	}
	for _, tc := range cases {
		got := AppendRemainingLength(nil, tc.n)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("encode %d = % X, want % X", tc.n, got, tc.want)
		}
		n, _, err := readRemainingLength(bufio.NewReader(bytes.NewReader(got)))
		if err != nil {
			t.Fatalf("decode % X: %v", got, err)
		}
		if n != tc.n {
			t.Errorf("decode % X = %d, want %d", got, n, tc.n)
		}
	}
}

func TestRemainingLengthTooLong(t *testing.T) {
	// Five continuation bytes are not a valid variable quantity integer.
	_, _, err := readRemainingLength(bufio.NewReader(bytes.NewReader([]byte{0x80, 0x80, 0x80, 0x80, 0x01})))
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestRoundTrip(t *testing.T) {
	cases := []Packet{
		&Connect{
			ProtocolName: ProtocolName, ProtocolLevel: ProtocolLevel,
			CleanSession: true, KeepAlive: 30, ClientID: "sensor-7",
		},
		&Connect{
			ProtocolName: ProtocolName, ProtocolLevel: ProtocolLevel,
			ClientID: "sensor-7", Username: "u", Password: []byte("p"),
			HasUsername: true, HasPassword: true,
		},
		&Connect{
			ProtocolName: ProtocolName, ProtocolLevel: ProtocolLevel,
			ClientID: "sensor-7", HasWill: true, WillTopic: "s/7/offline",
			WillPayload: []byte("bye"), WillQoS: QoS1, WillRetain: true,
		},
		&Connack{SessionPresent: true, ReturnCode: ConnAccepted},
		&Publish{Topic: "s/7/temp", QoS: QoS0, Payload: []byte("21.5")},
		&Publish{Topic: "s/7/temp", QoS: QoS1, PacketID: 4242, Payload: []byte("21.5"), Dup: true},
		&Publish{Topic: "s/7/temp", QoS: QoS2, PacketID: 1, Payload: bytes.Repeat([]byte("x"), 300), Retain: true},
		&Puback{PacketID: 7},
		&Pubrec{PacketID: 8},
		&Pubrel{PacketID: 9},
		&Pubcomp{PacketID: 10},
		&Subscribe{PacketID: 11, Subscriptions: []Subscription{{TopicFilter: "a/+", MaxQoS: QoS2}, {TopicFilter: "b/#", MaxQoS: QoS0}}},
		&Suback{PacketID: 12, ReturnCodes: []byte{QoS0, QoS1, SubAckFailure}},
		&Unsubscribe{PacketID: 13, TopicFilters: []string{"a/+", "b/#"}},
		&Unsuback{PacketID: 14},
		&Pingreq{},
		&Pingresp{},
		&Disconnect{},
	}

	for _, want := range cases {
		raw, err := EncodeBytes(want)
		if err != nil {
			t.Fatalf("encode %s: %v", want.Type(), err)
		}
		got, err := Decode(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			t.Fatalf("decode %s (% X): %v", want.Type(), raw, err)
		}
		if got.Type() != want.Type() {
			t.Fatalf("type = %s, want %s", got.Type(), want.Type())
		}
		if fmt.Sprintf("%+v", got) != fmt.Sprintf("%+v", want) {
			t.Errorf("%s round trip mismatch:\n got %+v\nwant %+v", want.Type(), got, want)
		}
	}
}

// TestFixedHeaderFlags locks down the reserved-flag rules: a peer that gets
// them wrong is not speaking MQTT and must be disconnected.
func TestFixedHeaderFlags(t *testing.T) {
	cases := []struct {
		name  string
		raw   []byte
		valid bool
	}{
		{"PUBLISH qos 3", []byte{0x3E, 0x00}, false},
		{"PUBREL with zero flags", []byte{0x60, 0x02, 0x00, 0x01}, false},
		{"PUBREL with correct flags", []byte{0x62, 0x02, 0x00, 0x01}, true},
		{"SUBSCRIBE with zero flags", []byte{0x80, 0x00}, false},
		{"PINGREQ with nonzero flags", []byte{0xC1, 0x00}, false},
		{"reserved type 0", []byte{0x00, 0x00}, false},
		{"reserved type 15", []byte{0xF0, 0x00}, false},
		{"CONNECT flags must be zero", []byte{0x11, 0x00}, false},
	}
	for _, tc := range cases {
		_, err := Decode(bufio.NewReader(bytes.NewReader(tc.raw)))
		if tc.valid {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tc.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", tc.name, err)
		}
	}
}

func TestRejectsMalformedBodies(t *testing.T) {
	cases := []struct {
		name string
		p    Packet
		// mutate rewrites the encoded bytes before decoding.
		mutate func([]byte) []byte
	}{
		{"truncated payload", &Publish{Topic: "a/b", QoS: QoS0, Payload: []byte("hello")},
			func(b []byte) []byte { return b[:len(b)-2] }},
		{"zero packet identifier", &Puback{PacketID: 1},
			func(b []byte) []byte { b[2] = 0; b[3] = 0; return b }},
		{"qos0 with dup", &Publish{Topic: "a", QoS: QoS0, Dup: true, Payload: []byte("x")}, nil},
		{"qos1 without identifier", &Publish{Topic: "a", QoS: QoS1, PacketID: 1, Payload: []byte("x")},
			func(b []byte) []byte { return b[:3] }},
		{"empty subscribe list", &Subscribe{PacketID: 1, Subscriptions: []Subscription{{TopicFilter: "a", MaxQoS: QoS0}}},
			func(b []byte) []byte { return b[:3] }},
		{"invalid utf8 topic", &Publish{Topic: "a/\xffb", QoS: QoS0, Payload: []byte("x")}, nil},
		{"trailing garbage", &Puback{PacketID: 5},
			func(b []byte) []byte { b[1] += 2; return append(b, 0xAA, 0xBB) }},
	}
	for _, tc := range cases {
		raw, err := EncodeBytes(tc.p)
		if err != nil {
			if errors.Is(err, ErrMalformed) {
				// The encoder refused an illegal construction outright.
				continue
			}
			t.Fatalf("%s: encode: %v", tc.name, err)
		}
		if tc.mutate != nil {
			raw = tc.mutate(raw)
		}
		if _, err := Decode(bufio.NewReader(bytes.NewReader(raw))); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed (bytes % X)", tc.name, err, raw)
		}
	}
}

// TestEncodeRejects covers the constructions the encoder refuses outright.
func TestEncodeRejects(t *testing.T) {
	bad := []Packet{
		&Publish{Topic: "a", QoS: 3, Payload: []byte("x")},
		&Publish{Topic: "a", QoS: QoS1, PacketID: 0, Payload: []byte("x")},
		&Subscribe{PacketID: 0},
		&Connect{ProtocolName: ProtocolName, ClientID: "\xff", ProtocolLevel: ProtocolLevel},
	}
	for _, p := range bad {
		if _, err := EncodeBytes(p); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", p.Type(), err)
		}
	}
}

// TestDecodeNeverPanics throws random bytes at the decoder. A broker that
// crashes on a fuzzed header is a broker an attacker can turn off.
func TestDecodeNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		n := rng.Intn(48) + 1
		buf := make([]byte, n)
		rng.Read(buf)
		_, _ = Decode(bufio.NewReader(bytes.NewReader(buf)))
	}
}

func TestDecodeConnectWireFormat(t *testing.T) {
	// Byte-for-byte check of the packet a real client sends first:
	// fixed header, "MQTT", level 4, flags 0x82 (username + clean session),
	// keepalive 30, client id "c1", username "u". The body is 17 bytes.
	raw := []byte{
		0x10, 0x11,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04,
		0x82,
		0x00, 0x1E,
		0x00, 0x02, 'c', '1',
		0x00, 0x01, 'u',
	}
	p, err := Decode(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	c, ok := p.(*Connect)
	if !ok {
		t.Fatalf("got %T", p)
	}
	if c.ProtocolName != "MQTT" || c.ProtocolLevel != 4 || c.KeepAlive != 30 {
		t.Errorf("header = %+v", c)
	}
	if !c.CleanSession || !c.HasUsername || c.Username != "u" || c.ClientID != "c1" {
		t.Errorf("payload = %+v", c)
	}
}

// mqtt.js and Mosquitto set bit 6 for a password, not bit 0: getting this wrong
// is invisible to a broker that only ever decodes its own packets.
func TestDecodeConnectWithPassword(t *testing.T) {
	raw := []byte{
		0x10, 0x14,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04,
		0xC2, // username (0x80) + password (0x40) + clean session (0x02)
		0x00, 0x1E,
		0x00, 0x02, 'c', '1',
		0x00, 0x01, 'u',
		0x00, 0x01, 'p',
	}
	p, err := Decode(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	c := p.(*Connect)
	if !c.HasUsername || c.Username != "u" {
		t.Errorf("username = %q (present=%v)", c.Username, c.HasUsername)
	}
	if !c.HasPassword || string(c.Password) != "p" {
		t.Errorf("password = %q (present=%v)", c.Password, c.HasPassword)
	}

	// The same bytes with the reserved bit set are a protocol violation.
	bad := append([]byte(nil), raw...)
	bad[9] |= 0x01
	if _, err := Decode(bufio.NewReader(bytes.NewReader(bad))); !errors.Is(err, ErrMalformed) {
		t.Errorf("reserved connect flag accepted: %v", err)
	}

	// Encoding the same session request must produce those exact bytes, so the
	// broker answers a real client with what a real client expects.
	frame, err := EncodeBytes(&Connect{
		ProtocolName: "MQTT", ProtocolLevel: 4, ClientID: "c1",
		CleanSession: true, KeepAlive: 30,
		HasUsername: true, Username: "u",
		HasPassword: true, Password: []byte("p"),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(frame, raw) {
		t.Errorf("encode produced %v, want %v", frame, raw)
	}
}

func TestDecodeFrameLimitedRefusesBeforeAllocating(t *testing.T) {
	// A PUBLISH announcing 1MB of body against a 128 byte receiver. The decoder
	// must stop at the length field: a limit consulted after make([]byte, n) has
	// already been paid for is a policy, not a guard.
	body := 1 << 20
	frame := append([]byte{byte(TypePublish) << 4, 0x80, 0x80, 0x40}, make([]byte, body)...)
	decode := func(limit int) error {
		_, _, err := DecodeFrameLimited(bufio.NewReader(bytes.NewReader(frame)), V311, limit)
		return err
	}

	err := decode(128)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
	if errors.Is(err, ErrProtocol) || errors.Is(err, ErrMalformed) {
		t.Errorf("over the receiver's limit is neither a protocol error nor malformed: %v", err)
	}
	// Four bytes were consumed: the type flag and the three length bytes.
	if _, size, err := DecodeFrameLimited(bufio.NewReader(bytes.NewReader(frame)), V311, 128); err == nil || size != 4 {
		t.Errorf("size = %d (err %v), want the 4 header bytes actually read", size, err)
	}

	// The claim worth proving is about memory, not about bytes off the wire: a
	// refused frame must not allocate the body it announced. The generous limit
	// is measured the same way so the number cannot be an artefact.
	if got := allocBytesPerRun(decode, 128); got > 64<<10 {
		t.Errorf("a refused 1MB frame allocated %d bytes per run", got)
	}
	if got := allocBytesPerRun(decode, 2<<20); got < 512<<10 {
		t.Fatalf("the measurement never allocated the body, so it proves nothing: %d bytes", got)
	}
}

// allocBytesPerRun reports how many heap bytes f allocates per call, measured
// across runs so the noise of one call cannot hide a 1MB allocation.
func allocBytesPerRun(f func(int) error, limit int) int64 {
	const runs = 20
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < runs; i++ {
		_ = f(limit)
	}
	runtime.ReadMemStats(&after)
	return int64(after.TotalAlloc-before.TotalAlloc) / runs
}
