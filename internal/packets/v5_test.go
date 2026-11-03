package packets

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// propsOf runs the setters over a fresh property area, so a test case reads as
// the properties it means to send.
func propsOf(set func(*Properties)) *Properties {
	p := &Properties{}
	if set != nil {
		set(p)
	}
	return p
}

// TestEncodeV5Connect pins the exact bytes of a 5.0 CONNECT. The property area
// sits between the keep alive and the client ID, and every property is written
// in the canonical order the encoder promises.
func TestEncodeV5Connect(t *testing.T) {
	want := []byte{
		0x10, 0x21,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x05,
		0x02,       // clean start
		0x00, 0x1E, // keep alive 30
		0x12,                         // property length 18
		0x11, 0x00, 0x00, 0x00, 0x3C, // Session Expiry Interval 60
		0x21, 0x00, 0x64, // Receive Maximum 100
		0x22, 0x00, 0x0A, // Topic Alias Maximum 10
		0x26, 0x00, 0x01, 'k', 0x00, 0x01, 'v', // User Property k=v
		0x00, 0x02, 'c', '1',
	}
	got, err := EncodeBytes(&Connect{
		ProtocolName: ProtocolName, ProtocolLevel: byte(V5),
		CleanSession: true, KeepAlive: 30, ClientID: "c1",
		Props: propsOf(func(p *Properties) {
			p.SetSessionExpiry(60)
			p.SetReceiveMax(100)
			p.SetTopicAliasMax(10)
			p.AddUser("k", "v")
		}),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("bytes:\n got % X\nwant % X", got, want)
	}

	// Decode without a version hint: CONNECT names its own level, so a 5.0
	// CONNECT must come back complete even through the 3.1.1 entry point.
	p, err := Decode(bufio.NewReader(bytes.NewReader(want)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	c := p.(*Connect)
	if c.ProtocolLevel != 5 {
		t.Fatalf("level = %d, want 5", c.ProtocolLevel)
	}
	if v, ok := c.Props.UserValue("k"); !ok || v != "v" {
		t.Errorf("user property k = %q (present=%v)", v, ok)
	}
	if c.Props.SessionExpiry != 60 || c.Props.ReceiveMax != 100 || c.Props.TopicAliasMax != 10 {
		t.Errorf("properties = %+v", c.Props)
	}
}

// TestEncodeV5WillProperties checks that the Will Properties block sits between
// the client ID and the will topic, where section 3.1.3 puts it.
func TestEncodeV5WillProperties(t *testing.T) {
	want := []byte{
		0x10, 0x23,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x05,
		0x0C, // will flag plus will QoS 1
		0x00, 0x1E,
		0x00, // no CONNECT properties
		0x00, 0x02, 'c', '1',
		0x05,                         // will property length
		0x18, 0x00, 0x00, 0x00, 0x0A, // Will Delay Interval 10s
		0x00, 0x07, 's', '/', '7', '/', 'o', 'f', 'f',
		0x00, 0x03, 'b', 'y', 'e',
	}
	got, err := EncodeBytes(&Connect{
		ProtocolName: ProtocolName, ProtocolLevel: byte(V5),
		KeepAlive: 30, ClientID: "c1",
		HasWill: true, WillTopic: "s/7/off", WillPayload: []byte("bye"), WillQoS: QoS1,
		WillProps: propsOf(func(p *Properties) { p.SetWillDelay(10) }),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("bytes:\n got % X\nwant % X", got, want)
	}
	p, err := Decode(bufio.NewReader(bytes.NewReader(want)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	c := p.(*Connect)
	if !c.HasWill || c.WillQoS != QoS1 || c.WillTopic != "s/7/off" || string(c.WillPayload) != "bye" {
		t.Errorf("will = %+v", c)
	}
	if c.WillProps.WillDelay != 10 {
		t.Errorf("will delay = %d", c.WillProps.WillDelay)
	}
	// Receive Maximum belongs to the CONNECT header, never to the will block.
	if c.WillProps.Has(PropReceiveMaximum) {
		t.Error("Receive Maximum leaked into Will Properties")
	}
}

func TestEncodeV5Connack(t *testing.T) {
	cases := []struct {
		name string
		p    *Connack
		want []byte
	}{
		{"success", &Connack{ReasonCode: RSuccess},
			[]byte{0x20, 0x03, 0x00, 0x00, 0x00}},
		{"session present plus keep alive",
			&Connack{SessionPresent: true, ReasonCode: RSuccess,
				Props: propsOf(func(p *Properties) { p.SetServerKeepAlive(30) })},
			[]byte{0x20, 0x06, 0x01, 0x00, 0x03, 0x13, 0x00, 0x1E}},
		{"refusal carries its reason",
			&Connack{ReasonCode: RNotAuthorized,
				Props: propsOf(func(p *Properties) { p.SetReasonString("no rule matched") })},
			[]byte{0x20, 0x15, 0x00, 0x87,
				0x12, 0x1F, 0x00, 0x0F, 'n', 'o', ' ', 'r', 'u', 'l', 'e', ' ',
				'm', 'a', 't', 'c', 'h', 'e', 'd'}},
	}
	for _, tc := range cases {
		got, err := EncodeBytesVersion(V5, tc.p)
		if err != nil {
			t.Fatalf("%s: encode: %v", tc.name, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s bytes:\n got % X\nwant % X", tc.name, got, tc.want)
		}
	}

	// A caller still thinking in 3.1.1 return codes gets the mapped reason code.
	raw, err := EncodeBytesVersion(V5, &Connack{ReturnCode: ConnBadCredentials})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	p, err := DecodeVersion(bufio.NewReader(bytes.NewReader(raw)), V5)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := p.(*Connack).ReasonCode; got != RBadUsernameOrPassword {
		t.Errorf("reason = %#02x, want %#02x", got, RBadUsernameOrPassword)
	}
}

// TestEncodeV5AckOmission locks the rule that a successful acknowledgement says
// nothing: a two byte body stands for reason code 0x00 and no properties.
func TestEncodeV5AckOmission(t *testing.T) {
	bare, err := EncodeBytesVersion(V5, &Puback{PacketID: 1})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if want := []byte{0x40, 0x02, 0x00, 0x01}; !bytes.Equal(bare, want) {
		t.Fatalf("bytes = % X, want % X", bare, want)
	}
	// The elided form decodes back to success with no properties.
	p, err := DecodeVersion(bufio.NewReader(bytes.NewReader(bare)), V5)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := p.(*Puback); got.ReasonCode != RSuccess || got.Props != nil {
		t.Errorf("decoded = %+v", got)
	}

	// A non-success reason is always written, followed by an empty property area.
	told, err := EncodeBytesVersion(V5, &Puback{PacketID: 1, ReasonCode: RNoMatchingSubscribers})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if want := []byte{0x40, 0x04, 0x00, 0x01, 0x10, 0x00}; !bytes.Equal(told, want) {
		t.Errorf("bytes = % X, want % X", told, want)
	}

	// PUBREL and PUBCOMP share the form; the flags byte keeps its reserved 2.
	rel, err := EncodeBytesVersion(V5, &Pubrel{PacketID: 9})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if want := []byte{0x62, 0x02, 0x00, 0x09}; !bytes.Equal(rel, want) {
		t.Errorf("pubrel = % X, want % X", rel, want)
	}
}

// TestEncodeV5Publish checks the 5.0 PUBLISH order: topic, packet identifier,
// properties, payload.
func TestEncodeV5Publish(t *testing.T) {
	want := []byte{
		0x32, 0x16,
		0x00, 0x03, 'a', '/', 'b',
		0x00, 0x07, // packet identifier
		0x0C,       // property length 12
		0x01, 0x01, // Payload Format Indicator = UTF-8
		0x02, 0x00, 0x00, 0x00, 0x78, // Message Expiry 120s
		0x0B, 0x05, // Subscription Identifier 5
		0x23, 0x00, 0x02, // Topic Alias 2
		'h', 'i',
	}
	got, err := EncodeBytesVersion(V5, &Publish{
		Topic: "a/b", PacketID: 7, QoS: QoS1, Payload: []byte("hi"),
		Props: propsOf(func(p *Properties) {
			p.SetPayloadFormat(1)
			p.SetMessageExpiry(120)
			p.AddSubscriptionID(5)
			p.SetTopicAlias(2)
		}),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("bytes:\n got % X\nwant % X", got, want)
	}
	p, err := DecodeVersion(bufio.NewReader(bytes.NewReader(want)), V5)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := p.(*Publish)
	if m.Topic != "a/b" || m.PacketID != 7 || m.QoS != QoS1 || string(m.Payload) != "hi" {
		t.Errorf("publish = %+v", m)
	}
	if m.Props.MessageExpiry != 120 || m.Props.TopicAlias != 2 || m.Props.PayloadFormat != 1 {
		t.Errorf("props = %+v", m.Props)
	}
	if len(m.Props.SubscriptionIDs) != 1 || m.Props.SubscriptionIDs[0] != 5 {
		t.Errorf("subscription ids = %v", m.Props.SubscriptionIDs)
	}
}

// TestV5VariableByteIntegerBoundaries exercises the widest values a property can
// carry, at both the VBI limit and the Four Byte Integer limit.
func TestV5VariableByteIntegerBoundaries(t *testing.T) {
	want := []byte{
		0x30, 0x0F,
		0x00, 0x01, 't',
		0x0A,                         // property length
		0x02, 0xFF, 0xFF, 0xFF, 0xFF, // Message Expiry 4294967295
		0x0B, 0xFF, 0xFF, 0xFF, 0x7F, // Subscription Identifier 268435455
		'x',
	}
	got, err := EncodeBytesVersion(V5, &Publish{
		Topic: "t", Payload: []byte("x"),
		Props: propsOf(func(p *Properties) {
			p.AddSubscriptionID(maxVBI)
			p.SetMessageExpiry(0xFFFFFFFF)
		}),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("bytes:\n got % X\nwant % X", got, want)
	}
	p, err := DecodeVersion(bufio.NewReader(bytes.NewReader(want)), V5)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := p.(*Publish)
	if m.Props.SubscriptionIDs[0] != maxVBI || m.Props.MessageExpiry != 0xFFFFFFFF {
		t.Errorf("decoded = %+v", m.Props)
	}
}

// TestEncodeV5SubscribeOptions pins the subscription options byte layout of
// section 3.8.3.1: QoS, No Local, Retain As Published, Retain Handling.
func TestEncodeV5SubscribeOptions(t *testing.T) {
	want := []byte{
		0x82, 0x0B,
		0x00, 0x03, // packet identifier
		0x02, 0x0B, 0x4D, // one property: Subscription Identifier 77
		0x00, 0x03, 'a', '/', 'b',
		0x2D, // 0b00101101: retain handling 2, RAP 1, no local 1, QoS 1
	}
	got, err := EncodeBytesVersion(V5, &Subscribe{
		PacketID: 3,
		Props:    propsOf(func(p *Properties) { p.AddSubscriptionID(77) }),
		Subscriptions: []Subscription{{
			TopicFilter: "a/b", MaxQoS: QoS1,
			NoLocal: true, RetainAsPublished: true, RetainHandling: 2,
		}},
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("bytes:\n got % X\nwant % X", got, want)
	}
	p, err := DecodeVersion(bufio.NewReader(bytes.NewReader(want)), V5)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	s := p.(*Subscribe).Subscriptions[0]
	if s.MaxQoS != QoS1 || !s.NoLocal || !s.RetainAsPublished || s.RetainHandling != 2 {
		t.Errorf("subscription = %+v", s)
	}
	if id := p.(*Subscribe).Props.SubscriptionIDs; len(id) != 1 || id[0] != 77 {
		t.Errorf("subscription id = %v", id)
	}
}

func TestEncodeV5UnsubackDisconnectAuth(t *testing.T) {
	// UNSUBACK: identifier, properties, then one reason code per filter.
	un, err := EncodeBytesVersion(V5, &Unsuback{
		PacketID:    3,
		Props:       propsOf(nil),
		ReasonCodes: []byte{RSuccess, RNoSubscriptionExisted},
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if want := []byte{0xB0, 0x05, 0x00, 0x03, 0x00, 0x00, 0x11}; !bytes.Equal(un, want) {
		t.Errorf("unsuback:\n got % X\nwant % X", un, want)
	}

	// A plain DISCONNECT stays the zero length packet 3.1.1 clients expect.
	by, err := EncodeBytesVersion(V5, &Disconnect{})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if want := []byte{0xE0, 0x00}; !bytes.Equal(by, want) {
		t.Errorf("disconnect = % X, want % X", by, want)
	}

	// DISCONNECT 0x04 keeps the will and expires the session immediately.
	dw, err := EncodeBytesVersion(V5, &Disconnect{
		ReasonCode: RDisconnectWithWill,
		Props:      propsOf(func(p *Properties) { p.SetSessionExpiry(0) }),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if want := []byte{0xE0, 0x07, 0x04, 0x05, 0x11, 0x00, 0x00, 0x00, 0x00}; !bytes.Equal(dw, want) {
		t.Errorf("disconnect with will:\n got % X\nwant % X", dw, want)
	}

	au, err := EncodeBytesVersion(V5, &Auth{
		ReasonCode: RContinueAuth,
		Props:      propsOf(func(p *Properties) { p.SetAuthMethod("EXAMPLE") }),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if want := []byte{0xF0, 0x0C, 0x18, 0x0A, 0x15, 0x00, 0x07, 'E', 'X', 'A', 'M', 'P', 'L', 'E'}; !bytes.Equal(au, want) {
		t.Errorf("auth:\n got % X\nwant % X", au, want)
	}
	p, err := DecodeVersion(bufio.NewReader(bytes.NewReader(au)), V5)
	if err != nil {
		t.Fatalf("decode auth: %v", err)
	}
	if a := p.(*Auth); a.ReasonCode != RContinueAuth || a.Props.AuthMethod != "EXAMPLE" {
		t.Errorf("auth = %+v %+v", a, a.Props)
	}
}

// TestV5MalformedVsProtocol separates the two failure classes the 5.0 spec
// distinguishes: bytes that do not parse (reason code 0x81) against values that
// parse cleanly but break a stated rule (0x82).
func TestV5MalformedVsProtocol(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"duplicated property", []byte{
			0x10, 0x18,
			0x00, 0x04, 'M', 'Q', 'T', 'T', 0x05, 0x00, 0x00, 0x00,
			0x0A, 0x11, 0x00, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0x00, 0x02,
			0x00, 0x01, 'c',
		}, ErrProtocol},
		{"retain available of 2", []byte{0x20, 0x05, 0x00, 0x00, 0x02, 0x25, 0x02}, ErrProtocol},
		{"receive maximum of 0", []byte{
			0x10, 0x11,
			0x00, 0x04, 'M', 'Q', 'T', 'T', 0x05, 0x00, 0x00, 0x00,
			0x03, 0x21, 0x00, 0x00,
			0x00, 0x01, 'c',
		}, ErrProtocol},
		{"topic alias of 0", []byte{0x30, 0x07, 0x00, 0x01, 'a', 0x03, 0x23, 0x00, 0x00}, ErrProtocol},
		{"subscription identifier of 0", []byte{0x30, 0x06, 0x00, 0x01, 'a', 0x02, 0x0B, 0x00}, ErrProtocol},
		{"response topic with wildcard", []byte{
			0x30, 0x0A, 0x00, 0x01, 'a',
			0x06, 0x08, 0x00, 0x03, 'a', '/', '#',
		}, ErrProtocol},
		{"zero topic without alias", []byte{0x30, 0x03, 0x00, 0x00, 0x00}, ErrProtocol},
		{"retain handling 3", []byte{0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, 'a', 0x30}, ErrProtocol},
		{"no local on shared subscription", []byte{
			0x82, 0x10, 0x00, 0x01, 0x00,
			0x00, 0x0A, '$', 's', 'h', 'a', 'r', 'e', '/', 'g', '/', 'a', 0x04,
		}, ErrProtocol},
		{"qos 3 in subscription", []byte{0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, 'a', 0x03}, ErrProtocol},
		{"reserved subscription bits", []byte{0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, 'a', 0x40}, ErrMalformed},
		{"reason code in the wrong packet", []byte{0x40, 0x04, 0x00, 0x01, 0x92, 0x00}, ErrProtocol},
		{"unknown reason code in suback", []byte{0x90, 0x04, 0x00, 0x01, 0x00, 0x03}, ErrProtocol},
		{"property in the wrong packet", []byte{
			0x30, 0x09, 0x00, 0x01, 'a',
			0x05, 0x11, 0x00, 0x00, 0x00, 0x01,
		}, ErrMalformed},
		{"unknown property identifier", []byte{0x30, 0x06, 0x00, 0x01, 'a', 0x02, 0x77, 0x00}, ErrMalformed},
		{"property length past the end", []byte{0x30, 0x04, 0x00, 0x01, 'a', 0x40}, ErrMalformed},
	}
	for _, tc := range cases {
		_, err := DecodeVersion(bufio.NewReader(bytes.NewReader(tc.raw)), V5)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

// TestV5TopicAliasOnlyPublish is the one case where an empty topic name is
// legal: the alias carries the name set earlier on this connection.
func TestV5TopicAliasOnlyPublish(t *testing.T) {
	raw := []byte{0x30, 0x06, 0x00, 0x00, 0x03, 0x23, 0x00, 0x01}
	p, err := DecodeVersion(bufio.NewReader(bytes.NewReader(raw)), V5)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := p.(*Publish)
	if m.Topic != "" || m.Props.TopicAlias != 1 {
		t.Errorf("publish = %+v props %+v", m, m.Props)
	}
}

// TestV5RoundTrip sends every packet type through the 5.0 codec and back.
func TestV5RoundTrip(t *testing.T) {
	cases := []Packet{
		&Connect{ProtocolName: ProtocolName, ProtocolLevel: byte(V5), CleanSession: true,
			KeepAlive: 30, ClientID: "c1",
			Props: propsOf(func(p *Properties) { p.SetMaxPacketSize(1024) })},
		&Connect{ProtocolName: ProtocolName, ProtocolLevel: byte(V5), ClientID: "c1",
			HasWill: true, WillTopic: "w", WillPayload: []byte("x"), WillQoS: QoS2, WillRetain: true,
			WillProps: propsOf(func(p *Properties) {
				p.SetWillDelay(5)
				p.SetContentType("text/plain")
			}),
			HasUsername: true, Username: "u", HasPassword: true, Password: []byte("p"),
			Props: propsOf(func(p *Properties) { p.SetTopicAliasMax(3) })},
		&Connack{ReasonCode: RSuccess, Props: propsOf(nil)},
		&Connack{SessionPresent: true, ReasonCode: RSuccess,
			Props: propsOf(func(p *Properties) {
				p.SetMaxQoS(QoS2)
				p.SetRetainAvail(1)
				p.SetWildcardAvail(1)
				p.SetSubIDAvail(1)
				p.SetSharedAvail(1)
				p.SetAssignedClientID("auto-1")
			})},
		&Connack{ReasonCode: RServerMoved,
			Props: propsOf(func(p *Properties) { p.SetServerReference("mqtt://other:1883") })},
		&Publish{Topic: "s/7/temp", QoS: QoS0, Payload: []byte("21.5"), Props: propsOf(nil)},
		&Publish{Topic: "s/7/temp", QoS: QoS2, PacketID: 4242, Dup: true, Retain: true,
			Payload: []byte("x"),
			Props: propsOf(func(p *Properties) {
				p.SetCorrelationData([]byte{1, 2, 3})
				p.SetResponseTopic("reply/1")
				p.AddUser("a", "1")
				p.AddUser("a", "2")
			})},
		&Puback{PacketID: 7, ReasonCode: RSuccess},
		&Puback{PacketID: 8, ReasonCode: RQuotaExceeded,
			Props: propsOf(func(p *Properties) { p.SetReasonString("over") })},
		&Pubrec{PacketID: 9, ReasonCode: RNoMatchingSubscribers, Props: propsOf(nil)},
		&Pubrel{PacketID: 10, ReasonCode: RSuccess},
		&Pubcomp{PacketID: 11, ReasonCode: RPacketIdentifierNotFound, Props: propsOf(nil)},
		&Subscribe{PacketID: 12, Props: propsOf(func(p *Properties) { p.AddSubscriptionID(9) }),
			Subscriptions: []Subscription{
				{TopicFilter: "a/+", MaxQoS: QoS2, RetainAsPublished: true},
				{TopicFilter: "$share/g/b/#", MaxQoS: QoS1, RetainHandling: 1},
			}},
		&Suback{PacketID: 13, ReturnCodes: []byte{RGrantedQoS2, RGrantedQoS1, RNotAuthorized},
			Props: propsOf(func(p *Properties) { p.SetReasonString("acl") })},
		&Unsubscribe{PacketID: 14, TopicFilters: []string{"a/+", "b/#"},
			Props: propsOf(func(p *Properties) { p.AddUser("why", "cleanup") })},
		&Unsuback{PacketID: 15, Props: propsOf(nil),
			ReasonCodes: []byte{RSuccess, RNoSubscriptionExisted}},
		&Unsuback{PacketID: 16, Props: propsOf(func(p *Properties) { p.AddUser("k", "v") })},
		&Pingreq{},
		&Pingresp{},
		&Disconnect{ReasonCode: RKeepAliveTimeout,
			Props: propsOf(func(p *Properties) { p.SetSessionExpiry(30) })},
		&Auth{ReasonCode: RReauthAuthenticate,
			Props: propsOf(func(p *Properties) { p.SetAuthData([]byte("tok")) })},
	}

	for _, want := range cases {
		raw, err := EncodeBytesVersion(V5, want)
		if err != nil {
			t.Fatalf("encode %s: %v", want.Type(), err)
		}
		got, err := DecodeVersion(bufio.NewReader(bytes.NewReader(raw)), V5)
		if err != nil {
			t.Fatalf("decode %s (% X): %v", want.Type(), raw, err)
		}
		// %+v cannot compare these structs: the property area is a pointer and
		// fmt prints nested pointers as addresses. Re-encoding what came back
		// and requiring the same bytes proves nothing was lost.
		again, err := EncodeBytesVersion(V5, got)
		if err != nil {
			t.Fatalf("re-encode %s: %v", want.Type(), err)
		}
		if !bytes.Equal(again, raw) {
			t.Errorf("%s round trip:\n out % X\nwant % X", want.Type(), again, raw)
		}
	}
}

// TestV311StreamIsUnchanged guards the compatibility claim: a 3.1.1 peer sees no
// property area at all.
func TestV311StreamIsUnchanged(t *testing.T) {
	packets := []Packet{
		&Connect{ProtocolName: ProtocolName, ProtocolLevel: ProtocolLevel, ClientID: "c", KeepAlive: 30},
		&Connack{ReturnCode: ConnAccepted},
		&Publish{Topic: "a", QoS: QoS1, PacketID: 1, Payload: []byte("m")},
		&Puback{PacketID: 1},
		&Subscribe{PacketID: 2, Subscriptions: []Subscription{{TopicFilter: "a", MaxQoS: QoS1}}},
		&Suback{PacketID: 2, ReturnCodes: []byte{QoS1}},
		&Disconnect{},
	}
	var buf bytes.Buffer
	raws := make([][]byte, 0, len(packets))
	for _, p := range packets {
		raw, err := EncodeBytes(p)
		if err != nil {
			t.Fatalf("encode %s: %v", p.Type(), err)
		}
		raws = append(raws, raw)
		buf.Write(raw)
	}
	// Acknowledgement bodies stay two bytes, SUBSCRIBE options stay a bare QoS,
	// and CONNACK stays the three byte packet a 3.1.1 client parses.
	if len(raws[3]) != 4 {
		t.Errorf("3.1.1 PUBACK is % X, want 4 bytes", raws[3])
	}
	if len(raws[1]) != 4 {
		t.Errorf("3.1.1 CONNACK is % X, want 4 bytes", raws[1])
	}
	if raws[4][len(raws[4])-1] != QoS1 {
		t.Errorf("3.1.1 subscription options = %#02x, want 01", raws[4][len(raws[4])-1])
	}

	// One stream, both versions read in sequence: the codec never loses sync.
	r := bufio.NewReader(&buf)
	for i, p := range packets {
		got, err := Decode(r)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if got.Type() != p.Type() {
			t.Errorf("packet %d = %s, want %s", i, got.Type(), p.Type())
		}
	}

	// The same 3.1.1 CONNACK is refused once the connection claims 5.0, because
	// the property length is mandatory there.
	if _, err := DecodeVersion(bufio.NewReader(bytes.NewReader(raws[1])), V5); !errors.Is(err, ErrMalformed) {
		t.Errorf("3.1.1 CONNACK under 5.0: err = %v, want ErrMalformed", err)
	}
	// A two byte PUBACK is legal in both versions, so it must still decode.
	if _, err := DecodeVersion(bufio.NewReader(bytes.NewReader(raws[3])), V5); err != nil {
		t.Errorf("3.1.1 PUBACK under 5.0: %v", err)
	}
	// AUTH is a 5.0 packet type; 3.1.1 reserves it.
	auth, err := EncodeBytesVersion(V5, &Auth{ReasonCode: RContinueAuth})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := Decode(bufio.NewReader(bytes.NewReader(auth))); !errors.Is(err, ErrMalformed) {
		t.Errorf("AUTH under 3.1.1: err = %v, want ErrMalformed", err)
	}
}

// TestEncodeRejectsBadV5Constructions keeps the encoder from writing packets a
// peer would reject: illegal option values and reason codes in the wrong place.
func TestEncodeRejectsBadV5Constructions(t *testing.T) {
	bad := []Packet{
		&Puback{PacketID: 1, ReasonCode: 0x7F},
		&Suback{PacketID: 1, ReturnCodes: []byte{0x03}},
		&Subscribe{PacketID: 1, Subscriptions: []Subscription{{TopicFilter: "a", RetainHandling: 3}}},
		&Connack{ReasonCode: RDisconnectWithWill},
		&Unsuback{PacketID: 1, ReasonCodes: []byte{RNoMatchingSubscribers}},
		&Publish{Topic: "a", Props: propsOf(func(p *Properties) { p.SetTopicAliasMax(4) })},
	}
	for _, p := range bad {
		if _, err := EncodeBytesVersion(V5, p); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", p.Type(), err)
		}
	}
}

// TestV5PropertiesClone checks the copy a stored Application Message keeps, so
// two subscribers never share one byte slice.
func TestV5PropertiesClone(t *testing.T) {
	src := propsOf(func(p *Properties) {
		p.AddUser("k", "v")
		p.SetCorrelationData([]byte{7})
		p.AddSubscriptionID(3)
		p.SetMessageExpiry(9)
	})
	cp := src.Clone()
	cp.User[0].Value = "changed"
	cp.CorrelationData[0] = 8
	cp.SubscriptionIDs[0] = 4
	if v, ok := src.UserValue("k"); !ok || v != "v" {
		t.Errorf("user property leaked: %q %v", v, ok)
	}
	if src.CorrelationData[0] != 7 {
		t.Error("correlation data leaked")
	}
	if src.SubscriptionIDs[0] != 3 {
		t.Error("subscription id leaked")
	}
	if !cp.Has(PropMessageExpiry) || cp.MessageExpiry != 9 {
		t.Error("presence mask lost in clone")
	}
	if nilProps := (*Properties)(nil); !nilProps.IsEmpty() || nilProps.Has(PropUser) {
		t.Error("nil properties are not empty")
	}
}

// TestPropertiesJSONRoundTrip keeps the store's encoding honest. encoding/json
// would otherwise reflect over the struct and drop `set`, and then a publisher
// that said "expire this in zero seconds" comes back as one that said nothing at
// all - the opposite instruction.
func TestPropertiesJSONRoundTrip(t *testing.T) {
	src := propsOf(func(p *Properties) {
		p.SetMessageExpiry(0)
		p.SetPayloadFormat(0)
		p.SetContentType("")
		p.AddUser("device", "")
		p.SetResponseTopic("reply/to/me")
		p.SetCorrelationData([]byte{1, 2})
		p.AddSubscriptionID(7)
	})
	b, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.HasPrefix(b, []byte("{")) {
		t.Fatalf("properties were reflected field by field, which loses presence: %s", b)
	}

	// A holder is how the store reaches them: a field inside a serialized Message.
	type holder struct{ Props *Properties }
	wrapped, err := json.Marshal(holder{Props: src})
	if err != nil {
		t.Fatalf("marshal inside a message: %v", err)
	}
	var back holder
	if err := json.Unmarshal(wrapped, &back); err != nil {
		t.Fatalf("a message's property area cannot be read back: %v (was %s)", err, wrapped)
	}
	if back.Props == nil {
		t.Fatalf("the property area vanished: %s", wrapped)
	}
	got, err := back.Props.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal the restored area: %v", err)
	}
	want, err := src.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal the original area: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("restored wire form = %x, want %x", got, want)
	}
	if !back.Props.Has(PropMessageExpiry) || back.Props.MessageExpiry != 0 {
		t.Error("a property that was present and zero came back absent")
	}
	if _, ok := back.Props.UserValue("device"); !ok {
		t.Error("a user property with an empty value was dropped")
	}

	// A 3.1.1 message has no property area, and null is how the store says so.
	var none holder
	if err := json.Unmarshal([]byte(`{"Props":null}`), &none); err != nil {
		t.Fatalf("unmarshal a null area: %v", err)
	}
	if none.Props != nil {
		t.Errorf("null properties restored as %v, want nil", none.Props)
	}
	if b, err := json.Marshal(&holder{}); err != nil || !bytes.Contains(b, []byte("null")) {
		t.Errorf("an absent area marshalled as %s (err %v), want null", b, err)
	}

	// A will's delay is not a PUBLISH property, so storing one that still carried
	// it must fail loudly instead of writing a file the next start refuses.
	var delayed holder
	delayed.Props = propsOf(func(p *Properties) { p.SetWillDelay(30) })
	if _, err := json.Marshal(delayed); err == nil {
		t.Error("a will delay inside a publish property area was accepted")
	}
}
