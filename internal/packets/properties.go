package packets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Property identifiers, from the OASIS MQTT 5.0 property identifier table.
// Although the identifier is encoded as a Variable Byte Integer, every
// identifier defined by this version of the spec fits in one byte.
const (
	PropPayloadFormat      byte = 0x01
	PropMessageExpiry      byte = 0x02
	PropContentType        byte = 0x03
	PropResponseTopic      byte = 0x08
	PropCorrelationData    byte = 0x09
	PropSubscriptionID     byte = 0x0B
	PropSessionExpiry      byte = 0x11
	PropAssignedClientID   byte = 0x12
	PropServerKeepAlive    byte = 0x13
	PropAuthMethod         byte = 0x15
	PropAuthData           byte = 0x16
	PropRequestProblemInfo byte = 0x17
	PropWillDelay          byte = 0x18
	PropRequestResponse    byte = 0x19
	PropResponseInfo       byte = 0x1A
	PropServerReference    byte = 0x1C
	PropReasonString       byte = 0x1F
	PropReceiveMaximum     byte = 0x21
	PropTopicAliasMaximum  byte = 0x22
	PropTopicAlias         byte = 0x23
	PropMaximumQoS         byte = 0x24
	PropRetainAvailable    byte = 0x25
	PropUser               byte = 0x26
	PropMaximumPacketSize  byte = 0x27
	PropWildcardAvailable  byte = 0x28
	PropSubIDAvailable     byte = 0x29
	PropSharedAvailable    byte = 0x2A
)

// propKind is the wire type of a property value.
type propKind byte

const (
	kindByte propKind = iota
	kindU16
	kindU32
	kindVBI
	kindBinary
	kindString
	kindPair
)

// ctxWill is the pseudo packet context for the Will Properties block inside the
// CONNECT payload. It shares the identifier space with real packet types, so it
// gets a value above them.
const ctxWill = Type(16)

// propSpec describes one property: how to decode it and where it may appear.
type propSpec struct {
	name    string
	kind    propKind
	allowed uint32
	multi   bool // may appear more than once
}

// Bits of `allowed` are indexed by packet context (Type value 1..15, plus
// ctxWill). The table below is the spec's property identifier table; a property
// that shows up in a packet type not listed here is a Malformed Packet.
var props = map[byte]propSpec{
	PropPayloadFormat:      {"Payload Format Indicator", kindByte, bit(TypePublish) | bit(ctxWill), false},
	PropMessageExpiry:      {"Message Expiry Interval", kindU32, bit(TypePublish) | bit(ctxWill), false},
	PropContentType:        {"Content Type", kindString, bit(TypePublish) | bit(ctxWill), false},
	PropResponseTopic:      {"Response Topic", kindString, bit(TypePublish) | bit(ctxWill), false},
	PropCorrelationData:    {"Correlation Data", kindBinary, bit(TypePublish) | bit(ctxWill), false},
	PropSubscriptionID:     {"Subscription Identifier", kindVBI, bit(TypePublish) | bit(TypeSubscribe), true},
	PropSessionExpiry:      {"Session Expiry Interval", kindU32, bit(TypeConnect) | bit(TypeConnack) | bit(TypeDisconnect), false},
	PropAssignedClientID:   {"Assigned Client Identifier", kindString, bit(TypeConnack), false},
	PropServerKeepAlive:    {"Server Keep Alive", kindU16, bit(TypeConnack), false},
	PropAuthMethod:         {"Authentication Method", kindString, bit(TypeConnect) | bit(TypeConnack) | bit(TypeAuth), false},
	PropAuthData:           {"Authentication Data", kindBinary, bit(TypeConnect) | bit(TypeConnack) | bit(TypeAuth), false},
	PropRequestProblemInfo: {"Request Problem Information", kindByte, bit(TypeConnect), false},
	PropWillDelay:          {"Will Delay Interval", kindU32, bit(ctxWill), false},
	PropRequestResponse:    {"Request Response Information", kindByte, bit(TypeConnect), false},
	PropResponseInfo:       {"Response Information", kindString, bit(TypeConnack), false},
	PropServerReference:    {"Server Reference", kindString, bit(TypeConnack) | bit(TypeDisconnect), false},
	PropReasonString:       {"Reason String", kindString, bit(TypeConnack) | bit(TypePuback) | bit(TypePubrec) | bit(TypePubrel) | bit(TypePubcomp) | bit(TypeSuback) | bit(TypeUnsuback) | bit(TypeDisconnect) | bit(TypeAuth), false},
	PropReceiveMaximum:     {"Receive Maximum", kindU16, bit(TypeConnect) | bit(TypeConnack), false},
	PropTopicAliasMaximum:  {"Topic Alias Maximum", kindU16, bit(TypeConnect) | bit(TypeConnack), false},
	PropTopicAlias:         {"Topic Alias", kindU16, bit(TypePublish), false},
	PropMaximumQoS:         {"Maximum QoS", kindByte, bit(TypeConnack), false},
	PropRetainAvailable:    {"Retain Available", kindByte, bit(TypeConnack), false},
	PropUser:               {"User Property", kindPair, allPackets | bit(ctxWill), true},
	PropMaximumPacketSize:  {"Maximum Packet Size", kindU32, bit(TypeConnect) | bit(TypeConnack), false},
	PropWildcardAvailable:  {"Wildcard Subscription Available", kindByte, bit(TypeConnack), false},
	PropSubIDAvailable:     {"Subscription Identifier Available", kindByte, bit(TypeConnack), false},
	PropSharedAvailable:    {"Shared Subscription Available", kindByte, bit(TypeConnack), false},
}

// allPackets is every packet type that can carry a User Property.
var allPackets = bit(TypeConnect) | bit(TypeConnack) | bit(TypePublish) | bit(TypePuback) |
	bit(TypePubrec) | bit(TypePubrel) | bit(TypePubcomp) | bit(TypeSubscribe) | bit(TypeSuback) |
	bit(TypeUnsubscribe) | bit(TypeUnsuback) | bit(TypeDisconnect) | bit(TypeAuth)

func bit(ctx Type) uint32 { return uint32(1) << ctx }

// Pair is one User Property.
type Pair struct{ Key, Value string }

// Properties holds the property area of an MQTT 5.0 packet. Fields are plain
// values; `set` records which were actually present, because a zero Session
// Expiry Interval and an absent one mean different things to the broker.
type Properties struct {
	set  uint64
	User []Pair

	PayloadFormat    byte
	MessageExpiry    uint32
	ContentType      string
	ResponseTopic    string
	CorrelationData  []byte
	SubscriptionIDs  []int
	SessionExpiry    uint32
	AssignedClientID string
	ServerKeepAlive  uint16
	AuthMethod       string
	AuthData         []byte
	RequestProblem   byte
	WillDelay        uint32
	RequestResponse  byte
	ResponseInfo     string
	ServerReference  string
	ReasonString     string
	ReceiveMax       uint16
	TopicAliasMax    uint16
	TopicAlias       uint16
	MaxQoS           byte
	RetainAvail      byte
	MaxPacketSize    uint32
	WildcardAvail    byte
	SubIDAvail       byte
	SharedAvail      byte
}

// Has reports whether the property was present on the wire (or was set).
func (p *Properties) Has(id byte) bool {
	if p == nil {
		return false
	}
	return p.set&(uint64(1)<<id) != 0
}

func (p *Properties) mark(id byte) { p.set |= uint64(1) << id }

// Clear forgets a property so the encoder skips it. A broker forwards a message
// with its own view of its lifetime, and the publisher's number must go first.
func (p *Properties) Clear(id byte) {
	p.set &^= uint64(1) << id
	if id == PropUser {
		p.User = nil
	}
	if id == PropSubscriptionID {
		p.SubscriptionIDs = nil
	}
}

// IsEmpty reports that nothing would be written. A nil *Properties and one with
// no marked values encode to the same one-byte zero property length, which is
// why acknowledgement packets can leave the whole tail out.
func (p *Properties) IsEmpty() bool { return p == nil || p.set == 0 }

// Setters keep presence and value in sync, so a caller cannot set a value the
// encoder will not write.
func (p *Properties) SetPayloadFormat(v byte)   { p.PayloadFormat = v; p.mark(PropPayloadFormat) }
func (p *Properties) SetMessageExpiry(v uint32) { p.MessageExpiry = v; p.mark(PropMessageExpiry) }
func (p *Properties) SetContentType(v string)   { p.ContentType = v; p.mark(PropContentType) }
func (p *Properties) SetResponseTopic(v string) { p.ResponseTopic = v; p.mark(PropResponseTopic) }
func (p *Properties) SetCorrelationData(v []byte) {
	p.CorrelationData = v
	p.mark(PropCorrelationData)
}
func (p *Properties) AddSubscriptionID(v int) {
	p.SubscriptionIDs = append(p.SubscriptionIDs, v)
	p.mark(PropSubscriptionID)
}
func (p *Properties) SetSessionExpiry(v uint32) { p.SessionExpiry = v; p.mark(PropSessionExpiry) }
func (p *Properties) SetAssignedClientID(v string) {
	p.AssignedClientID = v
	p.mark(PropAssignedClientID)
}
func (p *Properties) SetServerKeepAlive(v uint16) { p.ServerKeepAlive = v; p.mark(PropServerKeepAlive) }
func (p *Properties) SetAuthMethod(v string)      { p.AuthMethod = v; p.mark(PropAuthMethod) }
func (p *Properties) SetAuthData(v []byte)        { p.AuthData = v; p.mark(PropAuthData) }
func (p *Properties) SetRequestProblem(v byte)    { p.RequestProblem = v; p.mark(PropRequestProblemInfo) }
func (p *Properties) SetWillDelay(v uint32)       { p.WillDelay = v; p.mark(PropWillDelay) }
func (p *Properties) SetRequestResponse(v byte)   { p.RequestResponse = v; p.mark(PropRequestResponse) }
func (p *Properties) SetResponseInfo(v string)    { p.ResponseInfo = v; p.mark(PropResponseInfo) }
func (p *Properties) SetServerReference(v string) { p.ServerReference = v; p.mark(PropServerReference) }
func (p *Properties) SetReasonString(v string)    { p.ReasonString = v; p.mark(PropReasonString) }
func (p *Properties) SetReceiveMax(v uint16)      { p.ReceiveMax = v; p.mark(PropReceiveMaximum) }
func (p *Properties) SetTopicAliasMax(v uint16)   { p.TopicAliasMax = v; p.mark(PropTopicAliasMaximum) }
func (p *Properties) SetTopicAlias(v uint16)      { p.TopicAlias = v; p.mark(PropTopicAlias) }
func (p *Properties) SetMaxQoS(v byte)            { p.MaxQoS = v; p.mark(PropMaximumQoS) }
func (p *Properties) SetRetainAvail(v byte)       { p.RetainAvail = v; p.mark(PropRetainAvailable) }
func (p *Properties) SetMaxPacketSize(v uint32)   { p.MaxPacketSize = v; p.mark(PropMaximumPacketSize) }
func (p *Properties) SetWildcardAvail(v byte)     { p.WildcardAvail = v; p.mark(PropWildcardAvailable) }
func (p *Properties) SetSubIDAvail(v byte)        { p.SubIDAvail = v; p.mark(PropSubIDAvailable) }
func (p *Properties) SetSharedAvail(v byte)       { p.SharedAvail = v; p.mark(PropSharedAvailable) }

// AddUser appends a User Property. They are the only property that repeats
// freely, and the encoder preserves the order they were added in.
func (p *Properties) AddUser(key, value string) {
	p.User = append(p.User, Pair{key, value})
	p.mark(PropUser)
}

// UserValue returns the first value stored under key, mirroring how callers
// treat repeated keys in practice.
func (p *Properties) UserValue(key string) (string, bool) {
	if p == nil {
		return "", false
	}
	for _, kv := range p.User {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return "", false
}

// Clone returns a deep copy, so a stored Application Message can be handed to
// several subscribers without sharing byte slices.
func (p *Properties) Clone() *Properties {
	if p == nil {
		return nil
	}
	c := *p
	c.User = append([]Pair(nil), p.User...)
	c.SubscriptionIDs = append([]int(nil), p.SubscriptionIDs...)
	c.CorrelationData = cloneSlice(p.CorrelationData)
	c.AuthData = cloneSlice(p.AuthData)
	return &c
}

func cloneSlice(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

// MarshalBinary writes the property area in the same wire form it has inside a
// PUBLISH - variable-byte length, then the properties. Storing a message this
// way rather than field by field keeps the presence bitmap, which is what says
// "the publisher sent zero" apart from "the publisher sent nothing", and it
// means the durable format is the protocol rather than a second invention.
//
// The context is PUBLISH because that is all a stored message's property area
// ever is: the broker drops the connection-scoped properties (Topic Alias,
// Subscription Identifier, Message Expiry) when it takes ownership.
func (p *Properties) MarshalBinary() ([]byte, error) {
	e := &encoder{buf: &bytes.Buffer{}, ver: V5}
	writeProperties(e, TypePublish, p)
	if e.err != nil {
		return nil, e.err
	}
	return append([]byte(nil), e.buf.Bytes()...), nil
}

// UnmarshalBinary reverses MarshalBinary. A property the publish context does
// not allow is an error, so a store file written by a different build cannot be
// silently misread.
func (p *Properties) UnmarshalBinary(b []byte) error {
	d := &decoder{buf: b, ver: V5}
	q := d.readProperties(TypePublish)
	if d.err != nil {
		return d.err
	}
	*p = *q
	return nil
}

// MarshalJSON encodes the property area as the base64 form of MarshalBinary.
// The default marshalling would have reflected over the struct and quietly
// dropped `set`, which is the only record of which properties were present.
// This keeps the store's JSON format lossless without inventing a third
// encoding.
func (p *Properties) MarshalJSON() ([]byte, error) {
	b, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return []byte(`"` + base64.StdEncoding.EncodeToString(b) + `"`), nil
}

// UnmarshalJSON reverses MarshalJSON. A JSON null means no property area at all,
// which is how a 3.1.1 message is stored.
func (p *Properties) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*p = Properties{}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return p.UnmarshalBinary(raw)
}

// propOrder is the canonical encoding order. The wire format does not care,
// but a fixed order makes byte-level tests meaningful.
var propOrder = []byte{
	PropPayloadFormat, PropMessageExpiry, PropContentType, PropResponseTopic,
	PropCorrelationData, PropSubscriptionID, PropSessionExpiry, PropAssignedClientID,
	PropServerKeepAlive, PropAuthMethod, PropAuthData, PropRequestProblemInfo,
	PropWillDelay, PropRequestResponse, PropResponseInfo, PropServerReference,
	PropReasonString, PropReceiveMaximum, PropTopicAliasMaximum, PropTopicAlias,
	PropMaximumQoS, PropRetainAvailable, PropUser, PropMaximumPacketSize,
	PropWildcardAvailable, PropSubIDAvailable, PropSharedAvailable,
}

// writeProperties emits the property area for the given packet context.
func writeProperties(e *encoder, ctx Type, p *Properties) {
	if p == nil {
		e.vbi(0)
		return
	}
	var body bytes.Buffer
	pe := &encoder{buf: &body}

	for _, id := range propOrder {
		if !p.Has(id) {
			continue
		}
		spec, ok := props[id]
		if !ok {
			e.fail("%w: internal property table is missing %#02x", ErrMalformed, id)
			return
		}
		if spec.allowed&bit(ctx) == 0 {
			e.fail("%w: %s is not allowed in %s", ErrMalformed, spec.name, ctxName(ctx))
			return
		}
		switch id {
		case PropPayloadFormat:
			pe.pair(id, func() { pe.byte(p.PayloadFormat) })
		case PropMessageExpiry:
			pe.id4(id, p.MessageExpiry)
		case PropContentType:
			pe.idStr(id, p.ContentType)
		case PropResponseTopic:
			pe.idStr(id, p.ResponseTopic)
		case PropCorrelationData:
			pe.idBin(id, p.CorrelationData)
		case PropSubscriptionID:
			for _, v := range p.SubscriptionIDs {
				pe.idVBI(id, v)
			}
		case PropSessionExpiry:
			pe.id4(id, p.SessionExpiry)
		case PropAssignedClientID:
			pe.idStr(id, p.AssignedClientID)
		case PropServerKeepAlive:
			pe.id2(id, p.ServerKeepAlive)
		case PropAuthMethod:
			pe.idStr(id, p.AuthMethod)
		case PropAuthData:
			pe.idBin(id, p.AuthData)
		case PropRequestProblemInfo:
			pe.pair(id, func() { pe.byte(p.RequestProblem) })
		case PropWillDelay:
			pe.id4(id, p.WillDelay)
		case PropRequestResponse:
			pe.pair(id, func() { pe.byte(p.RequestResponse) })
		case PropResponseInfo:
			pe.idStr(id, p.ResponseInfo)
		case PropServerReference:
			pe.idStr(id, p.ServerReference)
		case PropReasonString:
			pe.idStr(id, p.ReasonString)
		case PropReceiveMaximum:
			pe.id2(id, p.ReceiveMax)
		case PropTopicAliasMaximum:
			pe.id2(id, p.TopicAliasMax)
		case PropTopicAlias:
			pe.id2(id, p.TopicAlias)
		case PropMaximumQoS:
			pe.pair(id, func() { pe.byte(p.MaxQoS) })
		case PropRetainAvailable:
			pe.pair(id, func() { pe.byte(p.RetainAvail) })
		case PropUser:
			for _, kv := range p.User {
				pe.idPair(id, kv)
			}
		case PropMaximumPacketSize:
			pe.id4(id, p.MaxPacketSize)
		case PropWildcardAvailable:
			pe.pair(id, func() { pe.byte(p.WildcardAvail) })
		case PropSubIDAvailable:
			pe.pair(id, func() { pe.byte(p.SubIDAvail) })
		case PropSharedAvailable:
			pe.pair(id, func() { pe.byte(p.SharedAvail) })
		}
		if pe.err != nil {
			e.err = pe.err
			return
		}
	}
	e.vbi(body.Len())
	e.raw(body.Bytes())
}

// pair writes an identifier and its value, which is all the byte-sized
// properties need.
func (e *encoder) pair(id byte, write func()) {
	if e.err != nil {
		return
	}
	e.byte(id)
	write()
}

func (e *encoder) id2(id byte, v uint16)   { e.pair(id, func() { e.u16(v) }) }
func (e *encoder) id4(id byte, v uint32)   { e.pair(id, func() { e.u32(v) }) }
func (e *encoder) idVBI(id byte, v int)    { e.pair(id, func() { e.vbi(v) }) }
func (e *encoder) idStr(id byte, v string) { e.pair(id, func() { e.str(v) }) }
func (e *encoder) idBin(id byte, v []byte) { e.pair(id, func() { e.bin(v) }) }
func (e *encoder) idPair(id byte, v Pair) {
	e.pair(id, func() {
		e.str(v.Key)
		e.str(v.Value)
	})
}

// readProperties consumes the property area. ctx is the packet type, or
// ctxWill for the Will Properties block.
func (d *decoder) readProperties(ctx Type) *Properties {
	p := &Properties{}
	size := d.vbi()
	if d.err != nil {
		return p
	}
	end := d.pos + size
	if end > len(d.buf) {
		d.fail("property length %d runs past the end of the packet", size)
		return p
	}
	for d.pos < end && d.err == nil {
		id := d.vbi()
		if d.err != nil {
			return p
		}
		spec, ok := props[byte(id)]
		if !ok {
			d.fail("unknown property identifier %#02x", id)
			return p
		}
		if spec.allowed&bit(ctx) == 0 {
			d.fail("%s is not allowed in %s", spec.name, ctxName(ctx))
			return p
		}
		if p.Has(byte(id)) && !spec.multi {
			d.pfail("%s appears more than once", spec.name)
			return p
		}
		p.mark(byte(id))
		switch spec.kind {
		case kindByte:
			v := d.byte()
			p.setByteValue(byte(id), v)
			if byteBool(byte(id)) && v > 1 {
				d.pfail("%s must be 0 or 1, got %d", spec.name, v)
			}
			if byte(id) == PropMaximumQoS && v > QoS2 {
				d.pfail("Maximum QoS must be 0, 1 or 2, got %d", v)
			}
		case kindU16:
			v := d.u16()
			switch byte(id) {
			case PropReceiveMaximum:
				p.ReceiveMax = v
				if v == 0 {
					d.pfail("Receive Maximum of 0 is not permitted")
				}
			case PropTopicAliasMaximum:
				p.TopicAliasMax = v
			case PropServerKeepAlive:
				p.ServerKeepAlive = v
			case PropTopicAlias:
				p.TopicAlias = v
				if v == 0 {
					d.pfailAs(ErrTopicAlias, "Topic Alias of 0 is not permitted")
				}
			}
		case kindU32:
			v := d.u32()
			switch byte(id) {
			case PropMessageExpiry:
				p.MessageExpiry = v
			case PropSessionExpiry:
				p.SessionExpiry = v
			case PropWillDelay:
				p.WillDelay = v
			case PropMaximumPacketSize:
				p.MaxPacketSize = v
			}
		case kindVBI:
			v := d.vbi()
			if byte(id) == PropSubscriptionID {
				if v == 0 {
					d.pfail("Subscription Identifier of 0 is not permitted")
				}
				p.SubscriptionIDs = append(p.SubscriptionIDs, v)
			}
		case kindBinary:
			v := d.binary()
			if byte(id) == PropCorrelationData {
				p.CorrelationData = v
			} else {
				p.AuthData = v
			}
		case kindString:
			v := d.str()
			p.setStringValue(byte(id), v)
			if byte(id) == PropResponseTopic && strings.ContainsAny(v, "#+") {
				d.pfail("Response Topic must not contain wildcards")
			}
		case kindPair:
			key := d.str()
			val := d.str()
			p.User = append(p.User, Pair{key, val})
		}
	}
	if d.err != nil {
		return p
	}
	if d.pos != end {
		d.fail("property area ended %d byte(s) early", end-d.pos)
	}
	return p
}

// setByteValue and setStringValue split one identifier's value into the field
// that owns it; callers read properties through named fields rather than ids.
func (p *Properties) setByteValue(id, v byte) {
	switch id {
	case PropPayloadFormat:
		p.PayloadFormat = v
	case PropRequestProblemInfo:
		p.RequestProblem = v
	case PropRequestResponse:
		p.RequestResponse = v
	case PropMaximumQoS:
		p.MaxQoS = v
	case PropRetainAvailable:
		p.RetainAvail = v
	case PropWildcardAvailable:
		p.WildcardAvail = v
	case PropSubIDAvailable:
		p.SubIDAvail = v
	case PropSharedAvailable:
		p.SharedAvail = v
	}
}

func (p *Properties) setStringValue(id byte, v string) {
	switch id {
	case PropContentType:
		p.ContentType = v
	case PropResponseTopic:
		p.ResponseTopic = v
	case PropAssignedClientID:
		p.AssignedClientID = v
	case PropAuthMethod:
		p.AuthMethod = v
	case PropResponseInfo:
		p.ResponseInfo = v
	case PropServerReference:
		p.ServerReference = v
	case PropReasonString:
		p.ReasonString = v
	}
}

// byteBool lists the properties that carry a 0/1 flag, per the spec's rule that
// a Byte property with a reserved value is an error.
func byteBool(id byte) bool {
	switch id {
	case PropRequestProblemInfo, PropRequestResponse, PropRetainAvailable,
		PropWildcardAvailable, PropSubIDAvailable, PropSharedAvailable:
		return true
	}
	return false
}

func ctxName(ctx Type) string {
	if ctx == ctxWill {
		return "Will Properties"
	}
	return Type(ctx).String()
}

// maxVBI is the largest value a Variable Byte Integer can hold.
const maxVBI = 268435455

// vbi reads a 1-4 byte "variable quantity" integer.
func (d *decoder) vbi() int {
	var (
		value      int
		multiplier = 1
	)
	for i := 0; i < 4; i++ {
		b := d.byte()
		if d.err != nil {
			return 0
		}
		value += int(b&0x7F) * multiplier
		if b&0x80 == 0 {
			if value > maxVBI {
				d.fail("variable byte integer is larger than 256MB-1")
				return 0
			}
			return value
		}
		if i == 3 {
			d.fail("variable byte integer longer than 4 bytes")
			return 0
		}
		multiplier *= 128
	}
	return value
}

func (d *decoder) u32() uint32 {
	hi := d.u16()
	lo := d.u16()
	return uint32(hi)<<16 | uint32(lo)
}

func (e *encoder) u32(v uint32) {
	e.u16(uint16(v >> 16))
	e.u16(uint16(v))
}

func (e *encoder) vbi(n int) {
	if e.err != nil {
		return
	}
	if n < 0 || n > maxVBI {
		e.fail("%w: value %d does not fit in a variable byte integer", ErrMalformed, n)
		return
	}
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		e.byte(b)
		if n == 0 {
			return
		}
	}
}
