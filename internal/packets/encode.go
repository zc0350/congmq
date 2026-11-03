package packets

import (
	"bytes"
	"fmt"
	"io"
)

// encoder accumulates a variable header plus payload into one buffer. It
// records the first error so the write methods stay readable.
type encoder struct {
	buf *bytes.Buffer
	err error
	ver Version
}

func (e *encoder) fail(format string, args ...any) {
	if e.err == nil {
		e.err = fmt.Errorf(format, args...)
	}
}

func (e *encoder) is5() bool { return e.ver.Is5() }

func (e *encoder) byte(b byte) {
	if e.err != nil {
		return
	}
	e.buf.WriteByte(b)
}

func (e *encoder) u16(v uint16) {
	e.byte(byte(v >> 8))
	e.byte(byte(v))
}

func (e *encoder) str(s string) {
	if len(s) > 0xFFFF {
		e.fail("%w: field longer than 65535 bytes: %q", ErrMalformed, trunc(s))
		return
	}
	if !utf8OK(s) {
		e.fail("%w: field is not valid UTF-8", ErrMalformed)
		return
	}
	e.u16(uint16(len(s)))
	e.buf.WriteString(s)
}

func (e *encoder) raw(b []byte) {
	if e.err != nil {
		return
	}
	e.buf.Write(b)
}

// bin writes a 2-byte length prefixed opaque block.
func (e *encoder) bin(b []byte) {
	if len(b) > 0xFFFF {
		e.fail("%w: binary field longer than 65535 bytes", ErrMalformed)
		return
	}
	e.u16(uint16(len(b)))
	e.buf.Write(b)
}

func utf8OK(s string) bool { return checkUTF8(s) == nil }

func trunc(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}

// Encode writes p using the version the packet itself implies: a CONNECT names
// its level, anything else is written as 3.1.1. A broker that negotiated 5.0
// uses EncodeVersion for every packet after CONNECT.
func Encode(w io.Writer, p Packet) error {
	return EncodeVersion(w, versionOf(p), p)
}

// EncodeVersion writes p with the field layout of the negotiated version.
func EncodeVersion(w io.Writer, ver Version, p Packet) error {
	body := &bytes.Buffer{}
	e := &encoder{buf: body, ver: ver}
	p.writeBody(e)
	if e.err != nil {
		return e.err
	}
	head := make([]byte, 0, 5)
	head = append(head, byte(p.Type())<<4|p.packetFlags())
	head = AppendRemainingLength(head, body.Len())
	if _, err := w.Write(head); err != nil {
		return err
	}
	_, err := w.Write(body.Bytes())
	return err
}

func versionOf(p Packet) Version {
	if c, ok := p.(*Connect); ok && c.ProtocolLevel == byte(V5) {
		return V5
	}
	return V311
}

// EncodeBytes is Encode against a fresh byte slice, used by tests and by the
// broker's per-connection writer.
func EncodeBytes(p Packet) ([]byte, error) {
	return EncodeBytesVersion(versionOf(p), p)
}

// EncodeBytesVersion is EncodeVersion against a fresh byte slice.
func EncodeBytesVersion(ver Version, p Packet) ([]byte, error) {
	var buf bytes.Buffer
	if err := EncodeVersion(&buf, ver, p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// AppendRemainingLength encodes the 1-4 byte "variable quantity" integer.
func AppendRemainingLength(dst []byte, n int) []byte {
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		dst = append(dst, b)
		if n == 0 {
			return dst
		}
	}
}

func (p *Connect) packetFlags() byte    { return 0 }
func (p *Connack) packetFlags() byte    { return 0 }
func (p *Puback) packetFlags() byte     { return 0 }
func (p *Pubrec) packetFlags() byte     { return 0 }
func (p *Pubcomp) packetFlags() byte    { return 0 }
func (p *Suback) packetFlags() byte     { return 0 }
func (p *Unsuback) packetFlags() byte   { return 0 }
func (p *Pingreq) packetFlags() byte    { return 0 }
func (p *Pingresp) packetFlags() byte   { return 0 }
func (p *Disconnect) packetFlags() byte { return 0 }
func (p *Auth) packetFlags() byte       { return 0 }

// PUBREL and the two request packets carry the reserved "2" flag; it is not
// optional, and a peer that omits it is non-compliant.
func (p *Publish) packetFlags() byte {
	f := p.QoS << 1
	if p.Dup {
		f |= 0x08
	}
	if p.Retain {
		f |= 0x01
	}
	return f
}

func (p *Pubrel) packetFlags() byte      { return 0x02 }
func (p *Subscribe) packetFlags() byte   { return 0x02 }
func (p *Unsubscribe) packetFlags() byte { return 0x02 }

// writeReason emits a reason code, refusing one that the packet type may not
// carry. A strict client treats an invalid code as a protocol error, so it is
// better caught here than on the wire.
func writeReason(e *encoder, t Type, code byte) {
	if !ReasonAllowed(code, t) {
		e.fail("%w: reason code %#02x is not valid in %s", ErrMalformed, code, t)
		return
	}
	e.byte(code)
}

// writeAckTail writes the reason code and property area of an acknowledgement.
// Success with nothing to say is left out entirely: the receiver then reads
// reason code 0x00 from a two byte body.
func writeAckTail(e *encoder, t Type, code byte, props *Properties) {
	if !e.is5() {
		return
	}
	if code == RSuccess && props.IsEmpty() {
		return
	}
	writeReason(e, t, code)
	writeProperties(e, t, props)
}

func (p *Connect) writeBody(e *encoder) {
	level := p.ProtocolLevel
	if level == 0 {
		level = ProtocolLevel
		if e.is5() {
			level = byte(V5)
		}
	}
	// The packet's own level byte wins, so a hand-built 5.0 CONNECT cannot be
	// written with the 3.1.1 layout.
	e.ver = Version(level)

	e.str(p.ProtocolName)
	e.byte(level)
	var flags byte
	if p.CleanSession {
		flags |= 0x02
	}
	if p.HasWill {
		flags |= 0x04
		q := p.WillQoS
		if !validQoS(q) {
			e.fail("%w: will QoS %d out of range", ErrMalformed, q)
			return
		}
		flags |= (q & 0x03) << 3
		if p.WillRetain {
			flags |= 0x20
		}
	}
	if p.HasPassword {
		// Section 3.1.2.1: bit 6 is the password, bit 0 is reserved and must be
		// zero. Conflating them is invisible to a broker that only talks to
		// itself, and fatal against any other client.
		flags |= 0x40
	}
	if p.HasUsername {
		flags |= 0x80
	}
	e.byte(flags)
	e.u16(p.KeepAlive)
	if e.is5() {
		writeProperties(e, TypeConnect, p.Props)
	}

	e.str(p.ClientID)
	if p.HasWill {
		if e.is5() {
			writeProperties(e, ctxWill, p.WillProps)
		}
		e.str(p.WillTopic)
		e.bin(p.WillPayload)
	}
	if p.HasUsername {
		e.str(p.Username)
	}
	if p.HasPassword {
		e.bin(p.Password)
	}
}

// v5Reason maps a 3.1.1 CONNACK return code onto the 5.0 reason code the spec
// pairs with it, so callers that still speak 3.1.1 codes emit a valid 5.0
// CONNACK.
func v5Reason(rc byte) byte {
	switch rc {
	case ConnAccepted:
		return RSuccess
	case ConnBadProtocol:
		return RUnsupportedProtocolVersion
	case ConnIDRejected:
		return RClientIdentifierNotValid
	case ConnUnavailable:
		return RServerUnavailable
	case ConnBadCredentials:
		return RBadUsernameOrPassword
	case ConnNotAuthorized:
		return RNotAuthorized
	}
	return rc
}

func (p *Connack) writeBody(e *encoder) {
	var b byte
	if p.SessionPresent {
		b = 0x01
	}
	e.byte(b)
	if !e.is5() {
		e.byte(p.ReturnCode)
		return
	}
	code := p.ReasonCode
	if code == 0 {
		code = v5Reason(p.ReturnCode)
	}
	writeReason(e, TypeConnack, code)
	writeProperties(e, TypeConnack, p.Props)
}

func (p *Publish) writeBody(e *encoder) {
	if !validQoS(p.QoS) {
		e.fail("%w: QoS %d out of range", ErrMalformed, p.QoS)
		return
	}
	if p.QoS == QoS0 && p.Dup {
		e.fail("%w: DUP flag set on a QoS 0 packet", ErrMalformed)
		return
	}
	e.str(p.Topic)
	if p.QoS > QoS0 {
		if p.PacketID == 0 {
			e.fail("%w: QoS %d packet without an identifier", ErrMalformed, p.QoS)
			return
		}
		e.u16(p.PacketID)
	}
	if e.is5() {
		writeProperties(e, TypePublish, p.Props)
	}
	e.raw(p.Payload)
}

func writeID(e *encoder, id uint16) {
	if id == 0 {
		e.fail("%w: packet identifier 0 is reserved", ErrMalformed)
		return
	}
	e.u16(id)
}

func (p *Puback) writeBody(e *encoder) {
	writeID(e, p.PacketID)
	writeAckTail(e, TypePuback, p.ReasonCode, p.Props)
}

func (p *Pubrec) writeBody(e *encoder) {
	writeID(e, p.PacketID)
	writeAckTail(e, TypePubrec, p.ReasonCode, p.Props)
}

func (p *Pubrel) writeBody(e *encoder) {
	writeID(e, p.PacketID)
	writeAckTail(e, TypePubrel, p.ReasonCode, p.Props)
}

func (p *Pubcomp) writeBody(e *encoder) {
	writeID(e, p.PacketID)
	writeAckTail(e, TypePubcomp, p.ReasonCode, p.Props)
}

func (p *Subscribe) writeBody(e *encoder) {
	writeID(e, p.PacketID)
	if e.is5() {
		writeProperties(e, TypeSubscribe, p.Props)
	}
	if len(p.Subscriptions) == 0 {
		e.fail("%w: SUBSCRIBE with no topic filters", ErrMalformed)
		return
	}
	for _, s := range p.Subscriptions {
		e.str(s.TopicFilter)
		if !validQoS(s.MaxQoS) {
			e.fail("%w: subscription QoS %d out of range", ErrMalformed, s.MaxQoS)
			return
		}
		opt := s.MaxQoS & 0x03
		if e.is5() {
			if s.RetainHandling > 2 {
				e.fail("%w: Retain Handling %d is reserved", ErrMalformed, s.RetainHandling)
				return
			}
			if s.NoLocal {
				opt |= 0x04
			}
			if s.RetainAsPublished {
				opt |= 0x08
			}
			opt |= (s.RetainHandling & 0x03) << 4
		}
		e.byte(opt)
	}
}

func (p *Suback) writeBody(e *encoder) {
	writeID(e, p.PacketID)
	if e.is5() {
		writeProperties(e, TypeSuback, p.Props)
	}
	for _, c := range p.ReturnCodes {
		writeReason(e, TypeSuback, c)
	}
}

func (p *Unsubscribe) writeBody(e *encoder) {
	writeID(e, p.PacketID)
	if e.is5() {
		writeProperties(e, TypeUnsubscribe, p.Props)
	}
	for _, f := range p.TopicFilters {
		e.str(f)
	}
}

func (p *Unsuback) writeBody(e *encoder) {
	writeID(e, p.PacketID)
	if !e.is5() {
		return
	}
	writeProperties(e, TypeUnsuback, p.Props)
	for _, c := range p.ReasonCodes {
		writeReason(e, TypeUnsuback, c)
	}
}

func (*Pingreq) writeBody(*encoder)  {}
func (*Pingresp) writeBody(*encoder) {}

func (p *Disconnect) writeBody(e *encoder) {
	if !e.is5() {
		return
	}
	// A zero length body means "Normal disconnection"; only deviate from it
	// when there is something to say.
	if p.ReasonCode == RNormalDisconnection && p.Props.IsEmpty() {
		return
	}
	writeReason(e, TypeDisconnect, p.ReasonCode)
	writeProperties(e, TypeDisconnect, p.Props)
}

func (p *Auth) writeBody(e *encoder) {
	writeReason(e, TypeAuth, p.ReasonCode)
	writeProperties(e, TypeAuth, p.Props)
}
