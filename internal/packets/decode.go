package packets

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// shareFilterPrefix marks a 5.0 shared subscription filter, $share/{group}/{filter}.
const shareFilterPrefix = "$share/"

// decoder walks one already-buffered packet body. Every read bounds-checks
// itself and latches the first error.
type decoder struct {
	buf   []byte
	pos   int
	err   error
	debug Type
	ver   Version
}

func (d *decoder) fail(format string, args ...any) {
	if d.err == nil {
		d.err = fmt.Errorf("%w (%s): "+format, append([]any{ErrMalformed, d.debug}, args...)...)
	}
}

// pfail latches a Protocol Error: the bytes parsed cleanly but break a rule the
// 5.0 spec names explicitly. It is a different failure from a malformed stream
// because the peer is told 0x82 rather than 0x81.
func (d *decoder) pfail(format string, args ...any) {
	if d.err == nil {
		d.err = fmt.Errorf("%w (%s): "+format, append([]any{ErrProtocol, d.debug}, args...)...)
	}
}

// pfailAs latches a Protocol Error that the specification gives its own reason
// code, so the broker can be as precise in its DISCONNECT as the rule it is
// enforcing. The sentinel must wrap ErrProtocol.
func (d *decoder) pfailAs(as error, format string, args ...any) {
	if d.err == nil {
		d.err = fmt.Errorf("%w (%s): "+format, append([]any{as, d.debug}, args...)...)
	}
}

// specErr reports a field value that 3.1.1 calls "reserved" and 5.0 calls a
// Protocol Error, so both versions get the diagnosis their own text promises.
func (d *decoder) specErr(format string, args ...any) {
	if d.is5() {
		d.pfail(format, args...)
		return
	}
	d.fail(format, args...)
}

func (d *decoder) is5() bool { return d.ver.Is5() }

func (d *decoder) need(n int) bool {
	if d.err != nil {
		return false
	}
	if d.pos+n > len(d.buf) {
		d.fail("truncated: want %d bytes at offset %d, body is %d", n, d.pos, len(d.buf))
		return false
	}
	return true
}

func (d *decoder) byte() byte {
	if !d.need(1) {
		return 0
	}
	b := d.buf[d.pos]
	d.pos++
	return b
}

func (d *decoder) u16() uint16 {
	if !d.need(2) {
		return 0
	}
	v := uint16(d.buf[d.pos])<<8 | uint16(d.buf[d.pos+1])
	d.pos += 2
	return v
}

func (d *decoder) str() string {
	n := int(d.u16())
	if d.err != nil {
		return ""
	}
	if !d.need(n) {
		return ""
	}
	s := string(d.buf[d.pos : d.pos+n])
	d.pos += n
	if err := checkUTF8(s); err != nil {
		d.err = err
		return ""
	}
	return s
}

// binary reads a 2-byte length prefixed block. MQTT 3.1.1 describes the will
// message and password as opaque data; every deployed client prefixes them,
// so we decode them that way.
func (d *decoder) binary() []byte {
	n := int(d.u16())
	if d.err != nil {
		return nil
	}
	if !d.need(n) {
		return nil
	}
	b := make([]byte, n)
	copy(b, d.buf[d.pos:d.pos+n])
	d.pos += n
	return b
}

func (d *decoder) rest() []byte {
	if d.err != nil {
		return nil
	}
	b := make([]byte, len(d.buf)-d.pos)
	copy(b, d.buf[d.pos:])
	d.pos = len(d.buf)
	return b
}

func (d *decoder) done() {
	if d.err != nil {
		return
	}
	if d.pos != len(d.buf) {
		d.fail("%d trailing byte(s) after the last field", len(d.buf)-d.pos)
	}
}

// Decode reads the next packet assuming MQTT 3.1.1. A CONNECT is the exception:
// it names its own version, so a 5.0 CONNECT passed to Decode is still parsed
// completely. The caller reads ProtocolLevel off the result and uses
// DecodeVersion for the rest of that connection.
func Decode(r *bufio.Reader) (Packet, error) {
	return DecodeVersion(r, V311)
}

// DecodeVersion reads the next packet decoded with the negotiated version. The
// broker calls it with the version it settled on in CONNECT.
func DecodeVersion(r *bufio.Reader, ver Version) (Packet, error) {
	p, _, err := DecodeFrame(r, ver)
	return p, err
}

// DecodeFrame is DecodeVersion plus the size of the packet it read, header
// included, so a caller can apply its own Maximum Packet Size without counting
// bytes off a buffered reader.
func DecodeFrame(r *bufio.Reader, ver Version) (Packet, int, error) {
	return DecodeFrameLimited(r, ver, 0)
}

// DecodeFrameLimited refuses to allocate a body larger than limit bytes, header
// included; limit 0 leaves only the protocol's own 256MB ceiling. The check is
// made on the declared length, before the body is read, which is the difference
// between a limit and a promise: a peer that announces 256MB would otherwise
// have already cost the receiver 256MB by the time the policy was consulted.
func DecodeFrameLimited(r *bufio.Reader, ver Version, limit int) (Packet, int, error) {
	first, err := r.ReadByte()
	if err != nil {
		return nil, 0, err
	}
	size := 1
	t := Type(first >> 4)
	flags := first & 0x0F
	if t < TypeConnect || t > TypeAuth {
		return nil, 0, fmt.Errorf("%w: packet type %d is reserved", ErrMalformed, t)
	}
	if t == TypeAuth && !ver.Is5() {
		return nil, 0, fmt.Errorf("%w: AUTH is not a 3.1.1 packet type", ErrMalformed)
	}
	if err := checkFlags(t, flags); err != nil {
		return nil, 0, err
	}
	n, lenBytes, err := readRemainingLength(r)
	if err != nil {
		return nil, 0, err
	}
	size += lenBytes
	if limit > 0 && size+n > limit {
		return nil, size, fmt.Errorf("%w: %d byte body with a %d byte header exceeds a %d byte limit",
			ErrFrameTooLarge, n, size, limit)
	}
	size += n
	body := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			if err == io.ErrUnexpectedEOF {
				return nil, size, fmt.Errorf("%w: short body, expected %d bytes", ErrMalformed, n)
			}
			return nil, size, err
		}
	}
	d := &decoder{buf: body, debug: t, ver: ver}
	p, err := decodeBody(t, flags, d)
	if err != nil {
		return nil, size, err
	}
	d.done()
	if d.err != nil {
		return nil, size, d.err
	}
	return p, size, nil
}

func readRemainingLength(r *bufio.Reader) (value, size int, err error) {
	var multiplier = 1
	for i := 0; i < 4; i++ {
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF && i == 0 {
				return 0, 0, io.EOF
			}
			return 0, 0, fmt.Errorf("%w: reading remaining length", ErrMalformed)
		}
		size++
		value += int(b&0x7F) * multiplier
		if b&0x80 == 0 {
			if value > MaxRemainingLength {
				return 0, size, fmt.Errorf("%w: remaining length %d exceeds the maximum", ErrMalformed, value)
			}
			return value, size, nil
		}
		multiplier *= 128
	}
	return 0, size, fmt.Errorf("%w: remaining length longer than 4 bytes", ErrMalformed)
}

func checkFlags(t Type, flags byte) error {
	switch t {
	case TypePublish:
		if q := (flags >> 1) & 0x03; q > QoS2 {
			return fmt.Errorf("%w: PUBLISH QoS %d is reserved", ErrMalformed, q)
		}
		return nil
	case TypePubrel, TypeSubscribe, TypeUnsubscribe:
		if flags != 0x02 {
			return fmt.Errorf("%w: %s flags must be 0x02, got 0x%02x", ErrMalformed, t, flags)
		}
		return nil
	default:
		if flags != 0x00 {
			return fmt.Errorf("%w: %s flags must be zero, got 0x%02x", ErrMalformed, t, flags)
		}
		return nil
	}
}

func decodeBody(t Type, flags byte, d *decoder) (Packet, error) {
	switch t {
	case TypeConnect:
		return decodeConnect(d)
	case TypeConnack:
		return decodeConnack(d)
	case TypePublish:
		return decodePublish(flags, d)
	case TypePuback:
		id, rc, props := readAck(d, t)
		return &Puback{PacketID: id, ReasonCode: rc, Props: props}, nil
	case TypePubrec:
		id, rc, props := readAck(d, t)
		return &Pubrec{PacketID: id, ReasonCode: rc, Props: props}, nil
	case TypePubrel:
		id, rc, props := readAck(d, t)
		return &Pubrel{PacketID: id, ReasonCode: rc, Props: props}, nil
	case TypePubcomp:
		id, rc, props := readAck(d, t)
		return &Pubcomp{PacketID: id, ReasonCode: rc, Props: props}, nil
	case TypeSubscribe:
		return decodeSubscribe(d)
	case TypeSuback:
		return decodeSuback(d)
	case TypeUnsubscribe:
		return decodeUnsubscribe(d)
	case TypeUnsuback:
		return decodeUnsuback(d)
	case TypePingreq:
		return &Pingreq{}, nil
	case TypePingresp:
		return &Pingresp{}, nil
	case TypeDisconnect:
		return decodeDisconnect(d)
	case TypeAuth:
		return decodeAuth(d)
	}
	return nil, fmt.Errorf("%w: unhandled packet type %d", ErrMalformed, t)
}

func decodeConnect(d *decoder) (Packet, error) {
	p := &Connect{}
	p.ProtocolName = d.str()
	p.ProtocolLevel = d.byte()
	// The CONNECT header names its own version; everything after this byte is
	// laid out differently in 5.0.
	d.ver = Version(p.ProtocolLevel)
	// CONNECT flags live in the variable header, not the fixed header.
	flags := d.byte()
	p.KeepAlive = d.u16()
	if d.is5() {
		p.Props = d.readProperties(TypeConnect)
	}
	p.CleanSession = flags&0x02 != 0
	p.ClientID = d.str()

	hasWill := flags&0x04 != 0
	hasPassword := flags&0x40 != 0
	hasUsername := flags&0x80 != 0
	if flags&0x01 != 0 {
		// Bit 0 of the CONNECT flags is reserved and must be zero.
		d.fail("reserved connect flag is set (%#02x)", flags)
	}
	if hasWill {
		p.HasWill = true
		p.WillQoS = (flags >> 3) & 0x03
		p.WillRetain = flags&0x20 != 0
		if d.is5() {
			p.WillProps = d.readProperties(ctxWill)
		}
		p.WillTopic = d.str()
		p.WillPayload = d.binary()
		if !validQoS(p.WillQoS) {
			d.specErr("will QoS %d is reserved", p.WillQoS)
		}
	}
	if hasUsername {
		p.HasUsername = true
		p.Username = d.str()
	}
	if hasPassword {
		p.HasPassword = true
		p.Password = d.binary()
	}
	return p, nil
}

func decodeConnack(d *decoder) (Packet, error) {
	b := d.byte()
	p := &Connack{SessionPresent: b&0x01 != 0}
	p.ReturnCode = d.byte()
	if d.is5() {
		p.ReasonCode = p.ReturnCode
		if !ReasonAllowed(p.ReasonCode, TypeConnack) {
			d.pfail("CONNACK: reason code %#02x is not valid", p.ReasonCode)
			return p, nil
		}
		p.Props = d.readProperties(TypeConnack)
	}
	return p, nil
}

func decodePublish(flags byte, d *decoder) (Packet, error) {
	p := &Publish{
		Dup:    flags&0x08 != 0,
		QoS:    (flags >> 1) & 0x03,
		Retain: flags&0x01 != 0,
	}
	p.Topic = d.str()
	if p.QoS > QoS0 {
		p.PacketID = readID(d)
	}
	if d.is5() {
		p.Props = d.readProperties(TypePublish)
		if p.Topic == "" && !p.Props.Has(PropTopicAlias) {
			d.pfail("zero length Topic Name with no Topic Alias")
		}
	}
	p.Payload = d.rest()
	if p.QoS == QoS0 && p.Dup {
		d.specErr("DUP flag set on a QoS 0 packet")
	}
	return p, nil
}

// readAck reads the variable header of PUBACK, PUBREC, PUBREL and PUBCOMP. In
// 5.0 a body of exactly two bytes means reason code 0x00 and no properties;
// sections 3.4.2.1 to 3.7.2.1 all say so.
func readAck(d *decoder, t Type) (uint16, byte, *Properties) {
	id := readID(d)
	if !d.is5() {
		return id, 0, nil
	}
	if d.pos >= len(d.buf) {
		return id, RSuccess, nil
	}
	rc := d.byte()
	if !ReasonAllowed(rc, t) {
		d.pfail("%s: reason code %#02x is not valid", t, rc)
		return id, rc, nil
	}
	return id, rc, d.readProperties(t)
}

func readID(d *decoder) uint16 {
	id := d.u16()
	if id == 0 {
		d.fail("packet identifier 0 is reserved")
	}
	return id
}

func decodeSubscribe(d *decoder) (Packet, error) {
	p := &Subscribe{PacketID: readID(d)}
	if d.is5() {
		p.Props = d.readProperties(TypeSubscribe)
	}
	for d.err == nil && d.pos < len(d.buf) {
		filter := d.str()
		opt := d.byte()
		s := Subscription{TopicFilter: filter, MaxQoS: opt & 0x03}
		if d.is5() {
			s.NoLocal = opt&0x04 != 0
			s.RetainAsPublished = opt&0x08 != 0
			s.RetainHandling = (opt >> 4) & 0x03
			if opt&0xC0 != 0 {
				d.fail("subscription options byte has reserved bits set (%#02x)", opt)
				break
			}
			if s.RetainHandling == 3 {
				d.pfail("Retain Handling value 3 is reserved")
				break
			}
			if s.NoLocal && strings.HasPrefix(filter, shareFilterPrefix) {
				d.pfail("No Local is not allowed on a shared subscription")
				break
			}
		}
		if !validQoS(s.MaxQoS) {
			d.specErr("subscription QoS %d is reserved", s.MaxQoS)
			break
		}
		p.Subscriptions = append(p.Subscriptions, s)
	}
	if len(p.Subscriptions) == 0 && d.err == nil {
		if d.is5() {
			d.pfail("SUBSCRIBE with no topic filters")
		} else {
			d.fail("SUBSCRIBE with no topic filters")
		}
	}
	return p, nil
}

func decodeSuback(d *decoder) (Packet, error) {
	p := &Suback{PacketID: readID(d)}
	if d.is5() {
		p.Props = d.readProperties(TypeSuback)
	}
	p.ReturnCodes = d.rest()
	if !d.is5() {
		return p, nil
	}
	for _, c := range p.ReturnCodes {
		if !ReasonAllowed(c, TypeSuback) {
			d.pfail("SUBACK: reason code %#02x is not valid", c)
			break
		}
	}
	return p, nil
}

func decodeUnsubscribe(d *decoder) (Packet, error) {
	p := &Unsubscribe{PacketID: readID(d)}
	if d.is5() {
		p.Props = d.readProperties(TypeUnsubscribe)
	}
	for d.err == nil && d.pos < len(d.buf) {
		p.TopicFilters = append(p.TopicFilters, d.str())
	}
	if len(p.TopicFilters) == 0 && d.err == nil {
		if d.is5() {
			d.pfail("UNSUBSCRIBE with no topic filters")
		} else {
			d.fail("UNSUBSCRIBE with no topic filters")
		}
	}
	return p, nil
}

func decodeUnsuback(d *decoder) (Packet, error) {
	p := &Unsuback{PacketID: readID(d)}
	if !d.is5() {
		return p, nil
	}
	p.Props = d.readProperties(TypeUnsuback)
	p.ReasonCodes = d.rest()
	for _, c := range p.ReasonCodes {
		if !ReasonAllowed(c, TypeUnsuback) {
			d.pfail("UNSUBACK: reason code %#02x is not valid", c)
			break
		}
	}
	return p, nil
}

func decodeDisconnect(d *decoder) (Packet, error) {
	p := &Disconnect{}
	if !d.is5() || d.pos >= len(d.buf) {
		// A zero length DISCONNECT body means "Normal disconnection".
		return p, nil
	}
	p.ReasonCode = d.byte()
	if !ReasonAllowed(p.ReasonCode, TypeDisconnect) {
		d.pfail("DISCONNECT: reason code %#02x is not valid", p.ReasonCode)
		return p, nil
	}
	p.Props = d.readProperties(TypeDisconnect)
	return p, nil
}

func decodeAuth(d *decoder) (Packet, error) {
	p := &Auth{}
	p.ReasonCode = d.byte()
	if !ReasonAllowed(p.ReasonCode, TypeAuth) {
		d.pfail("AUTH: reason code %#02x is not valid", p.ReasonCode)
		return p, nil
	}
	p.Props = d.readProperties(TypeAuth)
	return p, nil
}
