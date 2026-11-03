// Package packets implements the MQTT 3.1.1 and 5.0 wire format: packet
// structs, encoding and strict decoding. It touches no sockets, so the codec can
// be exercised byte-by-byte in tests and fuzzing.
package packets

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// Type is the 4-bit packet type in the fixed header.
type Type byte

const (
	TypeConnect Type = iota + 1
	TypeConnack
	TypePublish
	TypePuback
	TypePubrec
	TypePubrel
	TypePubcomp
	TypeSubscribe
	TypeSuback
	TypeUnsubscribe
	TypeUnsuback
	TypePingreq
	TypePingresp
	TypeDisconnect
	TypeAuth
)

var typeNames = map[Type]string{
	TypeConnect:     "CONNECT",
	TypeConnack:     "CONNACK",
	TypePublish:     "PUBLISH",
	TypePuback:      "PUBACK",
	TypePubrec:      "PUBREC",
	TypePubrel:      "PUBREL",
	TypePubcomp:     "PUBCOMP",
	TypeSubscribe:   "SUBSCRIBE",
	TypeSuback:      "SUBACK",
	TypeUnsubscribe: "UNSUBSCRIBE",
	TypeUnsuback:    "UNSUBACK",
	TypePingreq:     "PINGREQ",
	TypePingresp:    "PINGRESP",
	TypeDisconnect:  "DISCONNECT",
	TypeAuth:        "AUTH",
}

func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(%d)", int(t))
}

// ProtocolLevel is the level byte for MQTT 3.1.1. It is kept for callers that
// only speak 3.1.1; new code uses a Version.
const ProtocolLevel byte = 4

// ProtocolName is the name field every compliant client sends.
const ProtocolName = "MQTT"

// Version is a negotiated protocol level. The broker serves both: a CONNECT
// picks the version and the rest of the connection is encoded with it.
type Version byte

const (
	V311 Version = 4
	V5   Version = 5
)

func (v Version) String() string {
	switch v {
	case V311:
		return "3.1.1"
	case V5:
		return "5.0"
	}
	return fmt.Sprintf("unknown(%d)", int(v))
}

// Is5 reports the one difference that matters to most call sites: whether the
// packet carries a property area.
func (v Version) Is5() bool { return v == V5 }

// Quality of service levels.
const (
	QoS0 byte = 0
	QoS1 byte = 1
	QoS2 byte = 2
)

// CONNACK return codes, section 3.2.2.3.
const (
	ConnAccepted       byte = 0x00
	ConnBadProtocol    byte = 0x01
	ConnIDRejected     byte = 0x02
	ConnUnavailable    byte = 0x03
	ConnBadCredentials byte = 0x04
	ConnNotAuthorized  byte = 0x05
)

// SubAckFailure is the SUBACK return code meaning "subscription failed".
const SubAckFailure byte = 0x80

// MaxRemainingLength is 256MB-1, the largest value the 4-byte length field
// can encode.
const MaxRemainingLength = 268435455

// ErrMalformed reports a byte stream that is not a valid MQTT packet. The
// broker must close the connection when it sees one, per section 4.8.
var ErrMalformed = errors.New("malformed packet")

// ErrProtocol reports a packet that parses cleanly but breaks a rule the
// specification labels a Protocol Error - a duplicated property, a Receive
// Maximum of 0, a reserved flag value. MQTT 5.0 distinguishes it from a
// malformed stream because the two carry different reason codes.
var ErrProtocol = errors.New("protocol violation")

// ErrFrameTooLarge reports a frame whose declared length is more than the
// receiver is willing to hold. It is raised on the length field alone, before
// the body is read, so it costs the receiver nothing; it is deliberately not a
// Protocol Error, because the packet may be perfectly well formed and simply
// exceed a limit this broker chose to publish.
var ErrFrameTooLarge = errors.New("packet too large")

// ErrTopicAlias reports an unusable Topic Alias value. It is a Protocol Error
// and wraps it, so a caller that only tells malformed streams from protocol
// errors is unaffected; a caller that answers with a reason code uses the more
// precise 0x94 this case names [MQTT-3.3.2.1-1].
var ErrTopicAlias = fmt.Errorf("%w: topic alias invalid", ErrProtocol)

// Packet is implemented by every concrete packet in this package. The write
// hooks are unexported so that no other package can invent a packet type.
type Packet interface {
	Type() Type
	packetFlags() byte
	writeBody(e *encoder)
}

func (p *Connect) Type() Type     { return TypeConnect }
func (p *Connack) Type() Type     { return TypeConnack }
func (p *Publish) Type() Type     { return TypePublish }
func (p *Puback) Type() Type      { return TypePuback }
func (p *Pubrec) Type() Type      { return TypePubrec }
func (p *Pubrel) Type() Type      { return TypePubrel }
func (p *Pubcomp) Type() Type     { return TypePubcomp }
func (p *Subscribe) Type() Type   { return TypeSubscribe }
func (p *Suback) Type() Type      { return TypeSuback }
func (p *Unsubscribe) Type() Type { return TypeUnsubscribe }
func (p *Unsuback) Type() Type    { return TypeUnsuback }
func (p *Pingreq) Type() Type     { return TypePingreq }
func (p *Pingresp) Type() Type    { return TypePingresp }
func (p *Disconnect) Type() Type  { return TypeDisconnect }
func (p *Auth) Type() Type        { return TypeAuth }

// Connect is the first packet of a session.
type Connect struct {
	ProtocolName  string
	ProtocolLevel byte
	// CleanSession is the 3.1.1 name for the same flag bit; 5.0 calls it Clean
	// Start and pairs it with a Session Expiry Interval.
	CleanSession bool
	KeepAlive    uint16
	ClientID     string

	HasWill     bool
	WillTopic   string
	WillQoS     byte
	WillRetain  bool
	WillPayload []byte
	// WillProps is the 5.0 Will Properties block, which sits in the payload
	// between the client identifier and the will topic.
	WillProps *Properties

	HasUsername bool
	Username    string
	HasPassword bool
	Password    []byte

	Props *Properties
}

// Connack answers a Connect. 3.1.1 puts its verdict in ReturnCode, 5.0 in
// ReasonCode; both keep Session Present in the acknowledge flags.
type Connack struct {
	SessionPresent bool
	ReturnCode     byte
	ReasonCode     byte
	Props          *Properties
}

// Publish carries an application message.
type Publish struct {
	Topic    string
	PacketID uint16
	QoS      byte
	Retain   bool
	Dup      bool
	Props    *Properties
	Payload  []byte
}

// HasID reports whether the packet type uses a packet identifier.
func (p *Publish) HasID() bool { return p.QoS > QoS0 }

// Puback, Pubrec, Pubrel and Pubcomp are the acknowledgement packets; they
// differ only by type and reserved flags. Their reason code and property area
// belong to 5.0 and are omitted entirely when both are empty.
type (
	Puback struct {
		PacketID   uint16
		ReasonCode byte
		Props      *Properties
	}
	Pubrec struct {
		PacketID   uint16
		ReasonCode byte
		Props      *Properties
	}
	Pubrel struct {
		PacketID   uint16
		ReasonCode byte
		Props      *Properties
	}
	Pubcomp struct {
		PacketID   uint16
		ReasonCode byte
		Props      *Properties
	}
)

// Subscription is one topic filter and its options. Everything beyond MaxQoS
// is 5.0 only.
type Subscription struct {
	TopicFilter string
	MaxQoS      byte

	NoLocal           bool
	RetainAsPublished bool
	// RetainHandling selects what happens to retained messages when the
	// subscription is made: 0 sends them, 1 sends them only if the
	// subscription is new, 2 sends nothing.
	RetainHandling byte
}

// Subscribe requests one or more subscriptions.
type Subscribe struct {
	PacketID      uint16
	Subscriptions []Subscription
	Props         *Properties
}

// Suback grants or refuses each requested filter, in order. 3.1.1 return codes
// and 5.0 reason codes share this field.
type Suback struct {
	PacketID    uint16
	ReturnCodes []byte
	Props       *Properties
}

// Unsubscribe drops the listed filters.
type Unsubscribe struct {
	PacketID     uint16
	TopicFilters []string
	Props        *Properties
}

// Unsuback confirms an Unsubscribe. 3.1.1 sends an empty packet; 5.0 answers
// each filter with a reason code.
type Unsuback struct {
	PacketID    uint16
	ReasonCodes []byte
	Props       *Properties
}

// Pingreq and Pingresp keep the connection alive.
type (
	Pingreq  struct{}
	Pingresp struct{}
)

// Disconnect is a clean, deliberate close by the client. 5.0 can carry a reason
// code, a replacement Session Expiry Interval and a Server Reference.
type Disconnect struct {
	ReasonCode byte
	Props      *Properties
}

// Auth is the 5.0 extended authentication packet, and the only packet that may
// be exchanged on either side of the CONNACK.
type Auth struct {
	ReasonCode byte
	Props      *Properties
}

func validQoS(q byte) bool { return q <= QoS2 }

func checkUTF8(s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: field is not valid UTF-8", ErrMalformed)
	}
	return nil
}
