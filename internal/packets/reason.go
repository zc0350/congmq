package packets

// MQTT 5.0 reason codes. Values below 0x80 mean success; 0x80 and above mean
// failure. Each code is only valid in the packet types listed in validIn.
const (
	RSuccess               byte = 0x00 // CONNACK, PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK, AUTH
	RNormalDisconnection   byte = 0x00 // DISCONNECT
	RGrantedQoS0           byte = 0x00 // SUBACK
	RGrantedQoS1           byte = 0x01
	RGrantedQoS2           byte = 0x02
	RDisconnectWithWill    byte = 0x04
	RNoMatchingSubscribers byte = 0x10
	RNoSubscriptionExisted byte = 0x11
	RContinueAuth          byte = 0x18
	RReauthAuthenticate    byte = 0x19

	RUnspecifiedError               byte = 0x80
	RMalformedPacket                byte = 0x81
	RProtocolError                  byte = 0x82
	RImplementationSpecificError    byte = 0x83
	RUnsupportedProtocolVersion     byte = 0x84
	RClientIdentifierNotValid       byte = 0x85
	RBadUsernameOrPassword          byte = 0x86
	RNotAuthorized                  byte = 0x87
	RServerUnavailable              byte = 0x88
	RServerBusy                     byte = 0x89
	RBanned                         byte = 0x8A
	RServerShuttingDown             byte = 0x8B
	RBadAuthenticationMethod        byte = 0x8C
	RKeepAliveTimeout               byte = 0x8D
	RSessionTakenOver               byte = 0x8E
	RTopicFilterInvalid             byte = 0x8F
	RTopicNameInvalid               byte = 0x90
	RPacketIdentifierInUse          byte = 0x91
	RPacketIdentifierNotFound       byte = 0x92
	RReceiveMaximumExceeded         byte = 0x93
	RTopicAliasInvalid              byte = 0x94
	RPacketTooLarge                 byte = 0x95
	RMessageRateTooHigh             byte = 0x96
	RQuotaExceeded                  byte = 0x97
	RAdministrativeAction           byte = 0x98
	RPayloadFormatInvalid           byte = 0x99
	RRetainNotSupported             byte = 0x9A
	RQoSNotSupported                byte = 0x9B
	RUseAnotherServer               byte = 0x9C
	RServerMoved                    byte = 0x9D
	RSharedSubscriptionsUnsupported byte = 0x9E
	RConnectionRateExceeded         byte = 0x9F
	RMaximumConnectTime             byte = 0xA0
	RSubIDNotSupported              byte = 0xA1
)

// reasonSpec names a code and lists the packet contexts it may appear in.
type reasonSpec struct {
	name    string
	validIn uint32
}

var reasons = map[byte]reasonSpec{
	// 0x00 is shared by "Success", "Normal disconnection" and "Granted QoS 0",
	// so its validity is the union of every packet that carries a reason code.
	RSuccess: {"Success", bit(TypeConnack) | bit(TypePuback) | bit(TypePubrec) | bit(TypePubrel) |
		bit(TypePubcomp) | bit(TypeSuback) | bit(TypeUnsuback) | bit(TypeDisconnect) | bit(TypeAuth)},
	RGrantedQoS1:                    {"Granted QoS 1", bit(TypeSuback)},
	RGrantedQoS2:                    {"Granted QoS 2", bit(TypeSuback)},
	RDisconnectWithWill:             {"Disconnect with Will Message", bit(TypeDisconnect)},
	RNoMatchingSubscribers:          {"No matching subscribers", bit(TypePuback) | bit(TypePubrec)},
	RNoSubscriptionExisted:          {"No subscription existed", bit(TypeUnsuback)},
	RContinueAuth:                   {"Continue authentication", bit(TypeAuth)},
	RReauthAuthenticate:             {"Re-authenticate", bit(TypeAuth)},
	RUnspecifiedError:               {"Unspecified error", bit(TypeConnack) | bit(TypePuback) | bit(TypePubrec) | bit(TypeSuback) | bit(TypeUnsuback) | bit(TypeDisconnect)},
	RMalformedPacket:                {"Malformed Packet", bit(TypeConnack) | bit(TypeDisconnect)},
	RProtocolError:                  {"Protocol Error", bit(TypeConnack) | bit(TypeDisconnect)},
	RImplementationSpecificError:    {"Implementation specific error", bit(TypeConnack) | bit(TypePuback) | bit(TypePubrec) | bit(TypeSuback) | bit(TypeUnsuback) | bit(TypeDisconnect)},
	RUnsupportedProtocolVersion:     {"Unsupported Protocol Version", bit(TypeConnack)},
	RClientIdentifierNotValid:       {"Client Identifier not valid", bit(TypeConnack)},
	RBadUsernameOrPassword:          {"Bad User Name or Password", bit(TypeConnack)},
	RNotAuthorized:                  {"Not authorized", bit(TypeConnack) | bit(TypePuback) | bit(TypePubrec) | bit(TypeSuback) | bit(TypeUnsuback) | bit(TypeDisconnect)},
	RServerUnavailable:              {"Server unavailable", bit(TypeConnack)},
	RServerBusy:                     {"Server busy", bit(TypeConnack) | bit(TypeDisconnect)},
	RBanned:                         {"Banned", bit(TypeConnack)},
	RServerShuttingDown:             {"Server shutting down", bit(TypeDisconnect)},
	RBadAuthenticationMethod:        {"Bad authentication method", bit(TypeConnack) | bit(TypeDisconnect)},
	RKeepAliveTimeout:               {"Keep Alive timeout", bit(TypeDisconnect)},
	RSessionTakenOver:               {"Session taken over", bit(TypeDisconnect)},
	RTopicFilterInvalid:             {"Topic Filter invalid", bit(TypeSuback) | bit(TypeUnsuback) | bit(TypeDisconnect)},
	RTopicNameInvalid:               {"Topic Name invalid", bit(TypeConnack) | bit(TypePuback) | bit(TypePubrec) | bit(TypeDisconnect)},
	RPacketIdentifierInUse:          {"Packet Identifier in use", bit(TypePuback) | bit(TypePubrec) | bit(TypeSuback) | bit(TypeUnsuback)},
	RPacketIdentifierNotFound:       {"Packet Identifier not found", bit(TypePubrel) | bit(TypePubcomp)},
	RReceiveMaximumExceeded:         {"Receive Maximum exceeded", bit(TypeDisconnect)},
	RTopicAliasInvalid:              {"Topic Alias invalid", bit(TypeDisconnect)},
	RPacketTooLarge:                 {"Packet too large", bit(TypeConnack) | bit(TypeDisconnect)},
	RMessageRateTooHigh:             {"Message rate too high", bit(TypeDisconnect)},
	RQuotaExceeded:                  {"Quota exceeded", bit(TypeConnack) | bit(TypePuback) | bit(TypePubrec) | bit(TypeSuback) | bit(TypeDisconnect)},
	RAdministrativeAction:           {"Administrative action", bit(TypeDisconnect)},
	RPayloadFormatInvalid:           {"Payload format invalid", bit(TypeConnack) | bit(TypePuback) | bit(TypePubrec) | bit(TypeDisconnect)},
	RRetainNotSupported:             {"Retain not supported", bit(TypeConnack) | bit(TypeDisconnect)},
	RQoSNotSupported:                {"QoS not supported", bit(TypeConnack) | bit(TypeDisconnect)},
	RUseAnotherServer:               {"Use another server", bit(TypeConnack) | bit(TypeDisconnect)},
	RServerMoved:                    {"Server moved", bit(TypeConnack) | bit(TypeDisconnect)},
	RSharedSubscriptionsUnsupported: {"Shared Subscriptions not supported", bit(TypeSuback) | bit(TypeDisconnect)},
	RConnectionRateExceeded:         {"Connection rate exceeded", bit(TypeConnack) | bit(TypeDisconnect)},
	RMaximumConnectTime:             {"Maximum connect time", bit(TypeDisconnect)},
	RSubIDNotSupported:              {"Subscription Identifiers not supported", bit(TypeSuback) | bit(TypeDisconnect)},
}

// ReasonName renders a code for logs and error strings. Codes that mean
// different things per packet (0x00 above all) take their CONNACK-style name,
// which is good enough for a log line; the broker always knows the context.
func ReasonName(code byte) string {
	if s, ok := reasons[code]; ok {
		return s.name
	}
	switch code {
	case 0x00:
		return "Success"
	}
	return "UNKNOWN"
}

// ReasonAllowed reports whether a code may legally appear in this packet type.
// It guards the broker against emitting a code a strict client would reject.
func ReasonAllowed(code byte, t Type) bool {
	s, ok := reasons[code]
	if !ok {
		return code == 0x00
	}
	return s.validIn&bit(t) != 0
}
