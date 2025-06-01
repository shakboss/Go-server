package packet

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/uuid"
)

const (
	HeaderLen        = 1 + 4 + 4 + 12 // Type + SenderCounter + ReceiverCounterAck + Nonce
	GCMTagLen        = 16
	NonceLen         = 12
	SessionIDLen     = 16 // UUID length
	MaxPacketSize    = 1500 + HeaderLen + GCMTagLen // Max IP packet + Header + GCM Tag
	UDPHeaderPadding = 1 // Placeholder for alignment/future fields if needed
)

// Packet Types
const (
	PacketTypeDataInit   byte = 0x01 // First data packet after SSH auth, contains session token
	PacketTypeData       byte = 0x02 // Regular data packet
	PacketTypeControl    byte = 0x03 // For future control messages (e.g., keepalives, renegotiation)
	PacketTypeAuthRespOK byte = 0x04 // Response to auth with config
)

// Header is the fixed-size header for all UDP packets.
type Header struct {
	Type              byte
	SenderCounter     uint32
	ReceiverCounterAck uint32
	Nonce             [NonceLen]byte
}

// Marshal converts the Header to a byte slice.
func (h *Header) Marshal() []byte {
	buf := make([]byte, HeaderLen)
	buf[0] = h.Type
	binary.BigEndian.PutUint32(buf[1:5], h.SenderCounter)
	binary.BigEndian.PutUint32(buf[5:9], h.ReceiverCounterAck)
	copy(buf[9:HeaderLen], h.Nonce[:])
	return buf
}

// Unmarshal parses a byte slice into a Header.
func (h *Header) Unmarshal(data []byte) error {
	if len(data) < HeaderLen {
		return fmt.Errorf("packet header too short: %d bytes, expected %d", len(data), HeaderLen)
	}
	h.Type = data[0]
	h.SenderCounter = binary.BigEndian.Uint32(data[1:5])
	h.ReceiverCounterAck = binary.BigEndian.Uint32(data[5:9])
	copy(h.Nonce[:], data[9:HeaderLen])
	return nil
}

// SessionTokenPayload is the data signed/encrypted inside the session token.
type SessionTokenPayload struct {
	SessionID   uuid.UUID
	AssignedIP  net.IP
	Expiration  int64 // Unix timestamp
	KeyFingerprint []byte // Hash/fingerprint of the VPN session key
}

// Marshal converts SessionTokenPayload to byte slice.
func (s *SessionTokenPayload) Marshal() ([]byte, error) {
	buf := make([]byte, SessionIDLen + len(s.AssignedIP.To4()) + 8 + len(s.KeyFingerprint))
	copy(buf[0:SessionIDLen], s.SessionID[:])
	copy(buf[SessionIDLen:SessionIDLen+net.IPv4len], s.AssignedIP.To4())
	binary.BigEndian.PutInt64(buf[SessionIDLen+net.IPv4len:SessionIDLen+net.IPv4len+8], s.Expiration)
	copy(buf[SessionIDLen+net.IPv4len+8:], s.KeyFingerprint)
	return buf, nil
}

// Unmarshal parses a byte slice into SessionTokenPayload.
func (s *SessionTokenPayload) Unmarshal(data []byte) error {
	if len(data) < SessionIDLen+net.IPv4len+8 {
		return fmt.Errorf("session token payload too short")
	}
	copy(s.SessionID[:], data[0:SessionIDLen])
	s.AssignedIP = net.IP(data[SessionIDLen : SessionIDLen+net.IPv4len])
	s.Expiration = binary.BigEndian.Int64(data[SessionIDLen+net.IPv4len : SessionIDLen+net.IPv4len+8])
	s.KeyFingerprint = data[SessionIDLen+net.IPv4len+8:]
	return nil
}

// AuthResponseClientConfig is sent back to the client after successful SSH auth for initial config
type AuthResponseClientConfig struct {
	AssignedIP   net.IP
	DNSServers   []net.IP
	Routes       []*net.IPNet // Use IPNet for routes
	ServerNonce  []byte       // For HKDF Key derivation
}

// MarshalAuthResponseClientConfig marshals the client configuration.
func MarshalAuthResponseClientConfig(cfg *AuthResponseClientConfig) ([]byte, error) {
	// Calculate size: IP + (num_dns_ips * 4) + (num_routes * (4+4)) + nonce_len
	bufLen := net.IPv4len + 1 + len(cfg.DNSServers)*net.IPv4len + 1 + len(cfg.Routes)*(net.IPv4len+1) + len(cfg.ServerNonce)

	buf := make([]byte, bufLen)
	offset := 0

	copy(buf[offset:offset+net.IPv4len], cfg.AssignedIP.To4())
	offset += net.IPv4len

	buf[offset] = byte(len(cfg.DNSServers))
	offset++
	for _, dnsIP := range cfg.DNSServers {
		copy(buf[offset:offset+net.IPv4len], dnsIP.To4())
		offset += net.IPv4len
	}

	buf[offset] = byte(len(cfg.Routes))
	offset++
	for _, route := range cfg.Routes {
		copy(buf[offset:offset+net.IPv4len], route.IP.To4())
		offset += net.IPv4len
		ones, _ := route.Mask.Size()
		buf[offset] = byte(ones)
		offset++
	}

	copy(buf[offset:], cfg.ServerNonce)
	offset += len(cfg.ServerNonce)

	return buf[:offset], nil
}

// UnmarshalAuthResponseClientConfig unmarshals the client configuration.
func UnmarshalAuthResponseClientConfig(data []byte) (*AuthResponseClientConfig, error) {
	cfg := &AuthResponseClientConfig{}
	offset := 0

	if len(data) < net.IPv4len { return nil, fmt.Errorf("auth config too short for IP") }
	cfg.AssignedIP = net.IP(data[offset : offset+net.IPv4len])
	offset += net.IPv4len

	if len(data) < offset+1 { return nil, fmt.Errorf("auth config too short for DNS count") }
	numDNSServers := int(data[offset])
	offset++
	cfg.DNSServers = make([]net.IP, numDNSServers)
	for i := 0; i < numDNSServers; i++ {
		if len(data) < offset+net.IPv4len { return nil, fmt.Errorf("auth config too short for DNS IP") }
		cfg.DNSServers[i] = net.IP(data[offset : offset+net.IPv4len])
		offset += net.IPv4len
	}

	if len(data) < offset+1 { return nil, fmt.Errorf("auth config too short for routes count") }
	numRoutes := int(data[offset])
	offset++
	cfg.Routes = make([]*net.IPNet, numRoutes)
	for i := 0; i < numRoutes; i++ {
		if len(data) < offset+net.IPv4len+1 { return nil, fmt.Errorf("auth config too short for route IP/mask") }
		ip := net.IP(data[offset : offset+net.IPv4len])
		offset += net.IPv4len
		maskLen := int(data[offset])
		offset++
		cfg.Routes[i] = &net.IPNet{IP: ip, Mask: net.CIDRMask(maskLen, 32)}
	}

	cfg.ServerNonce = data[offset:] // Remaining data is server nonce

	return cfg, nil
}
