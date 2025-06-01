package udphandler

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/yourusername/vpn-server/crypto"
	"github.com/yourusername/vpn-server/packet"
	"github.com/yourusername/vpn-server/session"
	"github.com/yourusername/vpn-server/tun"
)

type UDPHandler struct {
	conn           *net.UDPConn
	sessionManager *session.SessionManager
	tunDevice      *tun.TunDevice
	masterKey      []byte
	tunWriteChan   chan<- packet.EncryptedPacket // For packets to be sent via TUN
}

type EncryptedPacket struct {
	SessionID uuid.UUID
	UDPAddr   *net.UDPAddr
	Payload   []byte // Encrypted payload with GCM tag
}

func NewUDPHandler(
	udpPort int,
	sm *session.SessionManager,
	tunDevice *tun.TunDevice,
	masterKey []byte,
	tunWriteChan chan<- packet.EncryptedPacket,
) (*UDPHandler, error) {
	addr := net.UDPAddr{Port: udpPort, IP: net.ParseIP("0.0.0.0")}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP port %d: %w", udpPort, err)
	}

	log.Printf("UDP data server listening on %s", conn.LocalAddr())

	return &UDPHandler{
		conn:           conn,
		sessionManager: sm,
		tunDevice:      tunDevice,
		masterKey:      masterKey,
		tunWriteChan:   tunWriteChan,
	}, nil
}

func (uh *UDPHandler) Start() {
	buffer := make([]byte, packet.MaxPacketSize)
	for {
		n, clientAddr, err := uh.conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("UDP ReadFromUDP error: %v", err)
			continue
		}
		go uh.handleUDPPacket(buffer[:n], clientAddr)
	}
}

func (uh *UDPHandler) handleUDPPacket(data []byte, clientAddr *net.UDPAddr) {
	if len(data) < packet.HeaderLen {
		log.Printf("Received malformed UDP packet from %s: too short for header (%d bytes)", clientAddr, len(data))
		return
	}

	var header packet.Header
	if err := header.Unmarshal(data); err != nil {
		log.Printf("Received malformed UDP packet from %s: header unmarshal error: %v", clientAddr, err)
		return
	}

	encryptedPayload := data[packet.HeaderLen:]

	switch header.Type {
	case packet.PacketTypeDataInit:
		uh.handleDataInitPacket(header, encryptedPayload, clientAddr)
	case packet.PacketTypeData:
		uh.handleDataPacket(header, encryptedPayload, clientAddr)
	case packet.PacketTypeControl:
		// TODO: Implement control packet handling (e.g., keepalives, stats)
		log.Printf("Received control packet from %s, type %X. Not yet implemented.", clientAddr, header.Type)
	default:
		log.Printf("Received unknown packet type %X from %s", header.Type, clientAddr)
	}
}

func (uh *UDPHandler) handleDataInitPacket(header packet.Header, encryptedPayload []byte, clientAddr *net.UDPAddr) {
	// For DATA_INIT, the payload is NOT encrypted with session key yet.
	// It's plaintext SessionID + SessionToken, followed by the actual IP packet encrypted with the session key.
	if len(encryptedPayload) < packet.SessionIDLen+4 { // SessionID + SessionTokenLen
		log.Printf("DataInit packet from %s too short for initial token data", clientAddr)
		return
	}

	sessionIDBytes := encryptedPayload[0:packet.SessionIDLen]
	sessionID, err := uuid.FromBytes(sessionIDBytes)
	if err != nil {
		log.Printf("DataInit from %s: Invalid SessionID bytes: %v", clientAddr, err)
		return
	}

	tokenLen := binary.BigEndian.Uint32(encryptedPayload[packet.SessionIDLen : packet.SessionIDLen+4])
	sessionToken := encryptedPayload[packet.SessionIDLen+4 : packet.SessionIDLen+4+tokenLen]

	// The remaining part of the payload is the actual IP packet encrypted with session key
	ipPacketEncrypted := encryptedPayload[packet.SessionIDLen+4+tokenLen:]

	sess, found := uh.sessionManager.GetBySessionID(sessionID)
	if !found {
		log.Printf("DataInit from %s for unknown session ID %s", clientAddr, sessionID)
		return
	}

	if sess.IsActive {
		log.Printf("DataInit from %s for already active session ID %s. Possible re-connection or duplicate.", clientAddr, sessionID)
		uh.handleDataPacket(header, ipPacketEncrypted, clientAddr) // Treat as normal data if active
		return
	}

	// Verify the session token
	tokenNonce := sessionToken[0:crypto.NonceLen]
	encryptedTokenPayload := sessionToken[crypto.NonceLen:]

	decryptedTokenPayload, err := crypto.DecryptGCM(uh.masterKey, tokenNonce, encryptedTokenPayload, nil)
	if err != nil {
		log.Printf("DataInit from %s: Failed to decrypt session token for ID %s: %v", clientAddr, sessionID, err)
		uh.sessionManager.Remove(sessionID) // Invalid token, remove session
		return
	}

	var token packet.SessionTokenPayload
	if err := token.Unmarshal(decryptedTokenPayload); err != nil {
		log.Printf("DataInit from %s: Failed to unmarshal session token payload for ID %s: %v", clientAddr, sessionID, err)
		uh.sessionManager.Remove(sessionID)
		return
	}

	// Validate token contents
	if token.SessionID != sessionID {
		log.Printf("DataInit from %s: Token SessionID mismatch: %s vs %s", clientAddr, token.SessionID, sessionID)
		uh.sessionManager.Remove(sessionID)
		return
	}
	if !token.AssignedIP.Equal(sess.AssignedIP) {
		log.Printf("DataInit from %s: Token AssignedIP mismatch for ID %s: %s vs %s", clientAddr, sessionID, token.AssignedIP, sess.AssignedIP)
		uh.sessionManager.Remove(sessionID)
		return
	}
	if time.Now().Unix() > token.Expiration {
		log.Printf("DataInit from %s: Session token for ID %s expired", clientAddr, sessionID)
		uh.sessionManager.Remove(sessionID)
		return
	}
	// Validate key fingerprint (optional but good for consistency)
	actualKeyFingerprint := sha256.Sum256(sess.SessionKey)
	if !bytes.Equal(token.KeyFingerprint, actualKeyFingerprint[:]) {
		log.Printf("DataInit from %s: Session key fingerprint mismatch for ID %s", clientAddr, sessionID)
		uh.sessionManager.Remove(sessionID)
		return
	}

	// Token is valid. Activate the session.
	activeSession, err := uh.sessionManager.Activate(sessionID, clientAddr)
	if err != nil {
		log.Printf("DataInit from %s: Error activating session %s: %v", clientAddr, sessionID, err)
		return
	}
	
	log.Printf("Session %s for user %s activated for UDP traffic from %s", sessionID, activeSession.Username, clientAddr)

	// Now handle the actual IP packet encrypted with the session key
	uh.processAndForwardIPPacket(activeSession, header, ipPacketEncrypted, clientAddr)
}

func (uh *UDPHandler) handleDataPacket(header packet.Header, encryptedPayload []byte, clientAddr *net.UDPAddr) {
	// Look up session by client's UDP address
	sess, found := uh.sessionManager.GetByUDPAddr(clientAddr)
	if !found {
		log.Printf("Received DATA packet from unknown UDP address %s", clientAddr)
		return
	}

	if !sess.IsActive {
		log.Printf("Received DATA packet from %s for a session not yet active (ID: %s)", clientAddr, sess.SessionID)
		// Client might have sent DATA before DATA_INIT was processed fully. Re-send DATA_INIT if needed by client.
		return
	}

	uh.processAndForwardIPPacket(sess, header, encryptedPayload, clientAddr)
}

// processAndForwardIPPacket decrypts, validates counters, and writes to TUN.
func (uh *UDPHandler) processAndForwardIPPacket(sess *session.ClientSession, header packet.Header, encryptedPayload []byte, clientAddr *net.UDPAddr) {
	// Decrypt the payload
	ipPacket, err := crypto.DecryptGCM(sess.SessionKey, header.Nonce[:], encryptedPayload, header.Marshal()) // AAD includes header
	if err != nil {
		log.Printf("Failed to decrypt packet from %s (SessionID: %s): %v", clientAddr, sess.SessionID, err)
		return
	}

	// Replay protection: Check sender counter
	if header.SenderCounter <= sess.LastReceivedCounter {
		log.Printf("Replay detected or out-of-order packet from %s (SessionID: %s): counter %d <= last_received %d",
			clientAddr, sess.SessionID, header.SenderCounter, sess.LastReceivedCounter)
		return // Drop packet
	}
	sess.LastReceivedCounter = header.SenderCounter

	// Write the IP packet to the TUN device
	_, err = uh.tunDevice.Write(ipPacket)
	if err != nil {
		log.Printf("Failed to write IP packet to TUN device for session %s: %v", sess.SessionID, err)
		return
	}
	// log.Printf("Forwarded IP packet from %s (VPN IP: %s) to TUN", clientAddr, tun.GetSourceIP(ipPacket))

	// Acknowledge received counter (can be sent in a separate ack packet or piggybacked on next data)
	// For simplicity, we assume client will implicitly know its packets are received if data flows.
	// For reliable counter ACK, you'd send a control packet or piggyback on a reply.
}

// SendEncryptedPacket sends an encrypted packet to a specific client UDP address.
func (uh *UDPHandler) SendEncryptedPacket(pkt packet.EncryptedPacket) {
	sess, found := uh.sessionManager.GetBySessionID(pkt.SessionID)
	if !found || !sess.IsActive {
		log.Printf("Attempted to send packet to non-existent or inactive session %s", pkt.SessionID)
		return
	}

	_, err := uh.conn.WriteToUDP(pkt.Payload, sess.UDPAddr)
	if err != nil {
		log.Printf("Failed to send encrypted packet to %s for session %s: %v", sess.UDPAddr, sess.SessionID, err)
	}
}
