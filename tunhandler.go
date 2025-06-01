package tunhandler

import (
	"log"
	"net"

	"github.com/google/uuid"
	"github.com/yourusername/vpn-server/crypto"
	"github.com/yourusername/vpn-server/packet"
	"github.com/yourusername/vpn-server/session"
	"github.com/yourusername/vpn-server/tun"
	"github.com/yourusername/vpn-server/udphandler"
)

type TUNHandler struct {
	tunDevice     *tun.TunDevice
	sessionManager *session.SessionManager
	udpSendChan    chan<- udphandler.EncryptedPacket // Channel to send encrypted packets via UDP
}

func NewTUNHandler(
	tunDevice *tun.TunDevice,
	sm *session.SessionManager,
	udpSendChan chan<- udphandler.EncryptedPacket,
) *TUNHandler {
	return &TUNHandler{
		tunDevice:     tunDevice,
		sessionManager: sm,
		udpSendChan:    udpSendChan,
	}
}

func (th *TUNHandler) Start() {
	buffer := make([]byte, tun.MaxIPPacketSize)
	for {
		n, err := th.tunDevice.Read(buffer)
		if err != nil {
			log.Printf("TUN Read error: %v", err)
			continue
		}
		go th.handleTUNPacket(buffer[:n])
	}
}

func (th *TUNHandler) handleTUNPacket(ipPacket []byte) {
	// Determine destination IP to find the correct client session
	destIP, err := tun.GetDestinationIP(ipPacket)
	if err != nil {
		log.Printf("Failed to get destination IP from TUN packet: %v", err)
		return
	}

	sess, found := th.sessionManager.GetByAssignedIP(destIP)
	if !found {
		log.Printf("Received TUN packet for unknown destination IP %s. Dropping.", destIP)
		return
	}

	// Encrypt the IP packet
	nonce, err := crypto.GenerateRandomBytes(packet.NonceLen)
	if err != nil {
		log.Printf("Failed to generate nonce for session %s: %v", sess.SessionID, err)
		return
	}

	header := packet.Header{
		Type:              packet.PacketTypeData,
		SenderCounter:     sess.LastReceivedCounter + 1, // Simple increment for now, client also tracks
		ReceiverCounterAck: 0, // Placeholder, client would fill this based on its last received from server
		Nonce:             ([packet.NonceLen]byte)(nonce),
	}

	encryptedPayload, err := crypto.EncryptGCM(sess.SessionKey, nonce, ipPacket, header.Marshal()) // AAD includes header
	if err != nil {
		log.Printf("Failed to encrypt IP packet for session %s: %v", sess.SessionID, err)
		return
	}

	finalPacket := append(header.Marshal(), encryptedPayload...)

	// Send the encrypted packet to the UDP handler
	th.udpSendChan <- udphandler.EncryptedPacket{
		SessionID: sess.SessionID,
		UDPAddr:   sess.UDPAddr, // Ensure UDPAddr is always set in active session
		Payload:   finalPacket,
	}
	// log.Printf("Forwarded IP packet from TUN to %s (VPN IP: %s) for session %s", sess.UDPAddr, destIP, sess.SessionID)
}
