package sshauth

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/shakboss/Go-server/blob/main/crypto"
	"github.com/shakboss/Go-server/blob/main/ippool"
	"github.com/shakboss/Go-server/blob/main/packet"
	"github.com/shakboss/Go-server/blob/main/session"
	"golang.org/x/crypto/ssh"
)

type SSHAuthServer struct {
	listener          net.Listener
	config            *ssh.ServerConfig
	authorizedKeysDir string
	sessionManager    *session.SessionManager
	ipPool            *ippool.IPPool
	masterKey         []byte // For signing/encrypting session tokens
	clientDNSServers  []net.IP
	clientRoutes      []*net.IPNet
}

func NewSSHAuthServer(
	tcpPort int,
	hostKeyPath string,
	authorizedKeysDir string,
	sm *session.SessionManager,
	ipPool *ippool.IPPool,
	masterKey []byte,
	dnsServers []string, // Passed as strings from config
	routes []string, // Passed as strings from config
) (*SSHAuthServer, error) {

	// Load host key
	hostKey, err := ioutil.ReadFile(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load SSH host key %s: %w", hostKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(hostKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH host key: %w", err)
	}

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			log.Printf("Public key authentication attempt for user %s with key type %s", conn.User(), key.Type())

			authorizedKeyFile := filepath.Join(authorizedKeysDir, conn.User())
			authorizedKeys, err := ioutil.ReadFile(authorizedKeyFile)
			if err != nil {
				log.Printf("User %s: authorized_keys file not found or readable: %v", conn.User(), err)
				return nil, fmt.Errorf("permission denied")
			}

			for len(authorizedKeys) > 0 {
				pubKey, comment, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeys)
				if err != nil {
					log.Printf("User %s: error parsing authorized_keys: %v", conn.User(), err)
					break // Stop on error, or continue if you want to skip invalid lines
				}
				if ssh.KeysEqual(key, pubKey) {
					log.Printf("User %s authenticated successfully with key %s (%s)", conn.User(), key.Type(), comment)
					return &ssh.Permissions{
						CriticalOptions: map[string]string{
							"username": conn.User(), // Store username for later retrieval
						},
					}, nil
				}
				authorizedKeys = rest
			}

			log.Printf("Public key authentication failed for user %s", conn.User())
			return nil, fmt.Errorf("permission denied")
		},
		// NoClientAuth: true, // Only if you want to allow anonymous access (NOT RECOMMENDED)
	}
	sshConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", tcpPort))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on TCP port %d: %w", tcpPort, err)
	}

	// Parse DNS servers
	var clientDNSServers []net.IP
	for _, dnsStr := range dnsServers {
		ip := net.ParseIP(dnsStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid DNS server IP in config: %s", dnsStr)
		}
		clientDNSServers = append(clientDNSServers, ip)
	}

	// Parse Routes
	var clientRoutes []*net.IPNet
	for _, routeStr := range routes {
		_, ipNet, err := net.ParseCIDR(routeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid route CIDR in config: %s, %w", routeStr, err)
		}
		clientRoutes = append(clientRoutes, ipNet)
	}


	return &SSHAuthServer{
		listener:          listener,
		config:            sshConfig,
		authorizedKeysDir: authorizedKeysDir,
		sessionManager:    sm,
		ipPool:            ipPool,
		masterKey:         masterKey,
		clientDNSServers:  clientDNSServers,
		clientRoutes:      clientRoutes,
	}, nil
}

func (s *SSHAuthServer) Start() {
	log.Printf("SSH authentication server listening on %s", s.listener.Addr())
	for {
		tcpConn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming SSH connection: %v", err)
			continue
		}
		go s.handleSSHConnection(tcpConn)
	}
}

func (s *SSHAuthServer) handleSSHConnection(tcpConn net.Conn) {
	defer tcpConn.Close()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, s.config)
	if err != nil {
		log.Printf("SSH handshake failed from %s: %v", tcpConn.RemoteAddr(), err)
		return
	}
	defer sshConn.Close()

	log.Printf("SSH connection established from %s (user %s)", sshConn.RemoteAddr(), sshConn.User())

	// The client might request channels or global requests, but we're only interested in authentication.
	// We'll close the connection immediately after processing authentication.
	go ssh.DiscardRequests(reqs)
	go s.handleSSHChannels(chans, sshConn.User(), sshConn.SessionID(), sshConn.RemoteAddr().String())

	// Keep the connection open until channels are closed or an idle timeout occurs
	// For this VPN, we just need authentication, so we will close it once the token is sent
	// Or, if no channels open, it will close after auth handshake.
	// Adding an explicit short timeout in case the client doesn't close immediately.
	time.AfterFunc(10*time.Second, func() {
		log.Printf("Closing idle SSH connection from %s after auth for user %s", tcpConn.RemoteAddr(), sshConn.User())
		tcpConn.Close()
	})
}

func (s *SSHAuthServer) handleSSHChannels(chans <-chan ssh.NewChannel, username string, sessionID []byte, remoteAddr string) {
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType()))
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}
		defer channel.Close()

		log.Printf("Channel accepted for user %s from %s", username, remoteAddr)

		// SSH session is established. Now derive VPN session key and send config.
		err = s.processVPNSession(channel, username, sessionID)
		if err != nil {
			log.Printf("Error processing VPN session for user %s: %v", username, err)
			channel.Stderr().Write([]byte(fmt.Sprintf("VPN session setup failed: %v\n", err)))
			return
		}

		// Discard any further requests on this channel.
		go func() {
			for req := range requests {
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}()

		// Keep channel open briefly for client to receive data, then close.
		time.Sleep(500 * time.Millisecond) // Give client time to read response
		log.Printf("VPN session setup complete for user %s. Closing SSH channel.", username)
		return // Exit the loop, closing the channel
	}
}

// processVPNSession handles key derivation, IP allocation, and sending config/token over SSH.
func (s *SSHAuthServer) processVPNSession(channel ssh.Channel, username string, sshSessionID []byte) error {
	// 1. Derive VPN Session Key
	serverSessionNonce, err := crypto.GenerateRandomBytes(crypto.NonceLen)
	if err != nil {
		return fmt.Errorf("failed to generate server session nonce: %w", err)
	}

	vpnSessionKey, err := crypto.DeriveSessionKey(sshSessionID, serverSessionNonce, fmt.Sprintf("VPN-Session-Key-Derivation-%s", username))
	if err != nil {
		return fmt.Errorf("failed to derive VPN session key: %w", err)
	}

	// 2. Allocate IP Address
	assignedIP, err := s.ipPool.Allocate(username)
	if err != nil {
		return fmt.Errorf("failed to allocate IP for user %s: %w", username, err)
	}

	// 3. Create ClientSession and add to pending
	sessionUUID := uuid.New()
	clientSession := &session.ClientSession{
		SessionID:         sessionUUID,
		Username:          username,
		AssignedIP:        assignedIP,
		SessionKey:        vpnSessionKey,
		LastActivity:      time.Now(),
		LastReceivedCounter: 0, // Counters reset for new session
		IsActive:          false,
	}
	s.sessionManager.AddPending(clientSession)

	// 4. Create Session Token for initial UDP handshake
	keyFingerprint := sha256.Sum256(vpnSessionKey) // Use hash of session key as fingerprint
	sessionTokenPayload := packet.SessionTokenPayload{
		SessionID:   sessionUUID,
		AssignedIP:  assignedIP,
		Expiration:  time.Now().Add(s.sessionManager.GetSessionTimeout()).Unix(),
		KeyFingerprint: keyFingerprint[:],
	}

	tokenPayloadBytes, err := sessionTokenPayload.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal session token payload: %w", err)
	}

	// Sign/Encrypt the token using the server's master key
	// For simplicity here, we'll just encrypt. In production, consider sign-then-encrypt.
	tokenNonce, err := crypto.GenerateRandomBytes(crypto.NonceLen)
	if err != nil {
		return fmt.Errorf("failed to generate token nonce: %w", err)
	}

	encryptedToken, err := crypto.EncryptGCM(s.masterKey, tokenNonce, tokenPayloadBytes, nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt session token: %w", err)
	}
	sessionToken := append(tokenNonce, encryptedToken...) // Prepend nonce to token

	// 5. Send VPN client config and session token over SSH channel
	vpnClientConfig := &packet.AuthResponseClientConfig{
		AssignedIP:  assignedIP,
		DNSServers:  s.clientDNSServers,
		Routes:      s.clientRoutes,
		ServerNonce: serverSessionNonce, // Client needs this for HKDF
	}
	
	configBytes, err := packet.MarshalAuthResponseClientConfig(vpnClientConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal client config: %w", err)
	}

	// Format: configBytesLen (4 bytes) + configBytes + sessionTokenLen (4 bytes) + sessionToken
	responseBuf := make([]byte, 4+len(configBytes)+4+len(sessionToken))
	offset := 0
	binary.BigEndian.PutUint32(responseBuf[offset:offset+4], uint32(len(configBytes)))
	offset += 4
	copy(responseBuf[offset:offset+len(configBytes)], configBytes)
	offset += len(configBytes)

	binary.BigEndian.PutUint32(responseBuf[offset:offset+4], uint32(len(sessionToken)))
	offset += 4
	copy(responseBuf[offset:offset+len(sessionToken)], sessionToken)
	offset += len(sessionToken)

	_, err = channel.Write(responseBuf)
	if err != nil {
		return fmt.Errorf("failed to send VPN config and token over SSH: %w", err)
	}

	log.Printf("Successfully provisioned VPN session for user %s. Assigned IP: %s", username, assignedIP)
	return nil
}
