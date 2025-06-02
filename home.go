package main

import (
        "bytes"
        "context"
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "crypto/sha256"
        "encoding/hex"
        "encoding/json"
        "errors"
        "fmt"
        "io"
        "log"
        "net"
        "os"
        "os/exec"
        "os/signal"
        "strings"
        "sync"
        "syscall"
        "time"

        "golang.org/x/crypto/hkdf"
        "golang.org/x/crypto/pbkdf2"

        "github.com/songgao/water" // TUN library
)

// --- Configuration Constants ---
const (
        DefaultConfigPath          = "server_config.json"
        HeaderLen                  = 1 + 1 + 1 + 12 // Type (1) + SenderCounter (1) + ReceiverCounterAck (1) + Nonce (12)
        GCMTagLen                  = 16
        NonceLen                   = 12
        SessionNonceLen            = 32
        MinUDPPacketLen            = HeaderLen
        PBKDF2SaltLen              = 16
        PBKDF2Iterations           = 4096
        PBKDF2KeyLen               = 32 // For password hashing, not AES key
        DefaultSessionTimeout      = 5 * time.Minute
        DefaultMaxAuthFails        = 5
        DefaultAuthFailBlockDur    = 5 * time.Minute
        DefaultAuthFailResetWindow = 15 * time.Minute
        DefaultMaxClientSessions   = 100
        CleanupCheckInterval       = 30 * time.Second
)

// Packet Types (mirrors C++ version)
const (
        PacketTypeAuthReq      byte = 0x01
        PacketTypeAuthRespOK   byte = 0x02
        PacketTypeAuthRespFail byte = 0x03
        PacketTypeData         byte = 0x04
)

// --- Global Variables & Structs ---

var (
        logger                     *log.Logger
        globalConfig               Config
        clientSessions             map[string]*ClientSession // Key: client UDP Addr string
        sessionsMutex              sync.RWMutex
        currentServerAuthKeyIndex  int
        authKeyIndexMutex          sync.Mutex
        virtualIPPool              []string
        virtualIPPoolMutex         sync.Mutex
        virtualIPToSessionKeyMap   map[string]string // Key: Virtual IP, Value: client UDP Addr string
        bruteForceTracker          map[string]BruteForceEntry // Key: Client IP (no port)
        bruteForceMutex            sync.Mutex
        tunInterface               *water.Interface
        serverUDPConn              *net.UDPConn
        rotatingAuthKeysParsed     [][]byte
)

// Config struct for server_config.json
type Config struct {
        ServerListenAddress     string   `json:"server_listen_address"`     // e.g., "0.0.0.0"
        ServerPort              int      `json:"server_port"`               // e.g., 8888
        TunInterfaceName        string   `json:"tun_interface_name"`        // e.g., "stun0"
        TunInterfaceIP          string   `json:"tun_interface_ip"`          // e.g., "10.8.0.1/24"
        VirtualIPRangeStart     string   `json:"virtual_ip_range_start"`    // e.g., "10.8.0.2"
        VirtualIPRangeEnd       string   `json:"virtual_ip_range_end"`      // e.g., "10.8.0.254"
        RotatingAuthKeysHex     []string `json:"rotating_auth_keys_hex"`    // List of PSKs in hex
        UserCredentials         map[string]string `json:"user_credentials"` // username -> "salt:hashed_password" (hex encoded)
        LogLevel                string   `json:"log_level"`                 // DEBUG, INFO, WARN, ERROR
        SessionTimeoutMinutes   int      `json:"session_timeout_minutes"`
        MaxAuthFails            int      `json:"max_auth_fails"`
        AuthFailBlockMinutes    int      `json:"auth_fail_block_minutes"`
        AuthFailResetMinutes    int      `json:"auth_fail_reset_minutes"`
        MaxClientSessions       int      `json:"max_client_sessions"`
        PublicNetworkInterface  string   `json:"public_network_interface"` // For iptables NAT e.g. "eth0"
}

// ClientSession stores state for each connected client
type ClientSession struct {
        ClientUDPAddr        *net.UDPAddr
        ClientUDPAddrStr     string
        SendCounter          byte
        RecvCounterExpected  byte
        LastRecvCounterAck   byte // What we last ACKed from client's send counter
        SessionKey           []byte
        Authenticated        bool
        ServerSessionNonce   []byte // Server's nonce for this session's key derivation
        LastActiveTime       time.Time
        LastAuthKeyIndexUsed int    // Index of server AuthKey that successfully authenticated this client
        VirtualIP            string
        LogPrefix            string
}

// PacketHeader represents our custom packet header
type PacketHeader struct {
        Type                 byte
        SenderCounter        byte
        ReceiverCounterAck   byte
        Nonce                []byte
}

// BruteForceEntry tracks failed authentication attempts
type BruteForceEntry struct {
        FailCount   int
        LastAttempt time.Time
        BlockUntil  time.Time
}

// --- Initialization Functions ---

func initLogger(logLevel string) {
        logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
        // In a real app, you'd parse logLevel and set log output/level accordingly
        // For now, all logs go to stdout
}

func loadConfiguration(configPath string) error {
        data, err := os.ReadFile(configPath)
        if err != nil {
                return fmt.Errorf("failed to read config file %s: %w", configPath, err)
        }
        err = json.Unmarshal(data, &globalConfig)
        if err != nil {
                return fmt.Errorf("failed to parse config file %s: %w", configPath, err)
        }

        // Set defaults if not provided
        if globalConfig.SessionTimeoutMinutes == 0 {
                globalConfig.SessionTimeoutMinutes = int(DefaultSessionTimeout.Minutes())
        }
        if globalConfig.MaxAuthFails == 0 {
                globalConfig.MaxAuthFails = DefaultMaxAuthFails
        }
        if globalConfig.AuthFailBlockMinutes == 0 {
                globalConfig.AuthFailBlockMinutes = int(DefaultAuthFailBlockDur.Minutes())
        }
        if globalConfig.AuthFailResetMinutes == 0 {
                globalConfig.AuthFailResetMinutes = int(DefaultAuthFailResetWindow.Minutes())
        }
        if globalConfig.MaxClientSessions == 0 {
                globalConfig.MaxClientSessions = DefaultMaxClientSessions
        }


        // Parse rotating auth keys
        if len(globalConfig.RotatingAuthKeysHex) == 0 {
                return errors.New("no rotating_auth_keys_hex found in config")
        }
        rotatingAuthKeysParsed = make([][]byte, len(globalConfig.RotatingAuthKeysHex))
        for i, hexKey := range globalConfig.RotatingAuthKeysHex {
                key, err := hex.DecodeString(hexKey)
                if err != nil {
                        return fmt.Errorf("failed to decode rotating auth key #%d from hex: %w", i, err)
                }
                if len(key) != 32 { // Assuming AES-256 keys
                        return fmt.Errorf("rotating auth key #%d has incorrect length %d, expected 32", i, len(key))
                }
                rotatingAuthKeysParsed[i] = key
        }
        logger.Printf("INFO: Loaded %d rotating authentication keys.", len(rotatingAuthKeysParsed))

        if globalConfig.UserCredentials == nil || len(globalConfig.UserCredentials) == 0 {
                return errors.New("no user_credentials found in config")
        }
        logger.Printf("INFO: Loaded credentials for %d users.", len(globalConfig.UserCredentials))

        return nil
}

func initializeVirtualIPPool() error {
        startIP := net.ParseIP(globalConfig.VirtualIPRangeStart)
        endIP := net.ParseIP(globalConfig.VirtualIPRangeEnd)

        if startIP == nil || endIP == nil {
                return errors.New("invalid virtual_ip_range_start or virtual_ip_range_end in config")
        }
        startIP = startIP.To4()
        endIP = endIP.To4()
        if startIP == nil || endIP == nil {
                return errors.New("virtual IP range must be IPv4")
        }

        virtualIPPool = []string{}
        virtualIPToSessionKeyMap = make(map[string]string)

        for ip := startIP; !ip.Equal(endIP) && bytes.Compare(ip, endIP) < 0; incrementIP(ip) {
                virtualIPPool = append(virtualIPPool, ip.String())
        }
        virtualIPPool = append(virtualIPPool, endIP.String()) // Add the last IP

        if len(virtualIPPool) == 0 {
                return errors.New("virtual IP pool is empty based on configured range")
        }
        logger.Printf("INFO: Initialized virtual IP pool with %d addresses (%s - %s)",
                len(virtualIPPool), globalConfig.VirtualIPRangeStart, globalConfig.VirtualIPRangeEnd)
        return nil
}

func incrementIP(ip net.IP) {
        for j := len(ip) - 1; j >= 0; j-- {
                ip[j]++
                if ip[j] > 0 {
                        break
                }
        }
}

func assignVirtualIP() string {
        virtualIPPoolMutex.Lock()
        defer virtualIPPoolMutex.Unlock()
        if len(virtualIPPool) == 0 {
                return ""
        }
        vip := virtualIPPool[0]
        virtualIPPool = virtualIPPool[1:]
        return vip
}

func releaseVirtualIP(vip string) {
        if vip == "" {
                return
        }
        virtualIPPoolMutex.Lock()
        defer virtualIPPoolMutex.Unlock()
        // To prevent duplicates if released multiple times, though logic should prevent this
        for _, existingVip := range virtualIPPool {
                if existingVip == vip {
                        logger.Printf("WARN: Virtual IP %s already in pool when trying to release.", vip)
                        return
                }
        }
        virtualIPPool = append(virtualIPPool, vip)
        logger.Printf("INFO: Released virtual IP %s back to pool. Pool size: %d", vip, len(virtualIPPool))
}


func setupTunInterface() error {
        var err error
        config := water.Config{DeviceType: water.TUN}
        config.Name = globalConfig.TunInterfaceName

        tunInterface, err = water.New(config)
        if err != nil {
                return fmt.Errorf("failed to allocate TUN interface %s: %w", globalConfig.TunInterfaceName, err)
        }
        globalConfig.TunInterfaceName = tunInterface.Name() // Update with actual name if kernel assigned
        logger.Printf("INFO: TUN interface %s created.", tunInterface.Name())

        // Configure TUN interface (IP address, bring up)
        // Example for Linux. This needs to be adapted for other OS or use netlink.
        commands := [][]string{
                {"ip", "addr", "add", globalConfig.TunInterfaceIP, "dev", tunInterface.Name()},
                {"ip", "link", "set", "dev", tunInterface.Name(), "up"},
                // Optionally set MTU, e.g., {"ip", "link", "set", "dev", tunInterface.Name(), "mtu", "1400"},
        }

        for _, cmdArgs := range commands {
                cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
                output, err := cmd.CombinedOutput()
                if err != nil {
                        return fmt.Errorf("failed to run command '%s': %w. Output: %s", strings.Join(cmdArgs, " "), err, string(output))
                }
                logger.Printf("INFO: Ran command: %s", strings.Join(cmdArgs, " "))
        }
        return nil
}

func setupIPTablesNAT() error {
    if globalConfig.PublicNetworkInterface == "" {
        logger.Println("WARN: PublicNetworkInterface not set in config. Skipping iptables NAT setup.")
        return nil
    }

    vpnSubnetParts := strings.Split(globalConfig.TunInterfaceIP, "/")
    if len(vpnSubnetParts) != 2 {
        return fmt.Errorf("invalid TunInterfaceIP format '%s', expected IP/CIDR", globalConfig.TunInterfaceIP)
    }
    vpnSubnet := globalConfig.TunInterfaceIP // Assume it's already in CIDR like 10.8.0.1/24

    commands := [][]string{
        // Enable IP forwarding (idempotent if already set)
        // {"sysctl", "-w", "net.ipv4.ip_forward=1"}, // May need sudo, or do this manually once

        // Flush existing relevant rules if you want a clean slate (use with caution)
        // {"iptables", "-t", "nat", "-F", "POSTROUTING"},
        // {"iptables", "-F", "FORWARD"},

        // NAT rule
        {"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", vpnSubnet, "-o", globalConfig.PublicNetworkInterface, "-j", "MASQUERADE"},
        // Forwarding rules
        {"iptables", "-A", "FORWARD", "-i", globalConfig.TunInterfaceName, "-o", globalConfig.PublicNetworkInterface, "-j", "ACCEPT"},
        {"iptables", "-A", "FORWARD", "-i", globalConfig.PublicNetworkInterface, "-o", globalConfig.TunInterfaceName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
    }

    logger.Println("INFO: Attempting to set up iptables NAT rules. This might require sudo or manual execution if server doesn't run as root.")
    for _, cmdArgs := range commands {
        cmd := exec.Command("sudo", cmdArgs...) // Adding sudo here
        output, err := cmd.CombinedOutput()
        cmdStr := strings.Join(cmdArgs, " ")
        if err != nil {
            logger.Printf("WARN: Failed to run iptables command 'sudo %s': %v. Output: %s. Manual setup might be required.", cmdStr, err, string(output))
            // Don't return error, allow server to continue, admin can set rules manually
        } else {
            logger.Printf("INFO: Ran iptables command: sudo %s", cmdStr)
        }
    }
    logger.Println("INFO: To make iptables rules persistent, use 'iptables-persistent' or similar tools.")
    return nil
}


// --- Cryptography & Packet Helpers ---

func generateRandomBytes(length int) ([]byte, error) {
        b := make([]byte, length)
        _, err := rand.Read(b)
        if err != nil {
                return nil, fmt.Errorf("failed to generate random bytes: %w", err)
        }
        return b, nil
}

// deriveKeyHKDF derives a key using HKDF-SHA256
func deriveKeyHKDF(masterKey, salt, info []byte, length int) ([]byte, error) {
        hash := sha256.New
        hkdfReader := hkdf.New(hash, masterKey, salt, info)
        derivedKey := make([]byte, length)
        _, err := io.ReadFull(hkdfReader, derivedKey)
        if err != nil {
                return nil, fmt.Errorf("hkdf key derivation failed: %w", err)
        }
        return derivedKey, nil
}

// encryptGCM encrypts plaintext using AES-GCM
func encryptGCM(key, plaintext, nonce, ad []byte) ([]byte, error) {
        if len(key) != 32 {
                return nil, fmt.Errorf("encryptGCM: invalid key length %d, expected 32", len(key))
        }
        if len(nonce) != NonceLen {
                return nil, fmt.Errorf("encryptGCM: invalid nonce length %d, expected %d", len(nonce), NonceLen)
        }

        block, err := aes.NewCipher(key)
        if err != nil {
                return nil, fmt.Errorf("failed to create AES cipher: %w", err)
        }
        aesgcm, err := cipher.NewGCM(block)
        if err != nil {
                return nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
        }

        ciphertextWithTag := aesgcm.Seal(nil, nonce, plaintext, ad)
        return ciphertextWithTag, nil
}

// decryptGCM decrypts ciphertextWithTag using AES-GCM
func decryptGCM(key, ciphertextWithTag, nonce, ad []byte) ([]byte, error) {
        if len(key) != 32 {
                return nil, fmt.Errorf("decryptGCM: invalid key length %d, expected 32", len(key))
        }
        if len(nonce) != NonceLen {
                return nil, fmt.Errorf("decryptGCM: invalid nonce length %d, expected %d", len(nonce), NonceLen)
        }
        if len(ciphertextWithTag) < GCMTagLen {
                return nil, fmt.Errorf("decryptGCM: ciphertext too short (len %d) to contain tag (len %d)", len(ciphertextWithTag), GCMTagLen)
        }

        block, err := aes.NewCipher(key)
        if err != nil {
                return nil, fmt.Errorf("failed to create AES cipher: %w", err)
        }
        aesgcm, err := cipher.NewGCM(block)
        if err != nil {
                return nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
        }

        plaintext, err := aesgcm.Open(nil, nonce, ciphertextWithTag, ad)
        if err != nil {
                return nil, fmt.Errorf("GCM decryption failed (tag mismatch or other error): %w", err)
        }
        return plaintext, nil
}

func (h *PacketHeader) Pack() ([]byte, error) {
        if len(h.Nonce) != NonceLen {
                return nil, fmt.Errorf("header pack: invalid nonce length %d", len(h.Nonce))
        }
        buf := make([]byte, HeaderLen)
        buf[0] = h.Type
        buf[1] = h.SenderCounter
        buf[2] = h.ReceiverCounterAck
        copy(buf[3:], h.Nonce)
        return buf, nil
}

func (h *PacketHeader) Unpack(data []byte) error {
        if len(data) < HeaderLen {
                return fmt.Errorf("header unpack: data too short (len %d), expected at least %d", len(data), HeaderLen)
        }
        h.Type = data[0]
        h.SenderCounter = data[1]
        h.ReceiverCounterAck = data[2]
        h.Nonce = make([]byte, NonceLen)
        copy(h.Nonce, data[3:HeaderLen])
        return nil
}

func (cs *ClientSession) incrementSendCounter() byte {
        if cs.SendCounter == 255 {
                cs.SendCounter = 1
        } else {
                cs.SendCounter++
        }
        return cs.SendCounter
}

func (cs *ClientSession) updateLastActive() {
        cs.LastActiveTime = time.Now()
}

func hashPasswordWithSalt(password string) (string, string, error) {
        salt, err := generateRandomBytes(PBKDF2SaltLen)
        if err != nil {
                return "", "", fmt.Errorf("failed to generate salt for password hashing: %w", err)
        }
        hashedPassword := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, PBKDF2KeyLen, sha256.New)
        return hex.EncodeToString(salt), hex.EncodeToString(hashedPassword), nil
}

func verifyPassword(password, storedSaltHex, storedHashHex string) (bool, error) {
        salt, err := hex.DecodeString(storedSaltHex)
        if err != nil {
                return false, fmt.Errorf("failed to decode stored salt from hex: %w", err)
        }
        // storedHash, err := hex.DecodeString(storedHashHex) // Not needed directly for comparison
        // if err != nil {
        //      return false, fmt.Errorf("failed to decode stored hash from hex: %w", err)
        // }

        inputHash := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, PBKDF2KeyLen, sha256.New)
        return hex.EncodeToString(inputHash) == storedHashHex, nil
}


// --- Core Server Logic ---

func sendPacketToClient(session *ClientSession, packetType byte, payloadData []byte, useSessionKey bool, serverAuthKeyIndexForResp int) error {
        var keyToSend []byte
        var keyTypeLogDetail string
        logEncPrefix := fmt.Sprintf("%s SrvSend PType=0x%02x:", session.LogPrefix, packetType)

        if useSessionKey && session.Authenticated && len(session.SessionKey) > 0 {
                keyToSend = session.SessionKey
                keyTypeLogDetail = "SessionKey"
        } else { // Typically for AUTH_RESP_OK or AUTH_RESP_FAIL
                if serverAuthKeyIndexForResp < 0 || serverAuthKeyIndexForResp >= len(rotatingAuthKeysParsed) {
                        authKeyIndexMutex.Lock()
                        keyIdxToUse := currentServerAuthKeyIndex // Fallback to current if invalid index given
                        authKeyIndexMutex.Unlock()
                        if keyIdxToUse < 0 || keyIdxToUse >= len(rotatingAuthKeysParsed) { // Should not happen if list not empty
                                return fmt.Errorf("%s cannot send auth resp: no rotating keys or invalid current index %d", logEncPrefix, keyIdxToUse)
                        }
                        keyToSend = rotatingAuthKeysParsed[keyIdxToUse]
                        keyTypeLogDetail = fmt.Sprintf("AuthKey (SrvIdx %d - fallback)", keyIdxToUse)
                        logger.Printf("WARN: %s Invalid serverAuthKeyIndexForResp %d provided for AUTH_RESP. Falling back to current SrvIdx %d.",
                                logEncPrefix, serverAuthKeyIndexForResp, keyIdxToUse)
                } else {
                        keyToSend = rotatingAuthKeysParsed[serverAuthKeyIndexForResp]
                        keyTypeLogDetail = fmt.Sprintf("AuthKey (SrvIdx %d)", serverAuthKeyIndexForResp)
                }
        }
        logEncPrefix += " With " + keyTypeLogDetail + ": "

        if len(keyToSend) == 0 {
                return fmt.Errorf("%s no key resolved for sending", logEncPrefix)
        }

        header := PacketHeader{
                Type:               packetType,
                SenderCounter:      session.incrementSendCounter(),
                ReceiverCounterAck: session.LastRecvCounterAck,
        }
        var err error
        header.Nonce, err = generateRandomBytes(NonceLen)
        if err != nil {
                return fmt.Errorf("%s failed to generate nonce: %w", logEncPrefix, err)
        }

        adData := []byte{header.Type, header.SenderCounter, header.ReceiverCounterAck}
        encryptedPayloadWithTag, err := encryptGCM(keyToSend, payloadData, header.Nonce, adData)
        if err != nil {
                return fmt.Errorf("%s GCM encryption failed: %w", logEncPrefix, err)
        }

        packedHeader, err := header.Pack()
        if err != nil {
                return fmt.Errorf("%s failed to pack header: %w", logEncPrefix, err)
        }
        fullPacketData := append(packedHeader, encryptedPayloadWithTag...)

        _, err = serverUDPConn.WriteToUDP(fullPacketData, session.ClientUDPAddr)
        if err != nil {
                return fmt.Errorf("%s socket error sending: %w", logEncPrefix, err)
        }

        logger.Printf("DEBUG: %s Sent UDP. SC=%d, AckClientSC=%d, Len=%d, Using %s",
                logEncPrefix, header.SenderCounter, header.ReceiverCounterAck, len(fullPacketData), keyTypeLogDetail)
        return nil
}

func sendAuthFailResponse(session *ClientSession, reason string, serverAuthKeyIdxTried int) {
        // For AUTH_FAIL, server's SendCounter should be 1 if it's the first response after an AUTH_REQ.
        // Resetting here as C++ code did, or ensure it's 0 before first call to incrementSendCounter.
        session.SendCounter = 0
        logger.Printf("WARN: %s SrvAuthFail. Reason: %s. Server tried decrypting with AuthKey SrvIdx %d",
                session.LogPrefix, reason, serverAuthKeyIdxTried)
        err := sendPacketToClient(session, PacketTypeAuthRespFail, []byte(reason), false, serverAuthKeyIdxTried)
        if err != nil {
                logger.Printf("ERROR: %s Failed to send AUTH_RESP_FAIL: %v", session.LogPrefix, err)
        }
}

func handleUDPDatagram(data []byte, clientAddr *net.UDPAddr) {
        clientAddrStr := clientAddr.String()
        clientIPOnly := clientAddr.IP.String()

        // --- Brute-Force Check (before session lookup for new connections) ---
        bruteForceMutex.Lock()
        bfEntry, bfOk := bruteForceTracker[clientIPOnly]
        if bfOk && bfEntry.BlockUntil.After(time.Now()) {
                bruteForceMutex.Unlock()
                logger.Printf("WARN: UDPPkt from %s: IP %s currently blocked due to brute-force. Dropping %d bytes.", clientAddrStr, clientIPOnly, len(data))
                return
        }
        // Reset fail count if fail window passed
        if bfOk && time.Since(bfEntry.LastAttempt) > time.Duration(globalConfig.AuthFailResetMinutes)*time.Minute {
                bfEntry.FailCount = 0
        }
        bruteForceMutex.Unlock() // Unlock early if not blocked

        // --- Session Lookup / Creation ---
        sessionsMutex.RLock()
        session, ok := clientSessions[clientAddrStr]
        sessionsMutex.RUnlock()

        logPrefixBase := fmt.Sprintf("SrvRcvPkt from %s", clientAddrStr)

        if !ok {
                sessionsMutex.Lock()
                // Double check after acquiring write lock
                if _, exists := clientSessions[clientAddrStr]; exists {
                        sessionsMutex.Unlock() // Another goroutine created it
                        sessionsMutex.RLock()
                        session = clientSessions[clientAddrStr] // Should exist
                        sessionsMutex.RUnlock()
                } else {
                        if len(clientSessions) >= globalConfig.MaxClientSessions {
                                sessionsMutex.Unlock()
                                logger.Printf("WARN: %s Max client sessions (%d) reached. Dropping new session request for %d bytes.",
                                        logPrefixBase, globalConfig.MaxClientSessions, len(data))
                                return
                        }
                        session = &ClientSession{
                                ClientUDPAddr:       clientAddr,
                                ClientUDPAddrStr:    clientAddrStr,
                                LastActiveTime:      time.Now(),
                                SendCounter:         0, // Will be 1 on first packet sent
                                RecvCounterExpected: 0, // Expect 1 for first data/auth packet from client
                                LogPrefix:           fmt.Sprintf("[%s]", clientAddrStr),
                        }
                        clientSessions[clientAddrStr] = session
                        sessionsMutex.Unlock()
                        logger.Printf("INFO: %s New potential session. Current sessions: %d", session.LogPrefix, len(clientSessions))
                }
        }
        session.updateLastActive()
        logPrefixBase = fmt.Sprintf("%s (CurSessAuth:%t)", session.LogPrefix, session.Authenticated)


        if len(data) < MinUDPPacketLen {
                logger.Printf("WARN: %s Malformed (too short, len %d). Dropping.", logPrefixBase, len(data))
                return
        }

        var receivedHeader PacketHeader
        err := receivedHeader.Unpack(data[:HeaderLen])
        if err != nil {
                logger.Printf("WARN: %s Failed to unpack header: %v. Dropping.", logPrefixBase, err)
                return
        }

        encryptedPayloadWithTag := data[HeaderLen:]
        logPrefixBase += fmt.Sprintf(": PType=0x%02x, ClientSC=%d, ClientAckMySC=%d",
                receivedHeader.Type, receivedHeader.SenderCounter, receivedHeader.ReceiverCounterAck)

        var keyForDecryption []byte
        keyTypeForLogDetail := ""
        serverAuthIdxUsedForAuthReq := -1 // For logging/AuthFail resp

        if receivedHeader.Type == PacketTypeAuthReq {
                authKeyIndexMutex.Lock()
                serverAuthIdxUsedForAuthReq = currentServerAuthKeyIndex
                authKeyIndexMutex.Unlock()

                if serverAuthIdxUsedForAuthReq < 0 || serverAuthIdxUsedForAuthReq >= len(rotatingAuthKeysParsed) {
                        logger.Printf("ERROR: %s No valid current server auth key index (%d). Cannot process AUTH_REQ. Dropping.",
                                logPrefixBase, serverAuthIdxUsedForAuthReq)
                        // No session to send fail to yet if it's a new client this instant, or can use generic.
                        // But if session obj exists, we can try sending fail.
                        sendAuthFailResponse(session, "Server Auth Key Config Error", serverAuthIdxUsedForAuthReq)
                        return
                }
                keyForDecryption = rotatingAuthKeysParsed[serverAuthIdxUsedForAuthReq]
                keyTypeForLogDetail = fmt.Sprintf("AuthKey (SrvIdx %d)", serverAuthIdxUsedForAuthReq)

                if session.Authenticated {
                        logger.Printf("WARN: %s Client sent AUTH_REQ on already authenticated session. Resetting for re-auth.", logPrefixBase)
                        // Reset session for re-authentication
                        sessionsMutex.Lock() // Full lock for modifying session fields
                        session.Authenticated = false
                        session.SessionKey = nil
                        session.ServerSessionNonce = nil
                        if session.VirtualIP != "" {
                                delete(virtualIPToSessionKeyMap, session.VirtualIP) // Remove old VIP mapping
                                releaseVirtualIP(session.VirtualIP)
                                session.VirtualIP = ""
                        }
                        // Counters are reset implicitly or on success.
                        sessionsMutex.Unlock()
                }
        } else if session.Authenticated && len(session.SessionKey) > 0 {
                keyForDecryption = session.SessionKey
                keyTypeForLogDetail = fmt.Sprintf("SessionKey (derived via SrvAuthKeyIdx %d)", session.LastAuthKeyIndexUsed)
        } else {
                logger.Printf("WARN: %s Non-AUTH_REQ PType=0x%02x on unauthenticated/keyless session. Dropping.", logPrefixBase, receivedHeader.Type)
                return
        }

        if len(keyForDecryption) == 0 {
                logger.Printf("ERROR: %s No key available for decryption (using %s). Dropping.", logPrefixBase, keyTypeForLogDetail)
                return
        }

        logDecPrefix := logPrefixBase + " DecryptWith " + keyTypeForLogDetail + ": "
        adForDecrypt := []byte{receivedHeader.Type, receivedHeader.SenderCounter, receivedHeader.ReceiverCounterAck}
        decryptedPayload, err := decryptGCM(keyForDecryption, encryptedPayloadWithTag, receivedHeader.Nonce, adForDecrypt)
        if err != nil {
                logger.Printf("WARN: %s Decryption failed: %v. Dropping.", logDecPrefix, err)
                if receivedHeader.Type == PacketTypeAuthReq {
                        // Increment brute-force counter for AUTH_REQ decryption failure
                        bruteForceMutex.Lock()
                        entry := bruteForceTracker[clientIPOnly] // Get or create
                        entry.FailCount++
                        entry.LastAttempt = time.Now()
                        if entry.FailCount >= globalConfig.MaxAuthFails {
                                entry.BlockUntil = time.Now().Add(time.Duration(globalConfig.AuthFailBlockMinutes) * time.Minute)
                                logger.Printf("WARN: %s IP %s reached max auth failures (%d). Blocking for %d mins.",
                                        logPrefixBase, clientIPOnly, entry.FailCount, globalConfig.AuthFailBlockMinutes)
                        }
                        bruteForceTracker[clientIPOnly] = entry
                        bruteForceMutex.Unlock()
                        sendAuthFailResponse(session, "Auth Decryption Failed", serverAuthIdxUsedForAuthReq)
                } else { // Data packet decryption failure with session key
                        logger.Printf("ERROR: %s DATA packet decryption failed. Session might be compromised/desynced. Resetting auth.", logDecPrefix)
                        sessionsMutex.Lock()
                        session.Authenticated = false
                        session.SessionKey = nil
                        // Keep VIP for now, but client needs to re-auth to use it. Or release it.
                        // For simplicity, let re-auth handle VIP reassignment or reuse.
                        sessionsMutex.Unlock()
                }
                return
        }

        logger.Printf("DEBUG: %s Decrypted OK. PayloadLen=%d", logDecPrefix, len(decryptedPayload))
        session.LastRecvCounterAck = receivedHeader.SenderCounter // Acknowledge what we just received

        // Counter Check
        if receivedHeader.Type == PacketTypeData && session.Authenticated {
                expectedDataSC := session.RecvCounterExpected
                if expectedDataSC == 0 { // First data packet after auth
                        expectedDataSC = 1
                } else {
                        if expectedDataSC == 255 { expectedDataSC = 1 } else { expectedDataSC++ }
                }

                if receivedHeader.SenderCounter != expectedDataSC {
                        logger.Printf("WARN: %s DATA Out-of-Order! Expected ClientSC=%d, Got=%d. BaseExpected=%d. Dropping.",
                                logPrefixBase, expectedDataSC, receivedHeader.SenderCounter, session.RecvCounterExpected)
                        return
                }
                session.RecvCounterExpected = receivedHeader.SenderCounter
        } else if receivedHeader.Type == PacketTypeAuthReq {
                if receivedHeader.SenderCounter != 1 {
                        // This is a soft warning. Client should ideally always start AUTH_REQ with SC=1.
                        logger.Printf("WARN: %s AUTH_REQ received with ClientSC=%d (expected 1). Processing, but client counter might be misaligned.",
                                logPrefixBase, receivedHeader.SenderCounter)
                }
                session.RecvCounterExpected = receivedHeader.SenderCounter // Will be 1 (or what client sent) for first valid data pkt
        }


        // --- Process Decrypted Payload by Type ---
        switch receivedHeader.Type {
        case PacketTypeAuthReq:
                logger.Printf("INFO: %s Processing AUTH_REQ payload (decrypted with SrvAuthKeyIdx %d).", logPrefixBase, serverAuthIdxUsedForAuthReq)
                // Payload: <username_len (1B)> <username> <password_len (1B)> <password>
                currentOffset := 0
                if len(decryptedPayload) < 1 {
                        sendAuthFailResponse(session, "Malformed Auth Req (Empty)", serverAuthIdxUsedForAuthReq)
                        return
                }
                usernameLen := int(decryptedPayload[currentOffset])
                currentOffset++
                if currentOffset+usernameLen > len(decryptedPayload) {
                        sendAuthFailResponse(session, "Malformed Auth Req (Username OOB)", serverAuthIdxUsedForAuthReq)
                        return
                }
                usernameBytes := decryptedPayload[currentOffset : currentOffset+usernameLen]
                currentOffset += usernameLen

                if currentOffset >= len(decryptedPayload) {
                        sendAuthFailResponse(session, "Malformed Auth Req (PasswdLen Missing)", serverAuthIdxUsedForAuthReq)
                        return
                }
                passwordLen := int(decryptedPayload[currentOffset])
                currentOffset++
                if currentOffset+passwordLen > len(decryptedPayload) {
                        sendAuthFailResponse(session, "Malformed Auth Req (Password OOB)", serverAuthIdxUsedForAuthReq)
                        return
                }
                passwordBytes := decryptedPayload[currentOffset : currentOffset+passwordLen]
                currentOffset += passwordLen

                if currentOffset != len(decryptedPayload) {
                        sendAuthFailResponse(session, "Malformed Auth Req (Length Mismatch)", serverAuthIdxUsedForAuthReq)
                        return
                }

                username := string(usernameBytes)
                password := string(passwordBytes)

                // Verify credentials
                storedCreds, userExists := globalConfig.UserCredentials[username]
                authSuccess := false
                if userExists {
                        parts := strings.Split(storedCreds, ":")
                        if len(parts) == 2 {
                                saltHex, hashHex := parts[0], parts[1]
                                var verifyErr error
                                authSuccess, verifyErr = verifyPassword(password, saltHex, hashHex)
                                if verifyErr != nil {
                                        logger.Printf("ERROR: %s Password verification error for user '%s': %v", logPrefixBase, username, verifyErr)
                                        sendAuthFailResponse(session, "Server Auth Internal Error", serverAuthIdxUsedForAuthReq)
                                        return
                                }
                        } else {
                                logger.Printf("ERROR: %s Malformed stored credentials for user '%s'", logPrefixBase, username)
                        }
                }

                if authSuccess {
                        logger.Printf("INFO: %s Credentials VALID for user '%s'.", logPrefixBase, username)

                        // Assign Virtual IP
                        newVIP := assignVirtualIP()
                        if newVIP == "" {
                                logger.Printf("ERROR: %s No virtual IPs available for user '%s'.", logPrefixBase, username)
                                sendAuthFailResponse(session, "No virtual IPs available", serverAuthIdxUsedForAuthReq)
                                return
                        }
                        session.VirtualIP = newVIP

                        var newServerSessionNonce []byte
                        newServerSessionNonce, err = generateRandomBytes(SessionNonceLen)
                        if err != nil {
                                logger.Printf("ERROR: %s Failed to generate server session nonce: %v", logPrefixBase, err)
                                releaseVirtualIP(session.VirtualIP) // Release acquired VIP
                                session.VirtualIP = ""
                                sendAuthFailResponse(session, "Server Internal Error (NonceGen)", serverAuthIdxUsedForAuthReq)
                                return
                        }
                        // +++ LOGGING: ServerSessionNonce +++
                        logger.Printf("DEBUG: %s Generated ServerSessionNonce (len %d): %s", logPrefixBase, len(newServerSessionNonce), hex.EncodeToString(newServerSessionNonce))

                        // Key used for AUTH_REQ decryption (keyForDecryption) IS the current server rotating key.
                        // Derive session key
                        hkdfInfo := []byte("vpn_session_key") // Consistent info string

                        // +++ LOGGING: Inputs to HKDF +++
                        logger.Printf("DEBUG: %s HKDF Input - PSK (IKM) (SrvAuthKeyIdx %d, len %d) ends: ...%s",
                                logPrefixBase, serverAuthIdxUsedForAuthReq, len(keyForDecryption),
                                hex.EncodeToString(keyForDecryption[len(keyForDecryption)-min(8, len(keyForDecryption)):]))
                        // For full PSK (IKM) if needed for direct comparison:
                        // logger.Printf("DEBUG: %s HKDF Input - PSK (IKM) HEX: %s", logPrefixBase, hex.EncodeToString(keyForDecryption))
                        logger.Printf("DEBUG: %s HKDF Input - Salt (ServerSessionNonce) HEX: %s", logPrefixBase, hex.EncodeToString(newServerSessionNonce))
                        logger.Printf("DEBUG: %s HKDF Input - Info: %s", logPrefixBase, string(hkdfInfo))


                        newSessionKey, err := deriveKeyHKDF(keyForDecryption, newServerSessionNonce, hkdfInfo, 32) // 32 bytes for AES-256
                        if err != nil {
                                logger.Printf("ERROR: %s Session key derivation failed: %v", logPrefixBase, err)
                                releaseVirtualIP(session.VirtualIP)
                                session.VirtualIP = ""
                                sendAuthFailResponse(session, "Server Key Derivation Error", serverAuthIdxUsedForAuthReq)
                                return
                        }

                        // +++ LOGGING: Derived Session Key +++
                        logger.Printf("DEBUG: %s Server DERIVED Session Key (len %d) HEX: %s", logPrefixBase, len(newSessionKey), hex.EncodeToString(newSessionKey))
                        // keyHash := sha256.Sum256(newSessionKey)
                        // logger.Printf("DEBUG: %s Server DERIVED Session Key SHA256: %s", logPrefixBase, hex.EncodeToString(keyHash[:]))


                        sessionsMutex.Lock()
                        session.SessionKey = newSessionKey
                        session.ServerSessionNonce = newServerSessionNonce // Store the generated nonce in session
                        session.Authenticated = true
                        session.LastAuthKeyIndexUsed = serverAuthIdxUsedForAuthReq
                        session.RecvCounterExpected = 0
                        session.SendCounter = 0

                        virtualIPToSessionKeyMap[session.VirtualIP] = session.ClientUDPAddrStr
                        sessionsMutex.Unlock()

                        // This log line was already good, but now we have more detail above
                        logger.Printf("INFO: %s Session key derived using SrvAuthKeyIdx %d. SK ends: ...%s. Assigned VIP: %s",
                                logPrefixBase, session.LastAuthKeyIndexUsed,
                                hex.EncodeToString(session.SessionKey[len(session.SessionKey)-min(8, len(session.SessionKey)):]),
                                session.VirtualIP)

                        // Prepare AUTH_RESP_OK payload: ServerSessionNonce (32B) + VIP_len (1B) + VIP_str
                        authRespPayload := make([]byte, 0, SessionNonceLen + 1 + len(session.VirtualIP))
                        authRespPayload = append(authRespPayload, session.ServerSessionNonce...) // Use the stored nonce
                        authRespPayload = append(authRespPayload, byte(len(session.VirtualIP)))
                        authRespPayload = append(authRespPayload, []byte(session.VirtualIP)...)


                        if err := sendPacketToClient(session, PacketTypeAuthRespOK, authRespPayload, false, serverAuthIdxUsedForAuthReq); err == nil {
                                logger.Printf("INFO: %s Client AUTHENTICATED (SrvAuthKeyIdx %d). VIP: %s", logPrefixBase, serverAuthIdxUsedForAuthReq, session.VirtualIP)

                                // Rotate server's key index for the *next entirely new* client authentication.
                                authKeyIndexMutex.Lock()
                                oldKeyIndex := currentServerAuthKeyIndex
                                currentServerAuthKeyIndex = (currentServerAuthKeyIndex + 1) % len(rotatingAuthKeysParsed)
                                newKeyIndex := currentServerAuthKeyIndex
                                authKeyIndexMutex.Unlock()
                                logger.Printf("INFO: AUTH KEY: Server rotated its current auth key index (for NEXT new auth) from %d to %d", oldKeyIndex, newKeyIndex)

                                // Clear brute-force entry on success
                                bruteForceMutex.Lock()
                                delete(bruteForceTracker, clientIPOnly)
                                bruteForceMutex.Unlock()
                        } else {
                                logger.Printf("ERROR: %s Failed to send AUTH_RESP_OK: %v", logPrefixBase, err)
                                // Reset auth state if send fails
                                sessionsMutex.Lock()
                                session.Authenticated = false
                                session.SessionKey = nil
                                delete(virtualIPToSessionKeyMap, session.VirtualIP)
                                releaseVirtualIP(session.VirtualIP)
                                session.VirtualIP = ""
                                sessionsMutex.Unlock()
                        }

                } else { // Auth failed (bad creds)
                        logger.Printf("WARN: %s Auth FAILED for user '%s' (Bad Credentials).", logPrefixBase, username)
                        // Increment brute-force counter for bad credentials
                        bruteForceMutex.Lock()
                        entry := bruteForceTracker[clientIPOnly] // Get or create
                        entry.FailCount++
                        entry.LastAttempt = time.Now()
                        if entry.FailCount >= globalConfig.MaxAuthFails {
                                entry.BlockUntil = time.Now().Add(time.Duration(globalConfig.AuthFailBlockMinutes) * time.Minute)
                                logger.Printf("WARN: %s IP %s reached max auth failures (%d). Blocking for %d mins.",
                                        logPrefixBase, clientIPOnly, entry.FailCount, globalConfig.AuthFailBlockMinutes)
                        }
                        bruteForceTracker[clientIPOnly] = entry
                        bruteForceMutex.Unlock()
                        sendAuthFailResponse(session, "Auth Failed (Credentials)", serverAuthIdxUsedForAuthReq)
                }

        case PacketTypeData:
                if session.Authenticated {
                        if tunInterface != nil {
                                _, err := tunInterface.Write(decryptedPayload)
                                if err != nil {
                                        logger.Printf("ERROR: %s Failed to write %dB to TUN: %v", logPrefixBase, len(decryptedPayload), err)
                                } else {
                                        // logger.Printf("DEBUG: %s Wrote %dB to TUN.", logPrefixBase, len(decryptedPayload))
                                }
                        } else {
                                logger.Printf("WARN: %s Global TUN FD not ready. Cannot write %dB to TUN.", logPrefixBase, len(decryptedPayload))
                        }
                } else {
                        logger.Printf("WARN: %s Internal Error: DATA packet processed but session not marked authenticated. Dropping.", logPrefixBase)
                }

        case PacketTypeAuthRespOK, PacketTypeAuthRespFail:
                logger.Printf("WARN: %s Server received an Auth Response PType from client. Unexpected. Ignoring.", logPrefixBase)

        default:
                logger.Printf("WARN: %s Unknown packet type after decryption: 0x%02x. Ignoring payload.", logPrefixBase, receivedHeader.Type)
        }
}

func udpReceiveLoop(ctx context.Context, conn *net.UDPConn) {
        defer logger.Println("INFO: UDP Receive Loop exiting.")
        buf := make([]byte, 2048) // Max UDP packet size to handle
        for {
                select {
                case <-ctx.Done():
                        return
                default:
                        // Set a read deadline to allow checking ctx.Done() periodically
                        conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
                        n, clientAddr, err := conn.ReadFromUDP(buf)
                        if err != nil {
                                if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                                        continue // Timeout is expected, loop again
                                }
                                if errors.Is(err, net.ErrClosed) {
                                        logger.Println("INFO: UDP socket closed, exiting receive loop.")
                                        return
                                }
                                logger.Printf("ERROR: UDP ReadFromUDP error: %v", err)
                                // Consider if critical, maybe signal shutdown
                                return
                        }
                        if n > 0 {
                                dataCopy := make([]byte, n)
                                copy(dataCopy, buf[:n])
                                go handleUDPDatagram(dataCopy, clientAddr) // Handle each packet in a new goroutine
                        }
                }
        }
}

func tunToUDPLoop(ctx context.Context) {
        defer logger.Println("INFO: TUN to UDP Loop exiting.")
        tunPacket := make([]byte, 2048) // Max IP packet size

        for {
                select {
                case <-ctx.Done():
                        if tunInterface != nil {
                                tunInterface.Close() // Close TUN to unblock Read
                        }
                        return
                default:
                        if tunInterface == nil {
                                time.Sleep(1 * time.Second) // TUN not ready yet
                                continue
                        }
                        // Reading from TUN. water's Read might block. A deadline isn't directly settable here.
                        // Closing the interface from another goroutine (on ctx.Done) is the typical way to unblock.
                        n, err := tunInterface.Read(tunPacket)
                        if err != nil {
                                if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "file already closed") {
                                        logger.Println("INFO: TUN interface closed, exiting tunToUDPLoop.")
                                        return
                                }
                                logger.Printf("ERROR: TUN Read error: %v", err)
                                // Critical TUN failure might warrant server shutdown
                                // For now, log and continue trying, or exit loop if persistent
                                time.Sleep(100 * time.Millisecond) // Avoid busy-looping on error
                                continue
                        }

                        if n > 0 {
                                ipPacket := make([]byte, n)
                                copy(ipPacket, tunPacket[:n])

                                // Basic IPv4 header parsing to get destination IP
                                // Dest IP is at offset 16, 4 bytes long.
                                if len(ipPacket) < 20 || (ipPacket[0]>>4) != 4 { // Min IPv4 header len and version check
                                        logger.Printf("WARN: TUN->UDP: Read non-IPv4 or too short packet from TUN. Size: %d. Dropping.", n)
                                        continue
                                }
                                destIP := net.IP(ipPacket[16:20])
                                destVirtualIP := destIP.String()

                                var targetSession *ClientSession
                                sessionsMutex.RLock()
                                targetSessionKey, foundVip := virtualIPToSessionKeyMap[destVirtualIP]
                                if foundVip {
                                        targetSession, _ = clientSessions[targetSessionKey]
                                }
                                sessionsMutex.RUnlock()


                                if targetSession != nil && targetSession.Authenticated {
                                        // logger.Printf("DEBUG: TUN->UDP: Forwarding %dB from TUN to %s (VIP: %s)",
                                        //      len(ipPacket), targetSession.ClientUDPAddrStr, destVirtualIP)
                                        err = sendPacketToClient(targetSession, PacketTypeData, ipPacket, true, -1)
                                        if err != nil {
                                                logger.Printf("ERROR: TUN->UDP: Failed to send DATA packet to %s: %v", targetSession.ClientUDPAddrStr, err)
                                                // Optionally mark session as problematic, or force re-auth
                                        }
                                } else {
                                        // logger.Printf("DEBUG: TUN->UDP: No authenticated client for VIP %s. Dropping %dB from TUN.",
                                        //      destVirtualIP, len(ipPacket))
                                }
                        }
                }
        }
}

func cleanupSessions(ctx context.Context) {
        ticker := time.NewTicker(CleanupCheckInterval)
        defer ticker.Stop()
        defer logger.Println("INFO: Session Cleanup Loop exiting.")

        for {
                select {
                case <-ctx.Done():
                        return
                case <-ticker.C:
                        now := time.Now()
                        sessionTimeout := time.Duration(globalConfig.SessionTimeoutMinutes) * time.Minute
                        sessionsToRemove := []string{} // Store keys to remove

                        sessionsMutex.RLock()
                        for key, session := range clientSessions {
                                if now.Sub(session.LastActiveTime) > sessionTimeout {
                                        sessionsToRemove = append(sessionsToRemove, key)
                                }
                        }
                        sessionsMutex.RUnlock()

                        if len(sessionsToRemove) > 0 {
                                sessionsMutex.Lock()
                                for _, keyToRemove := range sessionsToRemove {
                                        sessionToDel, exists := clientSessions[keyToRemove]
                                        if !exists { continue } // Already removed by another path

                                        logger.Printf("INFO: Session: Timeout for %s. Removing.", keyToRemove)
                                        if sessionToDel.VirtualIP != "" {
                                                delete(virtualIPToSessionKeyMap, sessionToDel.VirtualIP)
                                                releaseVirtualIP(sessionToDel.VirtualIP)
                                        }
                                        delete(clientSessions, keyToRemove)
                                }
                                sessionsMutex.Unlock()
                                logger.Printf("INFO: Session cleanup removed %d timed-out sessions. Current active: %d",
                                        len(sessionsToRemove), len(clientSessions))
                        }
                }
        }
}


// Utility to generate password hash if needed for config
func generatePasswordHashForConfig(username, password string) {
        salt, hash, err := hashPasswordWithSalt(password)
        if err != nil {
                fmt.Printf("Error generating hash for user %s: %v\n", username, err)
                return
        }
        fmt.Printf("For config.json, add/update user_credentials for \"%s\":\n", username)
        fmt.Printf("\"%s\": \"%s:%s\"\n", username, salt, hash)
}


// Helper for min
func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}

// --- Main Function ---
func main() {
        // Uncomment to generate a password hash for the config file:
     // generatePasswordHashForConfig("testuser", "testpassword")
     // return

        initLogger("INFO") // Default, config can override later if we enhance logger
        logger.Println("INFO: Starting VPN server...")

        err := loadConfiguration(DefaultConfigPath)
        if err != nil {
                logger.Fatalf("FATAL: Failed to load configuration: %v", err)
        }
        // Apply log level from config if desired

        clientSessions = make(map[string]*ClientSession)
        bruteForceTracker = make(map[string]BruteForceEntry)

        err = initializeVirtualIPPool()
        if err != nil {
                logger.Fatalf("FATAL: Failed to initialize virtual IP pool: %v", err)
        }

        err = setupTunInterface()
        if err != nil {
                logger.Fatalf("FATAL: Failed to setup TUN interface: %v", err)
        }
        defer func() {
                if tunInterface != nil {
                        logger.Println("INFO: Closing TUN interface...")
                        tunInterface.Close()
                }
        }()

        // Set up NAT rules (best effort, might need manual intervention/sudo)
    if err := setupIPTablesNAT(); err != nil {
        logger.Printf("WARN: Could not fully setup iptables NAT: %v. Manual configuration might be needed.", err)
    }


        // Setup UDP server
        listenAddr := fmt.Sprintf("%s:%d", globalConfig.ServerListenAddress, globalConfig.ServerPort)
        udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
        if err != nil {
                logger.Fatalf("FATAL: Failed to resolve UDP address %s: %v", listenAddr, err)
        }
        serverUDPConn, err = net.ListenUDP("udp", udpAddr)
        if err != nil {
                logger.Fatalf("FATAL: Failed to listen on UDP %s: %v", listenAddr, err)
        }
        defer func() {
                if serverUDPConn != nil {
                        logger.Println("INFO: Closing UDP socket...")
                        serverUDPConn.Close()
                }
        }()
        logger.Printf("INFO: UDP Server listening on %s", listenAddr)

        // Context for graceful shutdown
        ctx, cancel := context.WithCancel(context.Background())
        var wg sync.WaitGroup

        // Start goroutines
        wg.Add(1)
        go func() {
                defer wg.Done()
                udpReceiveLoop(ctx, serverUDPConn)
        }()

        wg.Add(1)
        go func() {
                defer wg.Done()
                tunToUDPLoop(ctx)
        }()

        wg.Add(1)
        go func() {
                defer wg.Done()
                cleanupSessions(ctx)
        }()

        logger.Println("INFO: Server successfully started. Press Ctrl+C to shutdown.")

        // Wait for shutdown signal
        sigChan := make(chan os.Signal, 1)
        signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
        receivedSignal := <-sigChan
        logger.Printf("INFO: Received signal: %s. Shutting down...", receivedSignal)

        cancel() // Signal all goroutines to stop

        // Wait for goroutines to finish
        // Add a timeout for shutdown
        shutdownComplete := make(chan struct{})
        go func() {
                wg.Wait()
                close(shutdownComplete)
        }()

        select {
        case <-shutdownComplete:
                logger.Println("INFO: All goroutines finished. Server shutdown complete.")
        case <-time.After(10 * time.Second): // Timeout for shutdown
                logger.Println("WARN: Timeout waiting for goroutines to finish. Forcing exit.")
        }
}
