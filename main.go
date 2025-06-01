package main

import (
	"encoding/hex"
	"flag"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/shakboss/Go-server/blob/main/config"
	"github.com/shakboss/Go-server/blob/main/crypto"
	"github.com/shakboss/Go-server/blob/main/ippool"
	"github.com/shakboss/Go-server/blob/main/session"
	"github.com/shakboss/Go-server/blob/main/sshauth"
	"github.com/shakboss/Go-server/blob/main/tun"
	"github.com/shakboss/Go-server/blob/main/tunhandler"
	"github.com/shakboss/Go-server/blob/main/udphandler"
)

var (
	configFile = flag.String("config", "server_config.json", "Path to the configuration file")
)

func main() {
	flag.Parse()

	// 1. Load Configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("Loaded config: %+v", cfg)

	// Convert master key from hex
	masterKey, err := crypto.MasterKeyFromHex(cfg.MasterKeyHex)
	if err != nil {
		log.Fatalf("Invalid master key in config: %v", err)
	}

	// 2. Initialize TUN Device
	tunDevice, err := tun.NewTunDevice(cfg.TunDeviceName, cfg.TunServerIP, cfg.TunNetmask)
	if err != nil {
		log.Fatalf("Failed to initialize TUN device: %v", err)
	}
	defer tunDevice.Close() // Ensure TUN is closed on exit

	// 3. Initialize IP Pool
	ipPool, err := ippool.NewIPPool(cfg.ClientIPPoolStart, cfg.ClientIPPoolEnd)
	if err != nil {
		log.Fatalf("Failed to initialize IP pool: %v", err)
	}

	// 4. Initialize Session Manager
	// Session Manager will release IP addresses when sessions time out
	sessionManager := session.NewSessionManager(cfg.SessionTimeoutSeconds, ipPool.Release)

	// 5. Setup Channel for TUN to UDP communication
	udpSendChan := make(chan udphandler.EncryptedPacket, 1024) // Buffer channel

	// 6. Initialize UDP Data Handler (receives from clients, sends to TUN)
	udpHandler, err := udphandler.NewUDPHandler(cfg.ListenUDPPort, sessionManager, tunDevice, masterKey, udpSendChan)
	if err != nil {
		log.Fatalf("Failed to initialize UDP handler: %v", err)
	}
	go udpHandler.Start() // Start listening for UDP packets

	// 7. Initialize TUN Handler (receives from TUN, sends to clients via UDPHandler)
	tunHandler := tunhandler.NewTUNHandler(tunDevice, sessionManager, udpSendChan)
	go tunHandler.Start() // Start reading from TUN device

	// 8. Start UDP Packet Sender (from TUNHandler to clients)
	go func() {
		for pkt := range udpSendChan {
			udpHandler.SendEncryptedPacket(pkt)
		}
	}()

	// 9. Initialize SSH Authentication Server
	sshAuthServer, err := sshauth.NewSSHAuthServer(
		cfg.ListenTCPAuthPort,
		cfg.SSHHostKeyPath,
		cfg.AuthorizedKeysDir,
		sessionManager,
		ipPool,
		masterKey,
		cfg.ClientDNSServers,
		cfg.ClientRoutes,
	)
	if err != nil {
		log.Fatalf("Failed to initialize SSH authentication server: %v", err)
	}
	go sshAuthServer.Start() // Start SSH listener

	// 10. Start Session Cleanup Goroutine
	go sessionManager.CleanupInactiveSessions()

	log.Println("VPN server started successfully!")

	// Keep main goroutine alive until interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down VPN server...")
	// Add graceful shutdown logic here if needed (e.g., closing listeners, channels)
	// For now, defer tunDevice.Close() handles the TUN part.
}

// Helper function to generate an SSH host key if it doesn't exist.
// For production, you'd manage this securely.
func ensureSSHHostKey(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("SSH host key not found at %s. Generating a new one...", path)
		cmd := exec.Command("ssh-keygen", "-t", "rsa", "-b", "4096", "-f", path, "-N", "") // -N "" for no passphrase
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to generate SSH host key: %s, %w", string(output), err)
		}
		log.Printf("Generated SSH host key at %s", path)
	}
	return nil
}

// generateMasterKey is a one-time use helper to get a random master key hex string.
// DO NOT call this in production code; generate once and store securely.
func generateMasterKey() {
	key, _ := crypto.GenerateRandomBytes(crypto.MasterKeyLen)
	log.Printf("Generated Master Key (Hex): %s", hex.EncodeToString(key))
}

func init() {
	// Call this once to generate a master key for your config, then hardcode it or put it in config.
	// generateMasterKey()
}
