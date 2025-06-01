package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
)

type Config struct {
	ListenUDPPort         int          `json:"listen_udp_port"`
	ListenTCPAuthPort     int          `json:"listen_tcp_auth_port"`
	TunDeviceName         string       `json:"tun_device_name"`
	TunServerIP           string       `json:"tun_server_ip"`
	TunNetmask            string       `json:"tun_netmask"`
	ClientIPPoolStart     string       `json:"client_ip_pool_start"`
	ClientIPPoolEnd       string       `json:"client_ip_pool_end"`
	AuthorizedKeysDir     string       `json:"authorized_keys_dir"`
	SSHHostKeyPath        string       `json:"ssh_host_key_path"`
	MasterKeyHex          string       `json:"master_key_hex"` // For session token signing/encryption
	SessionTimeoutSeconds int          `json:"session_timeout_seconds"`
	ClientDNSServers      []string     `json:"client_dns_servers"`
	ClientRoutes          []string     `json:"client_routes"` // CIDR blocks, e.g., ["0.0.0.0/0"]
	LogLevel              string       `json:"log_level"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Basic validation
	if cfg.ListenUDPPort == 0 || cfg.ListenTCPAuthPort == 0 || cfg.TunDeviceName == "" ||
		cfg.TunServerIP == "" || cfg.TunNetmask == "" || cfg.ClientIPPoolStart == "" ||
		cfg.ClientIPPoolEnd == "" || cfg.AuthorizedKeysDir == "" || cfg.SSHHostKeyPath == "" ||
		cfg.MasterKeyHex == "" || cfg.SessionTimeoutSeconds == 0 {
		return nil, fmt.Errorf("missing essential configuration parameters")
	}

	// Validate IPs (basic check)
	if net.ParseIP(cfg.TunServerIP) == nil || net.ParseIP(cfg.ClientIPPoolStart) == nil ||
		net.ParseIP(cfg.ClientIPPoolEnd) == nil {
		return nil, fmt.Errorf("invalid IP address format in config")
	}

	return &cfg, nil
}
