package tun

import (
	"fmt"
	"log"
	"net"
	"os/exec"

	"github.com/songgao/water"
	"golang.org/x/sys/unix"
)

// MaxIPPacketSize is typically 1500 (Ethernet MTU) minus IP/UDP headers
const MaxIPPacketSize = 1500 // Assuming full Ethernet MTU, adjust as needed

type TunDevice struct {
	iface *water.Interface
	name  string
}

func NewTunDevice(name, ipAddr, netmask string) (*TunDevice, error) {
	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	log.Printf("TUN device %s created", iface.Name())

	// Set IP address and netmask, and bring interface up
	if err := setIPAndUp(iface.Name(), ipAddr, netmask); err != nil {
		iface.Close() // Clean up on error
		return nil, fmt.Errorf("failed to configure TUN interface %s: %w", iface.Name(), err)
	}

	log.Printf("TUN device %s configured with IP %s/%s", iface.Name(), ipAddr, netmask)

	return &TunDevice{iface: iface, name: iface.Name()}, nil
}

func (t *TunDevice) Read(b []byte) (int, error) {
	return t.iface.Read(b)
}

func (t *TunDevice) Write(b []byte) (int, error) {
	return t.iface.Write(b)
}

func (t *TunDevice) Close() error {
	log.Printf("Closing TUN device %s", t.name)
	return t.iface.Close()
}

// setIPAndUp uses netlink/exec to configure the interface.
// For production, consider using a netlink library directly (e.g., github.com/vishvananda/netlink).
func setIPAndUp(name, ipAddr, netmask string) error {
	// Set IP address and netmask
	cmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", ipAddr, netmask), "dev", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set IP: %s, %w", string(output), err)
	}

	// Bring the interface up
	cmd = exec.Command("ip", "link", "set", "dev", name, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring up interface: %s, %w", string(output), err)
	}

	// Add routes if necessary for the TUN network (e.g., to reach client IPs)
	// Example: Add route for the entire client subnet through the TUN device
	// This might be done elsewhere, but for simplicity, adding it here.
	// You might also need to ensure IP forwarding is enabled: `sysctl -w net.ipv4.ip_forward=1`

	return nil
}

// GetDestinationIP extracts the destination IP from an IP packet (IPv4 only for now)
func GetDestinationIP(packet []byte) (net.IP, error) {
	if len(packet) < unix.IP_HDRLEN { // Minimal IP header length (20 bytes for IPv4)
		return nil, fmt.Errorf("packet too short for IP header")
	}
	// Basic IPv4 header check: Version (first 4 bits) should be 4
	if (packet[0] >> 4) != 4 {
		return nil, fmt.Errorf("not an IPv4 packet")
	}
	// Destination IP is bytes 16-19
	return net.IP(packet[16:20]), nil
}

// GetSourceIP extracts the source IP from an IP packet (IPv4 only for now)
func GetSourceIP(packet []byte) (net.IP, error) {
	if len(packet) < unix.IP_HDRLEN {
		return nil, fmt.Errorf("packet too short for IP header")
	}
	// Source IP is bytes 12-15
	return net.IP(packet[12:16]), nil
}
