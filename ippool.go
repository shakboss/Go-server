package ippool

import (
	"fmt"
	"log"
	"net"
	"sync"
)

type IPPool struct {
	sync.Mutex
	pool      []net.IP
	allocated map[string]net.IP // map[IP_string]assigned_IP
	freeIdx   int
}

func NewIPPool(startIP, endIP string) (*IPPool, error) {
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)

	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid start or end IP address")
	}
	if start.To4() == nil || end.To4() == nil {
		return nil, fmt.Errorf("only IPv4 supported for IP pool")
	}

	var ips []net.IP
	current := make(net.IP, len(start))
	copy(current, start)

	for {
		ips = append(ips, make(net.IP, len(current)))
		copy(ips[len(ips)-1], current)

		// Increment IP
		for i := len(current) - 1; i >= 0; i-- {
			current[i]++
			if current[i] != 0 {
				break
			}
		}

		if current.Equal(end) {
			ips = append(ips, make(net.IP, len(current)))
			copy(ips[len(ips)-1], current)
			break
		}
		if current.To4()[0] > end.To4()[0] && current.To4()[1] > end.To4()[1] && current.To4()[2] > end.To4()[2] && current.To4()[3] > end.To4()[3] {
            // Prevent infinite loop if end is effectively before start or invalid range
            break
        }
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("empty IP pool range provided")
	}

	log.Printf("Initialized IP pool with %d addresses from %s to %s", len(ips), startIP, endIP)

	return &IPPool{
		pool:      ips,
		allocated: make(map[string]net.IP),
		freeIdx:   0,
	}, nil
}

func (p *IPPool) Allocate(username string) (net.IP, error) {
	p.Lock()
	defer p.Unlock()

	// Simple check if user already has an IP (for reconnection scenarios)
	if existingIP, ok := p.allocated[username]; ok {
		log.Printf("User %s already has assigned IP %s, re-using.", username, existingIP)
		return existingIP, nil
	}

	if p.freeIdx >= len(p.pool) {
		return nil, fmt.Errorf("no available IP addresses in pool")
	}

	ip := p.pool[p.freeIdx]
	p.freeIdx++
	p.allocated[username] = ip // Map username to assigned IP
	log.Printf("Allocated IP %s for user %s. Remaining free: %d", ip, username, len(p.pool)-p.freeIdx)
	return ip, nil
}

func (p *IPPool) Release(username string) {
	p.Lock()
	defer p.Unlock()

	if ip, ok := p.allocated[username]; ok {
		// A simple way to release - not putting it back into `pool` array right now
		// For a more robust solution, you'd use a free list or similar.
		delete(p.allocated, username)
		log.Printf("Released IP %s for user %s.", ip, username)
		// Note: The `freeIdx` is not decremented, meaning IPs are effectively released
		// at the end of the pool, or by just removing from `allocated` map.
		// A more advanced pool would re-add released IPs for reuse.
	}
}

func (p *IPPool) GetIPForUsername(username string) (net.IP, bool) {
	p.Lock()
	defer p.Unlock()
	ip, ok := p.allocated[username]
	return ip, ok
}
