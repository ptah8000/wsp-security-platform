package proxy

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSDialer is a ContextDialer that can use administrator-configured DNS servers.
type DNSDialer struct {
	mu      sync.RWMutex
	servers []string // host or host:port
	timeout time.Duration
}

// NewDNSDialer builds a dialer. Empty servers uses the system resolver.
func NewDNSDialer(servers []string) *DNSDialer {
	d := &DNSDialer{timeout: 30 * time.Second}
	d.SetServers(servers)
	return d
}

// SetServers replaces the DNS server list (empty = system resolver).
func (d *DNSDialer) SetServers(servers []string) {
	if d == nil {
		return
	}
	clean := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// Accept IP or host; add port 53 when missing.
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		clean = append(clean, s)
	}
	d.mu.Lock()
	d.servers = clean
	d.mu.Unlock()
}

// Servers returns a copy of configured DNS endpoints.
func (d *DNSDialer) Servers() []string {
	if d == nil {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, len(d.servers))
	copy(out, d.servers)
	return out
}

// DialContext dials network/address using the custom or system resolver.
func (d *DNSDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: d.timeout}
	if d != nil {
		d.mu.RLock()
		servers := append([]string(nil), d.servers...)
		d.mu.RUnlock()
		if len(servers) > 0 {
			dialer.Resolver = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					var last error
					rd := net.Dialer{Timeout: 5 * time.Second}
					for _, srv := range servers {
						// DNS typically uses UDP; fall back to TCP on failure.
						c, err := rd.DialContext(ctx, "udp", srv)
						if err == nil {
							return c, nil
						}
						last = err
						c, err = rd.DialContext(ctx, "tcp", srv)
						if err == nil {
							return c, nil
						}
						last = err
					}
					return nil, last
				},
			}
		}
	}
	return dialer.DialContext(ctx, network, address)
}
