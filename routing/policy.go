// Package routing holds explicit client-side VPN exceptions. Unknown flows stay in the VPN.
package routing

import (
	"fmt"
	"golang.org/x/net/idna"
	"net/netip"
	"strings"
)

type Config struct {
	LAN     bool     `json:"lan"`
	Domains []string `json:"domains"`
	Apps    []string `json:"apps"`
}
type Policy struct{ Config }

func New(c Config) (*Policy, error) {
	p := &Policy{Config: c}
	p.Domains = nil
	p.Apps = nil
	for _, d := range c.Domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		d = strings.TrimPrefix(d, "*.")
		d = strings.TrimSuffix(d, ".")
		a, err := idna.Lookup.ToASCII(d)
		if err != nil || strings.ContainsAny(a, "/:\\ \t\r\n") || a == "" {
			return nil, fmt.Errorf("invalid bypass domain %q", d)
		}
		for _, l := range strings.Split(a, ".") {
			if l == "" {
				return nil, fmt.Errorf("invalid bypass domain %q", d)
			}
		}
		p.Domains = append(p.Domains, strings.ToLower(a))
	}
	for _, a := range c.Apps {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if strings.ContainsAny(a, "\r\n\x00") || !strings.HasSuffix(strings.ToLower(a), ".exe") {
			return nil, fmt.Errorf("bypass application must be an .exe file")
		}
		p.Apps = append(p.Apps, normalizeApp(a))
	}
	return p, nil
}
func (p *Policy) Enabled() bool { return p != nil && (p.LAN || len(p.Domains) > 0 || len(p.Apps) > 0) }
func (p *Policy) Domain(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range p.Domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
func normalizeApp(s string) string { return strings.ToLower(strings.ReplaceAll(s, "\\", "/")) }
func (p *Policy) App(path string) bool {
	path = normalizeApp(path)
	for _, a := range p.Apps {
		if path == a || (!strings.Contains(a, "/") && strings.HasSuffix(path, "/"+a)) {
			return true
		}
	}
	return false
}
func (p *Policy) Local(host string) bool {
	if !p.LAN || host == "" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return IsLAN(ip)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return !strings.Contains(host, ".") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".home")
}

// Link-local multicast is included for local discovery. Public destinations are never admitted here.
func LANPrefixes() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/24"), netip.MustParsePrefix("239.0.0.0/8"), netip.MustParsePrefix("255.255.255.255/32"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff02::/16")}
}
func IsLAN(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range LANPrefixes() {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Owner identifies a flow by its original OS socket tuple, before userspace forwarding.
type Owner func(network, source, destination string) (string, error)
