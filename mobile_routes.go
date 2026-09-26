package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

type mobileRoute struct {
	Destination string `json:"destination"`
	Mask        string `json:"mask"`
}

type mobileLookup func(context.Context, string) ([]net.IPAddr, error)

var mobileYandexPrefixes = [...]string{
	"5.45.192.0/18", "5.255.192.0/18", "37.9.64.0/18", "37.140.128.0/18",
	"77.88.0.0/18", "84.201.128.0/18", "87.250.224.0/19", "90.156.176.0/22",
	"93.158.128.0/18", "95.108.128.0/17", "100.43.64.0/19",
	"178.154.128.0/17", "213.180.192.0/19",
}

var mobileBlockedIPv4 = [...]netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
}

func mobileCarrierHosts(kind, rawURL string) ([]string, bool, error) {
	switch kind {
	case "yandex", "vyandex":
		urls := splitURLs(rawURL)
		if len(urls) > 8 {
			return nil, false, errors.New("too many Yandex documents")
		}
		hosts := []string{"disk.yandex.ru", "docs.yandex.ru", "docviewer.yandex.ru"}
		for _, raw := range urls {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" {
				return nil, false, errors.New("invalid Yandex document URL")
			}
			host := strings.ToLower(u.Hostname())
			if host != "yandex.ru" && !strings.HasSuffix(host, ".yandex.ru") {
				return nil, false, errors.New("document URL is outside yandex.ru")
			}
			hosts = append(hosts, host)
		}
		if kind == "vyandex" {
			hosts = append(hosts, "volga.yandex.ru", "push.yandex.ru")
		}
		return hosts, true, nil
	case "mailru":
		return []string{"cloud.mail.ru", "docs.datacloudmail.ru"}, false, nil
	case "cupsonline":
		return []string{"interview.cups.online"}, false, nil
	case "oneme":
		return []string{"ws-api.oneme.ru", "web.max.ru"}, false, nil
	default:
		return nil, false, errors.New("unsupported mobile transport")
	}
}

// planMobileRoutes runs before the VPN's default route is installed. Only
// Yandex bootstrap endpoints may use native DNS before route capture;
// application DNS and other carriers remain DoT-only. A failed lookup for an
// unbounded carrier fails closed.
func planMobileRoutes(ctx context.Context, kind, rawURL string, secure, system mobileLookup) ([]mobileRoute, error) {
	hosts, yandex, err := mobileCarrierHosts(kind, rawURL)
	if err != nil {
		return nil, err
	}
	addresses := map[netip.Addr]bool{}
	for _, s := range []string{"77.88.8.8", "8.8.8.8", "1.1.1.1"} {
		addresses[netip.MustParseAddr(s)] = true
	}
	seen := map[string]bool{}
	for _, host := range hosts {
		if seen[host] {
			continue
		}
		seen[host] = true
		ips := mobileLookupIPv4(ctx, host, secure)
		if len(ips) == 0 && yandex {
			ips = mobileLookupIPv4(ctx, host, system)
		}
		if len(ips) == 0 && !yandex {
			return nil, errors.New("cannot resolve carrier endpoint before VPN starts")
		}
		for _, ip := range ips {
			addresses[ip] = true
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	routes := make([]mobileRoute, 0, len(addresses)+len(mobileYandexPrefixes))
	if yandex {
		for _, raw := range mobileYandexPrefixes {
			prefix := netip.MustParsePrefix(raw)
			routes = append(routes, mobileRoute{prefix.Addr().String(), net.IP(net.CIDRMask(prefix.Bits(), 32)).String()})
		}
	}
	for ip := range addresses {
		routes = append(routes, mobileRoute{ip.String(), "255.255.255.255"})
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Destination == routes[j].Destination {
			return routes[i].Mask < routes[j].Mask
		}
		return routes[i].Destination < routes[j].Destination
	})
	return routes, nil
}

func mobileLookupIPv4(ctx context.Context, host string, lookup mobileLookup) []netip.Addr {
	if lookup == nil || ctx.Err() != nil {
		return nil
	}
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	result, err := lookup(callCtx, host)
	if err != nil || callCtx.Err() != nil {
		return nil
	}
	seen := map[netip.Addr]bool{}
	var ips []netip.Addr
	for _, raw := range result {
		ip, ok := netip.AddrFromSlice(raw.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || seen[ip] {
			continue
		}
		blocked := false
		for _, prefix := range mobileBlockedIPv4 {
			if prefix.Contains(ip) {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	return ips
}

func resolveMobileBypassRoutes(kind, rawURL string) ([]mobileRoute, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	system := (&net.Resolver{PreferGo: false}).LookupIPAddr
	return planMobileRoutes(ctx, kind, rawURL, net.DefaultResolver.LookupIPAddr, system)
}
