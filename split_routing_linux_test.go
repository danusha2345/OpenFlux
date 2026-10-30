//go:build linux && !android

package main

import (
	"github.com/p1neappleXpress/OpenFlux/routing"
	"strings"
	"testing"
)

func TestLANRuleDoesNotRemoveLinuxKillSwitch(t *testing.T) {
	old := tunBypass
	defer func() { tunBypass = old }()
	tunBypass, _ = routing.New(routing.Config{LAN: true})
	script := linuxGuardScript("openflux_test", "oflux0")
	if !strings.Contains(script, "ip daddr 192.168.0.0/16 accept") || !strings.Contains(script, "policy drop") || strings.Index(script, "ip6 daddr fe80::/10 accept") > strings.Index(script, "meta nfproto ipv6 reject") {
		t.Fatal(script)
	}
	tunBypass = nil
	off := linuxGuardScript("openflux_test", "oflux0")
	if strings.Contains(off, "daddr") {
		t.Fatal("LAN exception enabled by default")
	}
}
