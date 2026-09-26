package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestMobileYandexRouteBootstrap(t *testing.T) {
	var secureCalls, systemCalls int
	secure := func(_ context.Context, host string) ([]net.IPAddr, error) {
		secureCalls++
		return nil, errors.New("DoT unavailable")
	}
	system := func(_ context.Context, host string) ([]net.IPAddr, error) {
		systemCalls++
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.7")}, {IP: net.ParseIP("10.1.2.3")}, {IP: net.ParseIP("100.64.1.2")}}, nil
	}
	routes, err := planMobileRoutes(context.Background(), "vyandex",
		"https://disk.yandex.ru/i/one, https://docs.yandex.ru/edit/two", secure, system)
	if err != nil {
		t.Fatal(err)
	}
	if secureCalls != 5 || systemCalls != 5 {
		t.Fatalf("lookups: secure=%d system=%d", secureCalls, systemCalls)
	}
	var resolved, private, resolver, prefix bool
	for _, route := range routes {
		switch route.Destination {
		case "203.0.113.7":
			resolved = route.Mask == "255.255.255.255"
		case "10.1.2.3", "100.64.1.2":
			private = true
		case "1.1.1.1":
			resolver = true
		case "77.88.0.0":
			prefix = route.Mask == "255.255.192.0"
		}
	}
	if !resolved || private || !resolver || !prefix {
		t.Fatalf("unexpected route plan: %+v", routes)
	}
}

func TestMobileRouteBootstrapRejectsUnsafeInput(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) { return nil, nil }
	for _, raw := range []string{
		"http://docs.yandex.ru/edit/x", "https://docs.yandex.ru.evil.test/edit/x",
		"https://example.test/edit/x",
	} {
		if _, err := planMobileRoutes(context.Background(), "yandex", raw, lookup, lookup); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	if _, err := planMobileRoutes(context.Background(), "mailru", "", lookup, lookup); err == nil || !strings.Contains(err.Error(), "cannot resolve") {
		t.Fatalf("unresolved carrier error = %v", err)
	}
	systemCalls := 0
	system := func(_ context.Context, _ string) ([]net.IPAddr, error) {
		systemCalls++
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.7")}}, nil
	}
	if _, err := planMobileRoutes(context.Background(), "oneme", "", lookup, system); err == nil || systemCalls != 0 {
		t.Fatalf("MAX accepted system DNS: err=%v calls=%d", err, systemCalls)
	}
}
