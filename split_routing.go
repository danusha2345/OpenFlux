package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/p1neappleXpress/OpenFlux/netbind"
	"github.com/p1neappleXpress/OpenFlux/routing"
	"github.com/p1neappleXpress/OpenFlux/transport"
	"github.com/p1neappleXpress/OpenFlux/tunnel"
	"io"
	"net"
	"os"
	"time"
)

var tunBypass *routing.Policy

func loadBypass(path string) (*routing.Policy, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if e != nil {
		return nil, e
	}
	if len(data) > 64<<10 {
		return nil, fmt.Errorf("bypass configuration exceeds 64 KiB")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c routing.Config
	if e = dec.Decode(&c); e != nil {
		return nil, e
	}
	if e = dec.Decode(new(any)); e != io.EOF {
		return nil, fmt.Errorf("invalid trailing bypass configuration")
	}
	return routing.New(c)
}
func splitTransport(raw transport.Transport) (transport.Transport, func(), error) {
	if !tunBypass.Enabled() {
		return raw, func() {}, nil
	}
	var owner routing.Owner
	if len(tunBypass.Apps) > 0 {
		var e error
		owner, e = routing.NewOwner()
		if e != nil {
			return nil, nil, e
		}
	}
	resolver, e := netbind.PhysicalResolver()
	if e != nil {
		return nil, nil, e
	}
	direct := func(network, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if network == "dns" {
			return resolver.Dial(ctx, "tcp", address)
		}
		d := netbind.Dialer(10 * time.Second)
		d.Resolver = resolver
		return d.DialContext(ctx, network+"4", address)
	}
	r := tunnel.NewSplitTransport(raw, tunBypass, direct, owner)
	return r, func() { _ = r.Stop() }, nil
}
