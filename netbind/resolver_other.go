//go:build !windows

package netbind

import (
	"context"
	"net"
	"time"
)

// Bootstrap resolver follows netbind and never loops into our own TUN.
func PhysicalResolver() (*net.Resolver, error) {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return Dialer(10*time.Second).DialContext(ctx, network, "1.1.1.1:53")
	}}, nil
}
