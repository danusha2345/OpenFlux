//go:build windows

package netbind

import (
	"context"
	"golang.org/x/sys/windows"
	"net"
	"time"
	"unsafe"
)

// Snapshot the physical adapter's resolver before TUN changes DNS settings.
func PhysicalResolver() (*net.Resolver, error) {
	server := "1.1.1.1:53"
	size := uint32(16384)
	for tries := 0; tries < 5; tries++ {
		if size > 1<<20 {
			break
		}
		b := make([]byte, size)
		a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0]))
		e := windows.GetAdaptersAddresses(windows.AF_INET, 0, 0, a, &size)
		if e == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if e != nil {
			break
		}
		found := false
		for ; a != nil; a = a.Next {
			if a.IfIndex != Index() {
				continue
			}
			for s := a.FirstDnsServerAddress; s != nil; s = s.Next {
				if s.Address.Sockaddr == nil {
					continue
				}
				ip := s.Address.IP()
				if ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
					server = net.JoinHostPort(ip.String(), "53")
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		break
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return Dialer(10*time.Second).DialContext(ctx, network, server)
	}}, nil
}
