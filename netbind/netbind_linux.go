//go:build linux && !android

package netbind

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// SocketMark identifies the privileged core's control-plane sockets.
const SocketMark = 0x0f1f10

var boundIndex uint32

func Index() uint32 { return boundIndex }

// BindDefault chooses the physical default from the main table before TUN
// setup. SO_BINDTODEVICE keeps carrier traffic out of the split defaults.
func BindDefault() (uint32, error) {
	out, err := exec.Command("ip", "-j", "-4", "route", "show", "default", "table", "main").Output()
	if err != nil {
		return 0, fmt.Errorf("physical default: %w", err)
	}
	dev, err := defaultDevice(out)
	if err != nil {
		return 0, err
	}
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return 0, err
	}
	boundIndex = uint32(iface.Index)
	install(func(network, address string, c syscall.RawConn) error {
		if host, _, err := net.SplitHostPort(address); err == nil {
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				return nil
			}
		}
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev)
			if sockErr == nil {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, SocketMark)
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	})
	// resolved's loopback stub would route its upstream requests into TUN;
	// carrier bootstrap must use a bound external resolver instead.
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return Dialer(10*time.Second).DialContext(ctx, network, "1.1.1.1:53")
	}}
	return boundIndex, nil
}

func defaultDevice(data []byte) (string, error) {
	var routes []struct {
		Dev    string `json:"dev"`
		Metric int    `json:"metric"`
		Type   string `json:"type"`
	}
	if err := json.Unmarshal(data, &routes); err != nil {
		return "", err
	}
	best := ""
	metric := int(^uint(0) >> 1)
	for _, r := range routes {
		if r.Dev != "" && (r.Type == "" || r.Type == "unicast") && r.Metric < metric {
			best = r.Dev
			metric = r.Metric
		}
	}
	if best == "" {
		return "", fmt.Errorf("no physical IPv4 default route in main table")
	}
	return best, nil
}
