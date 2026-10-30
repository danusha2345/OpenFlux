//go:build linux && !android

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/p1neappleXpress/OpenFlux/netbind"
	"github.com/p1neappleXpress/OpenFlux/routing"
	"github.com/p1neappleXpress/OpenFlux/transport"
	"github.com/p1neappleXpress/OpenFlux/tunnel"
	"github.com/p1neappleXpress/OpenFlux/utils"
	"golang.zx2c4.com/wireguard/tun"
)

type TUNClient struct {
	trans          transport.Transport
	dev            tun.Device
	name, guard    string
	mtu            int
	closed         atomic.Bool
	guardInstalled bool
	dnsConfigured  bool
	guardPipe      *os.File
	guardProcess   *exec.Cmd
}

func NewTUNClient(trans transport.Transport, mtu int) (*TUNClient, error) {
	for _, command := range []string{"ip", "nft", "resolvectl"} {
		if _, err := exec.LookPath(command); err != nil {
			return nil, fmt.Errorf("full tunnel requires %s: %w", command, err)
		}
	}
	dev, err := tun.CreateTUN("oflux%d", mtu)
	if err != nil {
		return nil, fmt.Errorf("create TUN (requires root): %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	return &TUNClient{trans: trans, dev: dev, name: name, mtu: mtu, guard: fmt.Sprintf("openflux_%d", os.Getpid())}, nil
}
func (c *TUNClient) Name() string    { return c.name }
func (c *TUNClient) Gateway() string { return fmt.Sprintf("physical interface %d", netbind.Index()) }
func (c *TUNClient) SaveDefault() error {
	if netbind.Bound() {
		return nil
	}
	_, err := netbind.BindDefault()
	return err
}
func linuxCommand(command string, args ...string) error {
	out, err := exec.Command(command, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", command, err, strings.TrimSpace(string(out)))
	}
	return nil
}
func (c *TUNClient) SetupInterface() error {
	for _, args := range [][]string{
		{"addr", "add", "10.10.10.2/24", "dev", c.name},
		{"-6", "addr", "add", "fd0f:1f10:ec5::2/64", "dev", c.name, "nodad"},
		{"link", "set", "dev", c.name, "mtu", fmt.Sprint(c.mtu), "up"},
	} {
		if err := linuxCommand("ip", args...); err != nil {
			return err
		}
	}
	return nil
}

// The inet output hook covers both IP families, including sockets bound to
// another interface. Only marked carrier sockets and local IPC bypass TUN.
func linuxGuardScript(table, iface string) string {
	script := fmt.Sprintf(`add table inet %s
add chain inet %s output { type filter hook output priority -150; policy drop; }
add rule inet %s output oifname "lo" accept
add rule inet %s output meta mark 0x%x accept
add rule inet %s output meta nfproto ipv6 reject
add rule inet %s output oifname %q accept
add rule inet %s output udp sport 68 udp dport 67 accept
`, table, table, table, table, netbind.SocketMark, table, table, iface, table)
	if tunBypass != nil && tunBypass.LAN {
		var rules string
		for _, p := range routing.LANPrefixes() {
			family := "ip"
			if p.Addr().Is6() {
				family = "ip6"
			}
			rules += fmt.Sprintf("add rule inet %s output %s daddr %s accept\n", table, family, p)
		}
		// Insert before the IPv6 reject; keep loopback and marked-socket rules.
		marker := fmt.Sprintf("add rule inet %s output meta nfproto ipv6 reject", table)
		script = strings.Replace(script, marker, rules+marker, 1)
	}
	return script
}
func (c *TUNClient) ConfigureDefault() error {
	// A separate process waits for this pipe to close. On SIGKILL or a
	// panic it removes our rules as well; it never changes another table.
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		reader.Close()
		writer.Close()
		return err
	}
	cleanup := exec.Command("/bin/sh", "-c", `cat >/dev/null; "$1" delete table inet "$2"`, "openflux-cleanup", nft, c.guard)
	cleanup.Stdin = reader
	if err := cleanup.Start(); err != nil {
		reader.Close()
		writer.Close()
		return err
	}
	reader.Close()
	c.guardPipe, c.guardProcess = writer, cleanup
	cmd := exec.Command(nft, "-f", "-")
	cmd.Stdin = strings.NewReader(linuxGuardScript(c.guard, c.name))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("install leak guard: %w: %s", err, strings.TrimSpace(string(out)))
	}
	c.guardInstalled = true
	for _, family := range []struct {
		flag     string
		prefixes []string
	}{
		{"-4", []string{"0.0.0.0/1", "128.0.0.0/1"}}, {"-6", []string{"::/1", "8000::/1"}},
	} {
		for _, prefix := range family.prefixes {
			if err := linuxCommand("ip", family.flag, "route", "add", prefix, "dev", c.name); err != nil {
				return err
			}
		}
	}
	// Set DNS before announcing readiness; never alter global resolv.conf.
	if err := linuxCommand("resolvectl", "dns", c.name, "1.1.1.1"); err != nil {
		return err
	}
	c.dnsConfigured = true
	if err := linuxCommand("resolvectl", "domain", c.name, "~."); err != nil {
		return err
	}
	return linuxCommand("resolvectl", "default-route", c.name, "yes")
}
func (c *TUNClient) Start() {
	c.trans.Receive(func(pkt []byte) {
		if !c.closed.Load() {
			tunnel.ClampDeviceSyn(c.trans, pkt)
			if _, err := c.dev.Write([][]byte{pkt}, 0); err != nil {
				utils.Debugf("[TUN] write: %v", err)
			}
		}
	})
	go func() {
		bufs := [][]byte{make([]byte, 65535)}
		sizes := []int{0}
		for !c.closed.Load() {
			n, err := c.dev.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			if n == 0 || sizes[0] < 20 || bufs[0][0]>>4 != 4 {
				continue
			}
			pkt := append([]byte(nil), bufs[0][:sizes[0]]...)
			if err := tunnel.SendFromDevice(c.trans, pkt); err != nil {
				utils.Debugf("[TUN] send: %v", err)
			}
		}
	}()
}
func (c *TUNClient) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	if c.dnsConfigured {
		_ = linuxCommand("resolvectl", "revert", c.name)
	}
	err := c.dev.Close() // Interface destruction also removes its routes.
	if c.guardPipe != nil {
		_ = c.guardPipe.Close()
		if guardErr := c.guardProcess.Wait(); guardErr != nil && c.guardInstalled {
			return fmt.Errorf("remove leak guard: %w", guardErr)
		}
	}
	return err
}
func (c *TUNClient) RestoreDefault()       {}
func (c *TUNClient) purgeStaleHostRoutes() {}

type SocketWatcher struct{ onStable func() }

func NewSocketWatcher(gateway string, onStable func()) *SocketWatcher {
	return &SocketWatcher{onStable: onStable}
}
func (w *SocketWatcher) Start(interval time.Duration) { go w.onStable() }
func (w *SocketWatcher) Stop()                        {}
