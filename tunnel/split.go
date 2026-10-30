package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/p1neappleXpress/OpenFlux/routing"
	"github.com/p1neappleXpress/OpenFlux/transport"
	"github.com/p1neappleXpress/OpenFlux/utils"
)

// SplitDialer keeps the original socket tuple for application rules. DNS names
// have separate synthetic addresses, so sharing a CDN IP never bypasses another site.
type SplitDialer struct {
	Policy *routing.Policy
	VPN    interface {
		TCPDialer
		UDPDialer
	}
	Direct func(network, address string) (net.Conn, error)
	Owner  routing.Owner
	dns    *fakeDNS
}

func NewSplitDialer(p *routing.Policy, vpn interface {
	TCPDialer
	UDPDialer
}, direct func(string, string) (net.Conn, error), owner routing.Owner) *SplitDialer {
	return &SplitDialer{Policy: p, VPN: vpn, Direct: direct, Owner: owner, dns: newFakeDNS()}
}
func (d *SplitDialer) DialTCP(dst string) (net.Conn, error)          { return d.dial("tcp", "", dst) }
func (d *SplitDialer) DialUDP(dst string) (net.Conn, error)          { return d.dial("udp", "", dst) }
func (d *SplitDialer) DialTCPFrom(src, dst string) (net.Conn, error) { return d.dial("tcp", src, dst) }
func (d *SplitDialer) DialUDPFrom(src, dst string) (net.Conn, error) { return d.dial("udp", src, dst) }
func (d *SplitDialer) dial(network, source, dest string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(dest)
	if e != nil {
		return nil, e
	}
	if port == "53" {
		return d.dnsConn(network), nil
	}
	if ip := net.ParseIP(host).To4(); ip != nil && ip[0] == 198 && ip[1] == 18 {
		name, ok := d.dns.nameFor([4]byte(ip))
		if !ok {
			return nil, fmt.Errorf("unknown split DNS address")
		}
		host = name
	}
	direct := d.Policy.Domain(host) || d.Policy.Local(host)
	if !direct && d.Owner != nil && source != "" {
		if app, err := d.Owner(network, source, dest); err == nil {
			direct = d.Policy.App(app)
		} else {
			utils.Debugf("[ROUTING] socket owner unavailable; keeping flow in VPN: %v", err)
		}
	}
	target := net.JoinHostPort(host, port)
	if direct {
		return d.Direct(network, target)
	}
	if network == "udp" {
		return d.VPN.DialUDP(target)
	}
	return d.VPN.DialTCP(target)
}
func (d *SplitDialer) dnsConn(network string) net.Conn {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, 65535)
		for {
			n := 0
			if network == "tcp" {
				var size [2]byte
				if _, err := io.ReadFull(server, size[:]); err != nil {
					return
				}
				n = int(binary.BigEndian.Uint16(size[:]))
				if n == 0 {
					return
				}
				if _, err := io.ReadFull(server, buf[:n]); err != nil {
					return
				}
			} else {
				var err error
				n, err = server.Read(buf)
				if err != nil {
					return
				}
			}
			answer := d.answerDNS(buf[:n])
			if answer == nil {
				return
			}
			if network == "tcp" {
				answer = append(binary.BigEndian.AppendUint16(nil, uint16(len(answer))), answer...)
			}
			if _, err := server.Write(answer); err != nil {
				return
			}
		}
	}()
	return client
}

// Preserve local DNS records (including SRV/PTR) and names used for LAN
// services. Other application names receive synthetic IPv4 addresses; their
// actual resolution still happens only after selecting the direct/VPN dialer.
func (d *SplitDialer) answerDNS(query []byte) []byte {
	var parser dnsmessage.Parser
	h, err := parser.Start(query)
	if err != nil || h.Response {
		return nil
	}
	qs, err := parser.AllQuestions()
	if err != nil || len(qs) != 1 {
		return d.dns.answer(query)
	}
	q := qs[0]
	host := normName(q.Name.String())
	local := d.Policy.Local(host)
	special := q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA && q.Type != dnsmessage.Type(65)
	if !local && !special {
		return d.dns.answer(query)
	}
	var c net.Conn
	if local || (special && d.Policy.Domain(host)) {
		c, err = d.Direct("dns", "1.1.1.1:53")
	} else {
		c, err = d.VPN.DialTCP("1.1.1.1:53")
	}
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)); err != nil {
		return nil
	}
	var size [2]byte
	if _, err = io.ReadFull(c, size[:]); err != nil {
		return nil
	}
	response := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err = io.ReadFull(c, response); err != nil {
		return nil
	}
	return response
}

// SplitTransport is used only for an explicitly configured desktop full tunnel.
// Other transports and the exit protocol are unchanged. The core's direct sockets
// use netbind, so they remain on the physical adapter under the kill switch.
type SplitTransport struct {
	transport.Transport
	packet *PacketTunnel
	vpn    *TCPTunnel
	recv   atomic.Pointer[func([]byte)]
	cancel context.CancelFunc
	once   sync.Once
}
type splitReceiver struct {
	transport.Transport
	other func([]byte)
}

func (t *splitReceiver) Receive(cb func([]byte)) {
	t.Transport.Receive(func(p []byte) {
		if len(p) >= 20 && (p[9] == 6 || p[9] == 17) {
			cb(p)
		} else {
			t.other(p)
		}
	})
}
func NewSplitTransport(raw transport.Transport, p *routing.Policy, direct func(string, string) (net.Conn, error), owner routing.Owner) *SplitTransport {
	r := &SplitTransport{Transport: raw}
	r.vpn = NewTCPTunnel(&splitReceiver{raw, r.deliver}, false)
	r.packet = NewPacketTunnel(NewSplitDialer(p, r.vpn, direct, owner), 1280)
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() {
		for {
			p := r.packet.ReadOutbound(ctx)
			if p == nil {
				return
			}
			r.deliver(p)
		}
	}()
	return r
}
func (r *SplitTransport) deliver(p []byte) {
	if cb := r.recv.Load(); cb != nil {
		(*cb)(p)
	}
}
func (r *SplitTransport) Receive(cb func([]byte)) { r.recv.Store(&cb) }
func (r *SplitTransport) Send(p []byte) error {
	if len(p) < 20 || p[0]>>4 != 4 {
		return fmt.Errorf("split routing requires IPv4")
	}
	if p[9] != 6 && p[9] != 17 {
		return r.Transport.Send(p)
	}
	r.packet.WriteInbound(p)
	return nil
}
func (r *SplitTransport) Stop() error {
	r.once.Do(func() { r.cancel(); r.packet.Close(); r.vpn.Close() })
	return nil
}
func (r *SplitTransport) CarrierMTU() int { return 1280 }
