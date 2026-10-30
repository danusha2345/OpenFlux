package tunnel

import (
	"encoding/binary"
	"fmt"
	"github.com/p1neappleXpress/OpenFlux/netguard"
	"github.com/p1neappleXpress/OpenFlux/routing"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type routeRecorder struct{ calls chan string }

func (r *routeRecorder) connect(n, a string) (net.Conn, error) {
	r.calls <- n + ":" + a
	x, y := net.Pipe()
	go func() { defer y.Close(); io.Copy(y, y) }()
	return x, nil
}
func (r *routeRecorder) DialTCP(a string) (net.Conn, error) { return r.connect("tcp", a) }
func (r *routeRecorder) DialUDP(a string) (net.Conn, error) { return r.connect("udp", a) }
func splitDNSQuery(t *testing.T, name string) []byte {
	t.Helper()
	n, e := dnsmessage.NewName(name + ".")
	if e != nil {
		t.Fatal(e)
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	b, e := m.Pack()
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func splitDNSAddress(t *testing.T, d *SplitDialer, name, proto string) string {
	t.Helper()
	c, e := d.dial(proto, "10.10.10.2:50000", "1.1.1.1:53")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	q := splitDNSQuery(t, name)
	if proto == "tcp" {
		q = append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)
	}
	if _, e = c.Write(q); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 2048)
	var n int
	if proto == "tcp" {
		var size [2]byte
		if _, e = io.ReadFull(c, size[:]); e != nil {
			t.Fatal(e)
		}
		n = int(binary.BigEndian.Uint16(size[:]))
		_, e = io.ReadFull(c, buf[:n])
	} else {
		n, e = c.Read(buf)
	}
	if e != nil {
		t.Fatal(e)
	}
	var response dnsmessage.Message
	if e = response.Unpack(buf[:n]); e != nil {
		t.Fatal(e)
	}
	if response.ID != 42 || len(response.Answers) != 1 {
		t.Fatal("invalid DNS answer")
	}
	a := response.Answers[0].Body.(*dnsmessage.AResource).A
	return net.IP(a[:]).String()
}
func TestSplitRoutingNamesAppsLANAndUnknownOwners(t *testing.T) {
	vpn := &routeRecorder{make(chan string, 20)}
	direct := &routeRecorder{make(chan string, 20)}
	policy, _ := routing.New(routing.Config{LAN: true, Domains: []string{"outside.test"}, Apps: []string{`C:\Torrent\anything.exe`}})
	owner := func(n, s, d string) (string, error) {
		if s == "10.10.10.2:40000" {
			return `c:\torrent\anything.exe`, nil
		}
		return "", fmt.Errorf("no owner")
	}
	d := NewSplitDialer(policy, vpn, direct.connect, owner)
	outside := splitDNSAddress(t, d, "www.outside.test", "udp")
	inside := splitDNSAddress(t, d, "inside.test", "tcp")
	if outside == inside {
		t.Fatal("sites share synthetic IP")
	}
	cases := []struct {
		proto, src, dst, want string
		direct                bool
	}{{"tcp", "", outside + ":443", "tcp:www.outside.test:443", true}, {"udp", "", inside + ":443", "udp:inside.test:443", false}, {"tcp", "10.10.10.2:40000", inside + ":443", "tcp:inside.test:443", true}, {"tcp", "10.10.10.2:40001", inside + ":443", "tcp:inside.test:443", false}, {"tcp", "", "192.168.1.1:80", "tcp:192.168.1.1:80", true}, {"udp", "10.10.10.2:40000", "8.8.8.8:50000", "udp:8.8.8.8:50000", true}}
	for _, tt := range cases {
		c, e := d.dial(tt.proto, tt.src, tt.dst)
		if e != nil {
			t.Fatal(e)
		}
		c.Close()
		ch := vpn.calls
		if tt.direct {
			ch = direct.calls
		}
		select {
		case got := <-ch:
			if got != tt.want {
				t.Fatal(got, tt.want)
			}
		case <-time.After(time.Second):
			t.Fatal("wrong route", tt)
		}
	}
	if _, e := d.DialTCP("198.18.253.253:443"); e == nil {
		t.Fatal("unmapped synthetic address must not reach another host")
	}
}

// Exercise actual IPv4 TCP/UDP packets through both gVisor stacks, with the
// same split transport the Windows/Linux TUN uses. No host routes are changed.
func TestSplitTransportPacketPathAndOriginalOwnerTuple(t *testing.T) {
	netguard.SetAllowPrivate(true)
	t.Cleanup(func() { netguard.SetAllowPrivate(false) })
	internet, exitWire := newTransportPair()
	exit := NewTCPTunnel(exitWire, true)
	defer exit.Close()
	policy, _ := routing.New(routing.Config{Domains: []string{"outside.test"}, Apps: []string{"any-torrent.exe"}})
	direct := &routeRecorder{calls: make(chan string, 8)}
	ownerCalls := make(chan string, 8)
	owner := func(n, src, dst string) (string, error) {
		ownerCalls <- n + " " + src + " " + dst
		if dst == "203.0.113.7:51413" {
			return `C:\Torrent\any-torrent.exe`, nil
		}
		return "other.exe", nil
	}
	split := NewSplitTransport(internet, policy, direct.connect, owner)
	defer split.Stop()
	osWire, device := newTransportPair()
	device.Receive(func(p []byte) { _ = split.Send(p) })
	split.Receive(func(p []byte) { _ = device.Send(p) })
	osStack := NewTCPTunnel(osWire, false)
	defer osStack.Close()
	dns, e := osStack.DialUDP("1.1.1.1:53")
	if e != nil {
		t.Fatal(e)
	}
	dns.SetDeadline(time.Now().Add(3 * time.Second))
	_, e = dns.Write(splitDNSQuery(t, "outside.test"))
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 2048)
	n, e := dns.Read(b)
	dns.Close()
	if e != nil {
		t.Fatal(e)
	}
	var response dnsmessage.Message
	if e = response.Unpack(b[:n]); e != nil {
		t.Fatal(e)
	}
	a := response.Answers[0].Body.(*dnsmessage.AResource).A
	check := func(c net.Conn) {
		t.Helper()
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, e := c.Write([]byte("ping")); e != nil {
			t.Fatal(e)
		}
		buf := make([]byte, 4)
		if _, e := io.ReadFull(c, buf); e != nil || string(buf) != "ping" {
			t.Fatal(string(buf), e)
		}
	}
	c, e := osStack.DialTCP(net.JoinHostPort(net.IP(a[:]).String(), "443"))
	if e != nil {
		t.Fatal(e)
	}
	check(c)
	if got := <-direct.calls; got != "tcp:outside.test:443" {
		t.Fatal(got)
	}
	u, e := osStack.DialUDP("203.0.113.7:51413")
	if e != nil {
		t.Fatal(e)
	}
	check(u)
	if got := <-direct.calls; got != "udp:203.0.113.7:51413" {
		t.Fatal(got)
	}
	select {
	case tuple := <-ownerCalls:
		if !strings.HasPrefix(tuple, "udp 10.10.10.2:") || !strings.HasSuffix(tuple, " 203.0.113.7:51413") {
			t.Fatal("original OS tuple lost", tuple)
		}
	case <-time.After(time.Second):
		t.Fatal("owner lookup was never used")
	}
	// A non-excluded flow must still traverse the exit, not the direct dialer.
	ln, e := net.Listen("tcp4", net.JoinHostPort(testLANIPv4(t).String(), "0"))
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	c, e = osStack.DialTCP(ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	check(c)
	select {
	case unexpected := <-direct.calls:
		t.Fatal("ordinary flow bypassed VPN", unexpected)
	default:
	}
}
func TestLocalDNSRecordsUsePhysicalResolverWithoutExposingPublicDNS(t *testing.T) {
	policy, _ := routing.New(routing.Config{LAN: true})
	vpn := &routeRecorder{calls: make(chan string, 2)}
	physical := make(chan string, 2)
	d := NewSplitDialer(policy, vpn, func(n, a string) (net.Conn, error) {
		physical <- n
		x, y := net.Pipe()
		go func() {
			defer y.Close()
			var size [2]byte
			if _, e := io.ReadFull(y, size[:]); e != nil {
				return
			}
			b := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, e := io.ReadFull(y, b); e != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(b) != nil {
				return
			}
			m.Response = true
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 5}}}}
			b, _ = m.Pack()
			y.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...))
		}()
		return x, nil
	}, nil)
	answer := d.answerDNS(splitDNSQuery(t, "nas.home"))
	var m dnsmessage.Message
	if e := m.Unpack(answer); e != nil {
		t.Fatal(e)
	}
	if a := m.Answers[0].Body.(*dnsmessage.AResource).A; a != [4]byte{192, 168, 1, 5} {
		t.Fatal(a)
	}
	if got := <-physical; got != "dns" {
		t.Fatal(got)
	}
	if answer = d.answerDNS(splitDNSQuery(t, "public.test")); answer == nil {
		t.Fatal("public DNS missing")
	}
	select {
	case x := <-physical:
		t.Fatal("public DNS leaked", x)
	default:
	}
	select {
	case x := <-vpn.calls:
		t.Fatal("A records should be synthetic before connection", x)
	default:
	}
}
