package routing

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestDomainAndExecutableBoundaries(t *testing.T) {
	p, e := New(Config{Domains: []string{" *.Example.COM ", "пример.рф"}, Apps: []string{`C:\Apps\Torrent\client.exe`}})
	if e != nil {
		t.Fatal(e)
	}
	for h, want := range map[string]bool{"example.com": true, "www.example.com.": true, "badexample.com": false, "example.com.evil": false, "xn--e1afmkfd.xn--p1ai": true} {
		if p.Domain(h) != want {
			t.Errorf("domain %s", h)
		}
	}
	if !p.App(`c:\apps\torrent\CLIENT.EXE`) || p.App(`C:\Other\client.exe`) {
		t.Fatal("executable paths must match exactly")
	}
	p, _ = New(Config{Apps: []string{"any-client.exe"}})
	if !p.App(`C:\Other\any-client.exe`) || p.App(`C:\Other\not-any-client.exe`) {
		t.Fatal("name matching")
	}
	for _, d := range []string{"https://example.com", "example.com/path", "example..com", "foo\nbar"} {
		if _, e := New(Config{Domains: []string{d}}); e == nil {
			t.Errorf("accepted %q", d)
		}
	}
}
func TestLANIsExplicitAndCannotAdmitPublicIP(t *testing.T) {
	off, _ := New(Config{})
	on, _ := New(Config{LAN: true})
	for _, ip := range []string{"10.0.0.1", "172.31.255.254", "192.168.2.1", "169.254.1.1", "fe80::1", "fd00::2"} {
		if off.Local(ip) || !on.Local(ip) {
			t.Fatal(ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "172.32.0.1", "192.169.0.1", "169.255.0.1", "198.18.0.1", "2606:4700:4700::1111"} {
		if on.Local(ip) {
			t.Fatal("public or synthetic address allowed as LAN", ip)
		}
	}
}
func TestOwnerTablesUseFullTCPAndConservativeUDPIdentity(t *testing.T) {
	src := netip.MustParseAddrPort("10.10.10.2:40000")
	dst := netip.MustParseAddrPort("198.18.0.1:443")
	tcp := make([]byte, 28)
	binary.LittleEndian.PutUint32(tcp, 1)
	r := tcp[4:]
	a := src.Addr().As4()
	copy(r[4:8], a[:])
	binary.BigEndian.PutUint16(r[8:10], src.Port())
	a = dst.Addr().As4()
	copy(r[12:16], a[:])
	binary.BigEndian.PutUint16(r[16:18], dst.Port())
	binary.LittleEndian.PutUint32(r[20:], 1234)
	if pid, e := ownerPID(tcp, true, src, dst); e != nil || pid != 1234 {
		t.Fatalf("TCP owner %d %v", pid, e)
	}
	if _, e := ownerPID(tcp, true, src, netip.MustParseAddrPort("198.18.0.2:443")); e == nil {
		t.Fatal("destination mismatch accepted")
	}
	udp := make([]byte, 28)
	binary.LittleEndian.PutUint32(udp, 2)
	for i, pid := range []uint32{1234, 5678} {
		r := udp[4+i*12:]
		binary.BigEndian.PutUint16(r[4:6], src.Port())
		binary.LittleEndian.PutUint32(r[8:12], pid)
	}
	if _, e := ownerPID(udp, false, src, dst); e == nil {
		t.Fatal("ambiguous UDP owner accepted")
	}
	binary.LittleEndian.PutUint32(udp, 1)
	if pid, e := ownerPID(udp, false, src, dst); e != nil || pid != 1234 {
		t.Fatal(pid, e)
	}
	if _, e := ownerPID(tcp[:10], true, src, dst); e == nil {
		t.Fatal("short table accepted")
	}
}
