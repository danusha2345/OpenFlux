//go:build windows

package routing

import (
	"net"
	"os"
	"strings"
	"testing"
)

func TestWindowsOwnTCPAndUDP(t *testing.T) {
	owner, e := NewOwner()
	if e != nil {
		t.Fatal(e)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	c, e := net.Dial("tcp4", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	peer := <-ch
	defer peer.Close()
	path, e := owner("tcp", c.LocalAddr().String(), c.RemoteAddr().String())
	if e != nil || !strings.EqualFold(path, exe) {
		t.Fatal(path, e)
	}
	u, e := net.Dial("udp4", "127.0.0.1:9")
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	path, e = owner("udp", u.LocalAddr().String(), u.RemoteAddr().String())
	if e != nil || !strings.EqualFold(path, exe) {
		t.Fatal(path, e)
	}
}
