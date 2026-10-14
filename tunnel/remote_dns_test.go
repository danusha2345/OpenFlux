package tunnel

import (
	"context"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"testing"
	"time"
)

func TestNamesUseTunnelResolver(t *testing.T) {
	calls := make(chan string, 4)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			server.SetDeadline(time.Now().Add(time.Second))
			var size [2]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				return
			}
			b := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(server, b); err != nil {
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(b); err != nil {
				return
			}
			calls <- query.Questions[0].Name.String()
			answer := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 5}}}}}
			raw, err := answer.Pack()
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(size[:], uint16(len(raw)))
			server.Write(append(size[:], raw...))
		}()
		return client, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ip, err := resolveRemoteIPv4(ctx, "openflux-test.invalid.", dial)
	if err != nil || !ip.Equal(net.IPv4(203, 0, 113, 5)) {
		t.Fatalf("ip=%v err=%v", ip, err)
	}
	select {
	case name := <-calls:
		if name != "openflux-test.invalid." {
			t.Fatal(name)
		}
	default:
		t.Fatal("no tunnel DNS query")
	}
}

func TestLiteralAddressDoesNotNeedDNS(t *testing.T) {
	dial := func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("literal performed a lookup")
		return nil, nil
	}
	ip, err := resolveRemoteIPv4(context.Background(), "1.1.1.1", dial)
	if err != nil || ip.String() != "1.1.1.1" {
		t.Fatal(ip, err)
	}
	if _, err := resolveRemoteIPv4(context.Background(), "::1", dial); err == nil {
		t.Fatal("IPv6 unexpectedly accepted")
	}
}
