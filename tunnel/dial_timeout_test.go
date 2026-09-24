package tunnel

import (
	"testing"
	"time"
)

func TestDialTCPDisconnectedCarrierTimesOutWithNilConn(t *testing.T) {
	tun, err := NewTCPTunnel(stubTransport{}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	old := dialTimeout
	dialTimeout = 100 * time.Millisecond
	defer func() { dialTimeout = old }()
	started := time.Now()
	conn, err := tun.DialTCP("203.0.113.1:443")
	if err == nil || conn != nil {
		t.Fatalf("DialTCP returned conn=%v, err=%v", conn, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("DialTCP took %v after a 100ms deadline", elapsed)
	}
}
