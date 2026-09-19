package l3

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestRawSendAfterCloseRejectsReusedDescriptor(t *testing.T) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(pair[0])
	defer syscall.Close(pair[1])
	// Model a descriptor number already reused by the OS after backend Close.
	b := &rawBackend{sendFd: pair[0], closed: make(chan struct{})}
	close(b.closed)
	if err := b.Send(make([]byte, 40)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send reached reused fd: %v", err)
	}
}
