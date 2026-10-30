//go:build windows

package routing

import (
	"fmt"
	"golang.org/x/sys/windows"
	"net/netip"
	"runtime"
	"unsafe"
)

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")
var tcpTable = ipHelper.NewProc("GetExtendedTcpTable")
var udpTable = ipHelper.NewProc("GetExtendedUdpTable")

func NewOwner() (Owner, error) {
	if err := tcpTable.Find(); err != nil {
		return nil, err
	}
	if err := udpTable.Find(); err != nil {
		return nil, err
	}
	return processOwner, nil
}
func processOwner(network, source, destination string) (string, error) {
	src, e := netip.ParseAddrPort(source)
	if e != nil {
		return "", e
	}
	dst, e := netip.ParseAddrPort(destination)
	if e != nil {
		return "", e
	}
	tcp := network == "tcp"
	proc := udpTable
	class := uintptr(1)
	if tcp {
		proc = tcpTable
		class = 5
	}
	size := uint32(16384)
	for tries := 0; tries < 5; tries++ {
		if size > 16<<20 {
			return "", fmt.Errorf("owner table too large")
		}
		buf := make([]byte, size)
		code, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, class, 0)
		if code == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if code != 0 {
			return "", windows.Errno(code)
		}
		runtime.KeepAlive(buf)
		pid, e := ownerPID(buf, tcp, src, dst)
		if e != nil {
			return "", e
		}
		h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if e != nil {
			return "", e
		}
		defer windows.CloseHandle(h)
		path := make([]uint16, 32768)
		n := uint32(len(path))
		if e = windows.QueryFullProcessImageName(h, 0, &path[0], &n); e != nil {
			return "", e
		}
		return windows.UTF16ToString(path[:n]), nil
	}
	return "", fmt.Errorf("owner table kept changing")
}
