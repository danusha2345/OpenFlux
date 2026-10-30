package routing

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// ownerPID parses the DWORD-only IPv4 OWNER_PID tables; DWORD ports/addresses are in network order.
func ownerPID(table []byte, tcp bool, src, dst netip.AddrPort) (uint32, error) {
	if len(table) < 4 {
		return 0, errors.New("short owner table")
	}
	stride := 12
	if tcp {
		stride = 24
	}
	n := int(binary.LittleEndian.Uint32(table))
	if n > (len(table)-4)/stride {
		return 0, errors.New("truncated owner table")
	}
	var found uint32
	for i := 0; i < n; i++ {
		row := table[4+i*stride : 4+(i+1)*stride]
		off := 0
		if tcp {
			off = 4
		}
		ip := netip.AddrFrom4([4]byte(row[off : off+4]))
		port := binary.BigEndian.Uint16(row[off+4 : off+6])
		if port != src.Port() || (ip != src.Addr() && (!ip.IsUnspecified() || tcp)) {
			continue
		}
		if tcp && (netip.AddrFrom4([4]byte(row[12:16])) != dst.Addr() || binary.BigEndian.Uint16(row[16:18]) != dst.Port()) {
			continue
		}
		pid := binary.LittleEndian.Uint32(row[stride-4:])
		if pid == 0 {
			return 0, errors.New("owner PID unavailable")
		}
		if found != 0 && found != pid {
			return 0, errors.New("ambiguous socket owner")
		}
		found = pid
	}
	if found == 0 {
		return 0, errors.New("socket owner not found")
	}
	return found, nil
}
