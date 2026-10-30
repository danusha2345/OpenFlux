//go:build windows

package firewall

import (
	"encoding/binary"
	"github.com/p1neappleXpress/OpenFlux/routing"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

// Explicit LAN opt-in; no public addresses or application-wide permits are added.
func permitLAN(session uintptr, base *baseObjects, weight uint8) error {
	for _, p := range routing.LANPrefixes() {
		cond := wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_REMOTE_ADDRESS, matchType: cFWP_MATCH_EQUAL}
		var v4 wtFwpV4AddrAndMask
		var v6 wtFwpV6AddrAndMask
		var pin runtime.Pinner
		pin.Pin(&v4)
		pin.Pin(&v6)
		defer pin.Unpin()
		layers := []windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V4, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4}
		if p.Addr().Is4() {
			a := p.Addr().As4()
			v4 = wtFwpV4AddrAndMask{addr: binary.BigEndian.Uint32(a[:]), mask: ^uint32(0) << (32 - p.Bits())}
			cond.conditionValue = wtFwpConditionValue0{_type: cFWP_V4_ADDR_MASK, value: uintptr(unsafe.Pointer(&v4))}
		} else {
			v6 = wtFwpV6AddrAndMask{addr: p.Addr().As16(), prefixLength: uint8(p.Bits())}
			cond.conditionValue = wtFwpConditionValue0{_type: cFWP_V6_ADDR_MASK, value: uintptr(unsafe.Pointer(&v6))}
			layers = []windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V6, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}
		}
		display, e := createWtFwpmDisplayData0("OpenFlux explicit LAN exception", p.String())
		if e != nil {
			return e
		}
		for _, layer := range layers {
			filter := wtFwpmFilter0{providerKey: &base.provider, subLayerKey: base.filters, displayData: *display, layerKey: layer, weight: filterWeight(weight), numFilterConditions: 1, filterCondition: &cond, action: wtFwpmAction0{_type: cFWP_ACTION_PERMIT}}
			var id uint64
			if e := fwpmFilterAdd0(session, &filter, 0, &id); e != nil {
				return e
			}
		}
	}
	return nil
}
