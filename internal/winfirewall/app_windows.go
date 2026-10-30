//go:build windows

package firewall

import (
	"golang.org/x/sys/windows"
	"runtime"
	"strings"
	"unsafe"
)

// Keep Windows Defender and other providers' decisions intact: unlike the
// core's service permit this explicit app rule does NOT clear action rights.
func permitApplication(session uintptr, base *baseObjects, weight uint8, path string) error {
	if !strings.ContainsAny(path, "/\\") {
		return nil
	} // basename rules use socket ownership in the packet proxy
	wide, e := windows.UTF16PtrFromString(strings.ReplaceAll(path, "/", "\\"))
	if e != nil {
		return e
	}
	var appID *wtFwpByteBlob
	if e = fwpmGetAppIdFromFileName0(wide, unsafe.Pointer(&appID)); e != nil {
		return e
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))
	sd, e := getCurrentProcessSecurityDescriptor()
	if e != nil {
		return e
	}
	sdBlob := wtFwpByteBlob{sd.Length(), (*byte)(unsafe.Pointer(sd))}
	var pin runtime.Pinner
	pin.Pin(&sdBlob)
	pin.Pin(sd)
	defer pin.Unpin()
	conditions := [2]wtFwpmFilterCondition0{
		{fieldKey: cFWPM_CONDITION_ALE_APP_ID, matchType: cFWP_MATCH_EQUAL, conditionValue: wtFwpConditionValue0{_type: cFWP_BYTE_BLOB_TYPE, value: uintptr(unsafe.Pointer(appID))}},
		{fieldKey: cFWPM_CONDITION_ALE_USER_ID, matchType: cFWP_MATCH_EQUAL, conditionValue: wtFwpConditionValue0{_type: cFWP_SECURITY_DESCRIPTOR_TYPE, value: uintptr(unsafe.Pointer(&sdBlob))}},
	}
	display, e := createWtFwpmDisplayData0("OpenFlux selected application", path)
	if e != nil {
		return e
	}
	for _, layer := range []windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V4, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4} {
		filter := wtFwpmFilter0{providerKey: &base.provider, subLayerKey: base.filters, displayData: *display, layerKey: layer, weight: filterWeight(weight), numFilterConditions: 2, filterCondition: &conditions[0], action: wtFwpmAction0{_type: cFWP_ACTION_PERMIT}}
		var id uint64
		if e = fwpmFilterAdd0(session, &filter, 0, &id); e != nil {
			return e
		}
	}
	runtime.KeepAlive(sd)
	return nil
}
