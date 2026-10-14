//go:build windows

package firewall

import "testing"

// The desktop core is not a Windows service. This used to fail with
// ERROR_NO_SUCH_GROUP before any WFP filters could be installed.
func TestSecurityDescriptorWorksOutsideService(t *testing.T) {
	sd, err := getCurrentProcessSecurityDescriptor()
	if err != nil {
		t.Fatalf("desktop process identity: %v", err)
	}
	if !sd.IsValid() {
		t.Fatal("invalid descriptor")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("missing DACL: %v", err)
	}
}
