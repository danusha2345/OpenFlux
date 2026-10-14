//go:build windows

package firewall

// CheckPrerequisites opens a dynamic WFP session and resolves the process
// identity, without installing any traffic filters or changing routes.
func CheckPrerequisites() error {
	if _, err := getCurrentProcessSecurityDescriptor(); err != nil {
		return err
	}
	session, err := createWfpSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	return nil
}
