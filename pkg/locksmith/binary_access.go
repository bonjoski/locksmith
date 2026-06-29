package locksmith

import (
	"fmt"
	"os"
)

// checkBinaryAccess enforces binary whitelisting before accessing secrets.
// It checks the deny list first, then the allow list (if provided).
func (l *Locksmith) checkBinaryAccess() error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	// Use execPath directly for whitelist/deny checks

	// Deny list takes precedence
	for _, d := range l.Options.DenyBinaries {
		if d != "" && d == execPath {
			return fmt.Errorf("binary %s is explicitly denied by access control", execPath)
		}
	}

	// If an allow list is defined, the binary must be present there
	if len(l.Options.AllowBinaries) > 0 {
		for _, a := range l.Options.AllowBinaries {
			if a != "" && a == execPath {
				return nil
			}
		}
		return fmt.Errorf("binary %s is not in allowed list", execPath)
	}

	return nil
}
