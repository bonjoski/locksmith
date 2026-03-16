//go:build windows
// +build windows

package locksmith

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func deriveMasterKey() ([]byte, error) {
	// Read MachineGuid from HKLM\SOFTWARE\Microsoft\Cryptography
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("failed to open registry key: %w", err)
	}
	defer k.Close()

	uuid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return nil, fmt.Errorf("failed to read MachineGuid: %w", err)
	}

	if uuid == "" {
		return nil, fmt.Errorf("MachineGuid is empty")
	}

	// Hash the UUID to get a 32-byte key
	hash := sha256.Sum256([]byte(uuid))
	return hash[:], nil
}
