//go:build windows
// +build windows

package locksmith

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func getMachineID() (string, error) {
	// Read MachineGuid from HKLM\SOFTWARE\Microsoft\Cryptography
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("failed to open registry key: %w", err)
	}
	defer k.Close()

	uuid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", fmt.Errorf("failed to read MachineGuid: %w", err)
	}

	if uuid == "" {
		return "", fmt.Errorf("MachineGuid is empty")
	}

	return uuid, nil
}
