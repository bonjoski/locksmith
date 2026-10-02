//go:build linux
// +build linux

package locksmith

import (
	"fmt"
	"os"
	"strings"
)

func getMachineID() (string, error) {
	// Try standard systemd machine-id paths
	paths := []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	}

	var uuid string
	var err error
	var data []byte

	for _, path := range paths {
		data, err = os.ReadFile(path)
		if err == nil {
			defer func(b []byte) {
				for i := range b {
					b[i] = 0
				}
			}(data)
			uuid = strings.TrimSpace(string(data))
			if uuid != "" {
				break
			}
		}
	}

	if uuid == "" {
		if err != nil {
			return "", fmt.Errorf("failed to read machine-id files: %w", err)
		}
		return "", fmt.Errorf("machine-id was empty")
	}

	return uuid, nil
}
