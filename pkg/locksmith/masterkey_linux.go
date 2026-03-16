//go:build linux
// +build linux

package locksmith

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

func deriveMasterKey() ([]byte, error) {
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
			uuid = strings.TrimSpace(string(data))
			if uuid != "" {
				break
			}
		}
	}

	if uuid == "" {
		if err != nil {
			return nil, fmt.Errorf("failed to read machine-id files: %w", err)
		}
		return nil, fmt.Errorf("machine-id was empty")
	}

	// Hash the UUID to get a 32-byte key
	hash := sha256.Sum256([]byte(uuid))
	return hash[:], nil
}
