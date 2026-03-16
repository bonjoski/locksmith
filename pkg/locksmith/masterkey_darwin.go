//go:build darwin
// +build darwin

package locksmith

import (
	"crypto/sha256"
	"fmt"
	"os/exec"
	"strings"
)

func deriveMasterKey() ([]byte, error) {
	// Get Hardware UUID via ioreg
	// ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/ {print $(NF-1)}'
	cmd := exec.Command("ioreg", "-d2", "-c", "IOPlatformExpertDevice")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get hardware info: %w", err)
	}

	// Simple parsing for IOPlatformUUID
	lines := strings.Split(string(out), "\n")
	var uuid string
	for _, line := range lines {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.Split(line, "\"")
			if len(parts) >= 4 {
				uuid = parts[3]
				break
			}
		}
	}

	if uuid == "" {
		return nil, fmt.Errorf("failed to extract IOPlatformUUID")
	}

	// Hash the UUID to get a 32-byte key
	hash := sha256.Sum256([]byte(uuid))
	return hash[:], nil
}
