//go:build darwin
// +build darwin

package locksmith

import (
	"fmt"
	"os/exec"
	"strings"
)

func getMachineID() (string, error) {
	// Get Hardware UUID via ioreg
	// ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/ {print $(NF-1)}'
	cmd := exec.Command("ioreg", "-d2", "-c", "IOPlatformExpertDevice")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get hardware info: %w", err)
	}
	defer func() {
		for i := range out {
			out[i] = 0
		}
	}()

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
		return "", fmt.Errorf("failed to extract IOPlatformUUID")
	}

	return uuid, nil
}
