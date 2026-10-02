//go:build !darwin && !linux && !windows
// +build !darwin,!linux,!windows

package locksmith

import (
	"fmt"
	"os"
)

func getMachineID() (string, error) {
	// Fallback to /etc/machine-id or hostname
	if data, err := os.ReadFile("/etc/machine-id"); err == nil && len(data) > 0 {
		defer func() {
			for i := range data {
				data[i] = 0
			}
		}()
		return string(data), nil
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return hostname, nil
	}
	return "", fmt.Errorf("unable to determine machine identifier on this platform")
}
