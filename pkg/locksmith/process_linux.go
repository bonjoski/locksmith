//go:build linux
// +build linux

package locksmith

import (
	"fmt"
	"os"
	"strconv"
)

func getCallingBinaryPath() (string, error) {
	ppid := os.Getppid()
	if ppid <= 0 {
		return "", fmt.Errorf("invalid parent process ID: %d", ppid)
	}

	// Read the /proc/<ppid>/exe symlink to resolve the calling binary's path.
	exePath := "/proc/" + strconv.Itoa(ppid) + "/exe"
	path, err := os.Readlink(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to readlink %s: %w", exePath, err)
	}

	return path, nil
}
