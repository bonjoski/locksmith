//go:build darwin
// +build darwin

package locksmith

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func getCallingBinaryPath() (string, error) {
	ppid := os.Getppid()
	if ppid <= 0 {
		return "", fmt.Errorf("invalid parent process ID: %d", ppid)
	}

	// Use ps command on macOS to fetch the exact absolute path of the parent process executable.
	cmd := exec.Command("ps", "-p", strconv.Itoa(ppid), "-o", "comm=")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to run ps for ppid %d: %w", ppid, err)
	}

	path := strings.TrimSpace(out.String())
	if path == "" {
		return "", fmt.Errorf("empty process path for ppid %d", ppid)
	}

	return path, nil
}
