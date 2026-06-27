//go:build linux

package native

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func getProcessInfo(pid int) (*ProcessInfo, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	path, err := os.Readlink(exePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read proc exe for PID %d: %w", pid, err)
	}

	return &ProcessInfo{
		Path:       path,
		Identifier: "",
		TeamID:     "",
	}, nil
}

func getParentPID(pid int) (int, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return -1, fmt.Errorf("failed to read proc stat for PID %d: %w", pid, err)
	}
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()

	statStr := string(data)
	lastRParen := strings.LastIndex(statStr, ")")
	if lastRParen == -1 || lastRParen+2 >= len(statStr) {
		return -1, fmt.Errorf("failed to parse proc stat for PID %d: invalid format", pid)
	}

	fields := strings.Fields(statStr[lastRParen+2:])
	if len(fields) < 2 {
		return -1, fmt.Errorf("failed to parse proc stat for PID %d: missing ppid field", pid)
	}

	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return -1, fmt.Errorf("failed to parse ppid for PID %d: %w", pid, err)
	}

	return ppid, nil
}
