//go:build windows

package locksmith

import (
	"os"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

// isProcessAlive returns true if the PID exists and hasn't been recycled on Windows.
func isProcessAlive(pid int, recordedStartTime int64) bool {
	if pid <= 0 {
		return false
	}

	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p

	if recordedStartTime > 0 {
		currStartTime, err := protocol.GetProcessStartTime(pid)
		if err != nil || currStartTime != recordedStartTime {
			return false
		}
	}

	return true
}
