//go:build !windows

package locksmith

import (
	"errors"
	"syscall"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

// isProcessAlive returns true if the PID exists and hasn't been recycled.
func isProcessAlive(pid int, recordedStartTime int64) bool {
	if pid <= 0 {
		return false
	}

	// 1. Send signal 0 to test process existence
	err := syscall.Kill(pid, 0)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			// Process does not exist
			return false
		}
		// If err is EPERM, process exists but belongs to another user
	}

	// 2. Cross-verify start time to guard against PID recycling (VAL-02)
	if recordedStartTime > 0 {
		currStartTime, err := protocol.GetProcessStartTime(pid)
		if err != nil || currStartTime != recordedStartTime {
			return false
		}
	}

	return true
}
