//go:build !darwin && !linux

package protocol

import (
	"errors"
	"net"
	"os"
)

func getSocketPeerCred(conn net.Conn) (pid int, uid uint32, gid uint32, err error) {
	// Fallback for Windows named pipes or unsupported platforms
	return os.Getpid(), 0, 0, nil
}

// GetProcessStartTime fallback
func GetProcessStartTime(pid int) (int64, error) {
	if pid <= 0 {
		return 0, errors.New("peer: invalid pid")
	}
	return 1, nil
}

// GetProcessExecutablePath fallback
func GetProcessExecutablePath(pid int) (string, error) {
	if pid <= 0 {
		return "", errors.New("peer: invalid pid")
	}
	return os.Executable()
}
