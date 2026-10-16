//go:build linux

package protocol

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func getSocketPeerCred(conn net.Conn) (pid int, uid uint32, gid uint32, err error) {
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, 0, fmt.Errorf("peer: connection is not a unix socket")
	}

	rawConn, err := uconn.SyscallConn()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("peer: failed to get raw connection: %w", err)
	}

	var ucred *unix.Ucred
	var sysErr error

	err = rawConn.Control(func(fd uintptr) {
		ucred, sysErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})

	if err != nil {
		return 0, 0, 0, err
	}
	if sysErr != nil {
		return 0, 0, 0, fmt.Errorf("peer: getsockopt SO_PEERCRED failed: %w", sysErr)
	}

	return int(ucred.Pid), ucred.Uid, ucred.Gid, nil
}

// GetProcessStartTime extracts field 22 (starttime) from /proc/<pid>/stat.
func GetProcessStartTime(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("peer: invalid pid %d", pid)
	}

	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("peer: failed to read /proc/%d/stat: %w", pid, err)
	}

	// Format: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice num_threads itrealvalue starttime ...
	// Close parenthesis to handle spaces in comm
	content := string(data)
	closeIdx := strings.LastIndex(content, ")")
	if closeIdx == -1 || closeIdx+2 >= len(content) {
		return 0, fmt.Errorf("peer: malformed /proc/%d/stat", pid)
	}

	fields := strings.Fields(content[closeIdx+2:])
	// fields[0] is state (field 3 of /proc/stat)
	// field 22 is starttime, which corresponds to index 19 in fields slice (22 - 3 = 19)
	if len(fields) < 20 {
		return 0, fmt.Errorf("peer: insufficient fields in /proc/%d/stat", pid)
	}

	startTime, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("peer: failed to parse starttime for pid %d: %w", pid, err)
	}

	return startTime, nil
}

// GetProcessExecutablePath reads the symlink /proc/<pid>/exe.
func GetProcessExecutablePath(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("peer: invalid pid %d", pid)
	}
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}
