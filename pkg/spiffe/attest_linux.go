//go:build linux

package spiffe

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// LinuxAttestor performs peer attestation via Linux kernel SO_PEERCRED and /proc/<pid>/stat.
type LinuxAttestor struct{}

// NewAttestor creates a platform-appropriate WorkloadAttestor.
func NewAttestor() WorkloadAttestor {
	return &LinuxAttestor{}
}

func getConnFD(conn net.Conn) (int, error) {
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}
	sc, ok := conn.(syscallConner)
	if !ok {
		return -1, errors.New("connection does not support SyscallConn")
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return -1, err
	}
	var fileDesc int = -1
	err = rawConn.Control(func(fd uintptr) {
		fileDesc = int(fd)
	})
	if err != nil {
		return -1, err
	}
	return fileDesc, nil
}

func readProcStat(pid int) (string, time.Time, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("%w: process %d stat unreadable: %v", ErrProcessIdentityRace, pid, err)
	}

	content := string(data)
	// Parse comm in parentheses (comm)
	left := strings.Index(content, "(")
	right := strings.LastIndex(content, ")")
	if left == -1 || right == -1 || right <= left {
		return "", time.Time{}, errors.New("malformed /proc/<pid>/stat comm")
	}
	comm := content[left+1 : right]

	// Fields after the right parenthesis
	fields := strings.Fields(content[right+1:])
	// In Linux /proc/<pid>/stat, field 22 is starttime (index 19 in fields array after comm)
	var startTime time.Time
	if len(fields) > 19 {
		if jiffies, err := strconv.ParseInt(fields[19], 10, 64); err == nil {
			// Approximate timestamp based on boot time
			startTime = time.Unix(jiffies/100, 0)
		}
	}

	return comm, startTime, nil
}

// AttestPeer verifies caller identity via Linux SO_PEERCRED and procfs.
func (a *LinuxAttestor) AttestPeer(conn net.Conn) (*CallerIdentity, error) {
	fd, err := getConnFD(conn)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestationFailed, err)
	}

	ucred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read SO_PEERCRED: %v", ErrAttestationFailed, err)
	}

	pid := int(ucred.Pid)
	if pid <= 0 {
		return nil, fmt.Errorf("%w: invalid peer pid %d", ErrAttestationFailed, pid)
	}

	comm, startTime, err := readProcStat(pid)
	if err != nil {
		return nil, err
	}

	return &CallerIdentity{
		PID:       pid,
		UID:       ucred.Uid,
		GID:       ucred.Gid,
		Comm:      comm,
		StartTime: startTime,
	}, nil
}
