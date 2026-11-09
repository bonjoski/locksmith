//go:build darwin

package spiffe

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
	"golang.org/x/sys/unix"
)

// DarwinAttestor performs peer attestation via macOS kernel socket options and sysctl.
type DarwinAttestor struct{}

// NewAttestor creates a platform-appropriate WorkloadAttestor.
func NewAttestor() WorkloadAttestor {
	return &DarwinAttestor{}
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
	var fileDesc = -1
	err = rawConn.Control(func(fd uintptr) {
		fileDesc = int(fd)
	})
	if err != nil {
		return -1, err
	}
	return fileDesc, nil
}

func parseComm(comm [17]byte) string {
	var commBytes []byte
	for _, b := range comm {
		if b == 0 {
			break
		}
		commBytes = append(commBytes, b)
	}
	return string(commBytes)
}

// AttestPeer verifies the caller identity via Darwin kernel credentials.
func (a *DarwinAttestor) AttestPeer(conn net.Conn) (*CallerIdentity, error) {
	fd, err := getConnFD(conn)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestationFailed, err)
	}

	xucred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read LOCAL_PEERCRED: %v", ErrAttestationFailed, err)
	}

	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read LOCAL_PEERPID: %v", ErrAttestationFailed, err)
	}
	if pid <= 0 {
		return nil, fmt.Errorf("%w: invalid peer pid %d", ErrAttestationFailed, pid)
	}

	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil || int(kp.Proc.P_pid) != pid {
		return nil, fmt.Errorf("%w: process %d terminated (TOCTOU race): %v", ErrProcessIdentityRace, pid, err)
	}

	startTime := time.Unix(0, kp.Proc.P_starttime.Nano())

	var gid uint32
	if xucred.Ngroups > 0 {
		gid = xucred.Groups[0]
	}

	exePath, err := protocol.GetProcessExecutablePath(pid)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to resolve kernel executable path for pid %d: %v", ErrAttestationFailed, pid, err)
	}
	exeHash, err := protocol.HashFile(exePath)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to hash executable %q for pid %d: %v", ErrAttestationFailed, exePath, pid, err)
	}

	return &CallerIdentity{
		PID:       pid,
		UID:       xucred.Uid,
		GID:       gid,
		Comm:      parseComm(kp.Proc.P_comm),
		StartTime: startTime,
		ExePath:   exePath,
		ExeHash:   exeHash,
	}, nil
}
