//go:build darwin

package protocol

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	procInfoCallPidInfo    = 2    // PROC_INFO_CALL_PIDINFO
	procPidPathInfo        = 11   // PROC_PIDPATHINFO
	procPidPathInfoMaxSize = 4096 // PROC_PIDPATHINFO_MAXSIZE
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

	var xucred *unix.Xucred
	var credErr error
	var peerPID int
	var pidErr error

	err = rawConn.Control(func(fd uintptr) {
		xucred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr != nil {
			return
		}
		peerPID, pidErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if err != nil {
		return 0, 0, 0, err
	}
	if credErr != nil {
		return 0, 0, 0, fmt.Errorf("peer: getsockopt LOCAL_PEERCRED failed: %w", credErr)
	}
	if pidErr != nil {
		return 0, 0, 0, fmt.Errorf("peer: getsockopt LOCAL_PEERPID failed: %w", pidErr)
	}
	if peerPID <= 0 {
		return 0, 0, 0, fmt.Errorf("peer: invalid peer pid %d", peerPID)
	}

	expectedUID := uint32(os.Getuid())
	if xucred.Uid != expectedUID {
		return 0, 0, 0, fmt.Errorf("peer: unauthorized peer uid %d (expected %d)", xucred.Uid, expectedUID)
	}

	peerGID := uint32(os.Getgid())
	if xucred.Ngroups > 0 {
		peerGID = xucred.Groups[0]
	}

	return peerPID, xucred.Uid, peerGID, nil
}

// GetProcessStartTime queries Darwin kernel process start timestamp in nanoseconds via sysctl.
func GetProcessStartTime(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("peer: invalid pid %d", pid)
	}

	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, fmt.Errorf("peer: failed to inspect pid %d start time: %w", pid, err)
	}
	if kp == nil || int(kp.Proc.P_pid) != pid {
		return 0, fmt.Errorf("peer: pid %d no longer exists", pid)
	}

	ns := kp.Proc.P_starttime.Nano()
	if ns <= 0 {
		return 0, fmt.Errorf("peer: invalid kernel start timestamp for pid %d", pid)
	}
	return ns, nil
}

// GetProcessExecutablePath queries the kernel vnode executable path via SYS_PROC_INFO (proc_pidpath).
func GetProcessExecutablePath(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("peer: invalid pid %d", pid)
	}

	buf := make([]byte, procPidPathInfoMaxSize)
	ret, _, errno := unix.Syscall6(
		unix.SYS_PROC_INFO,
		procInfoCallPidInfo,
		uintptr(pid),
		procPidPathInfo,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return "", fmt.Errorf("peer: proc_pidpath failed for pid %d: %w", pid, errno)
	}

	raw := buf
	if n := int(ret); n > 0 && n < len(buf) {
		raw = buf[:n]
	}
	if nul := bytes.IndexByte(raw, 0); nul >= 0 {
		raw = raw[:nul]
	}
	exePath := string(raw)
	if exePath == "" || !strings.HasPrefix(exePath, "/") {
		return "", fmt.Errorf("peer: proc_pidpath returned empty path for pid %d", pid)
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil && resolved != "" {
		exePath = resolved
	}
	return exePath, nil
}
