package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
)

// HashFile returns the SHA-256 hash of an executable binary at path.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("peer: failed to open binary %q: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("peer: failed to read binary %q: %w", path, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// PeerCredentials holds validated OS identity information from a local socket.
type PeerCredentials struct {
	PID       int
	UID       uint32
	GID       uint32
	StartTime int64
	ExePath   string
	ExeHash   string
}

// GetPeerInfo gathers PID, start time, and binary path for an open connection.
func GetPeerInfo(conn net.Conn) (*PeerCredentials, error) {
	pid, uid, gid, err := getSocketPeerCred(conn)
	if err != nil {
		return nil, fmt.Errorf("peer: failed to get socket credentials: %w", err)
	}

	startTime, err := GetProcessStartTime(pid)
	if err != nil {
		return nil, fmt.Errorf("peer: failed to get start time for pid %d: %w", pid, err)
	}

	exePath, err := GetProcessExecutablePath(pid)
	if err != nil {
		return nil, fmt.Errorf("peer: failed to get executable path for pid %d: %w", pid, err)
	}

	var exeHash string
	if exePath != "" {
		hash, err := HashFile(exePath)
		if err == nil {
			exeHash = hash
		}
	}

	return &PeerCredentials{
		PID:       pid,
		UID:       uid,
		GID:       gid,
		StartTime: startTime,
		ExePath:   exePath,
		ExeHash:   exeHash,
	}, nil
}
