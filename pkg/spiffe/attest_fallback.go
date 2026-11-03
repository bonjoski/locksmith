//go:build !darwin && !linux

package spiffe

import (
	"net"
	"os"
	"path/filepath"
)

// FallbackAttestor provides a fallback attestor for non-Unix operating systems.
type FallbackAttestor struct{}

// NewAttestor creates a platform-appropriate WorkloadAttestor.
func NewAttestor() WorkloadAttestor {
	return &FallbackAttestor{}
}

// AttestPeer provides fallback attestation using process owner UID.
func (f *FallbackAttestor) AttestPeer(conn net.Conn) (*CallerIdentity, error) {
	comm := ""
	if exe, err := os.Executable(); err == nil {
		comm = filepath.Base(exe)
	}
	return &CallerIdentity{
		PID:  os.Getpid(),
		UID:  uint32(os.Getuid()),
		GID:  uint32(os.Getgid()),
		Comm: comm,
	}, nil
}
