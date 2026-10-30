//go:build linux

package slice

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

type linuxSlice struct {
	file *os.File
}

func (s *linuxSlice) FD() uintptr {
	return s.file.Fd()
}

func (s *linuxSlice) File() *os.File {
	return s.file
}

func (s *linuxSlice) Close() error {
	return s.file.Close()
}

func (s *linuxSlice) ReadAll() ([]byte, error) {
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(s.file)
}

// Create creates an anonymous in-memory memory slice using memfd_create with hardware memory seals.
// The file descriptor is sealed against writes and truncation before being handed off.
func Create(secret []byte) (Slice, error) {
	fd, err := unix.MemfdCreate("locksmith_slice", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("memfd_create failed: %w", err)
	}

	var total int
	for total < len(secret) {
		n, err := unix.Write(fd, secret[total:])
		if err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("failed writing to memfd: %w", err)
		}
		total += n
	}

	// Rewind file offset to 0 so child reader starts from beginning
	if _, err := unix.Seek(fd, 0, io.SeekStart); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed seeking memfd: %w", err)
	}

	// Apply hardware memory seals: F_SEAL_WRITE and F_SEAL_SHRINK (plus F_SEAL_GROW and F_SEAL_SEAL)
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed applying memory seals: %w", err)
	}

	file := os.NewFile(uintptr(fd), "locksmith_slice")
	return &linuxSlice{file: file}, nil
}

// GetSeals returns the current active seal bitmask on a file descriptor.
func GetSeals(fd uintptr) (int, error) {
	return unix.FcntlInt(fd, unix.F_GET_SEALS, 0)
}
