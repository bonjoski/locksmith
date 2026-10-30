//go:build !linux && !darwin && !windows

package slice

import (
	"fmt"
	"io"
	"os"
)

type otherSlice struct {
	reader *os.File
}

func (s *otherSlice) FD() uintptr {
	return s.reader.Fd()
}

func (s *otherSlice) File() *os.File {
	return s.reader
}

func (s *otherSlice) Close() error {
	return s.reader.Close()
}

func (s *otherSlice) ReadAll() ([]byte, error) {
	return io.ReadAll(s.reader)
}

// Create creates an anonymous pipe on POSIX platforms.
func Create(secret []byte) (Slice, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed creating pipe: %w", err)
	}

	if len(secret) <= 16384 {
		if len(secret) > 0 {
			var total int
			for total < len(secret) {
				n, err := w.Write(secret[total:])
				if err != nil {
					_ = r.Close()
					_ = w.Close()
					return nil, fmt.Errorf("failed writing to pipe: %w", err)
				}
				total += n
			}
		}
		if err := w.Close(); err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("failed closing write pipe: %w", err)
		}
	} else {
		go func() {
			defer w.Close()
			_, _ = w.Write(secret)
		}()
	}

	return &otherSlice{reader: r}, nil
}
