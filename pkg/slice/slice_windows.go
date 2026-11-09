//go:build windows

package slice

import (
	"fmt"
	"io"
	"os"
)

type windowsSlice struct {
	reader *os.File
}

func (s *windowsSlice) FD() uintptr {
	return s.reader.Fd()
}

func (s *windowsSlice) File() *os.File {
	return s.reader
}

func (s *windowsSlice) Close() error {
	return s.reader.Close()
}

func (s *windowsSlice) ReadAll() ([]byte, error) {
	return io.ReadAll(s.reader)
}

// Create creates an anonymous pipe on Windows.
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
		// For larger payloads exceeding typical pipe buffer sizes, copy into an owned buffer,
		// write asynchronously, zeroize the owned buffer upon completion, and close the writer.
		buf := make([]byte, len(secret))
		copy(buf, secret)
		go func(owned []byte) {
			defer ExplicitBzero(owned)
			defer func() {
				if closeErr := w.Close(); closeErr != nil {
					return
				}
			}()
			for total := 0; total < len(owned); {
				n, writeErr := w.Write(owned[total:])
				if writeErr != nil {
					return
				}
				total += n
			}
		}(buf)
	}

	return &windowsSlice{reader: r}, nil
}
