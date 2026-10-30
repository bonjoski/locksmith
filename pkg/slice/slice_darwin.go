//go:build darwin

package slice

import (
	"fmt"
	"io"
	"os"
)

type darwinSlice struct {
	reader *os.File
}

func (s *darwinSlice) FD() uintptr {
	return s.reader.Fd()
}

func (s *darwinSlice) File() *os.File {
	return s.reader
}

func (s *darwinSlice) Close() error {
	return s.reader.Close()
}

func (s *darwinSlice) ReadAll() ([]byte, error) {
	return io.ReadAll(s.reader)
}

// Create creates an anonymous unidirectional pipe on macOS Darwin.
// The credential payload is written into the kernel pipe buffer, and the write end
// of the pipe is closed immediately. The child inherits the read end as FD 3; once
// read, subsequent reads return EOF and the buffer is cleared.
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
		// For larger payloads exceeding typical pipe buffer sizes, write asynchronously
		// and close writer as soon as all bytes are pushed.
		go func() {
			defer w.Close()
			_, _ = w.Write(secret)
		}()
	}

	return &darwinSlice{reader: r}, nil
}
