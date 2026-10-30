package slice

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"unsafe"
)

// Slice represents an ephemeral in-memory secret slice backed by an anonymous descriptor.
type Slice interface {
	// FD returns the underlying operating system file descriptor.
	FD() uintptr
	// File returns the *os.File handle for passing to exec.Cmd.ExtraFiles.
	File() *os.File
	// Close releases descriptor resources.
	Close() error
	// ReadAll reads all bytes currently available in the slice.
	ReadAll() ([]byte, error)
}

// ExplicitBzero overwrites the given byte slice with zeroes in a manner that
// prevents compiler dead-store elimination (DSE).
//
//go:noinline
func ExplicitBzero(b []byte) {
	if len(b) == 0 {
		return
	}
	ptr := (*byte)(unsafe.Pointer(&b[0]))
	for i := 0; i < len(b); i++ {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i))) = 0
	}
	// Force the runtime to treat the memory as live and used
	runtime.KeepAlive(ptr)
	runtime.KeepAlive(b)
}

// Zeroize is an alias for ExplicitBzero.
func Zeroize(b []byte) {
	ExplicitBzero(b)
}

// AuthZeroizeHook provides an active memory zeroization mechanism that
// wipes credential slices from memory once an authentication handshake completes.
type AuthZeroizeHook struct {
	data []byte
	once sync.Once
}

// NewAuthZeroizeHook wraps credential bytes with an active zeroization hook.
func NewAuthZeroizeHook(data []byte) *AuthZeroizeHook {
	return &AuthZeroizeHook{data: data}
}

// HandshakeComplete triggers immediate active memory zeroization of the credential slice.
func (h *AuthZeroizeHook) HandshakeComplete() {
	if h == nil {
		return
	}
	h.once.Do(func() {
		ExplicitBzero(h.data)
	})
}

// IsZeroized reports whether all bytes in the credential slice are zero.
func (h *AuthZeroizeHook) IsZeroized() bool {
	if h == nil || len(h.data) == 0 {
		return true
	}
	for _, b := range h.data {
		if b != 0 {
			return false
		}
	}
	return true
}

// ReadSlice reads all bytes from the provided file descriptor (e.g. FD 3).
func ReadSlice(fd uintptr) ([]byte, error) {
	f := os.NewFile(fd, "locksmith_slice")
	if f == nil {
		return nil, fmt.Errorf("invalid file descriptor: %d", fd)
	}
	defer f.Close()
	return io.ReadAll(f)
}

// ConsumeSlice reads the secret from the designated file descriptor and returns
// the raw secret bytes along with an AuthZeroizeHook to wipe the secret from RAM
// as soon as the client or agent finishes its authentication handshake.
func ConsumeSlice(fd uintptr) ([]byte, *AuthZeroizeHook, error) {
	data, err := ReadSlice(fd)
	if err != nil {
		return nil, nil, err
	}
	hook := NewAuthZeroizeHook(data)
	return data, hook, nil
}

// ZeroizeOnHandshake listens on the handshakeDone channel and immediately zeroizes
// the credential slice when the handshake completes.
func ZeroizeOnHandshake(data []byte, handshakeDone <-chan struct{}) *AuthZeroizeHook {
	hook := NewAuthZeroizeHook(data)
	go func() {
		<-handshakeDone
		hook.HandshakeComplete()
	}()
	return hook
}

// connZeroizeWrapper wraps a net.Conn to automatically trigger zeroization of
// the credential slice after the first read/write (e.g., handshake completion).
type connZeroizeWrapper struct {
	net.Conn
	hook *AuthZeroizeHook
}

func (c *connZeroizeWrapper) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err == nil && c.hook != nil {
		c.hook.HandshakeComplete()
	}
	return n, err
}

func (c *connZeroizeWrapper) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == nil && c.hook != nil {
		c.hook.HandshakeComplete()
	}
	return n, err
}

// WrapConnWithZeroizeHook wraps an active network connection and automatically
// zeroes the secret slice when network I/O (such as a TLS/auth handshake) occurs.
func WrapConnWithZeroizeHook(conn net.Conn, secret []byte) net.Conn {
	return &connZeroizeWrapper{
		Conn: conn,
		hook: NewAuthZeroizeHook(secret),
	}
}
