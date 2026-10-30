package slice

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestSliceCreationAndRead(t *testing.T) {
	secret := []byte("super-secret-vault-token-xyz-987")
	sl, err := Create(secret)
	if err != nil {
		t.Fatalf("Create slice failed: %v", err)
	}
	defer sl.Close()

	if sl.FD() == 0 {
		t.Errorf("Expected valid FD, got 0")
	}
	if sl.File() == nil {
		t.Fatalf("Expected non-nil os.File")
	}

	readBytes, err := sl.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(readBytes, secret) {
		t.Errorf("Expected %q, got %q", string(secret), string(readBytes))
	}
}

func TestExplicitBzero(t *testing.T) {
	data := []byte("very-sensitive-master-key-that-must-be-wiped")
	origLen := len(data)

	ExplicitBzero(data)

	if len(data) != origLen {
		t.Fatalf("ExplicitBzero changed slice length: expected %d, got %d", origLen, len(data))
	}

	for i, b := range data {
		if b != 0 {
			t.Fatalf("Byte at index %d was not zeroized (val: %d)", i, b)
		}
	}
}

func TestExplicitBzeroEmpty(t *testing.T) {
	// Should not panic on empty or nil slices
	ExplicitBzero(nil)
	ExplicitBzero([]byte{})
}

func TestAuthZeroizeHook(t *testing.T) {
	secret := []byte("token-for-auth-handshake")
	hook := NewAuthZeroizeHook(secret)

	if hook.IsZeroized() {
		t.Error("Expected hook not to be zeroized before handshake completion")
	}

	// Trigger handshake completion
	hook.HandshakeComplete()

	if !hook.IsZeroized() {
		t.Error("Expected hook to report zeroized after handshake completion")
	}

	for i, b := range secret {
		if b != 0 {
			t.Fatalf("Secret byte at %d was not zero: %d", i, b)
		}
	}

	// Multiple calls should be idempotent
	hook.HandshakeComplete()
}

func TestZeroizeOnHandshakeChannel(t *testing.T) {
	secret := []byte("async-handshake-secret")
	handshakeDone := make(chan struct{})

	hook := ZeroizeOnHandshake(secret, handshakeDone)
	if hook.IsZeroized() {
		t.Error("Hook should not be zeroized prior to channel send")
	}

	close(handshakeDone)

	// Wait for goroutine to execute
	for i := 0; i < 50; i++ {
		if hook.IsZeroized() {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	if !hook.IsZeroized() {
		t.Error("Hook should be zeroized after handshakeDone channel was closed")
	}
}

func TestWrapConnWithZeroizeHook(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	secret := []byte("tls-client-cert-key")
	wrappedClient := WrapConnWithZeroizeHook(clientConn, secret)

	// In background, read from server to complete handshake write
	go func() {
		buf := make([]byte, 32)
		_, _ = serverConn.Read(buf)
	}()

	// Client writes handshake payload
	_, err := wrappedClient.Write([]byte("AUTH-HANDSHAKE-START"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Verify secret has been active-zeroized
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("Secret byte %d was not zeroized after connection write: %d", i, b)
		}
	}
}

func TestPipeEOFOnceRead(t *testing.T) {
	secret := []byte("single-read-token")
	sl, err := Create(secret)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer sl.Close()

	// First read consumes all available data
	b, err := io.ReadAll(sl.File())
	if err != nil {
		t.Fatalf("Initial ReadAll failed: %v", err)
	}
	if !bytes.Equal(b, secret) {
		t.Fatalf("Expected %q, got %q", string(secret), string(b))
	}

	// Subsequent read on the descriptor should return EOF (0 bytes)
	buf := make([]byte, 16)
	n, err := sl.File().Read(buf)
	if n != 0 {
		t.Errorf("Expected 0 bytes on subsequent read, got %d", n)
	}
	if err != io.EOF {
		t.Errorf("Expected EOF on subsequent read, got %v", err)
	}
}

func TestLargeSliceStreaming(t *testing.T) {
	// Test payload larger than standard pipe buffer (64KB)
	largeSecret := bytes.Repeat([]byte("A"), 128*1024)
	sl, err := Create(largeSecret)
	if err != nil {
		t.Fatalf("Create with large secret failed: %v", err)
	}
	defer sl.Close()

	readData, err := sl.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll on large secret failed: %v", err)
	}

	if len(readData) != len(largeSecret) {
		t.Fatalf("Length mismatch: expected %d, got %d", len(largeSecret), len(readData))
	}
	if !bytes.Equal(readData, largeSecret) {
		t.Fatal("Data content mismatch on large secret")
	}
}
