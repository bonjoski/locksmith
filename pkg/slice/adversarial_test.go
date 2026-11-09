package slice

import (
	"bytes"
	"io"
	"sync"
	"testing"
)

func TestAdversarialConcurrentZeroization(t *testing.T) {
	secret := []byte("high-entropy-master-secret-key-999")
	hook := NewAuthZeroizeHook(secret)

	var wg sync.WaitGroup
	// 50 goroutines attempting to race HandshakeComplete simultaneously
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hook.HandshakeComplete()
		}()
	}
	wg.Wait()

	if !hook.IsZeroized() {
		t.Fatal("Hook failed to zeroize under heavy concurrency")
	}

	for i, b := range secret {
		if b != 0 {
			t.Fatalf("Secret byte at index %d was not zeroed: %d", i, b)
		}
	}
}

func TestAdversarialPipeNoReplay(t *testing.T) {
	secret := []byte("ephemeral-credential-replay-probe")
	sl, err := Create(secret)
	if err != nil {
		t.Fatalf("Create slice failed: %v", err)
	}
	defer sl.Close()

	// Legitimate first read
	read1, err := io.ReadAll(sl.File())
	if err != nil {
		t.Fatalf("Read 1 failed: %v", err)
	}
	if !bytes.Equal(read1, secret) {
		t.Fatalf("Mismatch on read 1: got %q, expected %q", string(read1), string(secret))
	}

	// Adversarial replay attempt on the same descriptor
	buf := make([]byte, 128)
	n, err := sl.File().Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("Adversarial replay read should return 0 bytes and EOF; got n=%d, err=%v", n, err)
	}
}

func TestAdversarialZeroizeIntegrity(t *testing.T) {
	// Ensure memory cannot be recovered after ExplicitBzero
	canary := make([]byte, 256)
	for i := range canary {
		canary[i] = byte((i*37 + 13) % 255)
	}

	ExplicitBzero(canary)

	for i, b := range canary {
		if b != 0 {
			t.Fatalf("Adversarial check: canary byte %d retained non-zero value: %d", i, b)
		}
	}
}

// TestAdversarial_LCK06_LargeAsyncSliceCallerZeroizeRace verifies that >16KB secrets
// written asynchronously into an OS pipe are copied into an owned buffer before the
// goroutine launches, so immediate caller zeroization never corrupts the secret stream.
func TestAdversarial_LCK06_LargeAsyncSliceCallerZeroizeRace(t *testing.T) {
	const payloadSize = 64 * 1024 // > 16KB async threshold
	expected := make([]byte, payloadSize)
	for i := range expected {
		expected[i] = byte((i*73 + 19) % 251)
		if expected[i] == 0 {
			expected[i] = 1
		}
	}

	callerBuf := make([]byte, payloadSize)
	copy(callerBuf, expected)

	sl, err := Create(callerBuf)
	if err != nil {
		t.Fatalf("Create large slice failed: %v", err)
	}
	defer func() {
		if closeErr := sl.Close(); closeErr != nil {
			t.Logf("slice close: %v", closeErr)
		}
	}()

	// Immediately wipe caller's buffer before draining the pipe!
	ExplicitBzero(callerBuf)

	got, err := io.ReadAll(sl.File())
	if err != nil {
		t.Fatalf("reading large slice failed: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("CRITICAL (LCK-06): immediate caller zeroization corrupted async >16KB slice payload (got len=%d)", len(got))
	}
}
