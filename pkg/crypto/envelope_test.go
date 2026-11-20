package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
)

func TestEnvelopeRoundtrip(t *testing.T) {
	key := []byte("super-secret-hmac-key-32-bytes!!")
	payload := []byte("plain-text-secret-data-to-protect")

	frame, err := EncodeFrame(payload, key)
	if err != nil {
		t.Fatalf("EncodeFrame failed: %v", err)
	}

	decoded, err := VerifyAndDecodeFrame(frame, key)
	if err != nil {
		t.Fatalf("VerifyAndDecodeFrame failed: %v", err)
	}

	if !bytes.Equal(decoded, payload) {
		t.Fatalf("payload mismatch: expected %q, got %q", payload, decoded)
	}
}

func TestEnvelopeAdversarial_TrailingData_GHSA_j282(t *testing.T) {
	key := []byte("super-secret-hmac-key-32-bytes!!")
	payload := []byte("sensitive-api-token")

	frame, err := EncodeFrame(payload, key)
	if err != nil {
		t.Fatalf("EncodeFrame failed: %v", err)
	}

	// Attack 1: Appending trailing unauthenticated bytes to the envelope
	corrupted := append(frame, []byte("DEADBEEF-TRAILING-GARBAGE")...)
	_, err = VerifyAndDecodeFrame(corrupted, key)
	if !errors.Is(err, ErrTrailingData) {
		t.Fatalf("expected ErrTrailingData, got %v", err)
	}
}

func TestEnvelopeAdversarial_TruncatedDigest(t *testing.T) {
	key := []byte("super-secret-hmac-key-32-bytes!!")
	payload := []byte("sensitive-api-token")

	frame, err := EncodeFrame(payload, key)
	if err != nil {
		t.Fatalf("EncodeFrame failed: %v", err)
	}

	// Attack 2: Stripping part of the MAC digest (e.g. truncated MAC bypass)
	truncated := frame[:len(frame)-8]
	_, err = VerifyAndDecodeFrame(truncated, key)
	if !errors.Is(err, ErrEnvelopeCorrupt) {
		t.Fatalf("expected ErrEnvelopeCorrupt on truncated digest, got %v", err)
	}
}

func TestEnvelopeAdversarial_PayloadTampering(t *testing.T) {
	key := []byte("super-secret-hmac-key-32-bytes!!")
	payload := []byte("sensitive-api-token")

	frame, err := EncodeFrame(payload, key)
	if err != nil {
		t.Fatalf("EncodeFrame failed: %v", err)
	}

	// Attack 3: Modifying payload byte
	frame[6] ^= 0xFF
	_, err = VerifyAndDecodeFrame(frame, key)
	if !errors.Is(err, ErrEnvelopeCorrupt) {
		t.Fatalf("expected ErrEnvelopeCorrupt on altered payload, got %v", err)
	}
}

func TestEnvelopeAdversarial_EmptyKey(t *testing.T) {
	payload := []byte("test")
	_, err := EncodeFrame(payload, nil)
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}

	_, err = VerifyAndDecodeFrame([]byte{0, 0, 0, 0}, nil)
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
}

func TestEnvelope_ConcurrencyStress(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	payload := []byte("concurrent-agent-session-token")

	frame, err := EncodeFrame(payload, key)
	if err != nil {
		t.Fatalf("EncodeFrame failed: %v", err)
	}

	var wg sync.WaitGroup
	const subagents = 8

	for i := 0; i < subagents; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for iter := 0; iter < 1000; iter++ {
				dec, err := VerifyAndDecodeFrame(frame, key)
				if err != nil || !bytes.Equal(dec, payload) {
					t.Errorf("worker %d failed decoding: %v", id, err)
				}
			}
		}(i)
	}
	wg.Wait()
}
