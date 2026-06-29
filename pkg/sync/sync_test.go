package sync

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptPayload(t *testing.T) {
	plaintext := []byte("highly-sensitive-vault-data-to-sync")
	passphrase := "super-secure-passphrase-123!"

	// 1. Encrypt the plaintext
	ciphertext, err := EncryptPayload(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	if len(ciphertext) <= SaltSize+NonceSize {
		t.Fatalf("Ciphertext is too short: got %d bytes", len(ciphertext))
	}

	// 2. Decrypt it back
	decrypted, err := DecryptPayload(ciphertext, passphrase)
	if err != nil {
		t.Fatalf("DecryptPayload failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted data mismatch: expected '%s', got '%s'", plaintext, decrypted)
	}
}

func TestEncryptPayloadUniqueness(t *testing.T) {
	plaintext := []byte("same-plaintext")
	passphrase := "same-passphrase"

	// Encrypt twice
	c1, err := EncryptPayload(plaintext, passphrase)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	c2, err := EncryptPayload(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// The payloads must be completely different due to random salting and nonces
	if bytes.Equal(c1, c2) {
		t.Error("Expected different ciphertexts for separate encryption operations, but got identical bytes")
	}
}

func TestDecryptPayloadFailureIncorrectPassphrase(t *testing.T) {
	plaintext := []byte("plaintext")
	passphrase := "passphrase"

	ciphertext, err := EncryptPayload(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	// Try to decrypt with wrong passphrase
	_, err = DecryptPayload(ciphertext, "wrong-passphrase")
	if err == nil {
		t.Fatal("Expected decryption to fail with incorrect passphrase, but it succeeded")
	}
}

func TestDecryptPayloadFailureInvalidSize(t *testing.T) {
	// Payload is too small (e.g. less than 28 bytes)
	tooSmallPayload := make([]byte, 20)
	_, err := DecryptPayload(tooSmallPayload, "any-passphrase")
	if err == nil {
		t.Fatal("Expected decryption to fail for small payloads, but it succeeded")
	}
}
