package sync

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	SaltSize  = 16
	NonceSize = 12
)

// EncryptPayload derives a key using Argon2id and encrypts the plaintext with AES-256-GCM
func EncryptPayload(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	// Derive key from passphrase
	// Parameter settings matching OWASP: time=3, memory=64MB, threads=4, keyLen=32
	key := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm block: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil) // #nosec G407

	packed := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	packed = append(packed, salt...)
	packed = append(packed, nonce...)
	packed = append(packed, ciphertext...)

	return packed, nil
}

// DecryptPayload decrypts a packed binary payload using the derived Argon2id key and AES-256-GCM
func DecryptPayload(payload []byte, passphrase string) ([]byte, error) {
	minSize := SaltSize + NonceSize
	if len(payload) < minSize {
		return nil, fmt.Errorf("invalid payload: size is too small")
	}

	salt := payload[:SaltSize]
	nonce := payload[SaltSize:minSize]
	ciphertext := payload[minSize:]

	key := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm block: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload (invalid passphrase or tampered data): %w", err)
	}

	return plaintext, nil
}
