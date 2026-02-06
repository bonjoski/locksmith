package locksmith

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type DiskCache struct {
	Dir       string
	MasterKey []byte
}

func NewDiskCache(masterKey []byte) (*DiskCache, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("invalid master key length: expected 32 bytes, got %d", len(masterKey))
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".locksmith", "cache")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &DiskCache{Dir: dir, MasterKey: masterKey}, nil
}

func (c *DiskCache) validatePath(key string) (string, error) {
	path := filepath.Join(c.Dir, filepath.Clean(key))
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absDir, err := filepath.Abs(c.Dir)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absPath, absDir) {
		return "", fmt.Errorf("security: path traversal attempt detected")
	}
	return path, nil
}

func (c *DiskCache) Set(key string, secret Secret, ttl time.Duration) error {
	path, err := c.validatePath(key)
	if err != nil {
		return err
	}

	data, err := json.Marshal(secret)
	if err != nil {
		return err
	}

	encrypted, err := c.encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt cache item: %w", err)
	}

	return os.WriteFile(path, encrypted, 0600)
}

func (c *DiskCache) Get(key string) (*Secret, error) {
	path, err := c.validatePath(key)
	if err != nil {
		return nil, err
	}

	encrypted, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	data, err := c.decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt cache item: %w", err)
	}

	_, err = os.Stat(path)
	if err != nil {
		return nil, err
	}

	// We'll use file modification time to check against TTL if needed,
	// but the implementation plan suggests the Secret object itself might
	// be enough for logic. However, let's stick to the 0600 file check.
	// For now, simpler: if it exists and is readable, we return it.
	// The caller (Locksmith) will handle TTL logic or we can do it here.

	var secret Secret
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, err
	}

	return &secret, nil
}

func (c *DiskCache) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.MasterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (c *DiskCache) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.MasterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (c *DiskCache) Delete(key string) error {
	path, err := c.validatePath(key)
	if err != nil {
		return err
	}

	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (c *DiskCache) IsExpired(key string, ttl time.Duration) bool {
	path, err := c.validatePath(key)
	if err != nil {
		return true
	}

	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	return time.Since(info.ModTime()) > ttl
}
