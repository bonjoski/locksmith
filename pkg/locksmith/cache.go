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
	Dir             string
	MasterKey       []byte
	LegacyMasterKey []byte
}

func NewDiskCache(masterKey []byte) (*DiskCache, error) {
	return NewDiskCacheWithLegacy(masterKey, nil)
}

func NewDiskCacheWithLegacy(masterKey []byte, legacyMasterKey []byte) (*DiskCache, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("invalid master key length: expected 32 bytes, got %d", len(masterKey))
	}
	if len(legacyMasterKey) > 0 && len(legacyMasterKey) != 32 {
		return nil, fmt.Errorf("invalid legacy master key length: expected 32 bytes, got %d", len(legacyMasterKey))
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".locksmith", "cache")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &DiskCache{Dir: dir, MasterKey: masterKey, LegacyMasterKey: legacyMasterKey}, nil
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
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()

	encrypted, err := c.encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt cache item: %w", err)
	}
	defer func() {
		for i := range encrypted {
			encrypted[i] = 0
		}
	}()

	// Create parent directories in case the key contains slashes
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create cache subdirectory: %w", err)
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
	defer func() {
		for i := range encrypted {
			encrypted[i] = 0
		}
	}()

	data, err := c.decrypt(encrypted)
	var fromLegacy bool
	if err != nil {
		// If decryption with primary master key fails, attempt legacy key if available
		if len(c.LegacyMasterKey) == 32 {
			legacyData, legacyErr := c.decryptWithKey(encrypted, c.LegacyMasterKey)
			if legacyErr == nil {
				data = legacyData
				fromLegacy = true
			} else {
				return nil, fmt.Errorf("failed to decrypt cache item: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to decrypt cache item: %w", err)
		}
	}
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()

	_, err = os.Stat(path)
	if err != nil {
		return nil, err
	}

	var secret Secret
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, err
	}

	// Transparent auto-migration: if decrypted with legacy key, re-encrypt with user-bound key
	if fromLegacy {
		newEncrypted, encErr := c.encrypt(data)
		if encErr == nil {
			defer func() {
				for i := range newEncrypted {
					newEncrypted[i] = 0
				}
			}()
			_ = os.WriteFile(path, newEncrypted, 0600) // #nosec G306 - non-fatal cache auto-migration
		}
	}

	return &secret, nil
}

func (c *DiskCache) encrypt(data []byte) ([]byte, error) {
	return c.encryptWithKey(data, c.MasterKey)
}

func (c *DiskCache) encryptWithKey(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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
	return c.decryptWithKey(data, c.MasterKey)
}

func (c *DiskCache) decryptWithKey(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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
