package locksmith

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/slice"
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
	if strings.TrimSpace(key) == "" || strings.ContainsRune(key, 0) {
		return "", fmt.Errorf("security: path traversal attempt detected")
	}
	if strings.HasPrefix(key, "/") || strings.HasPrefix(key, "\\") || filepath.IsAbs(key) {
		return "", fmt.Errorf("security: path traversal attempt detected")
	}
	for _, seg := range strings.FieldsFunc(key, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("security: path traversal attempt detected")
		}
	}

	cleanDir, err := filepath.Abs(filepath.Clean(c.Dir))
	if err != nil {
		return "", err
	}
	cleanFull, err := filepath.Abs(filepath.Join(cleanDir, filepath.Clean(key)))
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(cleanFull, cleanDir+string(filepath.Separator)) {
		return "", fmt.Errorf("security: path traversal attempt detected")
	}
	return cleanFull, nil
}

func writeAndSyncTempFile(tmp *os.File, payload []byte) error {
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed setting 0600 permissions on temporary cache file: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed writing temporary cache file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed syncing temporary cache file: %w", err)
	}
	return tmp.Close()
}

func writeAtomicCacheFile(path string, payload []byte) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("security: refusing to overwrite symlink in cache")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create cache subdirectory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".cache-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary cache file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := writeAndSyncTempFile(tmp, payload); err != nil {
		return err
	}

	var renameErr error
	for attempt := 0; attempt < 10; attempt++ {
		renameErr = os.Rename(tmpPath, path)
		if renameErr == nil {
			return nil
		}
		if runtime.GOOS == "windows" {
			time.Sleep(time.Duration(attempt*5+5) * time.Millisecond)
			continue
		}
		break
	}
	return fmt.Errorf("failed renaming temporary cache file: %w", renameErr)
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
	defer slice.ExplicitBzero(data)

	encrypted, err := c.encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt cache item: %w", err)
	}
	defer slice.ExplicitBzero(encrypted)

	return writeAtomicCacheFile(path, encrypted)
}

func readCacheFileWithRetry(path string) ([]byte, error) {
	var encrypted []byte
	var readErr error
	for attempt := 0; attempt < 10; attempt++ {
		encrypted, readErr = os.ReadFile(path) // #nosec G304
		if readErr == nil || os.IsNotExist(readErr) {
			break
		}
		if runtime.GOOS == "windows" {
			time.Sleep(time.Duration(attempt*5+5) * time.Millisecond)
			continue
		}
		break
	}
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return nil, nil
		}
		return nil, readErr
	}
	return encrypted, nil
}

func (c *DiskCache) decryptCachePayload(encrypted []byte) ([]byte, bool, error) {
	data, err := c.decrypt(encrypted)
	if err == nil {
		return data, false, nil
	}
	if len(c.LegacyMasterKey) == 32 {
		legacyData, legacyErr := c.decryptWithKey(encrypted, c.LegacyMasterKey)
		if legacyErr == nil {
			return legacyData, true, nil
		}
	}
	return nil, false, fmt.Errorf("failed to decrypt cache item: %w", err)
}

func (c *DiskCache) migrateLegacyCache(path string, data []byte) {
	newEncrypted, encErr := c.encrypt(data)
	if encErr == nil {
		defer slice.ExplicitBzero(newEncrypted)
		_ = writeAtomicCacheFile(path, newEncrypted)
	}
}

func (c *DiskCache) Get(key string) (*Secret, error) {
	path, err := c.validatePath(key)
	if err != nil {
		return nil, err
	}

	encrypted, err := readCacheFileWithRetry(path)
	if err != nil || encrypted == nil {
		return nil, err
	}
	defer func() {
		for i := range encrypted {
			encrypted[i] = 0
		}
	}()

	data, fromLegacy, err := c.decryptCachePayload(encrypted)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()

	if _, err = os.Stat(path); err != nil {
		return nil, err
	}

	var secret Secret
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, err
	}

	// Transparent auto-migration: if decrypted with legacy key, re-encrypt with user-bound key
	if fromLegacy {
		c.migrateLegacyCache(path, data)
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
