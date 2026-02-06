package locksmith

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type DiskCache struct {
	Dir string
}

func NewDiskCache() (*DiskCache, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".locksmith", "cache")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &DiskCache{Dir: dir}, nil
}

func (c *DiskCache) Set(key string, secret Secret, ttl time.Duration) error {
	path := filepath.Join(c.Dir, filepath.Clean(key))
	// Ensure path starts with c.Dir to prevent traversal
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	absDir, err := filepath.Abs(c.Dir)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(absPath, absDir) {
		return fmt.Errorf("security: path traversal attempt detected")
	}

	data, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (c *DiskCache) Get(key string) (*Secret, error) {
	path := filepath.Join(c.Dir, filepath.Clean(key))
	absPath, _ := filepath.Abs(path)
	absDir, _ := filepath.Abs(c.Dir)
	if !strings.HasPrefix(absPath, absDir) {
		return nil, fmt.Errorf("security: path traversal attempt detected")
	}

	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
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

func (c *DiskCache) Delete(key string) error {
	path := filepath.Join(c.Dir, filepath.Clean(key))
	absPath, _ := filepath.Abs(path)
	absDir, _ := filepath.Abs(c.Dir)
	if !strings.HasPrefix(absPath, absDir) {
		return fmt.Errorf("security: path traversal attempt detected")
	}

	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (c *DiskCache) IsExpired(key string, ttl time.Duration) bool {
	path := filepath.Join(c.Dir, filepath.Clean(key))
	absPath, _ := filepath.Abs(path)
	absDir, _ := filepath.Abs(c.Dir)
	if !strings.HasPrefix(absPath, absDir) {
		return true
	}

	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	return time.Since(info.ModTime()) > ttl
}
