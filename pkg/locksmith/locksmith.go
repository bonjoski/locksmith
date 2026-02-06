package locksmith

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/pkg/native"
)

const (
	DefaultService   = "com.locksmith.keychain"
	DefaultCacheTTL  = 1 * time.Hour
	MasterKeyAccount = "locksmith-master-cache-key"
)

type Cache interface {
	Set(key string, secret Secret, ttl time.Duration) error
	Get(key string) (*Secret, error)
	Delete(key string) error
	IsExpired(key string, ttl time.Duration) bool
}

type Locksmith struct {
	Service string
	Cache   Cache
}

func New() (*Locksmith, error) {
	// 1. Derive Master Key from Hardware UUID
	// This ensures the cache is device-locked without triggering Keychain prompts
	masterKey, err := deriveMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to derive master key: %w", err)
	}

	cache, err := NewDiskCache(masterKey)
	if err != nil {
		return nil, err
	}
	return NewWithCache(cache), nil
}

func deriveMasterKey() ([]byte, error) {
	// Get Hardware UUID via ioreg
	// ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/ {print $(NF-1)}'
	cmd := exec.Command("ioreg", "-d2", "-c", "IOPlatformExpertDevice")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get hardware info: %w", err)
	}

	// Simple parsing for IOPlatformUUID
	lines := strings.Split(string(out), "\n")
	var uuid string
	for _, line := range lines {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.Split(line, "\"")
			if len(parts) >= 4 {
				uuid = parts[3]
				break
			}
		}
	}

	if uuid == "" {
		return nil, fmt.Errorf("failed to extract IOPlatformUUID")
	}

	// Hash the UUID to get a 32-byte key
	hash := sha256.Sum256([]byte(uuid))
	return hash[:], nil
}

func NewWithCache(cache Cache) *Locksmith {
	return &Locksmith{
		Service: DefaultService,
		Cache:   cache,
	}
}

func (l *Locksmith) Set(key string, value []byte, expiresAt time.Time) error {
	secret := Secret{
		Value:     value,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	data, err := json.Marshal(secret)
	if err != nil {
		return err
	}

	// Always require biometrics when storing a new secret in Keychain
	err = native.Set(l.Service, key, data, true)
	if err != nil {
		return err
	}

	// Update cache as well
	return l.Cache.Set(key, secret, DefaultCacheTTL)
}

func (l *Locksmith) Get(key string) ([]byte, error) {
	// 1. Check Cache
	if !l.Cache.IsExpired(key, DefaultCacheTTL) {
		secret, err := l.Cache.Get(key)
		if err == nil && secret != nil {
			// Return a copy to prevent cache modification
			valueCopy := make([]byte, len(secret.Value))
			copy(valueCopy, secret.Value)
			return valueCopy, nil
		}
	}

	// 2. Fallback to Keychain (triggers biometric prompt)
	prompt := fmt.Sprintf("Authentication required to access '%s'", key)
	data, err := native.Get(l.Service, key, true, prompt)
	if err != nil {
		return nil, err
	}

	var secret Secret
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, err
	}

	// 3. Update Cache for subsequent calls
	_ = l.Cache.Set(key, secret, DefaultCacheTTL)

	// Return a copy to prevent cache modification
	valueCopy := make([]byte, len(secret.Value))
	copy(valueCopy, secret.Value)
	return valueCopy, nil
}

func (l *Locksmith) List() (map[string]SecretMetadata, error) {
	prompt := "Authentication required to list secrets"
	keys, err := native.List(l.Service, true, prompt)
	if err != nil {
		return nil, err
	}

	result := make(map[string]SecretMetadata)
	for _, key := range keys {
		// Filter out the internal master key
		if key == MasterKeyAccount {
			continue
		}

		// To list metadata, we technically need to READ the item, which requires biometrics…
		// For now, let's just return what we have (the keys).
		result[key] = SecretMetadata{}
	}
	return result, nil
}

func (l *Locksmith) Delete(key string) error {
	_ = l.Cache.Delete(key)
	prompt := fmt.Sprintf("Authentication required to delete secret '%s'", key)
	return native.Delete(l.Service, key, true, prompt)
}
