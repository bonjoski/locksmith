package locksmith

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
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
	// 1. Get or Generate Master Key from Keychain
	// We store it without biometrics so we can decrypt the cache transparently
	masterKey, err := getOrGenerateMasterKey(DefaultService)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize master key: %w", err)
	}

	cache, err := NewDiskCache(masterKey)
	if err != nil {
		return nil, err
	}
	return NewWithCache(cache), nil
}

func getOrGenerateMasterKey(service string) ([]byte, error) {
	// Try to get existing key
	key, err := native.Get(service, MasterKeyAccount, false, "")
	if err == nil && len(key) == 32 {
		return key, nil
	}

	// Generate new key
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return nil, err
	}

	// Store in Keychain (no biometrics for the master key itself)
	if err := native.Set(service, MasterKeyAccount, newKey, false); err != nil {
		return nil, err
	}

	return newKey, nil
}

func NewWithCache(cache Cache) *Locksmith {
	return &Locksmith{
		Service: DefaultService,
		Cache:   cache,
	}
}

func (l *Locksmith) Set(key string, value string, expiresAt time.Time) error {
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

func (l *Locksmith) Get(key string) (string, error) {
	// 1. Check Cache
	if !l.Cache.IsExpired(key, DefaultCacheTTL) {
		secret, err := l.Cache.Get(key)
		if err == nil && secret != nil {
			return secret.Value, nil
		}
	}

	// 2. Fallback to Keychain (triggers biometric prompt)
	prompt := fmt.Sprintf("Authentication required to access '%s'", key)
	data, err := native.Get(l.Service, key, true, prompt)
	if err != nil {
		return "", err
	}

	var secret Secret
	if err := json.Unmarshal(data, &secret); err != nil {
		return "", err
	}

	// 3. Update Cache for subsequent calls
	_ = l.Cache.Set(key, secret, DefaultCacheTTL)

	return secret.Value, nil
}

func (l *Locksmith) List() (map[string]SecretMetadata, error) {
	keys, err := native.List(l.Service)
	if err != nil {
		return nil, err
	}

	result := make(map[string]SecretMetadata)
	for _, key := range keys {
		// To list metadata, we technically need to READ the item, which requires biometrics
		// if NOT using kSecAccessControlUserPresence without the secret part.
		// HOWEVER, in macOS Keychain, if we just want attributes, we can skip biometrics
		// if we only ask for attributes and the item isn't marked as "always prompt for attributes".
		// In our native_list, we only ask for attributes.

		// If we want more metadata, we might need a more complex native_list.
		// For now, let's just return what we have (the keys).
		result[key] = SecretMetadata{}
	}
	return result, nil
}

func (l *Locksmith) Delete(key string) error {
	_ = l.Cache.Delete(key)
	return native.Delete(l.Service, key)
}
