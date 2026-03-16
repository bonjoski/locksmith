package locksmith

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/pkg/native"
)

const (
	DefaultService   = "com.locksmith.keychain"
	DefaultCacheTTL  = 1 * time.Hour
	MasterKeyAccount = "locksmith-master-cache-key"
)

type Options struct {
	RequireBiometrics bool
	PromptMessage     string
}

func (o *Options) getPrompt(defaultPrompt, key string) string {
	if o.PromptMessage != "" {
		if key != "" && strings.Contains(o.PromptMessage, "%s") {
			return fmt.Sprintf(o.PromptMessage, key)
		}
		return o.PromptMessage
	}
	if key != "" {
		return fmt.Sprintf(defaultPrompt, key)
	}
	return defaultPrompt
}

type Cache interface {
	Set(key string, secret Secret, ttl time.Duration) error
	Get(key string) (*Secret, error)
	Delete(key string) error
	IsExpired(key string, ttl time.Duration) bool
}

type Locksmith struct {
	Service string
	Cache   Cache
	Options Options
}

func New() (*Locksmith, error) {
	// Default to requiring biometrics when invoked without options
	return NewWithOptions(Options{RequireBiometrics: true})
}

func NewWithOptions(opts Options) (*Locksmith, error) {
	// 1. Derive Master Key from platform-specific logic
	masterKey, err := deriveMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to derive master key: %w", err)
	}

	cache, err := NewDiskCache(masterKey)
	if err != nil {
		return nil, err
	}
	ls := NewWithCache(cache)
	ls.Options = opts
	return ls, nil
}

func NewWithCache(cache Cache) *Locksmith {
	return &Locksmith{
		Service: DefaultService,
		Cache:   cache,
		Options: Options{RequireBiometrics: true}, // Safe default
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

	// Use l.Options.RequireBiometrics
	err = native.Set(l.Service, key, data, l.Options.RequireBiometrics)
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

	// 2. Fallback to Keychain (triggers biometric prompt if required)
	prompt := l.Options.getPrompt("Authentication required to access '%s'", key)
	data, err := native.Get(l.Service, key, l.Options.RequireBiometrics, prompt)
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
	prompt := l.Options.getPrompt("Authentication required to list secrets", "")
	keys, err := native.List(l.Service, l.Options.RequireBiometrics, prompt)
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
	prompt := l.Options.getPrompt("Authentication required to delete secret '%s'", key)
	return native.Delete(l.Service, key, l.Options.RequireBiometrics, prompt)
}

// GetWithMetadata retrieves a secret with its metadata
func (l *Locksmith) GetWithMetadata(key string) (*Secret, error) {
	// Get the value
	value, err := l.Get(key)
	if err != nil {
		return nil, err
	}

	// Try to get metadata from cache
	cached, err := l.Cache.Get(key)
	if err == nil && cached != nil {
		return &Secret{
			Value:     value,
			CreatedAt: cached.CreatedAt,
			ExpiresAt: cached.ExpiresAt,
		}, nil
	}

	// If not in cache, get from keychain
	prompt := l.Options.getPrompt("Authentication required to access '%s'", key)
	data, err := native.Get(l.Service, key, l.Options.RequireBiometrics, prompt)
	if err != nil {
		return nil, err
	}

	var secret Secret
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, err
	}

	secret.Value = value
	return &secret, nil
}

// ListWithMetadata returns all secrets with their metadata
func (l *Locksmith) ListWithMetadata() (map[string]*SecretMetadata, error) {
	prompt := l.Options.getPrompt("Authentication required to list secrets", "")
	keys, err := native.List(l.Service, l.Options.RequireBiometrics, prompt)
	if err != nil {
		return nil, err
	}

	result := make(map[string]*SecretMetadata)
	for _, key := range keys {
		// Filter out the internal master key
		if key == MasterKeyAccount {
			continue
		}

		// Try to get metadata from cache first
		cached, _ := l.Cache.Get(key)
		if cached != nil {
			result[key] = &SecretMetadata{
				CreatedAt: cached.CreatedAt,
				ExpiresAt: cached.ExpiresAt,
			}
		} else {
			// If not in cache, we'd need to read from keychain
			// For now, return empty metadata
			result[key] = &SecretMetadata{}
		}
	}

	return result, nil
}
