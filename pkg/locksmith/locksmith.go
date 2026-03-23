package locksmith

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/native"
)

const (
	DefaultService   = "sh.locksmith.v2"
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

// Backend defines the interface for native secret storage
type Backend interface {
	Set(service, account string, data []byte, requireBiometrics bool) error
	Get(service, account string, useBiometrics bool, prompt string) ([]byte, error)
	Delete(service, account string, useBiometrics bool, prompt string) error
	List(service string, useBiometrics bool, prompt string) ([]string, error)
}

// DefaultBackend implements Backend using the native package
type DefaultBackend struct{}

func (b *DefaultBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	return native.Set(service, account, data, requireBiometrics)
}

func (b *DefaultBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	return native.Get(service, account, useBiometrics, prompt)
}

func (b *DefaultBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	return native.Delete(service, account, useBiometrics, prompt)
}

func (b *DefaultBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	return native.List(service, useBiometrics, prompt)
}

type Locksmith struct {
	Service string
	Cache   Cache
	Backend Backend
	Options Options
}

func New() (*Locksmith, error) {
	// Default to NOT requiring biometrics when invoked without options
	return NewWithOptions(Options{RequireBiometrics: false})
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
		Backend: &DefaultBackend{},
		Options: Options{RequireBiometrics: false}, // Default to read-only friendly behavior
	}
}

// Set and Delete are implemented in admin.go and require locksmith_admin build tag

func (l *Locksmith) Get(key string) ([]byte, error) {
	secret, err := l.getSecret(key)
	if err != nil {
		return nil, err
	}
	// Return a copy to prevent cache modification
	valueCopy := make([]byte, len(secret.Value))
	copy(valueCopy, secret.Value)
	return valueCopy, nil
}

func (l *Locksmith) getSecret(key string) (*Secret, error) {
	// 1. Check Cache
	if !l.Cache.IsExpired(key, DefaultCacheTTL) {
		secret, err := l.Cache.Get(key)
		if err == nil && secret != nil {
			return secret, nil
		}
	}

	// 2. Fallback to Keychain (triggers biometric prompt if required)
	prompt := l.Options.getPrompt("Authentication required to access '%s'", key)
	data, err := l.Backend.Get(l.Service, key, l.Options.RequireBiometrics, prompt)
	if err != nil {
		return nil, err
	}

	var secret Secret
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, err
	}

	// 3. Update Cache for subsequent calls
	_ = l.Cache.Set(key, secret, DefaultCacheTTL)

	return &secret, nil
}

func (l *Locksmith) List() (map[string]SecretMetadata, error) {
	// ... existing List implementation ...
	prompt := l.Options.getPrompt("Authentication required to list secrets", "")
	keys, err := l.Backend.List(l.Service, l.Options.RequireBiometrics, prompt)
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

// Delete is implemented in admin.go and requires locksmith_admin build tag

// GetWithMetadata retrieves a secret with its metadata
func (l *Locksmith) GetWithMetadata(key string) (*Secret, error) {
	return l.getSecret(key)
}

// ListWithMetadata returns all secrets with their metadata
func (l *Locksmith) ListWithMetadata() (map[string]*SecretMetadata, error) {
	prompt := l.Options.getPrompt("Authentication required to list secrets", "")
	keys, err := l.Backend.List(l.Service, l.Options.RequireBiometrics, prompt)
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
