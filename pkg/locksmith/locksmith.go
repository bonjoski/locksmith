package locksmith

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/native"
	"github.com/bonjoski/locksmith/v2/pkg/rotator"
)

const (
	DefaultService   = "sh.locksmith.v2"
	DefaultCacheTTL  = 1 * time.Hour
	MasterKeyAccount = "locksmith-master-cache-key"
)

type Options struct {
	RequireBiometrics bool
	PromptMessage     string
	BypassCache       bool
	// Binary access control
	AllowBinaries []string
	DenyBinaries  []string
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
	Service  string
	Cache    Cache
	Backend  Backend
	Options  Options
	Config   *Config // Loaded system configuration
	Rotators *rotator.HandlerRegistry
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

	// Load configuration and populate AccessControl
	cfg, cfgErr := LoadConfig()
	if cfgErr == nil && cfg != nil {
		ls.Config = cfg
		ls.Options.AllowBinaries = cfg.AccessControl.AllowBinaries
		ls.Options.DenyBinaries = cfg.AccessControl.DenyBinaries
	}
	return ls, nil
}

func NewWithCache(cache Cache) *Locksmith {
	ls := &Locksmith{
		Service:  DefaultService,
		Cache:    cache,
		Backend:  &DefaultBackend{},
		Options:  Options{RequireBiometrics: false}, // Default to read-only friendly behavior
		Rotators: rotator.NewHandlerRegistry(),
	}
	registerDefaultRotationHandlers(ls)
	return ls
}

// Set and Delete are implemented in admin.go and are compiled when locksmith_admin is enabled.

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
	secret, err := l.getSecretNoRotate(key)
	if err != nil {
		return nil, err
	}

	if secret == nil {
		return nil, nil
	}

	if !secret.IsExpired() {
		return secret, nil
	}

	if NormalizeSecretType(secret.SecretType) != SecretTypeOAuthToken {
		return secret, nil
	}

	if !l.hasRotationRuleForKey(key) {
		return secret, nil
	}

	if err := l.RotateSecret(key); err != nil {
		errMsg := strings.ToLower(strings.TrimSpace(err.Error()))
		if strings.Contains(errMsg, "rotation unavailable in this compile profile") {
			return secret, nil
		}
		return nil, fmt.Errorf("secret '%s' is expired and automatic oauth rotation failed: %w", key, err)
	}

	rotated, err := l.getSecretNoRotate(key)
	if err != nil {
		return nil, fmt.Errorf("secret '%s' rotated but retrieval failed: %w", key, err)
	}
	return rotated, nil
}

func (l *Locksmith) hasRotationRuleForKey(key string) bool {
	if l == nil || l.Config == nil {
		return false
	}
	for _, rule := range l.Config.Rotation {
		matched, err := filepath.Match(rule.Secret, key)
		if err != nil {
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

func (l *Locksmith) getSecretNoRotate(key string) (*Secret, error) {
	// 1. Check Cache (skip if BypassCache is true)
	if !l.Options.BypassCache && !l.Cache.IsExpired(key, DefaultCacheTTL) {
		secret, err := l.Cache.Get(key)
		if err == nil && secret != nil {
			return secret, nil
		}
	}

	// 1b. Binary whitelisting enforcement (moved to helper)
	if err := l.checkBinaryAccess(); err != nil {
		return nil, err
	}

	// 2. Fallback to Keychain (triggers biometric prompt if required)
	prompt := l.Options.getPrompt("Authentication required to access '%s'", key)
	data, err := l.Backend.Get(l.Service, key, l.Options.RequireBiometrics, prompt)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()

	var secret Secret
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, err
	}

	// 3. Update Cache for subsequent calls (skip if BypassCache is true)
	if !l.Options.BypassCache {
		_ = l.Cache.Set(key, secret, DefaultCacheTTL)
	}

	return &secret, nil
}

func (l *Locksmith) List() (map[string]SecretMetadata, error) {
	// ... existing List implementation ...
	// Binary whitelisting enforcement before listing
	if l.Config != nil {
		execPath, _ := os.Executable()
		ac := l.Config.AccessControl
		if len(ac.DenyBinaries) > 0 {
			for _, d := range ac.DenyBinaries {
				if execPath == d {
					return nil, fmt.Errorf("binary %s is explicitly denied by access control", execPath)
				}
			}
		}
		if len(ac.AllowBinaries) > 0 {
			allowed := false
			for _, a := range ac.AllowBinaries {
				if execPath == a {
					allowed = true
					break
				}
			}
			if !allowed {
				return nil, fmt.Errorf("binary %s is not in allowed list", execPath)
			}
		}
	}

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

// Delete is implemented in admin.go and is compiled when locksmith_admin is enabled.

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

		// Try to get metadata from cache first (skip if BypassCache is true)
		var cached *Secret
		if !l.Options.BypassCache {
			cached, _ = l.Cache.Get(key)
		}
		if cached != nil {
			result[key] = &SecretMetadata{
				CreatedAt:        cached.CreatedAt,
				ExpiresAt:        cached.ExpiresAt,
				SecretType:       cached.SecretType,
				OwnerApplication: cached.OwnerApplication,
				SourceURL:        cached.SourceURL,
				Metadata:         cached.Metadata,
			}
		} else {
			// If not in cache, we'd need to read from keychain
			// For now, return empty metadata
			result[key] = &SecretMetadata{}
		}
	}

	return result, nil
}
