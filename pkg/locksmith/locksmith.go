package locksmith

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/audit"
	"github.com/bonjoski/locksmith/v2/pkg/native"
	"github.com/bonjoski/locksmith/v2/pkg/protocol"
	"github.com/bonjoski/locksmith/v2/pkg/rotator"
	"github.com/bonjoski/locksmith/v2/pkg/slice"
	"golang.org/x/sync/singleflight"
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
	// OnlyCached mode: if true, only read from cache and don't fall back to keychain.
	// Cache misses return nil (secret not found) instead of prompting for biometrics.
	// This is useful for git credential helpers to avoid blocking prompts.
	OnlyCached bool
	// Binary access control
	AllowBinaries []string
	DenyBinaries  []string
	// Peer binary attestation for IPC callers (never evaluate os.Executable() when PeerInstalled is true)
	PeerInstalled bool
	PeerExePath   string
	PeerExeHash   string
	// Audit tracking options
	AuditIdentity string
	DisableAudit  bool
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
	Service     string
	Cache       Cache
	Backend     Backend
	Options     Options
	Config      *Config // Loaded system configuration
	Rotators    *rotator.HandlerRegistry
	unlockGroup singleflight.Group
}

func New() (*Locksmith, error) {
	// Default to NOT requiring biometrics when invoked without options
	return NewWithOptions(Options{RequireBiometrics: false})
}

func NewWithOptions(opts Options) (*Locksmith, error) {
	// 1. Derive user-bound master key (defense-in-depth: combines machine hardware ID and OS user identity)
	masterKey, err := deriveMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to derive master key: %w", err)
	}

	// 2. Derive legacy master key for transparent auto-migration of existing cache entries
	legacyKey, _ := deriveLegacyMasterKey()

	cache, err := NewDiskCacheWithLegacy(masterKey, legacyKey)
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

func cloneSecret(s *Secret) *Secret {
	if s == nil {
		return nil
	}
	cp := *s
	if s.Value != nil {
		cp.Value = make([]byte, len(s.Value))
		copy(cp.Value, s.Value)
	}
	if s.Metadata != nil {
		cp.Metadata = make(map[string]string, len(s.Metadata))
		for k, v := range s.Metadata {
			cp.Metadata[k] = v
		}
	}
	return &cp
}

func (l *Locksmith) Get(key string) ([]byte, error) {
	return l.GetWithOptions(key, l.Options)
}

// GetWithOptions retrieves a secret using call-scoped Options without mutating shared Locksmith state.
func (l *Locksmith) GetWithOptions(key string, opts Options) ([]byte, error) {
	secret, err := l.getSecretWithOptions(key, opts)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, nil
	}
	// Return a copy to prevent cache modification
	valueCopy := make([]byte, len(secret.Value))
	copy(valueCopy, secret.Value)
	return valueCopy, nil
}

// GetForPeer retrieves a secret on behalf of an IPC peer, enforcing binary access control
// against the peer's kernel-attested executable path and SHA-256 hash rather than os.Executable().
func (l *Locksmith) GetForPeer(key string, peer *protocol.PeerCredentials) ([]byte, error) {
	opts := l.Options
	opts.PeerInstalled = true
	if peer != nil {
		opts.PeerExePath = peer.ExePath
		opts.PeerExeHash = peer.ExeHash
	}
	return l.GetWithOptions(key, opts)
}

func (l *Locksmith) auditLogWithOptions(opts Options, key string, outcome audit.Outcome, reason string) {
	if key == MasterKeyAccount || opts.DisableAudit {
		return
	}
	if err := audit.Log(audit.Event{
		SecretName: key,
		Identity:   opts.AuditIdentity,
		Outcome:    outcome,
		Reason:     reason,
	}); err != nil {
		return
	}
}

func (l *Locksmith) getSecretWithOptions(key string, opts Options) (*Secret, error) {
	secret, err := l.getSecretNoRotateWithOptions(key, opts)
	if err != nil {
		l.auditLogWithOptions(opts, key, audit.OutcomeDenied, err.Error())
		return nil, err
	}

	if secret == nil {
		return nil, nil
	}

	if !secret.IsExpired() {
		reason := "Vault secret retrieved"
		if secret.SecretType != "" {
			reason = fmt.Sprintf("Vault secret retrieved (type: %s)", secret.SecretType)
		}
		l.auditLogWithOptions(opts, key, audit.OutcomeGranted, reason)
		return secret, nil
	}

	return l.handleExpiredSecretWithOptions(key, secret, opts)
}

func (l *Locksmith) handleExpiredSecretWithOptions(key string, secret *Secret, opts Options) (*Secret, error) {
	if NormalizeSecretType(secret.SecretType) != SecretTypeOAuthToken {
		l.auditLogWithOptions(opts, key, audit.OutcomeGranted, "Vault secret retrieved (expired non-oauth)")
		return secret, nil
	}

	if !l.hasRotationRuleForKey(key) {
		l.auditLogWithOptions(opts, key, audit.OutcomeGranted, "Vault secret retrieved (expired, no rotation rule)")
		return secret, nil
	}

	if err := l.RotateSecret(key); err != nil {
		errMsg := strings.ToLower(strings.TrimSpace(err.Error()))
		if strings.Contains(errMsg, "rotation unavailable in this compile profile") {
			return secret, nil
		}
		l.auditLogWithOptions(opts, key, audit.OutcomeDenied, fmt.Sprintf("secret '%s' is expired and rotation failed: %v", key, err))
		return nil, fmt.Errorf("secret '%s' is expired and automatic oauth rotation failed: %w", key, err)
	}

	rotated, err := l.getSecretNoRotateWithOptions(key, opts)
	if err != nil {
		l.auditLogWithOptions(opts, key, audit.OutcomeDenied, fmt.Sprintf("secret '%s' rotated but retrieval failed: %v", key, err))
		return nil, fmt.Errorf("secret '%s' rotated but retrieval failed: %w", key, err)
	}

	l.auditLogWithOptions(opts, key, audit.OutcomeGranted, "Vault secret retrieved after auto-rotation")
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
	return l.getSecretNoRotateWithOptions(key, l.Options)
}

func (l *Locksmith) checkActiveCache(key string, opts Options) *Secret {
	if !opts.BypassCache && l.Cache != nil && !l.Cache.IsExpired(key, DefaultCacheTTL) {
		if secret, err := l.Cache.Get(key); err == nil && secret != nil {
			return secret
		}
	}
	return nil
}

func (l *Locksmith) loadAndCacheSecret(key string, opts Options) (*Secret, error) {
	if cached := l.checkActiveCache(key, opts); cached != nil {
		return cloneSecret(cached), nil
	}

	prompt := opts.getPrompt("Authentication required to access '%s'", key)
	data, getErr := l.Backend.Get(l.Service, key, opts.RequireBiometrics, prompt)
	if getErr != nil {
		return nil, getErr
	}
	defer slice.ExplicitBzero(data)

	var secret Secret
	if unmarshalErr := json.Unmarshal(data, &secret); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	if !opts.BypassCache && l.Cache != nil {
		_ = l.Cache.Set(key, secret, DefaultCacheTTL)
	}

	return cloneSecret(&secret), nil
}

func (l *Locksmith) getSecretNoRotateWithOptions(key string, opts Options) (*Secret, error) {
	// 1. Check Cache (skip if BypassCache is true)
	if cached := l.checkActiveCache(key, opts); cached != nil {
		return cached, nil
	}

	// 1a. OnlyCached mode: if cache is expired or missing, return nil without keychain fallback
	if opts.OnlyCached {
		return nil, nil
	}

	// 1b. Binary whitelisting enforcement (evaluates peer binary if PeerInstalled/PeerExePath/PeerExeHash set)
	if err := l.checkBinaryAccessWithOptions(opts); err != nil {
		return nil, err
	}

	// 2. Coalesce concurrent cold-cache Keychain / MasterKey unlocks via singleflight
	// so N=8 parallel subagents do not trigger 8 simultaneous Touch ID prompts.
	flightKey := fmt.Sprintf("%s\x00%s\x00%t\x00%t", l.Service, key, opts.RequireBiometrics, opts.BypassCache)
	val, err, _ := l.unlockGroup.Do(flightKey, func() (any, error) {
		return l.loadAndCacheSecret(key, opts)
	})
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}
	return cloneSecret(val.(*Secret)), nil
}

func (l *Locksmith) List() (map[string]SecretMetadata, error) {
	if err := l.checkBinaryAccessWithOptions(l.Options); err != nil {
		return nil, err
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

// ListKeyNames returns configured key names without requiring biometric
// authentication. It exposes only key names, never secret values, so it's
// safe for internal resolution paths (e.g. the git credential helper
// matching a host to its stored key) that run on every git operation and
// would otherwise force a Face ID/Touch ID prompt just to find a key name.
// Binary access control still applies. Use List/ListWithMetadata for
// interactive/user-facing listing, which stays biometric-gated.
func (l *Locksmith) ListKeyNames() ([]string, error) {
	if err := l.checkBinaryAccess(); err != nil {
		return nil, err
	}

	keys, err := l.Backend.List(l.Service, false, "")
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == MasterKeyAccount {
			continue
		}
		result = append(result, key)
	}
	return result, nil
}

// Delete is implemented in admin.go and is compiled when locksmith_admin is enabled.

// GetWithMetadata retrieves a secret with its metadata
func (l *Locksmith) GetWithMetadata(key string) (*Secret, error) {
	return l.getSecretWithOptions(key, l.Options)
}

// GetWithMetadataAndOptions retrieves a secret with its metadata using call-scoped Options.
func (l *Locksmith) GetWithMetadataAndOptions(key string, opts Options) (*Secret, error) {
	return l.getSecretWithOptions(key, opts)
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
