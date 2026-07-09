//go:build !locksmith_admin
// +build !locksmith_admin

package locksmith

import (
	"encoding/json"
	"fmt"
	"time"
)

// SetWithBiometrics stores a secret with an explicit biometric requirement.
// In builds without the locksmith_admin tag, we store the secret without enforcing biometrics.
func (l *Locksmith) SetWithBiometrics(key string, value []byte, expiresAt time.Time, requireBiometrics bool) error {
	return l.SetWithContext(key, value, expiresAt, requireBiometrics, SecretTypeUnspecified, "", "", nil)
}

// SetWithContext stores a secret with explicit context used for rotator auto-loading.
func (l *Locksmith) SetWithContext(
	key string,
	value []byte,
	expiresAt time.Time,
	requireBiometrics bool,
	secretType SecretType,
	ownerApplication string,
	sourceURL string,
	metadata map[string]string,
) error {
	// Copy the value to avoid zeroing affecting cache storage
	valCopy := make([]byte, len(value))
	copy(valCopy, value)
	// Prepare secret struct with copied value
	secret := Secret{
		Value:            valCopy,
		CreatedAt:        time.Now(),
		ExpiresAt:        expiresAt,
		SecretType:       NormalizeSecretType(secretType),
		OwnerApplication: ownerApplication,
		SourceURL:        sourceURL,
		Metadata:         metadata,
	}
	// Marshal secret to JSON
	data, err := json.Marshal(secret)
	if err != nil {
		// Zero out original value before returning
		for i := range value {
			value[i] = 0
		}
		return err
	}
	// Store via backend (biometric flag ignored)
	err = l.Backend.Set(l.Service, key, data, requireBiometrics)
	// Zero out the original secret value after storage to avoid lingering plaintext
	for i := range value {
		value[i] = 0
	}
	if err != nil {
		return err
	}
	// Update cache with secret containing copied value
	return l.Cache.Set(key, secret, DefaultCacheTTL)
}

// Delete removes a secret from the backend and cache.
func (l *Locksmith) Delete(key string) error {
	// Remove from cache if present
	_ = l.Cache.Delete(key)
	// Prompt for authentication (still uses configured prompt)
	prompt := l.Options.getPrompt("Authentication required to delete secret '%s'", key)
	return l.Backend.Delete(l.Service, key, l.Options.RequireBiometrics, prompt)
}

// RotateSecret is unavailable when compiled without the locksmith_admin tag.
func (l *Locksmith) RotateSecret(key string) error {
	return fmt.Errorf("rotation unavailable in this compile profile; rebuild with -tags locksmith_admin")
}

// RotateExpiringSecrets is unavailable when compiled without the locksmith_admin tag.
func (l *Locksmith) RotateExpiringSecrets() (rotated []string, skipped []string, failed map[string]error, err error) {
	return nil, nil, nil, fmt.Errorf("rotation unavailable in this compile profile; rebuild with -tags locksmith_admin")
}
