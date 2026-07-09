//go:build locksmith_admin

package locksmith

import (
	"encoding/json"
	"time"
)

// Set stores a secret in the keychain using the default biometric requirement from options
func (l *Locksmith) Set(key string, value []byte, expiresAt time.Time) error {
	return l.SetWithContext(key, value, expiresAt, l.Options.RequireBiometrics, SecretTypeUnspecified, "", "", nil)
}

// SetWithBiometrics stores a secret with an explicit biometric requirement override
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
	defer zeroBytes(value)

	valCopy := make([]byte, len(value))
	copy(valCopy, value)

	secret := Secret{
		Value:            valCopy,
		CreatedAt:        time.Now(),
		ExpiresAt:        expiresAt,
		SecretType:       NormalizeSecretType(secretType),
		OwnerApplication: ownerApplication,
		SourceURL:        sourceURL,
		Metadata:         metadata,
	}

	data, err := json.Marshal(secret)
	if err != nil {
		return err
	}

	err = l.Backend.Set(l.Service, key, data, requireBiometrics)
	if err != nil {
		return err
	}

	// Update cache as well
	return l.Cache.Set(key, secret, DefaultCacheTTL)
}

// Delete removes a secret from the keychain and cache
func (l *Locksmith) Delete(key string) error {
	_ = l.Cache.Delete(key)
	prompt := l.Options.getPrompt("Authentication required to delete secret '%s'", key)
	return l.Backend.Delete(l.Service, key, l.Options.RequireBiometrics, prompt)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
