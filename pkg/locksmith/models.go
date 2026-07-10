package locksmith

import (
	"strings"
	"time"
)

// ExpirationStatus represents the state of a secret
type ExpirationStatus int

const (
	StatusValid ExpirationStatus = iota
	StatusExpiring
	StatusExpired
)

// SecretType classifies a secret for rotator selection and policy decisions.
type SecretType string

const (
	SecretTypeUnspecified SecretType = ""
	SecretTypePassword    SecretType = "password"
	SecretTypeAPIKey      SecretType = "api_key"
	SecretTypeOAuthToken  SecretType = "oauth_token" // #nosec G101 -- type discriminator value, not a hardcoded secret
	SecretTypeToken       SecretType = "token"
)

// ParseSecretType normalizes free-form input into a SecretType value.
func ParseSecretType(v string) SecretType {
	return SecretType(strings.ToLower(strings.TrimSpace(v)))
}

// NormalizeSecretType normalizes an existing SecretType value.
func NormalizeSecretType(v SecretType) SecretType {
	return ParseSecretType(string(v))
}

type Secret struct {
	Value            []byte            `json:"value"`
	CreatedAt        time.Time         `json:"created_at"`
	ExpiresAt        time.Time         `json:"expires_at"`
	SecretType       SecretType        `json:"secret_type,omitempty"`
	OwnerApplication string            `json:"owner_application,omitempty"`
	SourceURL        string            `json:"source_url,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// Zero clears the secret value from memory
func (s *Secret) Zero() {
	for i := range s.Value {
		s.Value[i] = 0
	}
	s.Value = nil
}

// GetExpirationStatus returns the current status of the secret
func (s *Secret) GetExpirationStatus(threshold time.Duration) ExpirationStatus {
	now := time.Now()

	if now.After(s.ExpiresAt) {
		return StatusExpired
	}

	if !now.Add(threshold).Before(s.ExpiresAt) {
		return StatusExpiring
	}

	return StatusValid
}

// TimeUntilExpiration returns the duration until expiration
func (s *Secret) TimeUntilExpiration() time.Duration {
	return time.Until(s.ExpiresAt)
}

// IsExpired returns true if the secret has expired
func (s *Secret) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

type SecretMetadata struct {
	CreatedAt        time.Time         `json:"created_at"`
	ExpiresAt        time.Time         `json:"expires_at"`
	SecretType       SecretType        `json:"secret_type,omitempty"`
	OwnerApplication string            `json:"owner_application,omitempty"`
	SourceURL        string            `json:"source_url,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// GetExpirationStatus returns the current status based on metadata
func (sm *SecretMetadata) GetExpirationStatus(threshold time.Duration) ExpirationStatus {
	secret := &Secret{ExpiresAt: sm.ExpiresAt}
	return secret.GetExpirationStatus(threshold)
}
