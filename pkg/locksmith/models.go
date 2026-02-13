package locksmith

import "time"

// ExpirationStatus represents the state of a secret
type ExpirationStatus int

const (
	StatusValid ExpirationStatus = iota
	StatusExpiring
	StatusExpired
)

type Secret struct {
	Value     []byte    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
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

	if now.Add(threshold).After(s.ExpiresAt) {
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
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetExpirationStatus returns the current status based on metadata
func (sm *SecretMetadata) GetExpirationStatus(threshold time.Duration) ExpirationStatus {
	secret := &Secret{ExpiresAt: sm.ExpiresAt}
	return secret.GetExpirationStatus(threshold)
}
