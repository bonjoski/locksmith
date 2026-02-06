package locksmith

import "time"

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

type SecretMetadata struct {
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
