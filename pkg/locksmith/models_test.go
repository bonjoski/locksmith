package locksmith

import (
	"testing"
	"time"
)

// TestExpirationStatus tests the GetExpirationStatus method
func TestExpirationStatus(t *testing.T) {
	threshold := 7 * 24 * time.Hour // 7 days

	tests := []struct {
		name      string
		expiresAt time.Time
		expected  ExpirationStatus
	}{
		{
			name:      "valid secret (30 days)",
			expiresAt: time.Now().Add(30 * 24 * time.Hour),
			expected:  StatusValid,
		},
		{
			name:      "expiring secret (5 days)",
			expiresAt: time.Now().Add(5 * 24 * time.Hour),
			expected:  StatusExpiring,
		},
		{
			name:      "expired secret",
			expiresAt: time.Now().Add(-24 * time.Hour),
			expected:  StatusExpired,
		},
		{
			name:      "just expired",
			expiresAt: time.Now().Add(-1 * time.Second),
			expected:  StatusExpired,
		},
		{
			name:      "on threshold boundary",
			expiresAt: time.Now().Add(7 * 24 * time.Hour),
			expected:  StatusExpiring,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &Secret{
				Value:     []byte("test"),
				CreatedAt: time.Now(),
				ExpiresAt: tt.expiresAt,
			}

			status := secret.GetExpirationStatus(threshold)
			if status != tt.expected {
				t.Errorf("Expected status %d, got %d", tt.expected, status)
			}
		})
	}
}

// TestIsExpired tests the IsExpired method
func TestIsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{"not expired", time.Now().Add(time.Hour), false},
		{"expired", time.Now().Add(-time.Hour), true},
		{"just expired", time.Now().Add(-time.Second), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &Secret{ExpiresAt: tt.expiresAt}
			if secret.IsExpired() != tt.expected {
				t.Errorf("Expected IsExpired=%v, got %v", tt.expected, secret.IsExpired())
			}
		})
	}
}

// TestTimeUntilExpiration tests the TimeUntilExpiration method
func TestTimeUntilExpiration(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	secret := &Secret{ExpiresAt: future}

	duration := secret.TimeUntilExpiration()

	// Should be approximately 24 hours (allow small variance)
	expected := 24 * time.Hour
	if duration < expected-time.Second || duration > expected+time.Second {
		t.Errorf("Expected ~24h, got %v", duration)
	}
}

// TestSecretMetadataExpirationStatus tests metadata expiration status
func TestSecretMetadataExpirationStatus(t *testing.T) {
	threshold := 7 * 24 * time.Hour

	metadata := &SecretMetadata{
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * 24 * time.Hour), // Expiring
	}

	status := metadata.GetExpirationStatus(threshold)
	if status != StatusExpiring {
		t.Errorf("Expected StatusExpiring, got %d", status)
	}
}
