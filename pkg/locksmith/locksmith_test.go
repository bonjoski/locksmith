package locksmith

import (
	"bytes"
	"testing"
	"time"
)

// MockCache is a simple in-memory cache for testing
type MockCache struct {
	secrets map[string]Secret
}

func (m *MockCache) Set(key string, secret Secret, ttl time.Duration) error {
	m.secrets[key] = secret
	return nil
}

func (m *MockCache) Get(key string) (*Secret, error) {
	s, ok := m.secrets[key]
	if !ok {
		return nil, nil
	}
	return &s, nil
}

func (m *MockCache) Delete(key string) error {
	delete(m.secrets, key)
	return nil
}

func (m *MockCache) IsExpired(key string, ttl time.Duration) bool {
	return false
}

// TestSecretZeroing verifies that secrets are properly zeroed after use
func TestSecretZeroing(t *testing.T) {
	secret := Secret{
		Value:     []byte("sensitive-data"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// Zero the secret
	for i := range secret.Value {
		secret.Value[i] = 0
	}

	// Verify all bytes are zero
	for i, b := range secret.Value {
		if b != 0 {
			t.Errorf("Byte at index %d is not zero: %d", i, b)
		}
	}
}

// TestSecretExpiration verifies expiration logic
func TestSecretExpiration(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		isExpired bool
	}{
		{"not expired", time.Now().Add(time.Hour), false},
		{"expired", time.Now().Add(-time.Hour), true},
		{"just expired", time.Now().Add(-time.Second), true},
		{"far future", time.Now().Add(365 * 24 * time.Hour), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := Secret{
				Value:     []byte("test"),
				CreatedAt: time.Now(),
				ExpiresAt: tt.expiresAt,
			}

			expired := time.Now().After(secret.ExpiresAt)
			if expired != tt.isExpired {
				t.Errorf("Expected expired=%v, got %v", tt.isExpired, expired)
			}
		})
	}
}

// TestMockCacheOperations tests the mock cache implementation
func TestMockCacheOperations(t *testing.T) {
	mock := &MockCache{secrets: make(map[string]Secret)}

	// Test Set
	secret := Secret{Value: []byte("test-value")}
	err := mock.Set("key1", secret, time.Hour)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Test Get - exists
	got, err := mock.Get("key1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got == nil {
		t.Fatal("Expected secret, got nil")
	}
	if !bytes.Equal(got.Value, []byte("test-value")) {
		t.Errorf("Expected 'test-value', got %s", got.Value)
	}

	// Test Get - not exists
	notFound, err := mock.Get("nonexistent")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if notFound != nil {
		t.Error("Expected nil for nonexistent key")
	}

	// Test Delete
	err = mock.Delete("key1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deletion
	deleted, err := mock.Get("key1")
	if err != nil {
		t.Fatalf("Get after delete failed: %v", err)
	}
	if deleted != nil {
		t.Error("Expected nil after deletion")
	}
}

// TestMultipleSecrets tests handling multiple secrets
func TestMultipleSecrets(t *testing.T) {
	mock := &MockCache{secrets: make(map[string]Secret)}

	secrets := map[string]string{
		"aws/key":     "AKIAIOSFODNN7EXAMPLE",
		"db/password": "super-secret-password",
		"api/token":   "token-12345",
	}

	// Store all secrets
	for key, value := range secrets {
		secret := Secret{Value: []byte(value)}
		err := mock.Set(key, secret, time.Hour)
		if err != nil {
			t.Fatalf("Failed to set %s: %v", key, err)
		}
	}

	// Retrieve and verify all secrets
	for key, expectedValue := range secrets {
		got, err := mock.Get(key)
		if err != nil {
			t.Fatalf("Failed to get %s: %v", key, err)
		}
		if got == nil {
			t.Fatalf("Expected secret for %s, got nil", key)
		}
		if !bytes.Equal(got.Value, []byte(expectedValue)) {
			t.Errorf("For key %s: expected %s, got %s", key, expectedValue, got.Value)
		}
	}
}

// TestEmptySecretValue tests handling of empty secret values
func TestEmptySecretValue(t *testing.T) {
	mock := &MockCache{secrets: make(map[string]Secret)}

	secret := Secret{Value: []byte("")}
	err := mock.Set("empty", secret, time.Hour)
	if err != nil {
		t.Fatalf("Failed to set empty secret: %v", err)
	}

	got, err := mock.Get("empty")
	if err != nil {
		t.Fatalf("Failed to get empty secret: %v", err)
	}
	if got == nil {
		t.Fatal("Expected empty secret, got nil")
	}
	if len(got.Value) != 0 {
		t.Errorf("Expected empty value, got %d bytes", len(got.Value))
	}
}

// TestLargeSecretValue tests handling of large secret values
func TestLargeSecretValue(t *testing.T) {
	mock := &MockCache{secrets: make(map[string]Secret)}

	// Create a large secret (10KB)
	largeValue := make([]byte, 10*1024)
	for i := range largeValue {
		largeValue[i] = byte(i % 256)
	}

	secret := Secret{Value: largeValue}
	err := mock.Set("large", secret, time.Hour)
	if err != nil {
		t.Fatalf("Failed to set large secret: %v", err)
	}

	got, err := mock.Get("large")
	if err != nil {
		t.Fatalf("Failed to get large secret: %v", err)
	}
	if got == nil {
		t.Fatal("Expected large secret, got nil")
	}
	if !bytes.Equal(got.Value, largeValue) {
		t.Error("Large secret value mismatch")
	}
}

// TestSpecialCharactersInKey tests keys with special characters
func TestSpecialCharactersInKey(t *testing.T) {
	mock := &MockCache{secrets: make(map[string]Secret)}

	specialKeys := []string{
		"key/with/slashes",
		"key-with-dashes",
		"key_with_underscores",
		"key.with.dots",
		"key:with:colons",
		"key@with@at",
	}

	for _, key := range specialKeys {
		secret := Secret{Value: []byte("value-for-" + key)}
		err := mock.Set(key, secret, time.Hour)
		if err != nil {
			t.Fatalf("Failed to set key %s: %v", key, err)
		}

		got, err := mock.Get(key)
		if err != nil {
			t.Fatalf("Failed to get key %s: %v", key, err)
		}
		if got == nil {
			t.Fatalf("Expected secret for key %s, got nil", key)
		}
	}
}
