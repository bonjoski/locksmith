package locksmith

import (
	"bytes"
	"testing"
	"time"
)

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

func TestLocksmithWithMockCache(t *testing.T) {
	mock := &MockCache{secrets: make(map[string]Secret)}
	ls := NewWithCache(mock)

	secret := Secret{Value: []byte("mock-value")}
	err := ls.Cache.Set("test", secret, time.Hour)
	if err != nil {
		t.Fatalf("Failed to set mock secret: %v", err)
	}

	got, err := ls.Cache.Get("test")
	if err != nil {
		t.Fatalf("Failed to get mock secret: %v", err)
	}
	if !bytes.Equal(got.Value, []byte("mock-value")) {
		t.Errorf("Expected mock-value, got %s", got.Value)
	}
}
