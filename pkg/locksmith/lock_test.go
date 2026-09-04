//go:build test_native && locksmith_admin

package locksmith

import (
	"bytes"
	"testing"
	"time"
)

// mockCache implements Cache in memory for tests.
type mockCache struct {
	store       map[string]Secret
	expiredKeys map[string]bool // Keys marked as expired for testing
}

func newMockCache() *mockCache {
	return &mockCache{
		store:       make(map[string]Secret),
		expiredKeys: make(map[string]bool),
	}
}

func (c *mockCache) Set(key string, secret Secret, ttl time.Duration) error {
	c.store[key] = secret
	// Clear expired flag when setting a fresh value
	delete(c.expiredKeys, key)
	return nil
}

func (c *mockCache) Get(key string) (*Secret, error) {
	if s, ok := c.store[key]; ok {
		return &s, nil
	}
	return nil, nil
}

func (c *mockCache) Delete(key string) error {
	delete(c.store, key)
	delete(c.expiredKeys, key)
	return nil
}

func (c *mockCache) IsExpired(key string, ttl time.Duration) bool {
	// Check if this key is marked as expired for testing
	if c.expiredKeys[key] {
		return true
	}
	// Otherwise, in-memory cache never expires for test simplicity
	return false
}

func TestSetGetAndList(t *testing.T) {
	cache := newMockCache()
	ls := &Locksmith{Service: DefaultService, Cache: cache, Backend: newMockBackend(), Options: Options{}}

	key := "testkey"
	value := []byte("secretvalue")
	expires := time.Now().Add(1 * time.Hour)

	// Set secret (note: Set zeros the input value for security, so we compare against a copy)
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)
	if err := ls.Set(key, value, expires); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Get secret
	got, err := ls.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	// Zero the returned slice after comparison
	defer func() {
		for i := range got {
			got[i] = 0
		}
		for i := range valueCopy {
			valueCopy[i] = 0
		}
	}()
	if !bytes.Equal(got, valueCopy) {
		t.Fatalf("Get returned %s, want %s", string(got), string(valueCopy))
	}

	// List secrets
	list, err := ls.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if _, ok := list[key]; !ok {
		t.Fatalf("List missing key %s", key)
	}
}
