//go:build test_native && locksmith_admin

package locksmith

import (
	"bytes"
	"testing"
	"time"
)

// mockCache implements Cache in memory for tests.
type mockCache struct {
	store map[string]Secret
}

func newMockCache() *mockCache {
	return &mockCache{store: make(map[string]Secret)}
}

func (c *mockCache) Set(key string, secret Secret, ttl time.Duration) error {
	c.store[key] = secret
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
	return nil
}

func (c *mockCache) IsExpired(key string, ttl time.Duration) bool {
	// In-memory cache never expires for test simplicity.
	return false
}

func TestSetGetAndList(t *testing.T) {
	cache := newMockCache()
	ls := &Locksmith{Service: DefaultService, Cache: cache, Backend: newMockBackend(), Options: Options{}}

	key := "testkey"
	value := []byte("secretvalue")
	// Ensure we zero the secret value after the test to avoid lingering plaintext
	defer func() { for i := range value { value[i] = 0 } }()
	expires := time.Now().Add(1 * time.Hour)

	// Set secret
	if err := ls.Set(key, value, expires); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Get secret
	got, err := ls.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	// Zero the returned slice after comparison
	defer func() { for i := range got { got[i] = 0 } }()
	if !bytes.Equal(got, value) {
		t.Fatalf("Get returned %s, want %s", string(got), string(value))
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
