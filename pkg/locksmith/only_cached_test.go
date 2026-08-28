//go:build test_native && locksmith_admin

package locksmith

import (
	"encoding/json"
	"testing"
	"time"
)

// TestOnlyCached_CacheHit verifies that OnlyCached mode returns from cache when secret exists
func TestOnlyCached_CacheHit(t *testing.T) {
	mc := newMockCache()
	mb := newMockBackend()

	ls := NewWithCache(mc)
	ls.Backend = mb
	ls.Options.OnlyCached = true

	// Pre-seed the cache
	testSecret := Secret{
		Value:     []byte("cached-password"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	err := mc.Set("test/key", testSecret, DefaultCacheTTL)
	if err != nil {
		t.Fatalf("Failed to seed cache: %v", err)
	}

	// Get should return from cache
	value, err := ls.Get("test/key")
	if err != nil {
		t.Fatalf("Expected Get to succeed, got error: %v", err)
	}

	if string(value) != "cached-password" {
		t.Errorf("Expected 'cached-password', got %q", string(value))
	}

	// Verify backend was NOT called (store should be empty)
	mb.mu.RLock()
	backendWasCalled := len(mb.store) > 0
	mb.mu.RUnlock()

	if backendWasCalled {
		t.Error("Expected backend to NOT be called in OnlyCached mode with cache hit")
	}
}

// TestOnlyCached_CacheMiss verifies that OnlyCached mode returns nil on cache miss instead of calling backend
func TestOnlyCached_CacheMiss(t *testing.T) {
	mc := newMockCache()
	mb := newMockBackend()

	ls := NewWithCache(mc)
	ls.Backend = mb
	ls.Options.OnlyCached = true

	// Seed backend with a secret (should NOT be accessed)
	backendSecret := Secret{
		Value:     []byte("backend-password"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	data, _ := json.Marshal(backendSecret)
	_ = mb.Set("sh.locksmith.v2", "test/key", data, false)

	// Get should return nil on cache miss (not fall back to backend)
	value, err := ls.Get("test/key")
	if err != nil {
		t.Fatalf("Expected Get to return nil without error, got error: %v", err)
	}

	if value != nil {
		t.Errorf("Expected nil on cache miss in OnlyCached mode, got %q", string(value))
	}

	// The key test: cache should still be empty (no backend fallback happened)
	cached, _ := mc.Get("test/key")
	if cached != nil {
		t.Error("Expected cache to remain empty after OnlyCached Get with cache miss")
	}
}

// TestOnlyCached_False_CacheMiss verifies that OnlyCached=false falls back to backend on cache miss
func TestOnlyCached_False_CacheMiss(t *testing.T) {
	mc := newMockCache()
	mb := newMockBackend()

	ls := NewWithCache(mc)
	ls.Backend = mb
	ls.Options.OnlyCached = false // Normal mode

	// Seed backend with a secret
	backendSecret := Secret{
		Value:     []byte("backend-password"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	data, _ := json.Marshal(backendSecret)
	_ = mb.Set("sh.locksmith.v2", "test/key", data, false)

	// Get should fall back to backend and populate cache
	value, err := ls.Get("test/key")
	if err != nil {
		t.Fatalf("Expected Get to succeed via backend fallback, got error: %v", err)
	}

	if string(value) != "backend-password" {
		t.Errorf("Expected 'backend-password' from backend, got %q", string(value))
	}

	// Verify cache was populated
	cached, err := mc.Get("test/key")
	if err != nil || cached == nil {
		t.Error("Expected cache to be populated after backend fallback")
	} else if string(cached.Value) != "backend-password" {
		t.Errorf("Expected cache to contain 'backend-password', got %q", string(cached.Value))
	}
}

// TestOnlyCached_GetWithMetadata verifies OnlyCached works with GetWithMetadata
func TestOnlyCached_GetWithMetadata(t *testing.T) {
	mc := newMockCache()
	mb := newMockBackend()

	ls := NewWithCache(mc)
	ls.Backend = mb
	ls.Options.OnlyCached = true

	// Pre-seed the cache with metadata
	testSecret := Secret{
		Value:            []byte("cached-password"),
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(time.Hour),
		SecretType:       SecretTypePassword,
		OwnerApplication: "git",
		Metadata: map[string]string{
			"host":     "github.com",
			"username": "testuser",
		},
	}
	err := mc.Set("git/github.com/testuser", testSecret, DefaultCacheTTL)
	if err != nil {
		t.Fatalf("Failed to seed cache: %v", err)
	}

	// GetWithMetadata should return from cache
	secret, err := ls.GetWithMetadata("git/github.com/testuser")
	if err != nil {
		t.Fatalf("Expected GetWithMetadata to succeed, got error: %v", err)
	}

	if secret == nil {
		t.Fatal("Expected secret to be returned from cache")
	}

	if string(secret.Value) != "cached-password" {
		t.Errorf("Expected 'cached-password', got %q", string(secret.Value))
	}

	if secret.Metadata["host"] != "github.com" {
		t.Errorf("Expected host metadata 'github.com', got %q", secret.Metadata["host"])
	}

	if secret.Metadata["username"] != "testuser" {
		t.Errorf("Expected username metadata 'testuser', got %q", secret.Metadata["username"])
	}
}

// TestOnlyCached_ListKeyNames verifies ListKeyNames works independently of OnlyCached
func TestOnlyCached_ListKeyNames(t *testing.T) {
	mc := newMockCache()
	mb := newMockBackend()

	ls := NewWithCache(mc)
	ls.Backend = mb
	ls.Options.OnlyCached = true

	// Seed backend with keys (ListKeyNames should still access backend)
	for _, key := range []string{"git/github.com/user1", "git/github.com/user2", "api/key"} {
		secret := Secret{Value: []byte("test")}
		data, _ := json.Marshal(secret)
		_ = mb.Set("sh.locksmith.v2", key, data, false)
	}

	// ListKeyNames should bypass OnlyCached and call backend without biometrics
	keys, err := ls.ListKeyNames()
	if err != nil {
		t.Fatalf("Expected ListKeyNames to succeed, got error: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(keys))
	}

	// Verify keys are correct
	expectedKeys := map[string]bool{
		"git/github.com/user1": true,
		"git/github.com/user2": true,
		"api/key":              true,
	}

	for _, key := range keys {
		if !expectedKeys[key] {
			t.Errorf("Unexpected key in ListKeyNames result: %q", key)
		}
		delete(expectedKeys, key)
	}

	if len(expectedKeys) > 0 {
		t.Errorf("Expected keys not found: %v", expectedKeys)
	}
}
