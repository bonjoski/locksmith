package locksmith

import (
	"strings"
	"testing"
	"time"
)

func TestDiskCache(t *testing.T) {
	cache, err := NewDiskCache()
	if err != nil {
		t.Fatalf("Failed to create disk cache: %v", err)
	}

	secret := Secret{
		Value:     "test-value",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	key := "test-key"

	// Cleanup before/after
	defer func() { _ = cache.Delete(key) }()
	_ = cache.Delete(key)

	// Test Set
	if err := cache.Set(key, secret, 1*time.Hour); err != nil {
		t.Errorf("Failed to set secret: %v", err)
	}

	// Test Get
	got, err := cache.Get(key)
	if err != nil {
		t.Errorf("Failed to get secret: %v", err)
	}
	if got == nil || got.Value != secret.Value {
		t.Errorf("Expected secret value %s, got %v", secret.Value, got)
	}

	// Test Expiration
	if cache.IsExpired(key, 1*time.Hour) {
		t.Error("Expected secret to not be expired")
	}

	if !cache.IsExpired(key, -1*time.Second) {
		t.Error("Expected secret to be expired with negative TTL")
	}

	// Test Delete
	if err := cache.Delete(key); err != nil {
		t.Errorf("Failed to delete secret: %v", err)
	}

	gotDeleted, _ := cache.Get(key)
	if gotDeleted != nil {
		t.Error("Expected deleted secret to be nil")
	}
}

func TestGosecTraversalFix(t *testing.T) {
	cache, _ := NewDiskCache()

	// Ensure that path traversal attempts are blocked
	key := "../../etc/passwd"
	secret := Secret{Value: "traversal-test"}

	err := cache.Set(key, secret, 1*time.Hour)
	if err == nil {
		t.Fatal("Expected error for traversal attempt, got nil")
	}

	if !strings.Contains(err.Error(), "traversal attempt detected") {
		t.Errorf("Expected traversal error message, got: %v", err)
	}
}
