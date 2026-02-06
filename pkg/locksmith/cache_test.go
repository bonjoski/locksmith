package locksmith

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDiskCache(t *testing.T) {
	mockKey := make([]byte, 32)
	cache, err := NewDiskCache(mockKey)
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
	mockKey := make([]byte, 32)
	cache, _ := NewDiskCache(mockKey)

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

func TestDiskCacheEncryption(t *testing.T) {
	mockKey := make([]byte, 32)
	copy(mockKey, "this-is-a-32-byte-long-mock-key!")
	cache, _ := NewDiskCache(mockKey)

	key := "encrypt-test"
	secret := Secret{Value: "super-secret"}
	defer func() { _ = cache.Delete(key) }()

	if err := cache.Set(key, secret, time.Hour); err != nil {
		t.Fatalf("Failed to set secret: %v", err)
	}

	// Manually read the file
	data, err := os.ReadFile(cache.Dir + "/" + key)
	if err != nil {
		t.Fatalf("Failed to read raw cache file: %v", err)
	}

	// Verify it's NOT valid JSON (or at least doesn't contain the secret)
	if strings.Contains(string(data), "super-secret") {
		t.Error("Cache file contains plain text secret!")
	}

	var s Secret
	if err := json.Unmarshal(data, &s); err == nil {
		t.Error("Cache file is valid JSON, expected encrypted binary")
	}

	// Verify we can still Get it
	got, err := cache.Get(key)
	if err != nil {
		t.Fatalf("Failed to get encrypted secret: %v", err)
	}
	if got.Value != "super-secret" {
		t.Errorf("Expected super-secret, got %s", got.Value)
	}
}
