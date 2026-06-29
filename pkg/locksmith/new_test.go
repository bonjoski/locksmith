//go:build test_native

package locksmith

import "testing"

func TestNewAndGetMissing(t *testing.T) {
	ls, err := New()
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if ls == nil {
		t.Fatalf("New returned nil Locksmith")
	}
	// Attempt to get a non‑existent secret; expect an error.
	if _, err = ls.Get("nonexistent-key"); err == nil {
		t.Fatalf("expected error when getting missing secret, got nil")
	}
}
