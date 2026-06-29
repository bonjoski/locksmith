//go:build test_native

package locksmith

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestListAndListWithMetadata(t *testing.T) {
	cache := newMockCache()
	ls := &Locksmith{Service: DefaultService, Cache: cache, Backend: newMockBackend(), Options: Options{}}
	// Use mock backend
	mb := newMockBackend()
	ls.Backend = mb

	// Insert a secret via mock backend directly
	key := "my/secret"
	secret := Secret{Value: []byte("val"), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	defer func() {
		for i := range secret.Value {
			secret.Value[i] = 0
		}
	}()
	data, _ := json.Marshal(secret)
	mb.Set(ls.Service, key, data, false)
	// Also cache it for metadata retrieval
	_ = cache.Set(key, secret, DefaultCacheTTL)

	// Allow binary list to include current executable
	execPath, _ := os.Executable()
	ls.Config = &Config{AccessControl: AccessControl{AllowBinaries: []string{execPath}}}

	// Test List
	list, err := ls.List()
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if _, ok := list[key]; !ok {
		t.Fatalf("List missing key: %s", key)
	}

	// Test ListWithMetadata
	metaMap, err := ls.ListWithMetadata()
	if err != nil {
		t.Fatalf("ListWithMetadata error: %v", err)
	}
	meta, ok := metaMap[key]
	if !ok {
		t.Fatalf("Metadata missing for key: %s", key)
	}
	if meta.CreatedAt.IsZero() || meta.ExpiresAt.IsZero() {
		t.Fatalf("Metadata timestamps not set")
	}
}

func TestListDenyBinary(t *testing.T) {
	cache := newMockCache()
	ls := &Locksmith{Service: DefaultService, Cache: cache, Backend: newMockBackend(), Options: Options{}}
	mb := newMockBackend()
	ls.Backend = mb

	// Populate a secret
	key := "secret"
	secret := Secret{Value: []byte("v"), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	defer func() {
		for i := range secret.Value {
			secret.Value[i] = 0
		}
	}()
	data, _ := json.Marshal(secret)
	mb.Set(ls.Service, key, data, false)

	execPath, _ := os.Executable()
	ls.Config = &Config{AccessControl: AccessControl{DenyBinaries: []string{execPath}}}

	_, err := ls.List()
	if err == nil {
		t.Fatalf("Expected error due to deny binary, got nil")
	}
}
