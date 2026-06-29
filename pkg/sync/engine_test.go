//go:build locksmith_admin

package sync

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

type mockSyncCache struct {
	secrets map[string]locksmith.Secret
}

func (m *mockSyncCache) Set(key string, secret locksmith.Secret, ttl time.Duration) error {
	m.secrets[key] = secret
	return nil
}

func (m *mockSyncCache) Get(key string) (*locksmith.Secret, error) {
	s, ok := m.secrets[key]
	if !ok {
		return nil, nil
	}
	return &s, nil
}

func (m *mockSyncCache) Delete(key string) error {
	delete(m.secrets, key)
	return nil
}

func (m *mockSyncCache) IsExpired(key string, ttl time.Duration) bool {
	return false
}

type mockSyncBackend struct {
	secrets map[string][]byte
}

func (m *mockSyncBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	m.secrets[account] = data
	return nil
}

func (m *mockSyncBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	data, ok := m.secrets[account]
	if !ok {
		return nil, fmt.Errorf("secret not found")
	}
	return data, nil
}

func (m *mockSyncBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	delete(m.secrets, account)
	return nil
}

func (m *mockSyncBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	var keys []string
	for k := range m.secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

func setupTestLocksmith() (*locksmith.Locksmith, *mockSyncCache, *mockSyncBackend) {
	mc := &mockSyncCache{secrets: make(map[string]locksmith.Secret)}
	mb := &mockSyncBackend{secrets: make(map[string][]byte)}
	ls := locksmith.NewWithCache(mc)
	ls.Backend = mb
	ls.Options.RequireBiometrics = false
	return ls, mc, mb
}

func TestExportImportVault(t *testing.T) {
	ls, _, _ := setupTestLocksmith()

	// 1. Populate some secrets
	t1 := time.Now().Add(-10 * time.Minute)
	t2 := time.Now().Add(-5 * time.Minute)

	_ = ls.ImportSecret("key1", locksmith.Secret{Value: []byte("val1"), CreatedAt: t1, ExpiresAt: t1.Add(time.Hour)}, false)
	_ = ls.ImportSecret("key2", locksmith.Secret{Value: []byte("val2"), CreatedAt: t2, ExpiresAt: t2.Add(time.Hour)}, false)

	// 2. Export
	data, err := ExportVault(ls)
	if err != nil {
		t.Fatalf("ExportVault failed: %v", err)
	}

	var payload SyncPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("Failed to parse exported JSON: %v", err)
	}

	if len(payload.Secrets) != 2 {
		t.Errorf("Expected 2 secrets in payload, got %d", len(payload.Secrets))
	}

	// 3. Import into a clean vault
	lsDest, mcDest, _ := setupTestLocksmith()
	imported, err := ImportVault(lsDest, data, "latest-wins")
	if err != nil {
		t.Fatalf("ImportVault failed: %v", err)
	}

	if imported != 2 {
		t.Errorf("Expected 2 imported secrets, got %d", imported)
	}

	s1, _ := mcDest.Get("key1")
	if s1 == nil || string(s1.Value) != "val1" {
		t.Error("Expected key1 to be imported correctly")
	}

	s2, _ := mcDest.Get("key2")
	if s2 == nil || string(s2.Value) != "val2" {
		t.Error("Expected key2 to be imported correctly")
	}
}

func TestImportMergePolicies(t *testing.T) {
	// Base secrets to import
	baseTime := time.Now().Add(-10 * time.Minute)
	importedPayload := SyncPayload{
		Secrets: map[string]SyncSecret{
			"conflict-key": {
				Value:     []byte("imported-value"),
				CreatedAt: baseTime,
				ExpiresAt: baseTime.Add(time.Hour),
			},
		},
		ExportedAt: time.Now(),
	}
	payloadBytes, _ := json.Marshal(importedPayload)

	// 1. Policy: latest-wins (Local is older, should be updated)
	t.Run("latest-wins-local-older", func(t *testing.T) {
		ls, mc, _ := setupTestLocksmith()
		olderTime := baseTime.Add(-5 * time.Minute)
		_ = ls.ImportSecret("conflict-key", locksmith.Secret{Value: []byte("local-value"), CreatedAt: olderTime}, false)

		count, err := ImportVault(ls, payloadBytes, "latest-wins")
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected 1 secret to be updated, got %d", count)
		}
		s, _ := mc.Get("conflict-key")
		if string(s.Value) != "imported-value" {
			t.Errorf("Expected 'imported-value', got '%s'", s.Value)
		}
	})

	// 2. Policy: latest-wins (Local is newer, should NOT be updated)
	t.Run("latest-wins-local-newer", func(t *testing.T) {
		ls, mc, _ := setupTestLocksmith()
		newerTime := baseTime.Add(5 * time.Minute)
		_ = ls.ImportSecret("conflict-key", locksmith.Secret{Value: []byte("local-value"), CreatedAt: newerTime}, false)

		count, err := ImportVault(ls, payloadBytes, "latest-wins")
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}
		if count != 0 {
			t.Errorf("Expected 0 secrets to be updated, got %d", count)
		}
		s, _ := mc.Get("conflict-key")
		if string(s.Value) != "local-value" {
			t.Errorf("Expected local secret to remain 'local-value', got '%s'", s.Value)
		}
	})

	// 3. Policy: overwrite (Should always update)
	t.Run("overwrite", func(t *testing.T) {
		ls, mc, _ := setupTestLocksmith()
		newerTime := baseTime.Add(5 * time.Minute)
		_ = ls.ImportSecret("conflict-key", locksmith.Secret{Value: []byte("local-value"), CreatedAt: newerTime}, false)

		count, err := ImportVault(ls, payloadBytes, "overwrite")
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected 1 secret to be updated, got %d", count)
		}
		s, _ := mc.Get("conflict-key")
		if string(s.Value) != "imported-value" {
			t.Errorf("Expected 'imported-value', got '%s'", s.Value)
		}
	})

	// 4. Policy: keep-local (Should never update)
	t.Run("keep-local", func(t *testing.T) {
		ls, mc, _ := setupTestLocksmith()
		olderTime := baseTime.Add(-5 * time.Minute)
		_ = ls.ImportSecret("conflict-key", locksmith.Secret{Value: []byte("local-value"), CreatedAt: olderTime}, false)

		count, err := ImportVault(ls, payloadBytes, "keep-local")
		if err != nil {
			t.Fatalf("Import failed: %v", err)
		}
		if count != 0 {
			t.Errorf("Expected 0 secrets to be updated, got %d", count)
		}
		s, _ := mc.Get("conflict-key")
		if string(s.Value) != "local-value" {
			t.Errorf("Expected local secret to remain 'local-value', got '%s'", s.Value)
		}
	})
}
