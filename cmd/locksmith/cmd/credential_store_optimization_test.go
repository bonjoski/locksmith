package cmd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

func TestCredentialStore_SkipsKeychainWriteWhenUnchanged(t *testing.T) {
	setupTest()

	// Pre-store a credential in cache and backend
	testPassword := "test-token-12345"
	mc := ls.Cache.(*mockCache)
	mb := ls.Backend.(*mockBackend)

	// Initialize mock backend storage
	if mb.storage == nil {
		mb.storage = make(map[string][]byte)
	}

	// Populate both cache and backend to simulate existing credential
	secret := locksmith.Secret{
		Value:     []byte(testPassword),
		CreatedAt: time.Now(),
		ExpiresAt: time.Time{},
	}
	_ = mc.Set("git/test.example.com/testuser", secret, locksmith.DefaultCacheTTL)

	// Store the JSON-encoded secret in backend (as it would be in real keychain)
	secretJSON, _ := json.Marshal(secret)
	mb.storage["git/test.example.com/testuser"] = secretJSON

	// Track backend Set calls
	initialSetCalls := mb.setCalls

	// Simulate git calling 'credential store' with the SAME credential
	stdin := "protocol=https\nhost=test.example.com\nusername=testuser\npassword=test-token-12345\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs([]string{"credential", "store"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential store: %v", err)
	}

	// Verify backend Set was NOT called (no keychain write, no biometric prompt)
	if mb.setCalls != initialSetCalls {
		t.Errorf("Expected backend Set to NOT be called when credential is unchanged, but setCalls went from %d to %d",
			initialSetCalls, mb.setCalls)
	}

	// Verify cache was refreshed
	cached, err := mc.Get("git/test.example.com/testuser")
	if err != nil || cached == nil {
		t.Error("Expected cache to be refreshed")
	}
	if string(cached.Value) != testPassword {
		t.Errorf("Expected cached password %q, got %q", testPassword, string(cached.Value))
	}
}

func TestCredentialStore_WritesKeychainWhenChanged(t *testing.T) {
	setupTest()

	// Pre-store a credential with OLD password
	oldPassword := "old-token"
	newPassword := "new-token-67890"
	mc := ls.Cache.(*mockCache)
	mb := ls.Backend.(*mockBackend)

	// Initialize mock backend storage
	if mb.storage == nil {
		mb.storage = make(map[string][]byte)
	}

	oldSecret := locksmith.Secret{
		Value:     []byte(oldPassword),
		CreatedAt: time.Now(),
		ExpiresAt: time.Time{},
	}
	_ = mc.Set("git/test.example.com/testuser", oldSecret, locksmith.DefaultCacheTTL)

	// Store the JSON-encoded secret in backend
	oldSecretJSON, _ := json.Marshal(oldSecret)
	mb.storage["git/test.example.com/testuser"] = oldSecretJSON

	// Track backend Set calls
	initialSetCalls := mb.setCalls

	// Simulate git calling 'credential store' with a NEW credential
	stdin := "protocol=https\nhost=test.example.com\nusername=testuser\npassword=new-token-67890\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs([]string{"credential", "store"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential store: %v", err)
	}

	// Verify backend Set WAS called (keychain write happened)
	if mb.setCalls == initialSetCalls {
		t.Error("Expected backend Set to be called when credential changed, but it was not")
	}

	// Verify new password is stored in backend
	storedData := mb.storage["git/test.example.com/testuser"]
	var storedSecret locksmith.Secret
	if err := json.Unmarshal(storedData, &storedSecret); err != nil {
		t.Fatalf("Failed to unmarshal stored secret: %v", err)
	}
	if string(storedSecret.Value) != newPassword {
		t.Errorf("Expected new password %q in backend, got %q",
			newPassword, string(storedSecret.Value))
	}
}
