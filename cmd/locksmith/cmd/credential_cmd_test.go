package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

func TestCredentialGet(t *testing.T) {
	outBuf, _ := setupTest()

	// Pre-seed some secrets into the mock cache/backend
	mc := ls.Cache.(*mockCache)
	_ = mc.Set("git/github.com/myuser", locksmith.Secret{
		Value:     []byte("password123"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, locksmith.DefaultCacheTTL)

	_ = mc.Set("github/gh/token", locksmith.Secret{
		Value:     []byte("ghtokenxyz"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, locksmith.DefaultCacheTTL)

	// Test 1: get exact match
	stdin := "protocol=https\nhost=github.com\nusername=myuser\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetOut(outBuf)
	rootCmd.SetArgs([]string{"credential", "get"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential get: %v", err)
	}

	outStr := outBuf.String()
	if !strings.Contains(outStr, "username=myuser") {
		t.Errorf("Expected username=myuser in output, got %q", outStr)
	}
	if !strings.Contains(outStr, "password=password123") {
		t.Errorf("Expected password=password123 in output, got %q", outStr)
	}

	// Direct lookup check
	directSecret, directErr := ls.GetWithMetadata("github/gh/token")
	t.Logf("Direct lookup of github/gh/token: secret=%+v, err=%v", directSecret, directErr)
	if directSecret != nil {
		t.Logf("Direct value: %q", string(directSecret.Value))
	}

	// Test 2: fallback to github/gh/token
	outBuf.Reset()
	stdin = "protocol=https\nhost=github.com\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetOut(outBuf)
	rootCmd.SetArgs([]string{"credential", "get"})

	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential get: %v", err)
	}

	outStr = outBuf.String()
	t.Logf("Fallback test output: %q", outStr)
	// Since no username is in stdin, it falls back to github/gh/token.
	// Since it's github/gh/token, the username outputs as "oauth2".
	if !strings.Contains(outStr, "username=oauth2") {
		t.Errorf("Expected username=oauth2, got %q", outStr)
	}
	if !strings.Contains(outStr, "password=ghtokenxyz") {
		t.Errorf("Expected password=ghtokenxyz, got %q", outStr)
	}
}

func TestCredentialStore(t *testing.T) {
	_, _ = setupTest()

	stdin := "protocol=https\nhost=gitlab.com\nusername=gitlabuser\npassword=tokenabc\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs([]string{"credential", "store"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential store: %v", err)
	}

	secret, err := ls.GetWithMetadata("git/gitlab.com/gitlabuser")
	if err != nil {
		t.Fatalf("Failed to retrieve stored secret: %v", err)
	}
	if secret == nil {
		t.Fatal("Secret was not stored")
		return
	}
	if string(secret.Value) != "tokenabc" {
		t.Errorf("Expected secret value tokenabc, got %q", string(secret.Value))
	}
	if secret.Metadata["username"] != "gitlabuser" {
		t.Errorf("Expected metadata username gitlabuser, got %q", secret.Metadata["username"])
	}
}

func TestCredentialErase(t *testing.T) {
	_, _ = setupTest()

	mc := ls.Cache.(*mockCache)
	_ = mc.Set("git/github.com/myuser", locksmith.Secret{
		Value: []byte("pass"),
	}, locksmith.DefaultCacheTTL)

	stdin := "protocol=https\nhost=github.com\nusername=myuser\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs([]string{"credential", "erase"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential erase: %v", err)
	}

	secret, _ := mc.Get("git/github.com/myuser")
	if secret != nil {
		t.Error("Expected secret to be deleted, but it still exists")
	}
}

func TestAddCommandWithGitFlag(t *testing.T) {
	outBuf, _ := setupTest()

	// Test 1: add with host and username (2 args)
	stdin := "mypassword123\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetOut(outBuf)
	rootCmd.SetArgs([]string{"add", "github.com", "mygituser", "--git"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute add command with --git flag: %v", err)
	}

	secret, err := ls.GetWithMetadata("git/github.com/mygituser")
	if err != nil {
		t.Fatalf("Failed to retrieve stored git secret: %v", err)
	}
	if secret == nil {
		t.Fatal("Secret was not stored")
		return
	}
	if string(secret.Value) != "mypassword123" {
		t.Errorf("Expected mypassword123, got %q", string(secret.Value))
	}
	if secret.Metadata["username"] != "mygituser" {
		t.Errorf("Expected mygituser, got %q", secret.Metadata["username"])
	}

	// Test 2: add with host only (1 arg) and username prompted
	outBuf.Reset()
	_, _ = setupTest() // reset
	addGit = true      // setupTest resets it, so we must set it back to true
	stdin = "promptuser\npromptpassword\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetOut(outBuf)
	rootCmd.SetArgs([]string{"add", "gitlab.com", "--git"})

	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute add command with --git flag: %v", err)
	}

	secret, err = ls.GetWithMetadata("git/gitlab.com/promptuser")
	if err != nil {
		t.Fatalf("Failed to retrieve stored git secret: %v", err)
	}
	if secret == nil {
		t.Fatal("Secret was not stored")
		return
	}
	if string(secret.Value) != "promptpassword" {
		t.Errorf("Expected promptpassword, got %q", string(secret.Value))
	}
	if secret.Metadata["username"] != "promptuser" {
		t.Errorf("Expected promptuser, got %q", secret.Metadata["username"])
	}
}

func TestCredentialCommand_SetsOnlyCached(t *testing.T) {
	outBuf, _ := setupTest()

	// Verify OnlyCached starts as false
	if ls.Options.OnlyCached {
		t.Error("Expected OnlyCached to be false before credential command")
	}

	// Pre-seed cache with a credential
	mc := ls.Cache.(*mockCache)
	_ = mc.Set("git/github.com/testuser", locksmith.Secret{
		Value:     []byte("cached-token"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, locksmith.DefaultCacheTTL)

	// Execute credential get command
	stdin := "protocol=https\nhost=github.com\nusername=testuser\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetOut(outBuf)
	rootCmd.SetArgs([]string{"credential", "get"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential get: %v", err)
	}

	// Verify OnlyCached is NOT set (we removed this feature)
	if ls.Options.OnlyCached {
		t.Error("Expected OnlyCached to remain false (feature removed)")
	}

	// Verify it returned from cache
	outStr := outBuf.String()
	if !strings.Contains(outStr, "password=cached-token") {
		t.Errorf("Expected credential to return from cache, got: %q", outStr)
	}
}

func TestCredentialStore_DoesNotSetOnlyCached(t *testing.T) {
	setupTest()

	// Verify OnlyCached starts as false
	if ls.Options.OnlyCached {
		t.Error("Expected OnlyCached to be false before credential command")
	}

	stdin := "protocol=https\nhost=gitlab.com\nusername=storeuser\npassword=storetoken\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs([]string{"credential", "store"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential store: %v", err)
	}

	// Verify OnlyCached was NOT set for 'store' action (it should still be false)
	if ls.Options.OnlyCached {
		t.Error("Expected credential STORE command to NOT set OnlyCached=true")
	}
}

func TestCredentialGet_CacheMiss_ReturnsEmpty(t *testing.T) {
	outBuf, _ := setupTest()

	// Don't seed cache - this simulates a cache miss
	// Without OnlyCached, cache miss falls back to keychain backend

	// Execute credential get for a key that doesn't exist in cache or backend
	stdin := "protocol=https\nhost=gitlab.com\nusername=nonexistent\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetOut(outBuf)
	rootCmd.SetArgs([]string{"credential", "get"})

	// Track backend calls
	mb := ls.Backend.(*mockBackend)
	initialGetCalls := mb.getCalls

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential get: %v", err)
	}

	// Verify OnlyCached was NOT set (feature removed)
	if ls.Options.OnlyCached {
		t.Error("Expected OnlyCached to remain false (feature removed)")
	}

	// Verify backend WAS called (cache miss triggers backend fallback)
	if mb.getCalls <= initialGetCalls {
		t.Errorf("Expected backend Get to be called on cache miss, but getCalls stayed at %d",
			mb.getCalls)
	}

	outStr := outBuf.String()
	// Should return empty (no output) because key doesn't exist in backend either
	if strings.Contains(outStr, "password=") {
		t.Errorf("Expected empty output when credential doesn't exist, got: %q", outStr)
	}
	if strings.Contains(outStr, "username=") {
		t.Errorf("Expected empty output when credential doesn't exist, got: %q", outStr)
	}
}
